// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The lock channel: an ephemeral P-256 agreement whose key opens exactly one
//! ChaCha20-Poly1305 box, so the unlock secret — and the SO-PIN that arms it —
//! never cross the wire in the clear, and a recorded exchange cannot be replayed
//! against the next power cycle's agreement.

use rsk_crypto::chachapoly::chacha20poly1305_decrypt;
use rsk_crypto::hkdf_sha256;
use rsk_crypto::pinproto::{ecdh_raw, public_xy};
use rsk_sdk::Rng;
use zeroize::Zeroize;

use crate::seal::{KEY_LEN, Wiped};

/// An uncompressed P-256 point, `04 ‖ X ‖ Y`.
pub(crate) const POINT_LEN: usize = 65;
const COORD: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// What a box adds around its plaintext: `nonce ‖ ct ‖ tag`.
pub(crate) const BOX_OVERHEAD: usize = NONCE_LEN + TAG_LEN;
/// Salt of the channel-key derivation, so it can never equal another agreement's.
const SALT: &[u8] = b"RSK-HSM/LOCK-CHANNEL";

/// One agreement: its key and the device half, which every box binds. Wipes its
/// key when it drops — which is at its one use, or when a newer agreement, a
/// selection or a power cycle replaces it.
pub(crate) struct Channel {
    key: [u8; KEY_LEN],
    dev_pub: [u8; POINT_LEN],
}

impl Drop for Channel {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl Channel {
    /// Agree with the host's ephemeral `host_pub`. `None` for a point that is not
    /// on the curve.
    pub(crate) fn agree(host_pub: &[u8], rng: &mut dyn Rng) -> Option<Channel> {
        if host_pub.len() != POINT_LEN || host_pub[0] != 0x04 {
            return None;
        }
        let mut hx = [0u8; COORD];
        let mut hy = [0u8; COORD];
        hx.copy_from_slice(&host_pub[1..1 + COORD]);
        hy.copy_from_slice(&host_pub[1 + COORD..]);
        let mut scalar = Wiped::<COORD>::zeroed();
        let (dx, dy) = loop {
            rng.fill(&mut scalar[..]);
            if let Some(p) = public_xy(&scalar) {
                break p;
            }
        };
        let z = Wiped::new(ecdh_raw(&scalar, &hx, &hy).ok()?);
        let mut dev_pub = [0u8; POINT_LEN];
        dev_pub[0] = 0x04;
        dev_pub[1..1 + COORD].copy_from_slice(&dx);
        dev_pub[1 + COORD..].copy_from_slice(&dy);
        let mut info = [0u8; 2 * POINT_LEN];
        info[..POINT_LEN].copy_from_slice(&dev_pub);
        info[POINT_LEN..].copy_from_slice(host_pub);
        let mut ch = Channel {
            key: [0u8; KEY_LEN],
            dev_pub,
        };
        hkdf_sha256(SALT, &z[..], &info, &mut ch.key).ok()?;
        Some(ch)
    }

    /// The device half, for the host to agree with.
    pub(crate) fn dev_pub(&self) -> &[u8; POINT_LEN] {
        &self.dev_pub
    }

    /// Open the channel's one box into `out`, which must be exactly the plaintext
    /// length. Consumes the channel whatever the outcome.
    pub(crate) fn open(self, blob: &[u8], out: &mut [u8]) -> bool {
        if blob.len() != BOX_OVERHEAD + out.len() {
            return false;
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&blob[..NONCE_LEN]);
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&blob[blob.len() - TAG_LEN..]);
        out.copy_from_slice(&blob[NONCE_LEN..blob.len() - TAG_LEN]);
        let ok = chacha20poly1305_decrypt(&self.key, &nonce, &self.dev_pub, out, &tag).is_ok();
        if !ok {
            out.zeroize();
        }
        ok
    }
}

#[cfg(test)]
#[path = "channel_tests.rs"]
mod tests;
