// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The device's attestation identity: the device key (`CC00`, P-256), which signs
//! every key request this device answers, and `2F02`, the two CV certificates
//! that tie it to the device root. The root is the device attestation key the
//! rescue applet holds (secp256k1), reached through a signing seam the wiring
//! fills at boot — so this crate never names another applet.
//!
//! `2F02` is what the driver binds the token by: it reads the serial out of the
//! first certificate's holder reference, and refuses a token without one.

use rsk_crypto::{Device, sha256};
use rsk_ec::{Curve, MAX_EC_POINT, PrivKey};
use rsk_fs::{Fs, Storage};
use rsk_sdk::{Rng, Sw};

use crate::consts::*;
use crate::cvc::{MNEMONIC_DEVICE, MNEMONIC_ROOT, PublicKey, SigAlg, Writer, put_body, reference};
use crate::domain::{K256, P256};
use crate::keyops::{EcRng, ec_sw};
use crate::keys::{self, COUNTER_UNLIMITED, KeyObject, KeyType};
use crate::store::{REC_DEVAUT, read_plain};

/// The root's public key: an uncompressed secp256k1 point.
pub const ROOT_POINT_LEN: usize = 65;
/// A root signature: secp256k1 ECDSA, `r ‖ s`.
pub const ROOT_SIG_LEN: usize = 64;
/// The most `2F02` may hold: the driver reads it into a buffer this size.
const DEVAUT_MAX: usize = 1024;

/// What a signing seam answers for a SHA-256 digest, or `None` when the root is
/// unavailable.
pub type RootSign<'s> = &'s mut dyn FnMut(&[u8; 32]) -> Option<[u8; ROOT_SIG_LEN]>;

/// One certificate, `7F21 { 7F4E, 5F37 }`, signed by the root.
fn put_certificate(
    w: &mut Writer,
    holder: &[u8],
    key: &PublicKey,
    root_ref: &[u8],
    sign: RootSign,
) -> Result<(), Sw> {
    let cert = w.open(TAG_CV_CERT)?;
    let start = put_body(w, Some(root_ref), SigAlg::EcdsaSha256, key, holder)?;
    let digest = sha256(&w.as_slice()[start..]);
    let sig = sign(&digest).ok_or(Sw::EXEC_ERROR)?;
    w.put(TAG_CV_SIGNATURE, &sig)?;
    w.close(cert)
}

/// Bring the device key and `2F02` into being: the key once, the certificates
/// whenever they no longer say what they should — a root that changed, a device
/// key re-made. Run by the wiring at boot, before the first command; with no
/// change it writes nothing. Any failure leaves what was there.
pub fn provision<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    rng: &mut dyn Rng,
    root_point: &[u8; ROOT_POINT_LEN],
    root_sign: RootSign,
) -> Result<(), Sw> {
    let device = match keys::load_device(fs, dev, rng)? {
        Some(k) => k,
        None => {
            let k = PrivKey::generate(Curve::P256, &mut EcRng(rng)).ok_or(Sw::EXEC_ERROR)?;
            let obj = KeyObject::new(KeyType::Ec(&P256), COUNTER_UNLIMITED, &[], k.scalar())
                .ok_or(Sw::EXEC_ERROR)?;
            keys::store_device(fs, dev, &obj, rng)?;
            obj
        }
    };
    let key = PrivKey::from_scalar(Curve::P256, device.material()).ok_or(Sw::MEMORY_FAILURE)?;
    let mut point = [0u8; MAX_EC_POINT];
    let pn = key.public_point(&mut point).map_err(ec_sw)?;
    let serial: [u8; 8] = dev.serial_id.try_into().map_err(|_| Sw::EXEC_ERROR)?;
    let root_ref = reference(MNEMONIC_ROOT, serial);
    let device_ref = reference(MNEMONIC_DEVICE, serial);

    let mut buf = [0u8; DEVAUT_MAX];
    let mut w = Writer::new(&mut buf);
    let device_key = PublicKey::Ec {
        domain: &P256,
        point: &point[..pn],
    };
    put_certificate(&mut w, &device_ref, &device_key, &root_ref, &mut *root_sign)?;
    let root_key = PublicKey::Ec {
        domain: &K256,
        point: root_point,
    };
    put_certificate(&mut w, &root_ref, &root_key, &root_ref, &mut *root_sign)?;
    let n = w.len();

    let mut stored = [0u8; DEVAUT_MAX];
    if read_plain(fs, REC_DEVAUT, &mut stored)? == Some(n) && stored[..n] == buf[..n] {
        return Ok(());
    }
    fs.put(REC_DEVAUT, &buf[..n])
        .map_err(|_| Sw::MEMORY_FAILURE)
}

#[cfg(test)]
#[path = "devaut_tests.rs"]
mod tests;
