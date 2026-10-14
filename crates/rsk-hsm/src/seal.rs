// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The key hierarchy and the one sealed-record format every HSM secret is stored in.
//!
//! Three keys, each answering one question. **DK** — is this the device, and is
//! the lock open? — is sealed under `K_dev = HKDF(serial_hash, kbase [‖ L])`, so it
//! inherits the OTP story of every other sealed record and, while the lock is
//! armed, needs the unlock secret `L` as well. **HMK** — is the PIN right? — is
//! sealed under a PIN-derived key keyed by DK, so a flash dump without DK has no
//! offline oracle for the PIN. Every **key object** is sealed under a key derived
//! from HMK and its own file identifier.

use core::ops::{Deref, DerefMut};

use rsk_crypto::{Device, aes256gcm_decrypt, aes256gcm_encrypt, hkdf_sha256, hmac_sha256};
use rsk_sdk::Rng;
use zeroize::Zeroize;

/// The only record format: AES-256-GCM, `fmt ‖ nonce ‖ ct ‖ tag`.
pub(crate) const FMT_GCM: u8 = 1;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// What sealing adds to a plaintext.
pub(crate) const SEAL_OVERHEAD: usize = 1 + NONCE_LEN + TAG_LEN;
/// Every key in the hierarchy is 256 bits.
pub(crate) const KEY_LEN: usize = 32;
/// A sealed 32-byte key.
pub(crate) const SEALED_KEY_LEN: usize = SEAL_OVERHEAD + KEY_LEN;

/// Associated data: the record's FID and format byte, then what the caller binds.
const AAD_MAX: usize = 96;

// Derivation labels. Distinct per use, so no key ever serves two roles.
const INFO_DEV: &[u8] = b"RSK-HSM/DEV";
const LABEL_PIN: &[u8] = b"RSK-HSM/PIN";
const LABEL_SO_VERIFIER: &[u8] = b"RSK-HSM/SO";
const INFO_OBJECT: &[u8] = b"RSK-HSM/OBJECT";
const INFO_DEVAUT: &[u8] = b"RSK-HSM/DEVAUT";

/// A fixed-size secret that wipes itself when it drops. Every key, unlock secret
/// and decrypted buffer in this crate is one, so a `?` that leaves a frame early
/// wipes what the frame held exactly as the normal return does.
pub(crate) struct Wiped<const N: usize>([u8; N]);

impl<const N: usize> Wiped<N> {
    pub(crate) const fn zeroed() -> Self {
        Wiped([0; N])
    }

    /// Take ownership of `bytes`. The array passed in is a copy the caller still
    /// holds, so pass a temporary rather than a binding.
    pub(crate) const fn new(bytes: [u8; N]) -> Self {
        Wiped(bytes)
    }
}

impl<const N: usize> Drop for Wiped<N> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<const N: usize> Deref for Wiped<N> {
    type Target = [u8; N];
    fn deref(&self) -> &[u8; N] {
        &self.0
    }
}

impl<const N: usize> DerefMut for Wiped<N> {
    fn deref_mut(&mut self) -> &mut [u8; N] {
        &mut self.0
    }
}

impl<const N: usize> Clone for Wiped<N> {
    fn clone(&self) -> Self {
        Wiped(self.0)
    }
}

/// A 256-bit key that wipes itself.
pub(crate) type Key = Wiped<KEY_LEN>;

/// Why a sealed record did not open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unseal {
    /// The bytes are not a record of this format or this size.
    Malformed,
    /// The tag did not verify: the wrong key, or bytes that were altered.
    Auth,
}

/// A fresh random 256-bit key.
pub(crate) fn random_key(rng: &mut dyn Rng) -> Key {
    let mut k = Key::zeroed();
    rng.fill(&mut k[..]);
    k
}

fn aad(fid: u16, bind: &[u8], out: &mut [u8; AAD_MAX]) -> usize {
    let [hi, lo] = fid.to_be_bytes();
    out[0] = hi;
    out[1] = lo;
    out[2] = FMT_GCM;
    let n = 3 + bind.len();
    out[3..n].copy_from_slice(bind);
    n
}

/// Seal `pt` for the record at `fid` into `out`, binding `bind` (the record's
/// clear header) as associated data. Returns the sealed length.
pub(crate) fn seal(
    key: &[u8; KEY_LEN],
    fid: u16,
    bind: &[u8],
    pt: &[u8],
    rng: &mut dyn Rng,
    out: &mut [u8],
) -> usize {
    assert!(bind.len() + 3 <= AAD_MAX && out.len() >= SEAL_OVERHEAD + pt.len());
    let mut a = [0u8; AAD_MAX];
    let an = aad(fid, bind, &mut a);
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill(&mut nonce);
    let ct_end = 1 + NONCE_LEN + pt.len();
    out[0] = FMT_GCM;
    out[1..1 + NONCE_LEN].copy_from_slice(&nonce);
    out[1 + NONCE_LEN..ct_end].copy_from_slice(pt);
    let tag = aes256gcm_encrypt(key, &nonce, &a[..an], &mut out[1 + NONCE_LEN..ct_end]);
    out[ct_end..ct_end + TAG_LEN].copy_from_slice(&tag);
    ct_end + TAG_LEN
}

/// Open the record at `fid` sealed by [`seal`] into `out`; returns the plaintext
/// length. On any failure `out` holds nothing of the plaintext.
pub(crate) fn open(
    key: &[u8; KEY_LEN],
    fid: u16,
    bind: &[u8],
    blob: &[u8],
    out: &mut [u8],
) -> Result<usize, Unseal> {
    if blob.len() < SEAL_OVERHEAD || blob[0] != FMT_GCM || bind.len() + 3 > AAD_MAX {
        return Err(Unseal::Malformed);
    }
    let n = blob.len() - SEAL_OVERHEAD;
    if n > out.len() {
        return Err(Unseal::Malformed);
    }
    let mut a = [0u8; AAD_MAX];
    let an = aad(fid, bind, &mut a);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&blob[1..1 + NONCE_LEN]);
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&blob[1 + NONCE_LEN + n..]);
    out[..n].copy_from_slice(&blob[1 + NONCE_LEN..1 + NONCE_LEN + n]);
    match aes256gcm_decrypt(key, &nonce, &a[..an], &mut out[..n], &tag) {
        Ok(()) => Ok(n),
        Err(_) => {
            out[..n].zeroize();
            Err(Unseal::Auth)
        }
    }
}

/// Seal a 32-byte key; the output is exactly [`SEALED_KEY_LEN`].
pub(crate) fn seal_key(
    key: &[u8; KEY_LEN],
    fid: u16,
    bind: &[u8],
    secret: &[u8; KEY_LEN],
    rng: &mut dyn Rng,
) -> [u8; SEALED_KEY_LEN] {
    let mut out = [0u8; SEALED_KEY_LEN];
    seal(key, fid, bind, secret, rng, &mut out);
    out
}

/// Open a sealed 32-byte key.
pub(crate) fn open_key(
    key: &[u8; KEY_LEN],
    fid: u16,
    bind: &[u8],
    blob: &[u8],
) -> Result<Key, Unseal> {
    if blob.len() != SEALED_KEY_LEN {
        return Err(Unseal::Malformed);
    }
    let mut k = Key::zeroed();
    open(key, fid, bind, blob, &mut k[..])?;
    Ok(k)
}

/// `K_dev`: what seals DK. The unlock secret joins the device root while the lock
/// is armed, so an armed DK needs both.
pub(crate) fn device_key(dev: &Device, unlock: Option<&[u8; KEY_LEN]>) -> Key {
    let mut ikm = Wiped::<{ 2 * KEY_LEN }>::zeroed();
    ikm[..KEY_LEN].copy_from_slice(&dev.derive_kbase());
    let n = match unlock {
        Some(l) => {
            ikm[KEY_LEN..].copy_from_slice(l);
            2 * KEY_LEN
        }
        None => KEY_LEN,
    };
    let mut k = Key::zeroed();
    hkdf_sha256(dev.serial_hash, &ikm[..n], INFO_DEV, &mut k[..]).expect("32-byte HKDF output");
    k
}

/// The key a PIN envelope is sealed under: keyed by DK, so it can only be tried
/// on a device that can open DK.
pub(crate) fn pin_key(dk: &[u8; KEY_LEN], reference: u8, pin: &[u8]) -> Key {
    let mut msg = Wiped::<64>::zeroed();
    let n = LABEL_PIN.len() + 1 + pin.len();
    assert!(n <= msg.len());
    msg[..LABEL_PIN.len()].copy_from_slice(LABEL_PIN);
    msg[LABEL_PIN.len()] = reference;
    msg[LABEL_PIN.len() + 1..n].copy_from_slice(pin);
    Key::new(hmac_sha256(dk, &msg[..n]))
}

/// The SO-PIN verifier: keyed by the device root alone, because re-initializing
/// a locked device — the one thing the SO can do without DK — still needs it.
pub(crate) fn so_verifier(dev: &Device, so_pin: &[u8]) -> [u8; KEY_LEN] {
    let kbase = Key::new(dev.derive_kbase());
    let mut msg = Wiped::<32>::zeroed();
    let n = LABEL_SO_VERIFIER.len() + so_pin.len();
    assert!(n <= msg.len());
    msg[..LABEL_SO_VERIFIER.len()].copy_from_slice(LABEL_SO_VERIFIER);
    msg[LABEL_SO_VERIFIER.len()..n].copy_from_slice(so_pin);
    hmac_sha256(&kbase[..], &msg[..n])
}

/// The key the device key (`CC00`) is sealed under: the device root's alone,
/// because that key outlives every owner and every PIN.
pub(crate) fn device_auth_key(dev: &Device) -> Key {
    let kbase = Key::new(dev.derive_kbase());
    let mut k = Key::zeroed();
    hkdf_sha256(dev.serial_hash, &kbase[..], INFO_DEVAUT, &mut k[..]).expect("32-byte HKDF output");
    k
}

/// The key an object at `fid` is sealed under.
pub(crate) fn object_key(hmk: &[u8; KEY_LEN], fid: u16) -> Key {
    let mut k = Key::zeroed();
    hkdf_sha256(&fid.to_be_bytes(), hmk, INFO_OBJECT, &mut k[..]).expect("32-byte HKDF output");
    k
}

#[cfg(test)]
#[path = "seal_tests.rs"]
mod tests;
