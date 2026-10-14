// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! SIGN and DECIPHER: the private-key operations, and the access every key use is
//! checked for before one runs. In order: the algorithm is one of the
//! instruction's, the device is initialized, the lock is open, the user PIN is
//! verified, the key exists and its type and its own list admit the algorithm, a
//! use is left — then the touch, if the owner asked for one, and the spent use is
//! persisted before the operation, so a power cut never refunds it.

use rsk_crypto::Device;
use rsk_ec::{EcError, MAX_EC_SIG, PrivKey};
use rsk_fs::{Fs, Storage};
use rsk_rsa::crt::crt_from_plain;
use rsk_rsa::{RsaCrt, RsaError};
use rsk_sdk::{Apdu, Confirm, ResBuf, Rng, Sw};

use crate::HsmApplet;
use crate::auth::{into_sw, require_init};
use crate::consts::*;
use crate::cvc::{SigAlg, Writer, put_ecdsa_der};
use crate::digest::{Hash, MAX_DIGEST};
use crate::keys::{self, COUNTER_UNLIMITED, KeyObject, KeyType};
use crate::seal::Wiped;

/// The applet's randomness behind the RSA layer's own seam.
pub(crate) struct RsaRng<'a>(pub(crate) &'a mut dyn Rng);

impl rsk_rsa::Rng for RsaRng<'_> {
    fn fill(&mut self, buf: &mut [u8]) {
        self.0.fill(buf);
    }
}

/// The applet's randomness behind the EC layer's own seam.
pub(crate) struct EcRng<'a>(pub(crate) &'a mut dyn Rng);

impl rsk_ec::Rng for EcRng<'_> {
    fn fill(&mut self, buf: &mut [u8]) {
        self.0.fill(buf);
    }
}

/// The widest signature or plaintext an operation answers: an RSA-4096 block.
pub(crate) const MAX_OUT: usize = rsk_rsa::MAX_RSA_BYTES;

/// The instruction a key is used through. Each algorithm belongs to one, and a
/// key serves it there and nowhere else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Use {
    Sign,
    Decipher,
    Cipher,
}

impl Use {
    fn of(algo: u8) -> Option<Use> {
        Some(match algo {
            ALGO_RSA_RAW
            | ALGO_RSA_PKCS1
            | ALGO_RSA_PKCS1_SHA256
            | ALGO_RSA_PKCS1_SHA384
            | ALGO_RSA_PKCS1_SHA512
            | ALGO_RSA_PSS
            | ALGO_RSA_PSS_SHA256
            | ALGO_RSA_PSS_SHA384
            | ALGO_RSA_PSS_SHA512
            | ALGO_EC_RAW
            | ALGO_EC_SHA224
            | ALGO_EC_SHA256
            | ALGO_EC_SHA384
            | ALGO_EC_SHA512 => Use::Sign,
            ALGO_RSA_DECRYPT | ALGO_EC_DH => Use::Decipher,
            ALGO_AES_CBC_ENCRYPT | ALGO_AES_CBC_DECRYPT | ALGO_AES_CMAC => Use::Cipher,
            _ => return None,
        })
    }
}

/// AES works in blocks of this many bytes.
pub(crate) const AES_BLOCK: usize = 16;

/// A key ready to operate. Both halves wipe themselves when dropped.
// One lives on the stack for one operation. Boxing the RSA half would put a
// private key on the heap the RSA layer's bignums share, to save stack nobody
// is short of.
#[allow(clippy::large_enum_variant)]
pub(crate) enum Private {
    Ec(PrivKey),
    Rsa(RsaCrt),
}

impl Private {
    pub(crate) fn of(obj: &KeyObject) -> Result<Private, Sw> {
        match obj.ty {
            KeyType::Ec(d) => PrivKey::from_scalar(d.curve, obj.material())
                .map(Private::Ec)
                .ok_or(Sw::MEMORY_FAILURE),
            KeyType::Rsa(_) => crt_from_plain(obj.material())
                .map(Private::Rsa)
                .map_err(|_| Sw::MEMORY_FAILURE),
            KeyType::Aes(_) => Err(Sw::EXEC_ERROR),
        }
    }
}

pub(crate) fn ec_sw(e: EcError) -> Sw {
    match e {
        EcError::Failed => Sw::EXEC_ERROR,
        EcError::BadPoint => Sw::WRONG_DATA,
        EcError::Unsupported => Sw::FUNC_NOT_SUPPORTED,
    }
}

fn rsa_sw(e: RsaError) -> Sw {
    match e {
        RsaError::BadBlock => Sw::WRONG_DATA,
        _ => Sw::EXEC_ERROR,
    }
}

/// ECDSA over a digest: raw `r ‖ s`.
pub(crate) fn ecdsa(key: &PrivKey, digest: &[u8], out: &mut [u8]) -> Result<usize, Sw> {
    key.sign(digest, out).map_err(ec_sw)
}

/// PKCS#1 v1.5 over a digest or a DigestInfo; the layer below builds the block.
pub(crate) fn rsa_pkcs1(
    crt: &RsaCrt,
    di_or_digest: &[u8],
    rng: &mut dyn Rng,
    out: &mut [u8],
) -> Result<usize, Sw> {
    let mut di = [0u8; rsk_rsa::MAX_RSA_DIGESTINFO];
    if rsk_rsa::pkcs1v15::rsa_sign_em(di_or_digest, &mut di).is_none() {
        return Err(Sw::WRONG_DATA);
    }
    rsk_rsa::pkcs1v15::rsa_sign_crt(crt, di_or_digest, &mut RsaRng(rng), out).map_err(rsa_sw)
}

/// MGF1 (RFC 8017 B.2.1) of `seed`, XORed into `mask`.
fn mgf1_xor(hash: Hash, seed: &[u8], mask: &mut [u8]) {
    let mut input = [0u8; MAX_DIGEST + 4];
    input[..seed.len()].copy_from_slice(seed);
    let mut block = [0u8; MAX_DIGEST];
    for (counter, chunk) in mask.chunks_mut(hash.len()).enumerate() {
        input[seed.len()..seed.len() + 4].copy_from_slice(&(counter as u32).to_be_bytes());
        hash.digest(&input[..seed.len() + 4], &mut block);
        for (m, b) in chunk.iter_mut().zip(block.iter()) {
            *m ^= b;
        }
    }
}

/// EMSA-PSS-ENCODE (RFC 8017 §9.1.1) into the whole of `em`, for a modulus of
/// `8 · em.len()` bits: MGF1 over the message hash, a salt as long as the hash.
fn pss_encode(hash: Hash, mhash: &[u8], rng: &mut dyn Rng, em: &mut [u8]) -> Result<(), Sw> {
    let h = hash.len();
    let em_len = em.len();
    if mhash.len() != h || em_len < 2 * h + 2 {
        return Err(Sw::WRONG_DATA);
    }
    let mut salt = [0u8; MAX_DIGEST];
    rng.fill(&mut salt[..h]);
    let mut m = [0u8; 8 + 2 * MAX_DIGEST];
    m[8..8 + h].copy_from_slice(mhash);
    m[8 + h..8 + 2 * h].copy_from_slice(&salt[..h]);
    let mut digest = [0u8; MAX_DIGEST];
    hash.digest(&m[..8 + 2 * h], &mut digest);
    let db_len = em_len - h - 1;
    let (db, rest) = em.split_at_mut(db_len);
    db.fill(0);
    db[db_len - h - 1] = 0x01;
    db[db_len - h..].copy_from_slice(&salt[..h]);
    mgf1_xor(hash, &digest[..h], db);
    // emBits is one short of the modulus, so the top bit of the block is clear.
    db[0] &= 0x7F;
    rest[..h].copy_from_slice(&digest[..h]);
    rest[h] = 0xBC;
    Ok(())
}

/// PSS over a digest taken with `hash`.
pub(crate) fn rsa_pss(
    crt: &RsaCrt,
    hash: Hash,
    digest: &[u8],
    rng: &mut dyn Rng,
    out: &mut [u8],
) -> Result<usize, Sw> {
    let mlen = crt.modulus_len();
    let mut em = Wiped::<MAX_OUT>::zeroed();
    pss_encode(hash, digest, rng, &mut em[..mlen])?;
    rsk_rsa::crt::private_op(crt, &em[..mlen], &mut RsaRng(rng), out).map_err(rsa_sw)
}

/// Sign `data` the way a CV certificate's algorithm says.
pub(crate) fn sign_cv(
    key: &Private,
    alg: SigAlg,
    data: &[u8],
    rng: &mut dyn Rng,
    out: &mut [u8],
) -> Result<usize, Sw> {
    let mut digest = [0u8; MAX_DIGEST];
    let n = alg.hash().digest(data, &mut digest);
    match (key, alg) {
        (Private::Ec(k), SigAlg::EcdsaSha256 | SigAlg::EcdsaSha384 | SigAlg::EcdsaSha512) => {
            ecdsa(k, &digest[..n], out)
        }
        (Private::Rsa(c), SigAlg::RsaV15Sha256 | SigAlg::RsaV15Sha512) => {
            rsa_pkcs1(c, &digest[..n], rng, out)
        }
        (Private::Rsa(c), SigAlg::RsaPssSha256 | SigAlg::RsaPssSha512) => {
            rsa_pss(c, alg.hash(), &digest[..n], rng, out)
        }
        _ => Err(Sw::WRONG_DATA),
    }
}

/// The hash a hash-on-card algorithm takes of its data, `None` for one that
/// signs what it is given.
fn card_hash(algo: u8) -> Option<Hash> {
    match algo {
        ALGO_EC_SHA224 => Some(Hash::Sha224),
        ALGO_EC_SHA256 | ALGO_RSA_PKCS1_SHA256 | ALGO_RSA_PSS_SHA256 => Some(Hash::Sha256),
        ALGO_EC_SHA384 | ALGO_RSA_PKCS1_SHA384 | ALGO_RSA_PSS_SHA384 => Some(Hash::Sha384),
        ALGO_EC_SHA512 | ALGO_RSA_PKCS1_SHA512 | ALGO_RSA_PSS_SHA512 => Some(Hash::Sha512),
        _ => None,
    }
}

/// Whether `data` is acceptable input for `algo` on this key, checked before a
/// use is spent: a malformed request must not cost one.
fn input_ok(ty: KeyType, algo: u8, data: &[u8]) -> bool {
    match (ty, algo) {
        (KeyType::Rsa(s), ALGO_RSA_RAW | ALGO_RSA_DECRYPT) => data.len() == s.modulus_len(),
        (KeyType::Rsa(_), ALGO_RSA_PSS) => Hash::of_len(data.len()).is_some(),
        (KeyType::Rsa(_), ALGO_RSA_PKCS1) => {
            let mut di = [0u8; rsk_rsa::MAX_RSA_DIGESTINFO];
            rsk_rsa::pkcs1v15::rsa_sign_em(data, &mut di).is_some()
        }
        (KeyType::Ec(d), ALGO_EC_RAW) => (d.field_len() / 2..=MAX_DIGEST).contains(&data.len()),
        (KeyType::Ec(d), ALGO_EC_DH) => data.len() == d.point_len() && data[0] == 0x04,
        (KeyType::Aes(_), ALGO_AES_CBC_ENCRYPT | ALGO_AES_CBC_DECRYPT) => {
            !data.is_empty() && data.len().is_multiple_of(AES_BLOCK)
        }
        (KeyType::Aes(_), ALGO_AES_CMAC) => true,
        _ => card_hash(algo).is_some(),
    }
}

impl HsmApplet<'_> {
    /// Every check a key use passes, the touch, and the spent use — what SIGN,
    /// DECIPHER and CIPHER SYMMETRIC share. Returns the key, opened.
    pub(crate) fn take_key<S: Storage>(
        &mut self,
        fs: &mut Fs<S>,
        kid: u8,
        via: Use,
        algo: u8,
        data: &[u8],
    ) -> Result<KeyObject, Sw> {
        if Use::of(algo) != Some(via) {
            return Err(Sw::INCORRECT_P1P2);
        }
        let init = require_init(fs)?;
        self.require_open(fs)?;
        let hmk = self
            .sess
            .hmk
            .clone()
            .ok_or(Sw::SECURITY_STATUS_NOT_SATISFIED)?;
        if kid == KEY_ID_DEVICE {
            return Err(Sw::SECURITY_STATUS_NOT_SATISFIED);
        }
        let mut obj = keys::load(fs, &hmk, kid)?.ok_or(Sw::FILE_NOT_FOUND)?;
        if !obj.ty.serves(algo) {
            return Err(Sw::INCORRECT_P1P2);
        }
        if !obj.allows(algo) {
            return Err(Sw::CONDITIONS_NOT_SATISFIED);
        }
        if !input_ok(obj.ty, algo, data) {
            return Err(Sw::WRONG_DATA);
        }
        if obj.counter == 0 {
            return Err(Sw::FILE_FULL);
        }
        if init.options & OPT_TOUCH_KEY_USE != 0 {
            self.require_touch(Confirm::titled("Use HSM key?"))?;
        }
        if obj.counter != COUNTER_UNLIMITED {
            obj.counter -= 1;
            keys::store(fs, &hmk, kid, &obj, &mut *self.rng.borrow_mut())?;
        }
        Ok(obj)
    }

    /// SIGN (`80 68 kid algo`).
    pub(crate) fn sign<S: Storage>(&mut self, fs: &mut Fs<S>, apdu: &Apdu, res: &mut ResBuf) -> Sw {
        into_sw(self.try_sign(fs, apdu, res))
    }

    fn try_sign<S: Storage>(
        &mut self,
        fs: &mut Fs<S>,
        apdu: &Apdu,
        res: &mut ResBuf,
    ) -> Result<(), Sw> {
        let (kid, algo, data) = (apdu.p1, apdu.p2, apdu.data);
        let obj = self.take_key(fs, kid, Use::Sign, algo, data)?;
        let key = Private::of(&obj)?;
        let mut digest = [0u8; MAX_DIGEST];
        let hashed = card_hash(algo).map(|h| h.digest(data, &mut digest));
        let msg = match hashed {
            Some(n) => &digest[..n],
            None => data,
        };
        let mut rng = self.rng.borrow_mut();
        let mut sig = Wiped::<MAX_OUT>::zeroed();
        match (&key, algo) {
            (Private::Ec(k), _) => {
                let mut raw = [0u8; MAX_EC_SIG];
                let n = ecdsa(k, msg, &mut raw)?;
                let mut w = Writer::new(res.spare_mut());
                put_ecdsa_der(&mut w, &raw[..n])?;
                let len = w.len();
                res.commit(len);
                Ok(())
            }
            (Private::Rsa(c), ALGO_RSA_RAW) => {
                let n = rsk_rsa::crt::private_op(c, msg, &mut RsaRng(&mut *rng), &mut sig[..])
                    .map_err(rsa_sw)?;
                put(res, &sig[..n])
            }
            (Private::Rsa(c), ALGO_RSA_PSS) => {
                let h = Hash::of_len(msg.len()).ok_or(Sw::WRONG_DATA)?;
                let n = rsa_pss(c, h, msg, &mut *rng, &mut sig[..])?;
                put(res, &sig[..n])
            }
            (Private::Rsa(c), ALGO_RSA_PSS_SHA256 | ALGO_RSA_PSS_SHA384 | ALGO_RSA_PSS_SHA512) => {
                let h = card_hash(algo).ok_or(Sw::INCORRECT_P1P2)?;
                let n = rsa_pss(c, h, msg, &mut *rng, &mut sig[..])?;
                put(res, &sig[..n])
            }
            (Private::Rsa(c), _) => {
                let n = rsa_pkcs1(c, msg, &mut *rng, &mut sig[..])?;
                put(res, &sig[..n])
            }
        }
    }

    /// DECIPHER (`80 62 kid algo`): raw RSA decryption, or ECDH answering the
    /// whole shared point.
    pub(crate) fn decipher<S: Storage>(
        &mut self,
        fs: &mut Fs<S>,
        apdu: &Apdu,
        res: &mut ResBuf,
    ) -> Sw {
        into_sw(self.try_decipher(fs, apdu, res))
    }

    fn try_decipher<S: Storage>(
        &mut self,
        fs: &mut Fs<S>,
        apdu: &Apdu,
        res: &mut ResBuf,
    ) -> Result<(), Sw> {
        let (kid, algo, data) = (apdu.p1, apdu.p2, apdu.data);
        let obj = self.take_key(fs, kid, Use::Decipher, algo, data)?;
        let mut out = Wiped::<MAX_OUT>::zeroed();
        let n = match Private::of(&obj)? {
            Private::Rsa(c) => {
                let mut rng = self.rng.borrow_mut();
                rsk_rsa::crt::private_op(&c, data, &mut RsaRng(&mut *rng), &mut out[..])
                    .map_err(rsa_sw)?
            }
            Private::Ec(k) => k.ecdh_point(data, &mut out[..]).map_err(ec_sw)?,
        };
        put(res, &out[..n])
    }
}

/// Answer `body`, or say it does not fit.
pub(crate) fn put(res: &mut ResBuf, body: &[u8]) -> Result<(), Sw> {
    if res.extend(body) {
        Ok(())
    } else {
        Err(Sw::WRONG_LENGTH)
    }
}

/// Load the device key behind the device root, ready to sign.
pub(crate) fn device_key<S: Storage>(
    fs: &mut Fs<S>,
    dev: &Device,
    rng: &mut dyn Rng,
) -> Result<Private, Sw> {
    let obj = keys::load_device(fs, dev, rng)?.ok_or(Sw::CONDITIONS_NOT_SATISFIED)?;
    Private::of(&obj)
}

#[cfg(test)]
#[path = "keyops_tests.rs"]
mod tests;
