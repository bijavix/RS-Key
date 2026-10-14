// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! WRAP KEY and UNWRAP KEY: a key leaves the device only as the SmartCard-HSM key
//! blob, encrypted and MACed under keys derived from the DKEK, and comes back the
//! same way — so a backup restores on any device holding the same DKEK.
//!
//! `KCV(8) ‖ type ‖ OID ‖ allowed algorithms ‖ access conditions ‖ key OID ‖ C ‖
//! MAC`, the four middle fields length-prefixed. `C` is AES-256-CBC (zero IV)
//! under `SHA-256(DKEK ‖ 00000001)` of `random(8) ‖ size(2) ‖ key fields ‖ 80
//! 00…`; `MAC` is AES-256-CMAC under `SHA-256(DKEK ‖ 00000002)` of all before it.

use rsk_crypto::{Device, Mode, aes_decrypt, aes_encrypt, ct_eq, sha256};
use rsk_ec::{MAX_EC_POINT, PrivKey};
use rsk_fs::{Fs, Storage};
use rsk_rsa::crt::crt_plaintext;
use rsk_rsa::{MAX_CRT_PLAIN, MAX_RSA_BYTES, RSA_PUB_EXP_BE, RsaKey, rsa_from_ned, rsa_from_pqe};
use rsk_sdk::{Apdu, ResBuf, Rng, Sw};

use crate::HsmApplet;
use crate::auth::{into_sw, require_init};
use crate::cmac::aes_cmac;
use crate::consts::*;
use crate::cvc::{OID_LEN, SigAlg, Writer};
use crate::dkek::kcv;
use crate::domain::{self, Domain};
use crate::files::room_for_object;
use crate::keyops::{AES_BLOCK, RsaRng, ec_sw};
use crate::keys::{self, ALGOS_MAX, AesSize, COUNTER_UNLIMITED, KeyObject, KeyType, RsaSize};
use crate::seal::{KEY_LEN, Key, Wiped};
use crate::store::{REC_STAGING, read_plain, size};

/// Blob key types. RSA leaves as `d, n, e` — the shorter form, and the one the
/// driver's 1500-byte buffer holds at 4096 bits — and comes back in either form.
const BLOB_RSA: u8 = 5;
const BLOB_RSA_CRT: u8 = 6;
const BLOB_EC: u8 = 12;
const BLOB_AES: u8 = 15;
/// AES (2.16.840.1.101.3.4.1), the algorithm OID of a symmetric key's blob.
const OID_AES: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01];
/// The labels of the two keys a DKEK is used through, never itself.
const LABEL_ENC: u8 = 1;
const LABEL_MAC: u8 = 2;

const NONCE_LEN: usize = 8;
const MAC_LEN: usize = 16;
/// The largest encrypted part: an RSA-4096 key in the CRT form — the nonce, the
/// size, five half-modulus fields, the modulus and the exponent, each prefixed.
const INNER_MAX: usize =
    (NONCE_LEN + 2 + 7 * 2 + 5 * (MAX_RSA_BYTES / 2) + MAX_RSA_BYTES + RSA_PUB_EXP_BE.len())
        .next_multiple_of(AES_BLOCK);
/// The largest blob UNWRAP reads: that part with room for a foreign blob's lists.
const BLOB_MAX: usize = 2048;
/// The fixed head ahead of the length-prefixed fields: KCV and type.
const HEAD_LEN: usize = DKEK_KCV_LEN + 1;
/// A scalar is as wide as a coordinate, and an uncompressed point holds two.
const SCALAR_MAX: usize = (MAX_EC_POINT - 1) / 2;

/// `SHA-256(DKEK ‖ 00 00 00 label)`.
fn derive(dkek: &[u8; KEY_LEN], label: u8) -> Key {
    let mut m = Wiped::<{ KEY_LEN + 4 }>::zeroed();
    m[..KEY_LEN].copy_from_slice(dkek);
    m[KEY_LEN + 3] = label;
    Key::new(sha256(&m[..]))
}

/// The algorithm OID a blob of `kind` names its key's family by.
fn family_oid(kind: u8, out: &mut [u8; OID_LEN]) -> Option<&[u8]> {
    *out = match kind {
        BLOB_AES => return Some(OID_AES),
        BLOB_EC => SigAlg::EcdsaSha256.oid(),
        BLOB_RSA | BLOB_RSA_CRT => SigAlg::RsaV15Sha256.oid(),
        _ => return None,
    };
    Some(&out[..])
}

/// `v` without its leading zero bytes, as an integer field carries it.
fn minimal(v: &[u8]) -> &[u8] {
    &v[v.iter().position(|&b| b != 0).unwrap_or(v.len())..]
}

/// One length-prefixed field.
fn put_field(w: &mut Writer, v: &[u8]) -> Result<(), Sw> {
    let len = u16::try_from(v.len()).map_err(|_| Sw::EXEC_ERROR)?;
    w.raw(&len.to_be_bytes())?;
    w.raw(v)
}

/// Read one length-prefixed field at `*at`.
fn take<'b>(b: &'b [u8], at: &mut usize) -> Result<&'b [u8], Sw> {
    let len = b
        .get(*at..*at + 2)
        .map(|l| u16::from_be_bytes([l[0], l[1]]) as usize)
        .ok_or(Sw::WRONG_DATA)?;
    let v = b.get(*at + 2..*at + 2 + len).ok_or(Sw::WRONG_DATA)?;
    *at += 2 + len;
    Ok(v)
}

/// The key fields of `obj`, after the nonce: `size ‖ fields`. Returns the type.
fn put_key(w: &mut Writer, obj: &KeyObject) -> Result<u8, Sw> {
    match obj.ty {
        KeyType::Aes(s) => {
            w.raw(&(s.len() as u16).to_be_bytes())?;
            w.raw(obj.material())?;
            Ok(BLOB_AES)
        }
        KeyType::Ec(d) => {
            let key = PrivKey::from_scalar(d.curve, obj.material()).ok_or(Sw::EXEC_ERROR)?;
            let mut q = [0u8; MAX_EC_POINT];
            let qn = key.public_point(&mut q).map_err(ec_sw)?;
            w.raw(&((8 * d.field_len()) as u16).to_be_bytes())?;
            for v in [d.a, d.b, d.p, d.n] {
                put_field(w, minimal(v))?;
            }
            put_field(w, d.g)?;
            // Full width: trimming a secret's leading zeros would time them.
            put_field(w, obj.material())?;
            put_field(w, &q[..qn])?;
            Ok(BLOB_EC)
        }
        KeyType::Rsa(s) => {
            let half = s.modulus_len() / 2;
            let m = obj.material();
            let key = rsa_from_pqe(RSA_PUB_EXP_BE, &m[..half], &m[half..2 * half])
                .ok_or(Sw::EXEC_ERROR)?;
            w.raw(&(s.bits() as u16).to_be_bytes())?;
            put_field(w, minimal(&key.d_be()))?;
            put_field(w, minimal(&key.n_be()))?;
            put_field(w, RSA_PUB_EXP_BE)?;
            Ok(BLOB_RSA)
        }
    }
}

/// The blob for `obj` under `dkek`.
fn encode(
    dkek: &[u8; KEY_LEN],
    obj: &KeyObject,
    rng: &mut dyn Rng,
    out: &mut [u8],
) -> Result<usize, Sw> {
    let mut inner = Wiped::<INNER_MAX>::zeroed();
    let mut w = Writer::new(&mut inner[..]);
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill(&mut nonce);
    w.raw(&nonce)?;
    let kind = put_key(&mut w, obj)?;
    // ISO padding, and none at all on a block boundary.
    let mut n = w.len();
    if !n.is_multiple_of(AES_BLOCK) {
        inner[n] = 0x80;
        n = n.next_multiple_of(AES_BLOCK);
    }
    let enc = derive(dkek, LABEL_ENC);
    aes_encrypt(&enc[..], &[0; AES_BLOCK], Mode::Cbc, &mut inner[..n])
        .map_err(|_| Sw::EXEC_ERROR)?;

    let mut oid = [0u8; OID_LEN];
    let mut w = Writer::new(out);
    w.raw(&kcv(dkek))?;
    w.raw(&[kind])?;
    put_field(&mut w, family_oid(kind, &mut oid).ok_or(Sw::EXEC_ERROR)?)?;
    put_field(&mut w, obj.algos())?;
    put_field(&mut w, &[])?;
    put_field(&mut w, &[])?;
    w.raw(&inner[..n])?;
    let mac = aes_cmac(&derive(dkek, LABEL_MAC)[..], w.as_slice())?;
    w.raw(&mac)?;
    Ok(w.len())
}

/// The allowed-algorithm list a restored key keeps: those its type serves. A list
/// that named only algorithms this device lacks is refused rather than emptied —
/// an empty list admits everything.
fn kept_algos(ty: KeyType, listed: &[u8], out: &mut [u8; ALGOS_MAX]) -> Result<usize, Sw> {
    let mut n = 0;
    for &a in listed.iter().filter(|&&a| ty.serves(a)) {
        *out.get_mut(n).ok_or(Sw::WRONG_DATA)? = a;
        n += 1;
    }
    if n == 0 && !listed.is_empty() {
        return Err(Sw::WRONG_DATA);
    }
    Ok(n)
}

/// A restored key, its list filtered, with no limit on its uses: a blob carries
/// no counter.
fn restored(ty: KeyType, algos: &[u8], material: &[u8]) -> Result<KeyObject, Sw> {
    let mut kept = [0u8; ALGOS_MAX];
    let n = kept_algos(ty, algos, &mut kept)?;
    KeyObject::new(ty, COUNTER_UNLIMITED, &kept[..n], material).ok_or(Sw::WRONG_DATA)
}

/// The EC curve a blob's parameters name, checked field by field.
fn ec_domain(a: &[u8], b: &[u8], p: &[u8], n: &[u8], g: &[u8]) -> Result<&'static Domain, Sw> {
    let d = domain::ALL
        .into_iter()
        .find(|d| minimal(d.p) == minimal(p))
        .ok_or(Sw::WRONG_DATA)?;
    let same = minimal(d.a) == minimal(a)
        && minimal(d.b) == minimal(b)
        && minimal(d.n) == minimal(n)
        && d.g == g;
    if same { Ok(d) } else { Err(Sw::WRONG_DATA) }
}

/// An EC key from `A, B, P, N, G, d, Q`: the curve one of ours, the scalar in
/// range, and `Q` — when given — its public point.
fn ec_key(inner: &[u8], at: &mut usize, algos: &[u8]) -> Result<KeyObject, Sw> {
    let mut f = [&[][..]; 7];
    for slot in f.iter_mut() {
        *slot = take(inner, at)?;
    }
    let [a, b, p, n, g, d, q] = f;
    let dom = ec_domain(a, b, p, n, g)?;
    let w = dom.field_len();
    let d = minimal(d);
    if d.len() > w {
        return Err(Sw::WRONG_DATA);
    }
    let mut scalar = Wiped::<SCALAR_MAX>::zeroed();
    scalar[w - d.len()..w].copy_from_slice(d);
    let key = PrivKey::from_scalar(dom.curve, &scalar[..w]).ok_or(Sw::WRONG_DATA)?;
    let mut point = [0u8; MAX_EC_POINT];
    let pn = key.public_point(&mut point).map_err(|_| Sw::WRONG_DATA)?;
    if !q.is_empty() && q != &point[..pn] {
        return Err(Sw::WRONG_DATA);
    }
    restored(KeyType::Ec(dom), algos, &scalar[..w])
}

/// An RSA key from `d, n, e` or from its CRT form, rebuilt and checked whole.
fn rsa_key(kind: u8, inner: &[u8], at: &mut usize, rng: &mut dyn Rng) -> Result<RsaKey, Sw> {
    if kind == BLOB_RSA {
        let d = take(inner, at)?;
        let n = take(inner, at)?;
        let e = take(inner, at)?;
        if minimal(e) != RSA_PUB_EXP_BE {
            return Err(Sw::WRONG_DATA);
        }
        return rsa_from_ned(n, e, d, &mut RsaRng(rng)).ok_or(Sw::WRONG_DATA);
    }
    let mut f = [&[][..]; 7];
    for slot in f.iter_mut() {
        *slot = take(inner, at)?;
    }
    // dP, dQ and qInv are recomputed from the primes, not trusted.
    let [_dp, _dq, p, _qinv, q, n, e] = f;
    if minimal(e) != RSA_PUB_EXP_BE {
        return Err(Sw::WRONG_DATA);
    }
    let key = rsa_from_pqe(e, p, q).ok_or(Sw::WRONG_DATA)?;
    if minimal(&key.n_be()) != minimal(n) {
        return Err(Sw::WRONG_DATA);
    }
    Ok(key)
}

/// An RSA key in this device's own form: a size it keeps, as its CRT blob.
fn rsa_object(key: &RsaKey, algos: &[u8]) -> Result<KeyObject, Sw> {
    let size = RsaSize::from_bits(8 * key.size()).ok_or(Sw::WRONG_DATA)?;
    let mut plain = Wiped::<MAX_CRT_PLAIN>::zeroed();
    let n = crt_plaintext(key, &mut plain[..]).map_err(|_| Sw::WRONG_DATA)?;
    restored(KeyType::Rsa(size), algos, &plain[..n])
}

/// The key a blob's decrypted part describes.
fn decode_key(kind: u8, inner: &[u8], algos: &[u8], rng: &mut dyn Rng) -> Result<KeyObject, Sw> {
    let mut at = NONCE_LEN;
    let size = inner
        .get(at..at + 2)
        .map(|s| u16::from_be_bytes([s[0], s[1]]) as usize)
        .ok_or(Sw::WRONG_DATA)?;
    at += 2;
    match kind {
        BLOB_AES => {
            let s = AesSize::from_len(size).ok_or(Sw::WRONG_DATA)?;
            let key = inner.get(at..at + size).ok_or(Sw::WRONG_DATA)?;
            restored(KeyType::Aes(s), algos, key)
        }
        BLOB_EC => ec_key(inner, &mut at, algos),
        BLOB_RSA | BLOB_RSA_CRT => rsa_object(&rsa_key(kind, inner, &mut at, rng)?, algos),
        _ => Err(Sw::WRONG_DATA),
    }
}

/// Check a blob against `dkek` — its KCV, then its MAC, before a byte of it is
/// parsed or decrypted — and open it.
fn decode(dkek: &[u8; KEY_LEN], blob: &[u8], rng: &mut dyn Rng) -> Result<KeyObject, Sw> {
    if blob.len() < HEAD_LEN + MAC_LEN || blob[..DKEK_KCV_LEN] != kcv(dkek) {
        return Err(Sw::WRONG_DATA);
    }
    let (body, mac) = blob.split_at(blob.len() - MAC_LEN);
    if !ct_eq(&aes_cmac(&derive(dkek, LABEL_MAC)[..], body)?, mac) {
        return Err(Sw::WRONG_DATA);
    }
    let kind = body[DKEK_KCV_LEN];
    let mut at = HEAD_LEN;
    let mut want = [0u8; OID_LEN];
    let oid = take(body, &mut at)?;
    if family_oid(kind, &mut want) != Some(oid) {
        return Err(Sw::WRONG_DATA);
    }
    let algos = take(body, &mut at)?;
    take(body, &mut at)?;
    take(body, &mut at)?;
    let enc = &body[at..];
    if enc.is_empty() || !enc.len().is_multiple_of(AES_BLOCK) || enc.len() > INNER_MAX {
        return Err(Sw::WRONG_DATA);
    }
    let mut inner = Wiped::<INNER_MAX>::zeroed();
    let part = &mut inner[..enc.len()];
    part.copy_from_slice(enc);
    let key = derive(dkek, LABEL_ENC);
    aes_decrypt(&key[..], &[0; AES_BLOCK], Mode::Cbc, part).map_err(|_| Sw::WRONG_DATA)?;
    decode_key(kind, part, algos, rng)
}

impl HsmApplet<'_> {
    /// What WRAP and UNWRAP share: the framing, an initialized device, the lock
    /// open, the user PIN verified, a key reference that is not the device's, and
    /// a complete DKEK. Returns HMK and the DKEK.
    fn wrap_checks<S: Storage>(
        &mut self,
        dev: &Device,
        fs: &mut Fs<S>,
        apdu: &Apdu,
        p2: u8,
    ) -> Result<(Key, Key), Sw> {
        if apdu.p2 != p2 {
            return Err(Sw::INCORRECT_P1P2);
        }
        if apdu.nc != 0 {
            return Err(Sw::WRONG_LENGTH);
        }
        require_init(fs)?;
        self.require_open(fs)?;
        let hmk = self
            .sess
            .hmk
            .clone()
            .ok_or(Sw::SECURITY_STATUS_NOT_SATISFIED)?;
        if apdu.p1 == KEY_ID_DEVICE {
            return Err(Sw::SECURITY_STATUS_NOT_SATISFIED);
        }
        let dkek = self.dkek(dev, fs)?;
        Ok((hmk, dkek))
    }

    /// WRAP KEY (`80 72 kid 92`): the key's blob under the DKEK, if the key's own
    /// list lets it leave.
    pub(crate) fn wrap_key<S: Storage>(
        &mut self,
        dev: &Device,
        fs: &mut Fs<S>,
        apdu: &Apdu,
        res: &mut ResBuf,
    ) -> Sw {
        into_sw(self.try_wrap_key(dev, fs, apdu, res))
    }

    fn try_wrap_key<S: Storage>(
        &mut self,
        dev: &Device,
        fs: &mut Fs<S>,
        apdu: &Apdu,
        res: &mut ResBuf,
    ) -> Result<(), Sw> {
        let (hmk, dkek) = self.wrap_checks(dev, fs, apdu, WRAP_WITH_DKEK)?;
        let obj = keys::load(fs, &hmk, apdu.p1)?.ok_or(Sw::FILE_NOT_FOUND)?;
        if !obj.allows(ALGO_WRAP) {
            return Err(Sw::CONDITIONS_NOT_SATISFIED);
        }
        let n = encode(&dkek, &obj, &mut *self.rng.borrow_mut(), res.spare_mut())?;
        res.commit(n);
        Ok(())
    }

    /// UNWRAP KEY (`80 74 kid 93`): restore the blob staged in `2F10` as key `kid`.
    pub(crate) fn unwrap_key<S: Storage>(
        &mut self,
        dev: &Device,
        fs: &mut Fs<S>,
        apdu: &Apdu,
    ) -> Sw {
        into_sw(self.try_unwrap_key(dev, fs, apdu))
    }

    fn try_unwrap_key<S: Storage>(
        &mut self,
        dev: &Device,
        fs: &mut Fs<S>,
        apdu: &Apdu,
    ) -> Result<(), Sw> {
        let (hmk, dkek) = self.wrap_checks(dev, fs, apdu, UNWRAP_FROM_STAGING)?;
        if keys::exists(fs, apdu.p1)? {
            return Err(Sw::FILE_EXISTS);
        }
        room_for_object(fs)?;
        let staged = size(fs, REC_STAGING)?.ok_or(Sw::FILE_NOT_FOUND)?;
        if staged > BLOB_MAX {
            return Err(Sw::WRONG_DATA);
        }
        let mut blob = [0u8; BLOB_MAX];
        let n = read_plain(fs, REC_STAGING, &mut blob)?.ok_or(Sw::FILE_NOT_FOUND)?;
        let mut rng = self.rng.borrow_mut();
        let obj = decode(&dkek, &blob[..n], &mut *rng)?;
        keys::store(fs, &hmk, apdu.p1, &obj, &mut *rng)
    }
}

#[cfg(test)]
#[path = "wrap_tests.rs"]
mod tests;
