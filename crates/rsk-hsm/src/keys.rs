// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Key objects (`CCxx`): what a key is, which algorithms it may serve, how many
//! more uses it has, and its private material — sealed as one record under a key
//! derived from HMK and the record's own FID, so it opens only behind the user PIN
//! and only where it was written. The device key (`CC00`) is the one exception:
//! it belongs to the device rather than to an owner, so the device root seals it
//! and a re-initialization leaves it standing.

use rsk_crypto::Device;
use rsk_ec::Curve;
use rsk_fs::{Fs, KeyFid, Sealed, Storage};
use rsk_rsa::MAX_CRT_PLAIN;
use rsk_sdk::{Rng, Sw};

use crate::consts::*;
use crate::domain::{self, Domain};
use crate::seal::{self, KEY_LEN, SEAL_OVERHEAD, Unseal, Wiped};
use crate::store::{Class, File, read_sealed};

/// The RSA sizes this device makes and uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RsaSize {
    R2048,
    R3072,
    R4096,
}

impl RsaSize {
    pub(crate) fn from_bits(bits: usize) -> Option<RsaSize> {
        Some(match bits {
            2048 => RsaSize::R2048,
            3072 => RsaSize::R3072,
            4096 => RsaSize::R4096,
            _ => return None,
        })
    }

    pub(crate) const fn bits(self) -> usize {
        match self {
            RsaSize::R2048 => 2048,
            RsaSize::R3072 => 3072,
            RsaSize::R4096 => 4096,
        }
    }

    /// The modulus in bytes.
    pub(crate) const fn modulus_len(self) -> usize {
        self.bits() / 8
    }

    /// The stored CRT blob: `P ‖ Q ‖ dP ‖ dQ ‖ qInv`, five half-modulus fields.
    const fn material_len(self) -> usize {
        5 * self.modulus_len() / 2
    }
}

/// The AES sizes, by key length in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AesSize {
    A128,
    A192,
    A256,
}

impl AesSize {
    pub(crate) fn from_len(len: usize) -> Option<AesSize> {
        Some(match len {
            16 => AesSize::A128,
            24 => AesSize::A192,
            32 => AesSize::A256,
            _ => return None,
        })
    }

    pub(crate) const fn len(self) -> usize {
        match self {
            AesSize::A128 => 16,
            AesSize::A192 => 24,
            AesSize::A256 => 32,
        }
    }
}

/// What a key object holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyType {
    Ec(&'static Domain),
    Rsa(RsaSize),
    Aes(AesSize),
}

impl KeyType {
    const fn material_len(self) -> usize {
        match self {
            KeyType::Ec(d) => d.field_len(),
            KeyType::Rsa(s) => s.material_len(),
            KeyType::Aes(s) => s.len(),
        }
    }

    /// Whether `algo` is one this kind of key does: a SIGN, DECIPHER or CIPHER
    /// SYMMETRIC algorithm of its family, or the wrap permission any key may hold.
    pub(crate) fn serves(self, algo: u8) -> bool {
        if algo == ALGO_WRAP {
            return true;
        }
        match self {
            KeyType::Ec(_) => matches!(
                algo,
                ALGO_EC_RAW
                    | ALGO_EC_SHA224
                    | ALGO_EC_SHA256
                    | ALGO_EC_SHA384
                    | ALGO_EC_SHA512
                    | ALGO_EC_DH
            ),
            KeyType::Rsa(_) => matches!(
                algo,
                ALGO_RSA_RAW
                    | ALGO_RSA_DECRYPT
                    | ALGO_RSA_PKCS1
                    | ALGO_RSA_PKCS1_SHA256
                    | ALGO_RSA_PKCS1_SHA384
                    | ALGO_RSA_PKCS1_SHA512
                    | ALGO_RSA_PSS
                    | ALGO_RSA_PSS_SHA256
                    | ALGO_RSA_PSS_SHA384
                    | ALGO_RSA_PSS_SHA512
            ),
            KeyType::Aes(_) => matches!(
                algo,
                ALGO_AES_CBC_ENCRYPT | ALGO_AES_CBC_DECRYPT | ALGO_AES_CMAC
            ),
        }
    }
}

/// Most algorithms a key's own list may name.
pub(crate) const ALGOS_MAX: usize = 16;
/// A use counter that never runs out.
pub(crate) const COUNTER_UNLIMITED: u32 = u32::MAX;

const VERSION: u8 = 1;
const KIND_EC: u8 = 1;
const KIND_RSA: u8 = 2;
const KIND_AES: u8 = 3;
/// `ver ‖ kind ‖ param(2) ‖ counter(4) ‖ n`, then the list and the material.
const HEADER_LEN: usize = 9;
const MATERIAL_MAX: usize = MAX_CRT_PLAIN;
const PLAIN_MAX: usize = HEADER_LEN + ALGOS_MAX + MATERIAL_MAX;
const RECORD_MAX: usize = PLAIN_MAX + SEAL_OVERHEAD;
const _: () = assert!(RECORD_MAX <= rsk_fs::MAX_VALUE_BYTES);

/// One key, opened.
pub(crate) struct KeyObject {
    pub ty: KeyType,
    pub counter: u32,
    algos: [u8; ALGOS_MAX],
    nalgos: usize,
    material: Wiped<MATERIAL_MAX>,
}

impl KeyObject {
    /// `None` when the material is not this type's width or the list is too long.
    pub(crate) fn new(ty: KeyType, counter: u32, algos: &[u8], material: &[u8]) -> Option<Self> {
        if material.len() != ty.material_len() || algos.len() > ALGOS_MAX {
            return None;
        }
        let mut k = KeyObject {
            ty,
            counter,
            algos: [0; ALGOS_MAX],
            nalgos: algos.len(),
            material: Wiped::zeroed(),
        };
        k.algos[..algos.len()].copy_from_slice(algos);
        k.material[..material.len()].copy_from_slice(material);
        Some(k)
    }

    /// The private material: an EC scalar, the RSA CRT blob, or the AES key.
    pub(crate) fn material(&self) -> &[u8] {
        &self.material[..self.ty.material_len()]
    }

    /// The key's own algorithm list; empty when it has none.
    pub(crate) fn algos(&self) -> &[u8] {
        &self.algos[..self.nalgos]
    }

    /// Whether the key's own list admits `algo`. No list admits everything the
    /// key's type does.
    pub(crate) fn allows(&self, algo: u8) -> bool {
        self.nalgos == 0 || self.algos[..self.nalgos].contains(&algo)
    }

    fn encode(&self, out: &mut [u8; PLAIN_MAX]) -> usize {
        let (kind, param) = match self.ty {
            KeyType::Ec(d) => (KIND_EC, d.curve.id() as u16),
            KeyType::Rsa(s) => (KIND_RSA, s.bits() as u16),
            KeyType::Aes(s) => (KIND_AES, s.len() as u16),
        };
        out[0] = VERSION;
        out[1] = kind;
        out[2..4].copy_from_slice(&param.to_be_bytes());
        out[4..8].copy_from_slice(&self.counter.to_be_bytes());
        out[8] = self.nalgos as u8;
        let m = HEADER_LEN + self.nalgos;
        out[HEADER_LEN..m].copy_from_slice(&self.algos[..self.nalgos]);
        let material = self.material();
        out[m..m + material.len()].copy_from_slice(material);
        m + material.len()
    }

    /// Strict: a version, kind, curve or size no build wrote is not a key.
    fn decode(b: &[u8]) -> Option<KeyObject> {
        if b.len() < HEADER_LEN || b[0] != VERSION {
            return None;
        }
        let param = u16::from_be_bytes([b[2], b[3]]);
        let ty = match b[1] {
            KIND_EC => KeyType::Ec(domain::of(Curve::from_id(u8::try_from(param).ok()?)?)?),
            KIND_RSA => KeyType::Rsa(RsaSize::from_bits(param as usize)?),
            KIND_AES => KeyType::Aes(AesSize::from_len(param as usize)?),
            _ => return None,
        };
        let counter = u32::from_be_bytes([b[4], b[5], b[6], b[7]]);
        let n = b[8] as usize;
        let algos = b.get(HEADER_LEN..HEADER_LEN + n)?;
        if !algos.iter().all(|&a| ty.serves(a)) {
            return None;
        }
        KeyObject::new(ty, counter, algos, &b[HEADER_LEN + n..])
    }
}

/// Where key `kid` is sealed.
pub(crate) fn fid(kid: u8) -> KeyFid {
    KeyFid::new(File::Object(Class::Key, kid).store())
}

fn seal_into<S: Storage>(
    fs: &mut Fs<S>,
    key: &[u8; KEY_LEN],
    at: KeyFid,
    obj: &KeyObject,
    rng: &mut dyn Rng,
) -> Result<(), Sw> {
    let mut plain = Wiped::<PLAIN_MAX>::zeroed();
    let n = obj.encode(&mut plain);
    let mut sealed = [0u8; RECORD_MAX];
    let m = seal::seal(key, at.get(), &[], &plain[..n], rng, &mut sealed);
    fs.put_key(at, Sealed::wrap(&sealed[..m]))
        .map_err(|_| Sw::MEMORY_FAILURE)
}

/// Open the record at `at` under `key`. `Ok(None)` is a confirmed absence.
fn open_from<S: Storage>(
    fs: &mut Fs<S>,
    key: &[u8; KEY_LEN],
    at: KeyFid,
) -> Result<Option<Result<KeyObject, Unseal>>, Sw> {
    let mut sealed = [0u8; RECORD_MAX];
    let Some(n) = read_sealed(fs, at, &mut sealed)? else {
        return Ok(None);
    };
    let mut plain = Wiped::<PLAIN_MAX>::zeroed();
    Ok(Some(
        match seal::open(key, at.get(), &[], &sealed[..n], &mut plain[..]) {
            Ok(m) => KeyObject::decode(&plain[..m]).ok_or(Unseal::Malformed),
            Err(e) => Err(e),
        },
    ))
}

/// Seal `obj` as key `kid` of the owner whose master key is `hmk`.
pub(crate) fn store<S: Storage>(
    fs: &mut Fs<S>,
    hmk: &[u8; KEY_LEN],
    kid: u8,
    obj: &KeyObject,
    rng: &mut dyn Rng,
) -> Result<(), Sw> {
    let at = fid(kid);
    seal_into(fs, &seal::object_key(hmk, at.get()), at, obj, rng)
}

/// Key `kid`, opened: `Ok(None)` when there is none. A record that does not open
/// under the owner's key is a memory failure, never "no key".
pub(crate) fn load<S: Storage>(
    fs: &mut Fs<S>,
    hmk: &[u8; KEY_LEN],
    kid: u8,
) -> Result<Option<KeyObject>, Sw> {
    let at = fid(kid);
    match open_from(fs, &seal::object_key(hmk, at.get()), at)? {
        None => Ok(None),
        Some(Ok(k)) => Ok(Some(k)),
        Some(Err(_)) => Err(Sw::MEMORY_FAILURE),
    }
}

/// Whether there is a key at `kid`, without opening it.
pub(crate) fn exists<S: Storage>(fs: &mut Fs<S>, kid: u8) -> Result<bool, Sw> {
    Ok(crate::store::size(fs, fid(kid).get())?.is_some())
}

/// Seal the device key under the device root.
pub(crate) fn store_device<S: Storage>(
    fs: &mut Fs<S>,
    dev: &Device,
    obj: &KeyObject,
    rng: &mut dyn Rng,
) -> Result<(), Sw> {
    seal_into(
        fs,
        &seal::device_auth_key(dev),
        fid(KEY_ID_DEVICE),
        obj,
        rng,
    )
}

/// The device key, `Ok(None)` when it was never made. One sealed before the OTP
/// root was burned is carried onto it, the at-rest lap re-armed first; if the
/// medium refuses that, the key is still returned and moves at the next boot.
pub(crate) fn load_device<S: Storage>(
    fs: &mut Fs<S>,
    dev: &Device,
    rng: &mut dyn Rng,
) -> Result<Option<KeyObject>, Sw> {
    let at = fid(KEY_ID_DEVICE);
    match open_from(fs, &seal::device_auth_key(dev), at)? {
        None => return Ok(None),
        Some(Ok(k)) => return Ok(Some(k)),
        Some(Err(Unseal::Malformed)) => return Err(Sw::MEMORY_FAILURE),
        Some(Err(Unseal::Auth)) if dev.otp_key.is_none() => return Err(Sw::MEMORY_FAILURE),
        Some(Err(Unseal::Auth)) => {}
    }
    let Some(Ok(k)) = open_from(fs, &seal::device_auth_key(&dev.without_otp()), at)? else {
        return Err(Sw::MEMORY_FAILURE);
    };
    if rsk_fs::request_rescrub(fs).is_ok() {
        let _ = store_device(fs, dev, &k, rng);
    }
    Ok(Some(k))
}

#[cfg(test)]
#[path = "keys_tests.rs"]
mod tests;
