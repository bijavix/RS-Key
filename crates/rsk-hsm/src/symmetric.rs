// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! AES keys: GENERATE SYMMETRIC KEY (`00 48 kid size`) makes one, CIPHER
//! SYMMETRIC (`80 78 kid algo`) uses it — AES-CBC under a zero IV either way, the
//! host owning the IV and the padding, or AES-CMAC. They live in the key store
//! beside the private keys, behind the same PIN, lock and use counter.

use rsk_crypto::{Mode, aes_decrypt, aes_encrypt};
use rsk_fs::{Fs, Storage};
use rsk_sdk::{Apdu, ResBuf, Sw};

use crate::auth::{into_sw, require_init};
use crate::cmac::aes_cmac;
use crate::consts::*;
use crate::files::{room_for_object, walk};
use crate::keygen::Limits;
use crate::keyops::{AES_BLOCK, Use, put};
use crate::keys::{self, AesSize, KeyObject, KeyType};
use crate::seal::Wiped;
use crate::{HsmApplet, dkek};

/// The key size GENERATE SYMMETRIC KEY's P2 names.
fn aes_size(p2: u8) -> Option<AesSize> {
    Some(match p2 {
        AES_128 => AesSize::A128,
        AES_192 => AesSize::A192,
        AES_256 => AesSize::A256,
        _ => return None,
    })
}

const AES_KEY_MAX: usize = AesSize::A256.len();

impl HsmApplet<'_> {
    /// GENERATE SYMMETRIC KEY: a random AES key at `kid`, its use counter and
    /// algorithm list from the optional `90`, `91` and `92` objects.
    pub(crate) fn generate_symmetric<S: Storage>(&mut self, fs: &mut Fs<S>, apdu: &Apdu) -> Sw {
        into_sw(self.try_generate_symmetric(fs, apdu))
    }

    fn try_generate_symmetric<S: Storage>(
        &mut self,
        fs: &mut Fs<S>,
        apdu: &Apdu,
    ) -> Result<(), Sw> {
        let size = aes_size(apdu.p2).ok_or(Sw::INCORRECT_P1P2)?;
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
        if dkek::pending(fs)? {
            return Err(Sw::CONDITIONS_NOT_SATISFIED);
        }
        let mut limits = Limits::default();
        walk(apdu.data, |tag, v| match limits.take(tag, v) {
            Some(true) => Ok(()),
            _ => Err(Sw::WRONG_DATA),
        })?;
        let ty = KeyType::Aes(size);
        let algos = limits.algos(ty)?;
        if keys::exists(fs, apdu.p1)? {
            return Err(Sw::FILE_EXISTS);
        }
        room_for_object(fs)?;
        let mut rng = self.rng.borrow_mut();
        let mut key = Wiped::<AES_KEY_MAX>::zeroed();
        rng.fill(&mut key[..size.len()]);
        let obj = KeyObject::new(ty, limits.counter(), algos, &key[..size.len()])
            .ok_or(Sw::EXEC_ERROR)?;
        keys::store(fs, &hmk, apdu.p1, &obj, &mut *rng)
    }

    /// CIPHER SYMMETRIC: the data encrypted or decrypted block for block, or its
    /// CMAC.
    pub(crate) fn cipher_symmetric<S: Storage>(
        &mut self,
        fs: &mut Fs<S>,
        apdu: &Apdu,
        res: &mut ResBuf,
    ) -> Sw {
        into_sw(self.try_cipher_symmetric(fs, apdu, res))
    }

    fn try_cipher_symmetric<S: Storage>(
        &mut self,
        fs: &mut Fs<S>,
        apdu: &Apdu,
        res: &mut ResBuf,
    ) -> Result<(), Sw> {
        let (kid, algo, data) = (apdu.p1, apdu.p2, apdu.data);
        // CBC answers as much as it was given: refuse what cannot come back
        // before a use is spent on it.
        if data.len() > res.spare_mut().len() {
            return Err(Sw::WRONG_LENGTH);
        }
        let obj = self.take_key(fs, kid, Use::Cipher, algo, data)?;
        let key = obj.material();
        if algo == ALGO_AES_CMAC {
            return put(res, &aes_cmac(key, data)?);
        }
        let out = &mut res.spare_mut()[..data.len()];
        out.copy_from_slice(data);
        let iv = [0u8; AES_BLOCK];
        let done = if algo == ALGO_AES_CBC_ENCRYPT {
            aes_encrypt(key, &iv, Mode::Cbc, out)
        } else {
            aes_decrypt(key, &iv, Mode::Cbc, out)
        };
        if done.is_err() {
            out.fill(0);
            return Err(Sw::EXEC_ERROR);
        }
        res.commit(data.len());
        Ok(())
    }
}

#[cfg(test)]
#[path = "symmetric_tests.rs"]
mod tests;
