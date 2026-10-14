// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The default key domain's DKEK, the key every backup is wrapped under. The
//! owners hold it as shares and the device holds their XOR, so no single share
//! holder knows it; or INITIALIZE draws it at random, for an owner who keeps no
//! copy outside the device. MANAGE KEY DOMAIN reports it and takes the shares.

use rsk_crypto::{Device, sha256};
use rsk_fs::{Fs, Sealed, Storage};
use rsk_sdk::{Apdu, ResBuf, Rng, Sw};

use crate::HsmApplet;
use crate::auth::{into_sw, require_init};
use crate::consts::*;
use crate::seal::{self, KEY_LEN, Key, SEALED_KEY_LEN, Wiped};
use crate::store::{REC_DKEK, read_sealed};

const VERSION: u8 = 1;
/// `ver ‖ total ‖ imported`, in the clear and bound into the seal.
const HEADER_LEN: usize = 3;
const RECORD_LEN: usize = HEADER_LEN + SEALED_KEY_LEN;
const _: () = assert!(DKEK_SHARE_LEN == KEY_LEN);

/// A DKEK's key check value: how a share holder sees that the device combined
/// what they think it did, and how a backup names the DKEK it needs.
pub(crate) fn kcv(value: &[u8; KEY_LEN]) -> [u8; DKEK_KCV_LEN] {
    let mut kcv = [0u8; DKEK_KCV_LEN];
    kcv.copy_from_slice(&sha256(value)[..DKEK_KCV_LEN]);
    kcv
}

/// The DKEK as far as it is assembled: `imported` of `total` shares, XORed.
pub(crate) struct Dkek {
    pub total: u8,
    pub imported: u8,
    value: Key,
}

impl Dkek {
    /// A DKEK to be assembled from `total` shares.
    pub(crate) fn awaiting(total: u8) -> Dkek {
        Dkek {
            total,
            imported: 0,
            value: Key::zeroed(),
        }
    }

    /// A DKEK drawn at random, complete from the start.
    pub(crate) fn random(rng: &mut dyn Rng) -> Dkek {
        Dkek {
            total: 1,
            imported: 1,
            value: seal::random_key(rng),
        }
    }

    pub(crate) fn complete(&self) -> bool {
        self.imported == self.total
    }

    /// The key check value of what is assembled so far.
    pub(crate) fn kcv(&self) -> [u8; DKEK_KCV_LEN] {
        kcv(&self.value)
    }

    /// The DKEK itself, once every share is in.
    pub(crate) fn key(&self) -> Option<&Key> {
        self.complete().then_some(&self.value)
    }

    fn import(&mut self, share: &[u8; DKEK_SHARE_LEN]) {
        for (v, s) in self.value.iter_mut().zip(share) {
            *v ^= s;
        }
        self.imported += 1;
    }

    fn header(&self) -> [u8; HEADER_LEN] {
        [VERSION, self.total, self.imported]
    }
}

/// The header alone: `(total, imported)`, or `None` with no DKEK configured. A
/// header no build wrote is a memory failure.
fn header<S: Storage>(fs: &mut Fs<S>) -> Result<Option<(u8, u8)>, Sw> {
    let mut buf = [0u8; RECORD_LEN];
    let Some(n) = read_sealed(fs, REC_DKEK, &mut buf)? else {
        return Ok(None);
    };
    match buf[..n] {
        [VERSION, total, imported, ..] if n == RECORD_LEN && total > 0 && imported <= total => {
            Ok(Some((total, imported)))
        }
        _ => Err(Sw::MEMORY_FAILURE),
    }
}

/// Whether shares are still owed. Keys wait for the last one: until the DKEK is
/// complete no key could be backed up, and an owner who asked for backups has
/// not finished setting the device up.
pub(crate) fn pending<S: Storage>(fs: &mut Fs<S>) -> Result<bool, Sw> {
    Ok(header(fs)?.is_some_and(|(total, imported)| imported < total))
}

pub(crate) fn load<S: Storage>(fs: &mut Fs<S>, dk: &[u8; KEY_LEN]) -> Result<Option<Dkek>, Sw> {
    let Some((total, imported)) = header(fs)? else {
        return Ok(None);
    };
    let mut buf = [0u8; RECORD_LEN];
    read_sealed(fs, REC_DKEK, &mut buf)?.ok_or(Sw::MEMORY_FAILURE)?;
    let value = seal::open_key(
        &seal::dkek_key(dk, REC_DKEK.get()),
        REC_DKEK.get(),
        &buf[..HEADER_LEN],
        &buf[HEADER_LEN..],
    )
    .map_err(|_| Sw::MEMORY_FAILURE)?;
    Ok(Some(Dkek {
        total,
        imported,
        value,
    }))
}

pub(crate) fn store<S: Storage>(
    fs: &mut Fs<S>,
    dk: &[u8; KEY_LEN],
    d: &Dkek,
    rng: &mut dyn Rng,
) -> Result<(), Sw> {
    let header = d.header();
    let mut rec = [0u8; RECORD_LEN];
    rec[..HEADER_LEN].copy_from_slice(&header);
    rec[HEADER_LEN..].copy_from_slice(&seal::seal_key(
        &seal::dkek_key(dk, REC_DKEK.get()),
        REC_DKEK.get(),
        &header,
        &d.value,
        rng,
    ));
    fs.put_key(REC_DKEK, Sealed::wrap(&rec))
        .map_err(|_| Sw::MEMORY_FAILURE)
}

impl HsmApplet<'_> {
    /// The complete DKEK, for WRAP and UNWRAP: `6A88` with none configured, `6985`
    /// while shares are owed.
    pub(crate) fn dkek<S: Storage>(&mut self, dev: &Device, fs: &mut Fs<S>) -> Result<Key, Sw> {
        let dk = self.dk(dev, fs)?;
        let d = load(fs, &dk)?.ok_or(Sw::REFERENCE_NOT_FOUND)?;
        d.key().cloned().ok_or(Sw::CONDITIONS_NOT_SATISFIED)
    }

    /// MANAGE KEY DOMAIN (`80 52 00 00`): with no data, the status; with a share,
    /// its import. Either way the answer is `total ‖ outstanding ‖ KCV`.
    pub(crate) fn key_domain<S: Storage>(
        &mut self,
        dev: &Device,
        fs: &mut Fs<S>,
        apdu: &Apdu,
        res: &mut ResBuf,
    ) -> Sw {
        into_sw(self.try_key_domain(dev, fs, apdu, res))
    }

    fn try_key_domain<S: Storage>(
        &mut self,
        dev: &Device,
        fs: &mut Fs<S>,
        apdu: &Apdu,
        res: &mut ResBuf,
    ) -> Result<(), Sw> {
        if apdu.p1 != KEY_DOMAIN_DKEK || apdu.p2 != KEY_DOMAIN_DEFAULT {
            return Err(Sw::INCORRECT_P1P2);
        }
        let share = match apdu.data.len() {
            0 => None,
            DKEK_SHARE_LEN => Some(Wiped::<DKEK_SHARE_LEN>::new(
                apdu.data.try_into().map_err(|_| Sw::WRONG_LENGTH)?,
            )),
            _ => return Err(Sw::WRONG_LENGTH),
        };
        require_init(fs)?;
        let dk = self.dk(dev, fs)?;
        let mut d = load(fs, &dk)?.ok_or(Sw::REFERENCE_NOT_FOUND)?;
        if let Some(share) = share {
            if d.complete() {
                return Err(Sw::COMMAND_NOT_ALLOWED);
            }
            d.import(&share);
            store(fs, &dk, &d, &mut *self.rng.borrow_mut())?;
        }
        let ok = res.push(d.total) && res.push(d.total - d.imported) && res.extend(&d.kcv());
        if ok { Ok(()) } else { Err(Sw::WRONG_LENGTH) }
    }
}

#[cfg(test)]
#[path = "dkek_tests.rs"]
mod tests;
