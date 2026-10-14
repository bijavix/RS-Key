// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Where the HSM keeps things in `rsk-fs`.
//!
//! The applet owns `0xA000..=0xA8FF` and nothing else, so an image that never had
//! the HSM reads none of it and a reflash between images leaves both sides intact.
//! SmartCard-HSM file identifiers are translated, never stored as they are: `CE14`
//! is a live EE-certificate FID there and `rsk-fs`'s own at-rest marker here.

use rsk_fs::{Fs, KeyFid, Storage};
use rsk_sdk::Sw;

use crate::consts::*;

/// The initialization record: options, the retry limit, the SO-PIN verifier and
/// the SO's sealed copy of HMK. Present ⇔ initialized; it is written last.
pub(crate) const REC_INIT: KeyFid = KeyFid::new(0xA001);
/// The two retry counters.
pub(crate) const REC_COUNTERS: u16 = 0xA002;
/// DK, sealed under the device root (and the unlock secret while armed), behind
/// the clear lock header that says which.
pub(crate) const REC_DEV: KeyFid = KeyFid::new(0xA003);
/// The user's sealed copy of HMK.
pub(crate) const REC_USER: KeyFid = KeyFid::new(0xA004);
/// The token label EF.TokenInfo is synthesized around.
pub(crate) const REC_LABEL: u16 = 0xA006;
/// The device certificate chain (`2F02`).
pub(crate) const REC_DEVAUT: u16 = 0xA009;
/// UNWRAP KEY's staging file (`2F10`).
pub(crate) const REC_STAGING: u16 = 0xA00B;

/// The whole range, for the re-initialization sweep.
const RANGE_LO: u16 = 0xA000;
const RANGE_HI: u16 = 0xA8FF;

/// Largest value a plain record may hold, and so a public object.
pub(crate) const MAX_PLAIN: usize = rsk_fs::MAX_VALUE_BYTES;

/// A class of SmartCard-HSM object: its FID prefix and where its 256 ids live.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Class {
    /// Private and secret keys (`CCxx`). Sealed; never read back.
    Key,
    /// PKCS#15 private-key descriptions (`C4xx`).
    Prkd,
    /// PKCS#15 certificate descriptions (`C8xx`).
    Cd,
    /// PKCS#15 data-object descriptions (`C9xx`).
    Dcod,
    /// CA certificates (`CAxx`).
    CaCert,
    /// PIN-protected data (`CDxx`). Sealed under HMK.
    ProtData,
    /// End-entity certificates and requests (`CExx`).
    EeCert,
    /// Readable data (`CFxx`).
    Data,
}

impl Class {
    /// Every class, in the order ENUMERATE lists them.
    pub(crate) const ALL: [Class; 8] = [
        Class::Key,
        Class::Prkd,
        Class::Cd,
        Class::Dcod,
        Class::CaCert,
        Class::ProtData,
        Class::EeCert,
        Class::Data,
    ];

    pub(crate) const fn prefix(self) -> u8 {
        match self {
            Class::Key => PREFIX_KEY,
            Class::Prkd => PREFIX_PRKD,
            Class::Cd => PREFIX_CD,
            Class::Dcod => PREFIX_DCOD,
            Class::CaCert => PREFIX_CA_CERT,
            Class::ProtData => PREFIX_PROT_DATA,
            Class::EeCert => PREFIX_EE_CERT,
            Class::Data => PREFIX_DATA,
        }
    }

    /// The `rsk-fs` FID of id 0 in this class.
    pub(crate) const fn base(self) -> u16 {
        match self {
            Class::Key => 0xA100,
            Class::Prkd => 0xA200,
            Class::Cd => 0xA300,
            Class::Dcod => 0xA400,
            Class::CaCert => 0xA500,
            Class::ProtData => 0xA600,
            Class::EeCert => 0xA700,
            Class::Data => 0xA800,
        }
    }

    fn from_prefix(p: u8) -> Option<Class> {
        Class::ALL.into_iter().find(|c| c.prefix() == p)
    }

    /// Whether the content is sealed rather than stored as written.
    pub(crate) const fn sealed(self) -> bool {
        matches!(self, Class::Key | Class::ProtData)
    }
}

/// What a SmartCard-HSM file identifier names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum File {
    Object(Class, u8),
    /// `2F02`, written once by the device and never by a host.
    DevAut,
    /// `2F03`, synthesized from [`REC_LABEL`].
    TokenInfo,
    /// `2F10`.
    Staging,
}

impl File {
    pub(crate) fn from_fid(fid: u16) -> Option<File> {
        match fid {
            FID_DEVAUT => Some(File::DevAut),
            FID_TOKENINFO => Some(File::TokenInfo),
            FID_STAGING => Some(File::Staging),
            _ => {
                let [prefix, id] = fid.to_be_bytes();
                Class::from_prefix(prefix).map(|c| File::Object(c, id))
            }
        }
    }

    /// The `rsk-fs` FID the content lives at.
    pub(crate) fn store(self) -> u16 {
        match self {
            File::Object(c, id) => c.base() | id as u16,
            File::DevAut => REC_DEVAUT,
            File::TokenInfo => REC_LABEL,
            File::Staging => REC_STAGING,
        }
    }
}

/// The records a re-initialization keeps: the device's own identity, which is
/// not the owner's data and outlives every owner.
fn survives_reinit(fid: u16) -> bool {
    fid == REC_DEVAUT || fid == File::Object(Class::Key, KEY_ID_DEVICE).store()
}

/// FIDs one sweep pass collects before deleting them: `for_each_key` cannot run
/// while the store mutates.
const SWEEP_BATCH: usize = 32;
/// More deletions than the range has FIDs means a backend that keeps yielding
/// what it was told to remove: the sweep is not converging.
const SWEEP_MAX_DELETES: usize = (RANGE_HI - RANGE_LO) as usize + 1;

/// Delete every HSM record but the device identity. An enumeration a read fault
/// cut short fails rather than reading as "the range is clear", and so does a
/// metadata drop that could not be proven — after the rest of the range is gone.
pub(crate) fn sweep<S: Storage>(fs: &mut Fs<S>) -> Result<(), Sw> {
    let mut deleted = 0usize;
    let mut orphaned = false;
    loop {
        let mut batch = [0u16; SWEEP_BATCH];
        let mut n = 0usize;
        let complete = fs.for_each_key(&mut |fid| {
            if (RANGE_LO..=RANGE_HI).contains(&fid)
                && !survives_reinit(fid)
                && n < SWEEP_BATCH
                && !batch[..n].contains(&fid)
            {
                batch[n] = fid;
                n += 1;
            }
        });
        if n == 0 {
            return if complete && !orphaned {
                Ok(())
            } else {
                Err(Sw::MEMORY_FAILURE)
            };
        }
        deleted += n;
        if deleted > SWEEP_MAX_DELETES {
            return Err(Sw::MEMORY_FAILURE);
        }
        for &fid in &batch[..n] {
            let gone = fs.force_delete_halves(fid);
            gone.value.map_err(|_| Sw::MEMORY_FAILURE)?;
            orphaned |= gone.record.is_err();
        }
    }
}

/// Which object ids of each class are live, read from one walk of the store.
/// `None` when a read fault cut the walk short: an id it never reached is not
/// evidence of absence.
pub(crate) fn live_objects<S: Storage>(fs: &mut Fs<S>) -> Option<[[u8; 32]; 8]> {
    let mut live = [[0u8; 32]; 8];
    let complete = fs.for_each_key(&mut |fid| {
        for (i, c) in Class::ALL.into_iter().enumerate() {
            if fid & 0xFF00 == c.base() {
                let id = (fid & 0xFF) as usize;
                live[i][id / 8] |= 1 << (id % 8);
            }
        }
    });
    complete.then_some(live)
}

/// Read a whole plain record into `buf`: `Ok(None)` is a confirmed absence, a
/// value larger than `buf` or a failed probe is a memory failure.
pub(crate) fn read_plain<S: Storage>(
    fs: &mut Fs<S>,
    fid: u16,
    buf: &mut [u8],
) -> Result<Option<usize>, Sw> {
    match fs.try_read(fid, buf) {
        Ok(Some(n)) if n <= buf.len() => Ok(Some(n)),
        Ok(Some(_)) | Err(_) => Err(Sw::MEMORY_FAILURE),
        Ok(None) => Ok(None),
    }
}

/// The length of the record at `fid`, or `None` when it is absent.
pub(crate) fn size<S: Storage>(fs: &mut Fs<S>, fid: u16) -> Result<Option<usize>, Sw> {
    fs.try_read(fid, &mut []).map_err(|_| Sw::MEMORY_FAILURE)
}

/// [`read_plain`] for a sealed record.
pub(crate) fn read_sealed<S: Storage>(
    fs: &mut Fs<S>,
    fid: KeyFid,
    buf: &mut [u8],
) -> Result<Option<usize>, Sw> {
    match fs.try_read_key(fid, buf) {
        Ok(Some(n)) if n <= buf.len() => Ok(Some(n)),
        Ok(Some(_)) | Err(_) => Err(Sw::MEMORY_FAILURE),
        Ok(None) => Ok(None),
    }
}

#[cfg(test)]
#[path = "store_tests.rs"]
mod tests;
