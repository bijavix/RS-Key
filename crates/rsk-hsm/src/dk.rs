// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! DK and its record: written at initialization, re-sealed as the lock is armed
//! and disarmed, and carried forward when the OTP root is burned under it.

use rsk_crypto::Device;
use rsk_fs::{Fs, Sealed, Storage};
use rsk_sdk::{Rng, Sw};

use crate::records::{DEV_HDR_MAX, DEV_MAX_LEN, DevRecord, Factor};
use crate::seal::{self, KEY_LEN, Key, SEALED_KEY_LEN, Unseal};
use crate::store::{REC_DEV, read_sealed};

/// The device record's factor, or `None` when there is no record — a device that
/// was never initialized.
pub(crate) fn factor<S: Storage>(fs: &mut Fs<S>) -> Result<Option<Factor>, Sw> {
    let mut buf = [0u8; DEV_MAX_LEN];
    let Some(n) = read_sealed(fs, REC_DEV, &mut buf)? else {
        return Ok(None);
    };
    let rec = DevRecord::decode(&buf[..n]).ok_or(Sw::MEMORY_FAILURE)?;
    Ok(Some(rec.factor))
}

/// Write the device record around `dk`: armed under `unlock` for a factor, or
/// disarmed under the device root alone.
pub(crate) fn write<S: Storage>(
    fs: &mut Fs<S>,
    dev: &Device,
    rng: &mut dyn Rng,
    dk: &[u8; KEY_LEN],
    factor: Factor,
    unlock: Option<&[u8; KEY_LEN]>,
) -> Result<(), Sw> {
    if (factor == Factor::None) != unlock.is_none() {
        return Err(Sw::UNKNOWN);
    }
    let mut hdr = [0u8; DEV_HDR_MAX];
    let h = DevRecord::header(factor, &[], &mut hdr);
    let k = seal::device_key(dev, unlock);
    let env = seal::seal_key(&k, REC_DEV.get(), &hdr[..h], dk, rng);
    let mut rec = [0u8; DEV_MAX_LEN];
    rec[..h].copy_from_slice(&hdr[..h]);
    rec[h..h + SEALED_KEY_LEN].copy_from_slice(&env);
    fs.put_key(REC_DEV, Sealed::wrap(&rec[..h + SEALED_KEY_LEN]))
        .map_err(|_| Sw::MEMORY_FAILURE)
}

/// What a candidate unlock secret did to the record.
pub(crate) enum Opened {
    Key(Key),
    /// The tag did not verify: the wrong secret for an armed record — and, for a
    /// disarmed one, a record this device's root never sealed.
    Refused,
}

/// Open DK — with the unlock secret for an armed record, without one for a
/// disarmed record — and, when it only opens under the pre-OTP root, re-seal it
/// under the current one before handing it back. The re-seal is best-effort:
/// the at-rest lap is re-armed first and the write is skipped if that refuses,
/// so the next open simply migrates again.
pub(crate) fn open_and_migrate<S: Storage>(
    fs: &mut Fs<S>,
    dev: &Device,
    rng: &mut dyn Rng,
    unlock: Option<&[u8; KEY_LEN]>,
) -> Result<Opened, Sw> {
    let mut buf = [0u8; DEV_MAX_LEN];
    let n = read_sealed(fs, REC_DEV, &mut buf)?.ok_or(Sw::MEMORY_FAILURE)?;
    let rec = DevRecord::decode(&buf[..n]).ok_or(Sw::MEMORY_FAILURE)?;
    if (rec.factor == Factor::None) != unlock.is_none() {
        return Ok(Opened::Refused);
    }
    let k = seal::device_key(dev, unlock);
    match seal::open_key(&k, REC_DEV.get(), rec.bind, rec.envelope) {
        Ok(dk) => return Ok(Opened::Key(dk)),
        Err(Unseal::Malformed) => return Err(Sw::MEMORY_FAILURE),
        Err(Unseal::Auth) => {}
    }
    if dev.otp_key.is_none() {
        return Ok(Opened::Refused);
    }
    let k = seal::device_key(&dev.without_otp(), unlock);
    let Ok(dk) = seal::open_key(&k, REC_DEV.get(), rec.bind, rec.envelope) else {
        return Ok(Opened::Refused);
    };
    let factor = rec.factor;
    if rsk_fs::request_rescrub(fs).is_ok() {
        let _ = write(fs, dev, rng, &dk, factor, unlock);
    }
    Ok(Opened::Key(dk))
}

/// Boot pass: carry a disarmed record sealed before the OTP root was burned onto
/// the current root. An armed record cannot be opened here — it migrates at its
/// next unlock — and an absent or unreadable one is left for the commands to
/// report.
pub fn migrate_seal<S: Storage>(dev: &Device, fs: &mut Fs<S>, rng: &mut dyn Rng) {
    if dev.otp_key.is_none() || factor(fs) != Ok(Some(Factor::None)) {
        return;
    }
    let _ = open_and_migrate(fs, dev, rng, None);
}

#[cfg(test)]
#[path = "dk_tests.rs"]
mod tests;
