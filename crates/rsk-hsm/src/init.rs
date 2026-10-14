// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! INITIALIZE DEVICE: set the SO-PIN, the user PIN and the options on a new
//! device, or — with the current SO-PIN and a touch — wipe every key and start
//! over, the lock included.
//!
//! The initialization record is written last and is what "initialized" means, so
//! a power cut part-way leaves either the old device (the SO can run it again) or
//! one that reads as never initialized, whose next INITIALIZE sweeps the rest.

use rsk_crypto::Device;
use rsk_fs::{Fs, Storage};
use rsk_sdk::{Apdu, Confirm, Sw};

use crate::auth::{
    check_so, into_sw, load_init, seal_so_envelope, store_counters, write_init, write_user_envelope,
};
use crate::consts::*;
use crate::files::walk;
use crate::records::{Counters, Factor, Init};
use crate::{HsmApplet, Session, dk, seal, store};

/// What INITIALIZE carries.
struct Params<'d> {
    options: u16,
    user_pin: &'d [u8],
    so_pin: &'d [u8],
    retries: u8,
}

/// Parse the data objects strictly: an object this build does not implement —
/// DKEK shares, key domains, public-key authentication, biometrics — is refused,
/// never silently dropped.
fn parse(data: &[u8]) -> Result<Params<'_>, Sw> {
    let mut options = None;
    let mut user_pin = None;
    let mut so_pin = None;
    let mut retries = None;
    walk(data, |tag, v| {
        let fresh = match tag {
            TAG_INIT_OPTIONS => match *v {
                [hi, lo] => options.replace(u16::from_be_bytes([hi, lo])).is_none(),
                _ => false,
            },
            TAG_INIT_USER_PIN if (USER_PIN_MIN..=USER_PIN_MAX).contains(&v.len()) => {
                user_pin.replace(v).is_none()
            }
            TAG_INIT_SO_PIN if v.len() == SO_PIN_LEN => so_pin.replace(v).is_none(),
            TAG_INIT_RETRIES => match *v {
                [r] if (1..=USER_RETRIES_MAX).contains(&r) => retries.replace(r).is_none(),
                _ => false,
            },
            _ => false,
        };
        if fresh { Ok(()) } else { Err(Sw::WRONG_DATA) }
    })?;
    let options = options.unwrap_or(0);
    if options & !OPT_SUPPORTED != 0 {
        return Err(Sw::WRONG_DATA);
    }
    Ok(Params {
        options,
        user_pin: user_pin.ok_or(Sw::WRONG_DATA)?,
        so_pin: so_pin.ok_or(Sw::WRONG_DATA)?,
        retries: retries.unwrap_or(USER_RETRIES_DEFAULT),
    })
}

impl HsmApplet<'_> {
    pub(crate) fn initialize<S: Storage>(
        &mut self,
        dev: &Device,
        fs: &mut Fs<S>,
        apdu: &Apdu,
    ) -> Sw {
        if apdu.p1 != 0 || apdu.p2 != 0 {
            return Sw::INCORRECT_P1P2;
        }
        into_sw(self.try_initialize(dev, fs, apdu.data))
    }

    fn try_initialize<S: Storage>(
        &mut self,
        dev: &Device,
        fs: &mut Fs<S>,
        data: &[u8],
    ) -> Result<(), Sw> {
        let p = parse(data)?;
        // A re-initialization needs the current SO-PIN — the device root alone
        // checks it, so a locked device can still be reset by its SO — and a touch,
        // because it destroys every key.
        if let Some(mut init) = load_init(fs)? {
            check_so(fs, dev, &mut init, p.so_pin)?;
            self.require_touch(Confirm::titled("Erase all HSM keys?"))?;
        }
        // Tombstones supersede sealed records like any re-seal does: the at-rest
        // lap is re-armed around the sweep, best-effort, as every wipe does.
        let _ = rsk_fs::request_rescrub(fs);
        let swept = store::sweep(fs);
        let _ = rsk_fs::request_rescrub(fs);
        swept?;
        let mut rng = self.rng.borrow_mut();
        let dk = seal::random_key(&mut *rng);
        let hmk = seal::random_key(&mut *rng);
        dk::write(fs, dev, &mut *rng, &dk, Factor::None, None)?;
        write_user_envelope(fs, &mut *rng, &dk, p.user_pin, &hmk)?;
        store_counters(
            fs,
            Counters {
                user: p.retries,
                so: SO_RETRIES,
            },
        )?;
        let init = Init {
            options: p.options,
            retry_max: p.retries,
            so_verifier: seal::so_verifier(dev, p.so_pin),
            so_envelope: seal_so_envelope(&mut *rng, &dk, p.so_pin, p.options, p.retries, &hmk),
        };
        write_init(fs, &init)?;
        drop(rng);
        self.lock.reinitialized();
        self.channel = None;
        self.sess = Session {
            label_grant: true,
            ..Session::default()
        };
        Ok(())
    }
}

#[cfg(test)]
#[path = "init_tests.rs"]
mod tests;
