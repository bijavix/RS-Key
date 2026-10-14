// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The user PIN and the SO-PIN: VERIFY, CHANGE REFERENCE DATA and RESET RETRY
//! COUNTER, and the record reads they share with INITIALIZE and the lock.
//!
//! A try is spent and persisted before the PIN is checked, so cutting power on a
//! wrong guess cannot refund it, and given back only once the PIN has proven
//! itself. A closed lock and an unreadable record both refuse before a try is
//! spent: neither is a wrong PIN.

use rsk_crypto::{Device, ct_eq};
use rsk_fs::{Fs, Sealed, Storage};
use rsk_sdk::{Apdu, Rng, Sw};

use crate::HsmApplet;
use crate::consts::*;
use crate::records::{Counters, Init};
use crate::seal::{self, KEY_LEN, Key, SEALED_KEY_LEN, Unseal};
use crate::store::{REC_COUNTERS, REC_INIT, REC_USER, read_plain, read_sealed};

/// The initialization record, or `None` on a device never initialized.
pub(crate) fn load_init<S: Storage>(fs: &mut Fs<S>) -> Result<Option<Init>, Sw> {
    let mut buf = [0u8; Init::LEN];
    match read_sealed(fs, REC_INIT, &mut buf)? {
        Some(n) => Init::decode(&buf[..n]).map(Some).ok_or(Sw::MEMORY_FAILURE),
        None => Ok(None),
    }
}

/// [`load_init`] for the commands that need an initialized device.
pub(crate) fn require_init<S: Storage>(fs: &mut Fs<S>) -> Result<Init, Sw> {
    load_init(fs)?.ok_or(Sw::REFERENCE_NOT_FOUND)
}

pub(crate) fn write_init<S: Storage>(fs: &mut Fs<S>, init: &Init) -> Result<(), Sw> {
    fs.put_key(REC_INIT, Sealed::wrap(&init.encode()))
        .map_err(|_| Sw::MEMORY_FAILURE)
}

pub(crate) fn load_counters<S: Storage>(fs: &mut Fs<S>) -> Result<Counters, Sw> {
    let mut buf = [0u8; Counters::MAX_LEN];
    let n = read_plain(fs, REC_COUNTERS, &mut buf)?.ok_or(Sw::MEMORY_FAILURE)?;
    Counters::decode(&buf[..n]).ok_or(Sw::MEMORY_FAILURE)
}

pub(crate) fn store_counters<S: Storage>(fs: &mut Fs<S>, c: Counters) -> Result<(), Sw> {
    fs.put(REC_COUNTERS, &c.encode())
        .map_err(|_| Sw::MEMORY_FAILURE)
}

/// What a PIN with `left` tries answers.
fn tries(left: u8) -> Sw {
    if left == 0 {
        Sw::PIN_BLOCKED
    } else {
        Sw::retries(left)
    }
}

/// Check the SO-PIN against its verifier, spending a try first and giving it back
/// on a match. A verifier that only matches under the pre-OTP root is carried onto
/// the current one, best-effort: the at-rest lap is re-armed ahead of the write,
/// and a refusal leaves the old verifier to migrate at the next presentation.
pub(crate) fn check_so<S: Storage>(
    fs: &mut Fs<S>,
    dev: &Device,
    init: &mut Init,
    so_pin: &[u8],
) -> Result<(), Sw> {
    let mut c = load_counters(fs)?;
    if c.so == 0 {
        return Err(Sw::PIN_BLOCKED);
    }
    c.so -= 1;
    store_counters(fs, c)?;
    let current = seal::so_verifier(dev, so_pin);
    let matched = if ct_eq(&current, &init.so_verifier) {
        true
    } else if dev.otp_key.is_some()
        && ct_eq(
            &seal::so_verifier(&dev.without_otp(), so_pin),
            &init.so_verifier,
        )
    {
        let migrated = Init {
            so_verifier: current,
            ..init.clone()
        };
        if rsk_fs::request_rescrub(fs).is_ok() && write_init(fs, &migrated).is_ok() {
            *init = migrated;
        }
        true
    } else {
        false
    };
    if !matched {
        return Err(tries(c.so));
    }
    c.so = SO_RETRIES;
    store_counters(fs, c)
}

/// Seal HMK under `pin` into the user envelope.
pub(crate) fn write_user_envelope<S: Storage>(
    fs: &mut Fs<S>,
    rng: &mut dyn Rng,
    dk: &[u8; KEY_LEN],
    pin: &[u8],
    hmk: &[u8; KEY_LEN],
) -> Result<(), Sw> {
    let k = seal::pin_key(dk, PIN_USER, pin);
    let env = seal::seal_key(&k, REC_USER.get(), &[], hmk, rng);
    fs.put_key(REC_USER, Sealed::wrap(&env))
        .map_err(|_| Sw::MEMORY_FAILURE)
}

/// The user envelope as stored.
fn read_user_envelope<S: Storage>(fs: &mut Fs<S>) -> Result<[u8; SEALED_KEY_LEN], Sw> {
    let mut env = [0u8; SEALED_KEY_LEN];
    match read_sealed(fs, REC_USER, &mut env)? {
        Some(SEALED_KEY_LEN) => Ok(env),
        _ => Err(Sw::MEMORY_FAILURE),
    }
}

/// Try `pin` on the user envelope: `Ok(None)` is the wrong PIN.
fn try_user_pin(
    env: &[u8; SEALED_KEY_LEN],
    dk: &[u8; KEY_LEN],
    pin: &[u8],
) -> Result<Option<Key>, Sw> {
    let k = seal::pin_key(dk, PIN_USER, pin);
    match seal::open_key(&k, REC_USER.get(), &[], env) {
        Ok(hmk) => Ok(Some(hmk)),
        Err(Unseal::Auth) => Ok(None),
        Err(Unseal::Malformed) => Err(Sw::MEMORY_FAILURE),
    }
}

/// Seal HMK under the SO-PIN, bound to the record header it will sit behind.
pub(crate) fn seal_so_envelope(
    rng: &mut dyn Rng,
    dk: &[u8; KEY_LEN],
    so_pin: &[u8],
    options: u16,
    retry_max: u8,
    hmk: &[u8; KEY_LEN],
) -> [u8; SEALED_KEY_LEN] {
    let k = seal::pin_key(dk, PIN_SO, so_pin);
    seal::seal_key(
        &k,
        REC_INIT.get(),
        &Init::header(options, retry_max),
        hmk,
        rng,
    )
}

/// Open the SO envelope. Only reached once the verifier has matched, so a refusal
/// is a record that disagrees with itself, not a wrong PIN.
fn open_so_envelope(init: &Init, dk: &[u8; KEY_LEN], so_pin: &[u8]) -> Result<Key, Sw> {
    let k = seal::pin_key(dk, PIN_SO, so_pin);
    let header = Init::header(init.options, init.retry_max);
    seal::open_key(&k, REC_INIT.get(), &header, &init.so_envelope).map_err(|_| Sw::MEMORY_FAILURE)
}

/// Whether a user PIN of this length can exist.
fn user_pin_len_ok(n: usize) -> bool {
    (USER_PIN_MIN..=USER_PIN_MAX).contains(&n)
}

/// The SO-PIN's status: tries left, or blocked. It is never "verified".
fn so_status<S: Storage>(fs: &mut Fs<S>) -> Result<(), Sw> {
    require_init(fs)?;
    Err(tries(load_counters(fs)?.so))
}

pub(crate) fn into_sw(r: Result<(), Sw>) -> Sw {
    r.err().unwrap_or(Sw::OK)
}

impl HsmApplet<'_> {
    /// VERIFY. With no data it reports the reference's status; with data it
    /// presents the user PIN. The SO-PIN is never "verified": it travels with
    /// each command that needs it.
    pub(crate) fn verify<S: Storage>(&mut self, dev: &Device, fs: &mut Fs<S>, apdu: &Apdu) -> Sw {
        if apdu.p1 != 0 {
            return Sw::INCORRECT_P1P2;
        }
        into_sw(match apdu.p2 {
            PIN_USER if apdu.nc == 0 => self.user_status(fs),
            PIN_USER => self.verify_user(dev, fs, apdu.data),
            PIN_SO if apdu.nc == 0 => so_status(fs),
            PIN_SO => Err(Sw::COMMAND_NOT_ALLOWED),
            _ => Err(Sw::REFERENCE_NOT_FOUND),
        })
    }

    fn user_status<S: Storage>(&self, fs: &mut Fs<S>) -> Result<(), Sw> {
        require_init(fs)?;
        if self.sess.hmk.is_some() {
            return Ok(());
        }
        Err(tries(load_counters(fs)?.user))
    }

    fn verify_user<S: Storage>(
        &mut self,
        dev: &Device,
        fs: &mut Fs<S>,
        pin: &[u8],
    ) -> Result<(), Sw> {
        let init = require_init(fs)?;
        if !user_pin_len_ok(pin.len()) {
            return Err(Sw::WRONG_LENGTH);
        }
        self.require_open(fs)?;
        let dk = self.dk(dev, fs)?;
        let env = read_user_envelope(fs)?;
        let mut c = load_counters(fs)?;
        if c.user == 0 {
            return Err(Sw::PIN_BLOCKED);
        }
        // A failed attempt must not leave the previous login standing.
        self.sess.hmk = None;
        c.user -= 1;
        store_counters(fs, c)?;
        let Some(hmk) = try_user_pin(&env, &dk, pin)? else {
            return Err(tries(c.user));
        };
        c.user = init.retry_max;
        store_counters(fs, c)?;
        self.sess.hmk = Some(hmk);
        Ok(())
    }

    /// CHANGE REFERENCE DATA: `old ‖ new` for the user PIN, `old(8) ‖ new(8)` for
    /// the SO-PIN.
    pub(crate) fn change_reference<S: Storage>(
        &mut self,
        dev: &Device,
        fs: &mut Fs<S>,
        apdu: &Apdu,
    ) -> Sw {
        if apdu.p1 != 0 {
            return Sw::INCORRECT_P1P2;
        }
        into_sw(match apdu.p2 {
            PIN_USER => self.change_user(dev, fs, apdu.data),
            PIN_SO => self.change_so(dev, fs, apdu.data),
            _ => Err(Sw::REFERENCE_NOT_FOUND),
        })
    }

    /// The host sends the two PINs back to back with no lengths, and the device
    /// keeps no record of the current PIN's length — that would be one more thing
    /// a dump gives away. Every split that leaves two valid PINs is tried under one
    /// spent try; a match at the wrong split would be a forged GCM tag.
    fn change_user<S: Storage>(
        &mut self,
        dev: &Device,
        fs: &mut Fs<S>,
        data: &[u8],
    ) -> Result<(), Sw> {
        let init = require_init(fs)?;
        if !(2 * USER_PIN_MIN..=2 * USER_PIN_MAX).contains(&data.len()) {
            return Err(Sw::WRONG_LENGTH);
        }
        self.require_open(fs)?;
        let dk = self.dk(dev, fs)?;
        let env = read_user_envelope(fs)?;
        let mut c = load_counters(fs)?;
        if c.user == 0 {
            return Err(Sw::PIN_BLOCKED);
        }
        self.sess.hmk = None;
        c.user -= 1;
        store_counters(fs, c)?;
        let mut found = None;
        for old_len in USER_PIN_MIN..=USER_PIN_MAX {
            if !user_pin_len_ok(data.len().saturating_sub(old_len)) {
                continue;
            }
            if let Some(hmk) = try_user_pin(&env, &dk, &data[..old_len])? {
                found = Some((old_len, hmk));
                break;
            }
        }
        let Some((old_len, hmk)) = found else {
            return Err(tries(c.user));
        };
        // The superseded envelope still opens under the old PIN until the at-rest
        // lap reclaims it, so the lap is re-armed first and the write waits on it.
        rsk_fs::request_rescrub(fs).map_err(|_| Sw::MEMORY_FAILURE)?;
        let mut rng = self.rng.borrow_mut();
        write_user_envelope(fs, &mut *rng, &dk, &data[old_len..], &hmk)?;
        c.user = init.retry_max;
        store_counters(fs, c)?;
        self.sess.hmk = Some(hmk);
        Ok(())
    }

    fn change_so<S: Storage>(
        &mut self,
        dev: &Device,
        fs: &mut Fs<S>,
        data: &[u8],
    ) -> Result<(), Sw> {
        let mut init = require_init(fs)?;
        if data.len() != 2 * SO_PIN_LEN {
            return Err(Sw::WRONG_LENGTH);
        }
        self.require_open(fs)?;
        let (old, new) = data.split_at(SO_PIN_LEN);
        check_so(fs, dev, &mut init, old)?;
        let dk = self.dk(dev, fs)?;
        let hmk = open_so_envelope(&init, &dk, old)?;
        let mut rng = self.rng.borrow_mut();
        let changed = Init {
            so_verifier: seal::so_verifier(dev, new),
            so_envelope: seal_so_envelope(&mut *rng, &dk, new, init.options, init.retry_max, &hmk),
            ..init
        };
        rsk_fs::request_rescrub(fs).map_err(|_| Sw::MEMORY_FAILURE)?;
        write_init(fs, &changed)
    }

    /// RESET RETRY COUNTER for the user PIN, authorized by the SO-PIN: `P1 = 00`
    /// carries `SO ‖ new PIN`, `P1 = 01` the SO-PIN alone and only unblocks.
    pub(crate) fn reset_retry<S: Storage>(
        &mut self,
        dev: &Device,
        fs: &mut Fs<S>,
        apdu: &Apdu,
    ) -> Sw {
        if apdu.p2 != PIN_USER {
            return Sw::REFERENCE_NOT_FOUND;
        }
        into_sw(self.try_reset_retry(dev, fs, apdu))
    }

    fn try_reset_retry<S: Storage>(
        &mut self,
        dev: &Device,
        fs: &mut Fs<S>,
        apdu: &Apdu,
    ) -> Result<(), Sw> {
        let new_pin = match apdu.p1 {
            0x00 if apdu.data.len() > SO_PIN_LEN => Some(&apdu.data[SO_PIN_LEN..]),
            0x01 if apdu.data.len() == SO_PIN_LEN => None,
            0x00 | 0x01 => return Err(Sw::WRONG_LENGTH),
            _ => return Err(Sw::INCORRECT_P1P2),
        };
        let mut init = require_init(fs)?;
        if init.options & OPT_RRC == 0
            || (new_pin.is_some() && init.options & OPT_RRC_UNBLOCK_ONLY != 0)
        {
            return Err(Sw::CONDITIONS_NOT_SATISFIED);
        }
        if new_pin.is_some_and(|p| !user_pin_len_ok(p.len())) {
            return Err(Sw::WRONG_LENGTH);
        }
        self.require_open(fs)?;
        let so = &apdu.data[..SO_PIN_LEN];
        check_so(fs, dev, &mut init, so)?;
        if let Some(pin) = new_pin {
            let dk = self.dk(dev, fs)?;
            let hmk = open_so_envelope(&init, &dk, so)?;
            rsk_fs::request_rescrub(fs).map_err(|_| Sw::MEMORY_FAILURE)?;
            let mut rng = self.rng.borrow_mut();
            write_user_envelope(fs, &mut *rng, &dk, pin, &hmk)?;
        }
        let mut c = load_counters(fs)?;
        c.user = init.retry_max;
        store_counters(fs, c)
    }
}
