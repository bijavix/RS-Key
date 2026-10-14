// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![cfg_attr(not(test), no_std)]

//! `rsk-hsm` — the HSM applet of the HSM image: a SmartCard-HSM-compatible APDU
//! subset, so OpenSC's built-in `sc-hsm` driver serves it as a PKCS#11 token with
//! no driver of our own. Keys at rest are sealed under the device root (`seal`),
//! the user PIN opens them (`auth`), and an armed lock (`lock`) keeps the whole
//! store closed until an unlock secret is presented, every power cycle.

mod auth;
mod channel;
pub mod consts;
mod cvc;
mod devaut;
mod digest;
mod dk;
mod domain;
mod files;
mod init;
mod keygen;
mod keyops;
mod keys;
mod lock;
mod lockcmd;
mod records;
mod seal;
mod store;

use core::cell::RefCell;

use rsk_crypto::{Device, FusedKey, FusedRead, read_fused};
use rsk_fs::{Fs, Storage};
pub use rsk_sdk::{AlwaysConfirm, Presence, Rng, UserPresence};
use rsk_sdk::{Apdu, Applet, Confirm, ResBuf, Sw};

pub use consts::HSM_AID;
pub use devaut::{ROOT_POINT_LEN, ROOT_SIG_LEN, RootSign, provision};
pub use dk::migrate_seal;

use channel::Channel;
use consts::*;
use lock::{Event, Lock, Refusal};
use records::Factor;
use seal::Key;

/// Volatile per-selection state: dropped by SELECT, a card reset and a power
/// cycle, and with it HMK.
#[derive(Default)]
pub(crate) struct Session {
    /// HMK, while the user PIN is verified.
    hmk: Option<Key>,
    /// The currently selected EF, by its SmartCard-HSM file identifier.
    ef: Option<u16>,
    /// Set by INITIALIZE until the next selection: the token label may be written
    /// before a user PIN has ever been verified, which is how OpenSC follows an
    /// initialization.
    label_grant: bool,
}

/// Why the unlock seam refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlockError {
    /// The lock is not armed: there is nothing to unlock.
    NotArmed,
    /// The secret does not open the device record.
    Refused,
    /// The store could not be read or written.
    Memory,
}

pub struct HsmApplet<'a> {
    serial_id: [u8; 8],
    serial_hash: [u8; 32],
    /// How to read the OTP MKEK, once provisioned — never the key itself.
    mkek_source: Option<FusedKey>,
    rng: &'a RefCell<dyn Rng>,
    presence: &'a RefCell<dyn UserPresence>,
    lock: Lock,
    sess: Session,
    /// The lock channel the next UNLOCK or ARM box is sealed to; single use.
    channel: Option<Channel>,
}

impl<'a> HsmApplet<'a> {
    pub fn new(
        serial_id: [u8; 8],
        serial_hash: [u8; 32],
        mkek_source: Option<FusedKey>,
        rng: &'a RefCell<dyn Rng>,
        presence: &'a RefCell<dyn UserPresence>,
    ) -> Self {
        HsmApplet {
            serial_id,
            serial_hash,
            mkek_source,
            rng,
            presence,
            lock: Lock::Unknown,
            sess: Session::default(),
            channel: None,
        }
    }

    /// Owned copies of the device identifiers, for a [`Device`] that does not
    /// borrow `self`. The MKEK is read here, so it is live only while the caller
    /// holds the tuple.
    fn device_ids(&self) -> ([u8; 32], [u8; 8], FusedRead) {
        (
            self.serial_hash,
            self.serial_id,
            read_fused(self.mkek_source),
        )
    }

    /// Unlock an armed device with its 32-byte secret. The secret's source is not
    /// this function's business: the host channel calls it today, and a token on
    /// the board's USB-A port can call it the same way — the record's factor says
    /// which source an owner chose, the check is the same.
    pub fn unlock<S: Storage>(
        &mut self,
        fs: &mut Fs<S>,
        secret: &[u8; UNLOCK_SECRET_LEN],
    ) -> Result<(), UnlockError> {
        self.probe(fs).map_err(|_| UnlockError::Memory)?;
        match self.lock.admits(Event::Unlock) {
            Ok(()) => {}
            Err(Refusal::NotArmed) => return Err(UnlockError::NotArmed),
            Err(_) => return Err(UnlockError::Memory),
        }
        let (serial_hash, serial_id, mkek) = self.device_ids();
        let dev = Device {
            serial_hash: &serial_hash,
            serial_id: &serial_id,
            otp_key: mkek.as_deref(),
        };
        let mut rng = self.rng.borrow_mut();
        match dk::open_and_migrate(fs, &dev, &mut *rng, Some(secret)) {
            Ok(dk::Opened::Key(dk)) => {
                self.lock.unlocked(dk);
                Ok(())
            }
            Ok(dk::Opened::Refused) => Err(UnlockError::Refused),
            Err(_) => Err(UnlockError::Memory),
        }
    }

    /// Settle the lock from the device record, once per power cycle. A failed
    /// read leaves it undecided, and the next command reads again.
    fn probe<S: Storage>(&mut self, fs: &mut Fs<S>) -> Result<(), Sw> {
        if let Lock::Unknown = self.lock {
            let factor = dk::factor(fs)?.unwrap_or(Factor::None);
            self.lock = Lock::at_power_up(factor);
        }
        Ok(())
    }

    /// DK, if the lock lets anyone have it: held since the unlock, or opened from
    /// the device root on a disarmed device.
    fn dk<S: Storage>(&mut self, dev: &Device, fs: &mut Fs<S>) -> Result<Key, Sw> {
        self.probe(fs)?;
        match &self.lock {
            Lock::Unlocked(dk) => Ok(dk.clone()),
            Lock::Disarmed => {
                let mut rng = self.rng.borrow_mut();
                match dk::open_and_migrate(fs, dev, &mut *rng, None)? {
                    dk::Opened::Key(dk) => Ok(dk),
                    dk::Opened::Refused => Err(Sw::MEMORY_FAILURE),
                }
            }
            Lock::Locked | Lock::Unknown => Err(Sw::CONDITIONS_NOT_SATISFIED),
        }
    }

    /// Fail with `6985` unless the lock is open. Commands that need DK ask this
    /// before they spend a retry, so a closed lock never costs one.
    fn require_open<S: Storage>(&mut self, fs: &mut Fs<S>) -> Result<(), Sw> {
        self.probe(fs)?;
        if self.lock.is_open() {
            Ok(())
        } else {
            Err(Sw::CONDITIONS_NOT_SATISFIED)
        }
    }

    /// Ask for a touch; anything but a confirmation refuses the command. Callers
    /// spell the title out at the call site, where the trusted display's title
    /// census can see it.
    fn require_touch(&self, confirm: Confirm<'_>) -> Result<(), Sw> {
        match self.presence.borrow_mut().request(confirm) {
            Presence::Confirmed => Ok(()),
            _ => Err(Sw::SECURITY_STATUS_NOT_SATISFIED),
        }
    }

    fn get_challenge(&mut self, apdu: &Apdu, res: &mut ResBuf) -> Sw {
        if apdu.p1 != 0 || apdu.p2 != 0 {
            return Sw::INCORRECT_P1P2;
        }
        if apdu.nc != 0 {
            return Sw::WRONG_LENGTH;
        }
        let n = apdu.ne.min(MAX_CHALLENGE);
        let out = res.spare_mut();
        if out.len() < n {
            return Sw::WRONG_LENGTH;
        }
        self.rng.borrow_mut().fill(&mut out[..n]);
        res.commit(n);
        Sw::OK
    }
}

/// The class byte each instruction arrives with; `None` for an instruction this
/// applet does not have.
fn expected_cla(ins: u8) -> Option<u8> {
    Some(match ins {
        INS_VERIFY
        | INS_CHANGE_REFERENCE
        | INS_RESET_RETRY
        | INS_GENERATE_KEYPAIR
        | INS_GET_CHALLENGE
        | INS_SELECT
        | INS_READ_BINARY
        | INS_READ_BINARY_ODD
        | INS_UPDATE_BINARY_ODD
        | INS_DELETE_FILE => CLA_ISO,
        INS_INITIALIZE | INS_ENUMERATE | INS_DECIPHER | INS_SIGN | INS_LOCK => CLA_PROPRIETARY,
        _ => return None,
    })
}

impl<S: Storage> Applet<Fs<S>> for HsmApplet<'_> {
    fn aid(&self) -> &'static [u8] {
        HSM_AID
    }

    /// Short-`Le` hosts read certificates and requests through GET RESPONSE.
    fn response_chaining(&self) -> bool {
        true
    }

    /// Every SELECT of the application ends the session — it is how the driver
    /// logs out — and drops an unused lock channel with it.
    fn select(&mut self, _reselect: bool, fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        self.sess = Session::default();
        self.channel = None;
        let _ = self.probe(fs);
        files::application_fcp(fs, res)
    }

    fn deselect(&mut self, _fs: &mut Fs<S>) {
        self.sess = Session::default();
        self.channel = None;
    }

    fn process(&mut self, apdu: &Apdu, fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        let Some(cla) = expected_cla(apdu.ins) else {
            return Sw::INS_NOT_SUPPORTED;
        };
        if apdu.cla != cla {
            return Sw::CLA_NOT_SUPPORTED;
        }
        let (serial_hash, serial_id, mkek) = self.device_ids();
        let dev = Device {
            serial_hash: &serial_hash,
            serial_id: &serial_id,
            otp_key: mkek.as_deref(),
        };
        match apdu.ins {
            INS_SELECT => self.select_file(fs, apdu, res),
            INS_VERIFY => self.verify(&dev, fs, apdu),
            INS_CHANGE_REFERENCE => self.change_reference(&dev, fs, apdu),
            INS_RESET_RETRY => self.reset_retry(&dev, fs, apdu),
            INS_INITIALIZE => self.initialize(&dev, fs, apdu),
            INS_GENERATE_KEYPAIR => self.generate_keypair(&dev, fs, apdu, res),
            INS_SIGN => self.sign(fs, apdu, res),
            INS_DECIPHER => self.decipher(fs, apdu, res),
            INS_ENUMERATE => files::enumerate(fs, apdu, res),
            INS_READ_BINARY | INS_READ_BINARY_ODD => self.read_binary(fs, apdu, res),
            INS_UPDATE_BINARY_ODD => self.update_binary(fs, apdu),
            INS_DELETE_FILE => self.delete_file(fs, apdu),
            INS_GET_CHALLENGE => self.get_challenge(apdu, res),
            INS_LOCK => self.lock_command(&dev, fs, apdu, res),
            _ => Sw::INS_NOT_SUPPORTED,
        }
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
