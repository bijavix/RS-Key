// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The lock as a state machine, kept apart from the commands that drive it and
//! from the flash writes they make, so every transition it refuses is testable on
//! its own.
//!
//! The state lives in RAM and is rebuilt from the device record at every power-up,
//! which is what makes an armed device relock on every power cycle: nothing that
//! survives a reset says it was ever unlocked.

use crate::consts::{
    LOCK_STATE_DISARMED, LOCK_STATE_LOCKED, LOCK_STATE_UNKNOWN, LOCK_STATE_UNLOCKED,
};
use crate::records::Factor;
use crate::seal::Key;

/// Where the lock stands this power cycle.
pub(crate) enum Lock {
    /// No read of the device record has succeeded yet; nothing can be decided.
    Unknown,
    /// Not armed: DK opens from the device root alone. An uninitialized device
    /// is here too — there is no DK to protect yet.
    Disarmed,
    /// Armed, and the unlock secret has not been presented since power-up.
    Locked,
    /// Armed and unlocked: DK is held until power-off.
    Unlocked(Key),
}

/// What a command asks of the lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Event {
    Arm,
    Unlock,
    Disarm,
}

/// Why the lock refused an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// The device record has not been read yet.
    Unknown,
    /// Already armed: it cannot be armed again.
    Armed,
    /// Not armed: there is nothing to unlock or disarm.
    NotArmed,
    /// Armed and closed: disarming needs the secret presented first.
    Closed,
}

impl Lock {
    /// The state a device record with this factor leaves at power-up.
    pub(crate) fn at_power_up(factor: Factor) -> Lock {
        match factor {
            Factor::None => Lock::Disarmed,
            Factor::HostKey | Factor::Fido2HmacSecret => Lock::Locked,
        }
    }

    /// Whether `ev` may run from here. Asked before any flash write, so a refused
    /// event changes nothing.
    pub(crate) fn admits(&self, ev: Event) -> Result<(), Refusal> {
        match (self, ev) {
            (Lock::Unknown, _) => Err(Refusal::Unknown),
            (Lock::Disarmed, Event::Arm) => Ok(()),
            (Lock::Disarmed, Event::Unlock | Event::Disarm) => Err(Refusal::NotArmed),
            (Lock::Locked | Lock::Unlocked(_), Event::Arm) => Err(Refusal::Armed),
            (Lock::Locked | Lock::Unlocked(_), Event::Unlock) => Ok(()),
            (Lock::Locked, Event::Disarm) => Err(Refusal::Closed),
            (Lock::Unlocked(_), Event::Disarm) => Ok(()),
        }
    }

    /// Commit an admitted arm: the record is armed and the arming session holds DK.
    pub(crate) fn armed(&mut self, dk: Key) {
        debug_assert_eq!(self.admits(Event::Arm), Ok(()));
        *self = Lock::Unlocked(dk);
    }

    /// Commit an admitted unlock.
    pub(crate) fn unlocked(&mut self, dk: Key) {
        debug_assert_eq!(self.admits(Event::Unlock), Ok(()));
        *self = Lock::Unlocked(dk);
    }

    /// Commit an admitted disarm.
    pub(crate) fn disarmed(&mut self) {
        debug_assert_eq!(self.admits(Event::Disarm), Ok(()));
        *self = Lock::Disarmed;
    }

    /// A re-initialization rewrote the device record disarmed, whatever stood here.
    pub(crate) fn reinitialized(&mut self) {
        *self = Lock::Disarmed;
    }

    /// Whether DK is reachable: from the root, or held.
    pub(crate) fn is_open(&self) -> bool {
        matches!(self, Lock::Disarmed | Lock::Unlocked(_))
    }

    /// The DK an unlock left in RAM.
    pub(crate) fn held(&self) -> Option<&Key> {
        match self {
            Lock::Unlocked(dk) => Some(dk),
            _ => None,
        }
    }

    /// The one-byte state the LOCK status reports.
    pub(crate) fn wire(&self) -> u8 {
        match self {
            Lock::Unknown => LOCK_STATE_UNKNOWN,
            Lock::Disarmed => LOCK_STATE_DISARMED,
            Lock::Locked => LOCK_STATE_LOCKED,
            Lock::Unlocked(_) => LOCK_STATE_UNLOCKED,
        }
    }
}

#[cfg(test)]
#[path = "lock_tests.rs"]
mod tests;
