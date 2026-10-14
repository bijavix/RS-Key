// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The layouts of the HSM's own records, read back strictly: an unknown version or
//! a wrong length is a memory failure, never a default. A default is how a faulted
//! record turns into "not configured", and here that would mean "not protected".

use crate::consts::{
    LOCK_FACTOR_FIDO2_HMAC_SECRET, LOCK_FACTOR_HOST_KEY, LOCK_FACTOR_NONE, SO_RETRIES,
    USER_RETRIES_MAX,
};
use crate::seal::{KEY_LEN, SEALED_KEY_LEN};

/// Every record starts with this version byte.
const VERSION: u8 = 1;

/// The initialization record: `ver ‖ options ‖ retry limit ‖ SO verifier ‖ SO
/// envelope`. The envelope binds the header but not the verifier, so carrying the
/// verifier onto the OTP root never needs DK — the re-initialization of a locked
/// device checks the SO-PIN against it without one.
#[derive(Clone)]
pub(crate) struct Init {
    pub options: u16,
    pub retry_max: u8,
    pub so_verifier: [u8; KEY_LEN],
    pub so_envelope: [u8; SEALED_KEY_LEN],
}

/// The clear header of [`Init`], bound into the envelope.
pub(crate) const INIT_HDR_LEN: usize = 4;
const INIT_LEN: usize = INIT_HDR_LEN + KEY_LEN + SEALED_KEY_LEN;

impl Init {
    /// The header the SO envelope binds, for a record with these values.
    pub(crate) fn header(options: u16, retry_max: u8) -> [u8; INIT_HDR_LEN] {
        let [hi, lo] = options.to_be_bytes();
        [VERSION, hi, lo, retry_max]
    }

    pub(crate) fn encode(&self) -> [u8; INIT_LEN] {
        let mut b = [0u8; INIT_LEN];
        b[..INIT_HDR_LEN].copy_from_slice(&Self::header(self.options, self.retry_max));
        b[INIT_HDR_LEN..INIT_HDR_LEN + KEY_LEN].copy_from_slice(&self.so_verifier);
        b[INIT_HDR_LEN + KEY_LEN..].copy_from_slice(&self.so_envelope);
        b
    }

    pub(crate) fn decode(b: &[u8]) -> Option<Init> {
        if b.len() != INIT_LEN || b[0] != VERSION {
            return None;
        }
        let retry_max = b[3];
        if !(1..=USER_RETRIES_MAX).contains(&retry_max) {
            return None;
        }
        let mut so_verifier = [0u8; KEY_LEN];
        so_verifier.copy_from_slice(&b[INIT_HDR_LEN..INIT_HDR_LEN + KEY_LEN]);
        let mut so_envelope = [0u8; SEALED_KEY_LEN];
        so_envelope.copy_from_slice(&b[INIT_HDR_LEN + KEY_LEN..]);
        Some(Init {
            options: u16::from_be_bytes([b[1], b[2]]),
            retry_max,
            so_verifier,
            so_envelope,
        })
    }

    /// The encoding's length, for a read buffer.
    pub(crate) const LEN: usize = INIT_LEN;
}

/// The retry counters: tries left for the user PIN and the SO-PIN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Counters {
    pub user: u8,
    pub so: u8,
}

const COUNTERS_LEN: usize = 3;

impl Counters {
    pub(crate) const MAX_LEN: usize = COUNTERS_LEN;

    pub(crate) fn encode(&self) -> [u8; COUNTERS_LEN] {
        [VERSION, self.user, self.so]
    }

    pub(crate) fn decode(b: &[u8]) -> Option<Counters> {
        if b.len() != COUNTERS_LEN
            || b[0] != VERSION
            || b[1] > USER_RETRIES_MAX
            || b[2] > SO_RETRIES
        {
            return None;
        }
        Some(Counters {
            user: b[1],
            so: b[2],
        })
    }
}

/// Who holds the unlock secret of an armed device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Factor {
    /// Not armed: DK opens from the device root alone.
    None,
    /// A 32-byte secret the host delivers over the lock channel.
    HostKey,
    /// FIDO2 `hmac-secret` from a token on the board's own USB-A port. Reserved:
    /// a record may name it, this build cannot arm or satisfy it.
    Fido2HmacSecret,
}

impl Factor {
    pub(crate) const fn id(self) -> u8 {
        match self {
            Factor::None => LOCK_FACTOR_NONE,
            Factor::HostKey => LOCK_FACTOR_HOST_KEY,
            Factor::Fido2HmacSecret => LOCK_FACTOR_FIDO2_HMAC_SECRET,
        }
    }

    pub(crate) fn from_id(b: u8) -> Option<Factor> {
        Some(match b {
            LOCK_FACTOR_NONE => Factor::None,
            LOCK_FACTOR_HOST_KEY => Factor::HostKey,
            LOCK_FACTOR_FIDO2_HMAC_SECRET => Factor::Fido2HmacSecret,
            _ => return None,
        })
    }
}

/// Opaque factor parameters (a token's credential and salt, for the reserved
/// FIDO2 factor) are bounded so the header stays inside the envelope's AAD.
pub(crate) const FACTOR_PARAMS_MAX: usize = 64;
const DEV_HDR: usize = 3;

/// The device record: `ver ‖ factor ‖ params length ‖ params ‖ DK envelope`. The
/// lock lives in its header so arming and disarming are each one atomic write —
/// a separate lock record would leave a power cut between two of them.
pub(crate) struct DevRecord<'a> {
    pub factor: Factor,
    /// The header as stored — factor parameters included — which the envelope binds.
    pub bind: &'a [u8],
    pub envelope: &'a [u8],
}

/// Largest device record, for a read buffer.
pub(crate) const DEV_MAX_LEN: usize = DEV_HDR_MAX + SEALED_KEY_LEN;
/// Largest clear header.
pub(crate) const DEV_HDR_MAX: usize = DEV_HDR + FACTOR_PARAMS_MAX;

impl<'a> DevRecord<'a> {
    /// The clear header for `factor` and `params`, bound into the envelope.
    pub(crate) fn header(factor: Factor, params: &[u8], out: &mut [u8; DEV_HDR_MAX]) -> usize {
        assert!(params.len() <= FACTOR_PARAMS_MAX);
        out[0] = VERSION;
        out[1] = factor.id();
        out[2] = params.len() as u8;
        out[DEV_HDR..DEV_HDR + params.len()].copy_from_slice(params);
        DEV_HDR + params.len()
    }

    pub(crate) fn decode(b: &'a [u8]) -> Option<DevRecord<'a>> {
        if b.len() < DEV_HDR || b[0] != VERSION {
            return None;
        }
        let factor = Factor::from_id(b[1])?;
        let plen = b[2] as usize;
        if plen > FACTOR_PARAMS_MAX || b.len() != DEV_HDR + plen + SEALED_KEY_LEN {
            return None;
        }
        Some(DevRecord {
            factor,
            bind: &b[..DEV_HDR + plen],
            envelope: &b[DEV_HDR + plen..],
        })
    }
}

#[cfg(test)]
#[path = "records_tests.rs"]
mod tests;
