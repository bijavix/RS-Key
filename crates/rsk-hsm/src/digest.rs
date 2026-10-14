// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The hashes a signature on this device can be taken over. SHA-1 is not one of
//! them: nothing here hashes a new signature with it.

use rsk_crypto::{sha224, sha256, sha384, sha512};

/// The widest digest.
pub(crate) const MAX_DIGEST: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Hash {
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    pub(crate) const fn len(self) -> usize {
        match self {
            Hash::Sha224 => 28,
            Hash::Sha256 => 32,
            Hash::Sha384 => 48,
            Hash::Sha512 => 64,
        }
    }

    /// The hash a host-taken digest of this length was taken with.
    pub(crate) fn of_len(n: usize) -> Option<Hash> {
        [Hash::Sha224, Hash::Sha256, Hash::Sha384, Hash::Sha512]
            .into_iter()
            .find(|h| h.len() == n)
    }

    /// Hash `data` into the front of `out`; returns the digest's length.
    pub(crate) fn digest(self, data: &[u8], out: &mut [u8; MAX_DIGEST]) -> usize {
        let n = self.len();
        match self {
            Hash::Sha224 => out[..n].copy_from_slice(&sha224(data)),
            Hash::Sha256 => out[..n].copy_from_slice(&sha256(data)),
            Hash::Sha384 => out[..n].copy_from_slice(&sha384(data)),
            Hash::Sha512 => out[..n].copy_from_slice(&sha512(data)),
        }
        n
    }
}
