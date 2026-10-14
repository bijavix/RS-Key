// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! AES-CMAC (NIST SP 800-38B, RFC 4493): the MAC over a key backup, and the one
//! CIPHER SYMMETRIC answers. Built on the block cipher the crypto layer already
//! exposes, block by block, so it needs no buffer the size of the message.

use rsk_crypto::aes_ecb_encrypt_block;
use rsk_sdk::Sw;

use crate::seal::Wiped;

const BLOCK: usize = 16;
/// The reduction constant for doubling in GF(2^128).
const RB: u8 = 0x87;

/// Multiply a block by `x` in GF(2^128): the subkey derivation.
fn dbl(b: &[u8; BLOCK]) -> [u8; BLOCK] {
    let mut out = [0u8; BLOCK];
    for i in 0..BLOCK {
        let next = if i + 1 < BLOCK { b[i + 1] >> 7 } else { 0 };
        out[i] = (b[i] << 1) | next;
    }
    // Branch-free: the subkeys are secret.
    out[BLOCK - 1] ^= RB & 0u8.wrapping_sub(b[0] >> 7);
    out
}

/// The AES-CMAC of `data` under a 128-, 192- or 256-bit `key`.
pub(crate) fn aes_cmac(key: &[u8], data: &[u8]) -> Result<[u8; BLOCK], Sw> {
    let mut l = Wiped::<BLOCK>::zeroed();
    aes_ecb_encrypt_block(key, &mut l).map_err(|_| Sw::EXEC_ERROR)?;
    let k1 = Wiped::new(dbl(&l));
    let k2 = Wiped::new(dbl(&k1));
    let n = data.len().div_ceil(BLOCK).max(1);
    let complete = !data.is_empty() && data.len().is_multiple_of(BLOCK);
    let mut x = Wiped::<BLOCK>::zeroed();
    for chunk in data.chunks(BLOCK).take(n - 1) {
        for (a, b) in x.iter_mut().zip(chunk) {
            *a ^= b;
        }
        aes_ecb_encrypt_block(key, &mut x).map_err(|_| Sw::EXEC_ERROR)?;
    }
    let mut last = [0u8; BLOCK];
    let tail = &data[(n - 1) * BLOCK..];
    last[..tail.len()].copy_from_slice(tail);
    let sub = if complete {
        &k1
    } else {
        last[tail.len()] = 0x80;
        &k2
    };
    for ((a, m), k) in x.iter_mut().zip(last.iter()).zip(sub.iter()) {
        *a ^= m ^ k;
    }
    aes_ecb_encrypt_block(key, &mut x).map_err(|_| Sw::EXEC_ERROR)?;
    Ok(*x)
}

#[cfg(test)]
#[path = "cmac_tests.rs"]
mod tests;
