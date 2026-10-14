// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! What the two HSM targets (`hsm_apdu`, `hsm_blob`) share: the commands that set
//! a device up, and the host halves of the two secrets no mutator can invent — a
//! backup blob sealed under a DKEK the harness holds, and a box over the lock
//! channel. Each target is its own `[[bin]]`, so they pull this in as
//! `mod hsm_fixture;`, the way the applet targets pull in `apdu_frame`.
//!
//! The blob and the box are built here from the format's description, not from
//! the applet's code: a harness that sealed with the device's own functions would
//! agree with them however wrong both were.

// Each target compiles its own copy and uses its own part of it.
#![allow(dead_code)]

use rsk_crypto::pinproto::{ecdh_raw, public_xy};
use rsk_crypto::{Mode, aes_decrypt, aes_ecb_encrypt_block, aes_encrypt, sha256};
use rsk_hsm::consts::*;

/// `sc-hsm-tool`'s documented default SO-PIN, `3537363231383830`.
pub const SO_PIN: [u8; SO_PIN_LEN] = *b"57621880";
pub const USER_PIN: &[u8] = b"648219";
/// The one DKEK share the device is initialized to await. With one share the
/// DKEK *is* the share, which is what lets the harness seal blobs under it.
pub const DKEK: [u8; DKEK_SHARE_LEN] = [
    0x9C, 0x41, 0x0E, 0x77, 0x2B, 0xD5, 0x63, 0xF0, 0x18, 0xAA, 0x4D, 0x36, 0xE2, 0x7B, 0x05, 0xC9,
    0x51, 0x8F, 0x3E, 0x60, 0xB7, 0x24, 0xDA, 0x93, 0x0C, 0x6E, 0xF1, 0x45, 0x2A, 0x87, 0xBD, 0x13,
];
/// The unlock secret LOCK ARM installs.
pub const LOCK_SECRET: [u8; UNLOCK_SECRET_LEN] = [0xC3; UNLOCK_SECRET_LEN];
/// The host's ephemeral scalar for the lock channel.
const HOST_SCALAR: [u8; 32] = [0x42; 32];

/// Blob key types, as the format numbers them.
pub const BLOB_RSA: u8 = 5;
pub const BLOB_RSA_CRT: u8 = 6;
pub const BLOB_EC: u8 = 12;
pub const BLOB_AES: u8 = 15;
/// The largest blob OpenSC's driver reads back from WRAP KEY.
pub const DRIVER_WRAP_BUF: usize = 1500;

const BLOCK: usize = 16;
const NONCE_LEN: usize = 8;
const MAC_LEN: usize = 16;
const LABEL_ENC: u8 = 1;
const LABEL_MAC: u8 = 2;
/// The SmartCard-HSM key types' algorithm OIDs: id-TA-RSA-v1-5-SHA-256,
/// id-TA-ECDSA-SHA-256 (BSI TR-03110) and AES (2.16.840.1.101.3.4.1).
const OID_RSA: &[u8] = &[0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x02, 0x01, 0x02];
const OID_EC: &[u8] = &[0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x02, 0x02, 0x03];
const OID_AES: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01];

/// NIST P-256 (FIPS 186-4 D.1.2.3): the curve every EC blob below names.
const P256_P: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
];
const P256_A: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC,
];
const P256_B: [u8; 32] = [
    0x5A, 0xC6, 0x35, 0xD8, 0xAA, 0x3A, 0x93, 0xE7, 0xB3, 0xEB, 0xBD, 0x55, 0x76, 0x98, 0x86, 0xBC,
    0x65, 0x1D, 0x06, 0xB0, 0xCC, 0x53, 0xB0, 0xF6, 0x3B, 0xCE, 0x3C, 0x3E, 0x27, 0xD2, 0x60, 0x4B,
];
const P256_G: [u8; 65] = [
    0x04, 0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40,
    0xF2, 0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2,
    0x96, 0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B, 0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E,
    0x16, 0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE, 0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51,
    0xF5,
];
const P256_N: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
];
const P256_BITS: u16 = 256;

/// A command with extended lengths and `Le = 65536`, so no response is clipped
/// and no GET RESPONSE stands between the harness and its answer.
pub fn apdu(cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8]) -> Vec<u8> {
    let mut raw = vec![cla, ins, p1, p2, 0];
    if !data.is_empty() {
        raw.extend_from_slice(&(data.len() as u16).to_be_bytes());
        raw.extend_from_slice(data);
    }
    raw.extend_from_slice(&[0, 0]);
    raw
}

pub fn select_hsm() -> Vec<u8> {
    let mut raw = vec![CLA_ISO, INS_SELECT, SEL_DF_NAME, 0x00, HSM_AID.len() as u8];
    raw.extend_from_slice(HSM_AID);
    raw
}

/// INITIALIZE: RESET RETRY COUNTER allowed, [`USER_PIN`], [`SO_PIN`], one DKEK
/// share awaited.
pub fn initialize() -> Vec<u8> {
    let mut d = vec![TAG_INIT_OPTIONS as u8, 2];
    d.extend_from_slice(&OPT_RRC.to_be_bytes());
    d.extend_from_slice(&[TAG_INIT_USER_PIN as u8, USER_PIN.len() as u8]);
    d.extend_from_slice(USER_PIN);
    d.extend_from_slice(&[TAG_INIT_SO_PIN as u8, SO_PIN_LEN as u8]);
    d.extend_from_slice(&SO_PIN);
    d.extend_from_slice(&[TAG_INIT_DKEK_SHARES as u8, 1, 1]);
    apdu(CLA_PROPRIETARY, INS_INITIALIZE, 0, 0, &d)
}

pub fn import_share() -> Vec<u8> {
    apdu(
        CLA_PROPRIETARY,
        INS_KEY_DOMAIN,
        KEY_DOMAIN_DKEK,
        KEY_DOMAIN_DEFAULT,
        &DKEK,
    )
}

pub fn verify_user() -> Vec<u8> {
    apdu(CLA_ISO, INS_VERIFY, 0, PIN_USER, USER_PIN)
}

/// UPDATE BINARY of the whole of `fid` at offset 0: `54 02 0000 ‖ 53 len data`.
pub fn update_binary(fid: u16, data: &[u8]) -> Vec<u8> {
    let mut d = vec![TAG_OFFSET as u8, 2, 0, 0, TAG_DATA as u8];
    match data.len() {
        n @ 0..=0x7F => d.push(n as u8),
        n @ 0x80..=0xFF => d.extend_from_slice(&[0x81, n as u8]),
        n => d.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]),
    }
    d.extend_from_slice(data);
    apdu(
        CLA_ISO,
        INS_UPDATE_BINARY_ODD,
        (fid >> 8) as u8,
        fid as u8,
        &d,
    )
}

pub fn unwrap_into(kid: u8) -> Vec<u8> {
    apdu(
        CLA_PROPRIETARY,
        INS_UNWRAP_KEY,
        kid,
        UNWRAP_FROM_STAGING,
        &[],
    )
}

pub fn wrap_out(kid: u8) -> Vec<u8> {
    apdu(CLA_PROPRIETARY, INS_WRAP_KEY, kid, WRAP_WITH_DKEK, &[])
}

/// AES-CMAC (RFC 4493) over the AES-256 block function.
fn cmac(key: &[u8; 32], data: &[u8]) -> [u8; BLOCK] {
    let dbl = |b: [u8; BLOCK]| {
        let mut out = [0u8; BLOCK];
        for i in 0..BLOCK {
            out[i] = (b[i] << 1) | b.get(i + 1).map_or(0, |n| n >> 7);
        }
        if b[0] & 0x80 != 0 {
            out[BLOCK - 1] ^= 0x87;
        }
        out
    };
    let mut l = [0u8; BLOCK];
    aes_ecb_encrypt_block(key, &mut l).expect("a 256-bit key");
    let k1 = dbl(l);
    let k2 = dbl(k1);
    let blocks = data.len().div_ceil(BLOCK).max(1);
    let mut x = [0u8; BLOCK];
    for chunk in data.chunks(BLOCK).take(blocks - 1) {
        for (a, b) in x.iter_mut().zip(chunk) {
            *a ^= b;
        }
        aes_ecb_encrypt_block(key, &mut x).expect("a 256-bit key");
    }
    let tail = &data[(blocks - 1) * BLOCK..];
    let mut last = [0u8; BLOCK];
    last[..tail.len()].copy_from_slice(tail);
    let sub = if !data.is_empty() && tail.len() == BLOCK {
        k1
    } else {
        last[tail.len()] = 0x80;
        k2
    };
    for i in 0..BLOCK {
        x[i] ^= last[i] ^ sub[i];
    }
    aes_ecb_encrypt_block(key, &mut x).expect("a 256-bit key");
    x
}

/// `SHA-256(DKEK ‖ 00 00 00 label)`, one of the two keys a DKEK is used through.
fn derive(dkek: &[u8; 32], label: u8) -> [u8; 32] {
    let mut m = [0u8; 36];
    m[..32].copy_from_slice(dkek);
    m[35] = label;
    sha256(&m)
}

fn field(out: &mut Vec<u8>, v: &[u8]) {
    out.extend_from_slice(&(v.len() as u16).to_be_bytes());
    out.extend_from_slice(v);
}

/// The algorithm OID a blob of `kind` must carry; empty for a kind the format
/// does not have.
pub fn family_oid(kind: u8) -> &'static [u8] {
    match kind {
        BLOB_RSA | BLOB_RSA_CRT => OID_RSA,
        BLOB_EC => OID_EC,
        BLOB_AES => OID_AES,
        _ => &[],
    }
}

/// A blob of `kind` whose encrypted part is `nonce ‖ inner`, under `dkek`.
pub fn seal_blob(dkek: &[u8; 32], kind: u8, algos: &[u8], inner: &[u8]) -> Vec<u8> {
    let mut plain = vec![0xA5; NONCE_LEN];
    plain.extend_from_slice(inner);
    if !plain.len().is_multiple_of(BLOCK) {
        plain.push(0x80);
        plain.resize(plain.len().next_multiple_of(BLOCK), 0);
    }
    aes_encrypt(&derive(dkek, LABEL_ENC), &[0; BLOCK], Mode::Cbc, &mut plain)
        .expect("whole blocks under a 256-bit key");
    let mut blob = sha256(dkek)[..DKEK_KCV_LEN].to_vec();
    blob.push(kind);
    field(&mut blob, family_oid(kind));
    field(&mut blob, algos);
    field(&mut blob, &[]);
    field(&mut blob, &[]);
    blob.extend_from_slice(&plain);
    let mac = cmac(&derive(dkek, LABEL_MAC), &blob);
    blob.extend_from_slice(&mac);
    blob
}

/// Everything ahead of a blob's encrypted part: KCV, type, OID, algorithm list
/// and the two fields this format leaves empty.
pub fn blob_head(blob: &[u8]) -> Option<&[u8]> {
    let mut at = DKEK_KCV_LEN + 1;
    for _ in 0..4 {
        let len = u16::from_be_bytes(blob.get(at..at + 2)?.try_into().ok()?) as usize;
        at += 2 + len;
    }
    blob.get(..at)
}

/// The decrypted part of a blob after its nonce, once its KCV and MAC check out
/// under `dkek`; `None` for a blob that is not one.
pub fn open_blob(dkek: &[u8; 32], blob: &[u8]) -> Option<Vec<u8>> {
    if blob.len() < DKEK_KCV_LEN + 1 + MAC_LEN || blob[..DKEK_KCV_LEN] != sha256(dkek)[..8] {
        return None;
    }
    let (body, mac) = blob.split_at(blob.len() - MAC_LEN);
    if cmac(&derive(dkek, LABEL_MAC), body) != mac {
        return None;
    }
    let head = blob_head(body)?.len();
    let mut enc = body[head..].to_vec();
    if enc.len() < NONCE_LEN || !enc.len().is_multiple_of(BLOCK) {
        return None;
    }
    aes_decrypt(&derive(dkek, LABEL_ENC), &[0; BLOCK], Mode::Cbc, &mut enc).ok()?;
    Some(enc.split_off(NONCE_LEN))
}

/// The encrypted part of an AES key's blob after the nonce: `size ‖ key`.
pub fn aes_inner(key: &[u8]) -> Vec<u8> {
    let mut inner = (key.len() as u16).to_be_bytes().to_vec();
    inner.extend_from_slice(key);
    inner
}

/// The start of a P-256 key's encrypted part, up to the scalar: `size ‖ A ‖ B ‖
/// P ‖ N ‖ G`, each field length-prefixed.
pub fn p256_head() -> Vec<u8> {
    let mut inner = P256_BITS.to_be_bytes().to_vec();
    for v in [&P256_A[..], &P256_B, &P256_P, &P256_N, &P256_G] {
        field(&mut inner, v);
    }
    inner
}

/// A whole P-256 key's encrypted part, with its public point left out (optional).
pub fn p256_inner(d: &[u8; 32]) -> Vec<u8> {
    let mut inner = p256_head();
    field(&mut inner, d);
    field(&mut inner, &[]);
    inner
}

/// The host's half of the lock channel: its point, for LOCK CHANNEL.
pub fn host_point() -> Vec<u8> {
    let (x, y) = public_xy(&HOST_SCALAR).expect("a valid scalar");
    let mut p = vec![0x04];
    p.extend_from_slice(&x);
    p.extend_from_slice(&y);
    p
}

/// Box `plain` to the device point LOCK CHANNEL answered; `None` for an answer
/// that is not a P-256 point.
pub fn lock_box(dev_pub: &[u8], plain: &[u8]) -> Option<Vec<u8>> {
    if dev_pub.len() != 65 || dev_pub[0] != 0x04 {
        return None;
    }
    let z = ecdh_raw(
        &HOST_SCALAR,
        dev_pub[1..33].try_into().ok()?,
        dev_pub[33..].try_into().ok()?,
    )
    .ok()?;
    let mut info = dev_pub.to_vec();
    info.extend_from_slice(&host_point());
    let mut key = [0u8; 32];
    rsk_crypto::hkdf_sha256(b"RSK-HSM/LOCK-CHANNEL", &z, &info, &mut key).ok()?;
    let nonce = [0x24u8; 12];
    let mut ct = plain.to_vec();
    let tag = rsk_crypto::chacha20poly1305_encrypt(&key, &nonce, dev_pub, &mut ct);
    let mut blob = nonce.to_vec();
    blob.extend_from_slice(&ct);
    blob.extend_from_slice(&tag);
    Some(blob)
}
