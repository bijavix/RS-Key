// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::tests::{HASH, MKEK, SERIAL, TestRng};

const K: [u8; KEY_LEN] = [7; KEY_LEN];

fn dev(otp: bool) -> Device<'static> {
    Device {
        serial_hash: &HASH,
        serial_id: &SERIAL,
        otp_key: otp.then_some(&MKEK),
    }
}

#[test]
fn a_sealed_record_opens_only_under_its_key_fid_and_header() {
    let mut rng = TestRng(1);
    let mut blob = [0u8; 64];
    let n = seal(&K, 0xA123, b"hdr", b"secret bytes", &mut rng, &mut blob);
    assert_eq!(n, SEAL_OVERHEAD + 12);
    assert_eq!(blob[0], FMT_GCM);
    let mut out = [0u8; 32];
    assert_eq!(open(&K, 0xA123, b"hdr", &blob[..n], &mut out), Ok(12));
    assert_eq!(&out[..12], b"secret bytes");
    assert_eq!(
        open(&[8; KEY_LEN], 0xA123, b"hdr", &blob[..n], &mut out),
        Err(Unseal::Auth)
    );
    assert_eq!(
        open(&K, 0xA124, b"hdr", &blob[..n], &mut out),
        Err(Unseal::Auth),
        "moved to another fid"
    );
    assert_eq!(
        open(&K, 0xA123, b"hdx", &blob[..n], &mut out),
        Err(Unseal::Auth),
        "header altered"
    );
    assert_eq!(out, [0u8; 32], "a refusal leaves no plaintext behind");
    let mut flipped = blob;
    flipped[5] ^= 1;
    assert_eq!(
        open(&K, 0xA123, b"hdr", &flipped[..n], &mut out),
        Err(Unseal::Auth)
    );
}

#[test]
fn malformed_records_are_told_apart_from_forged_ones() {
    let mut rng = TestRng(1);
    let mut blob = [0u8; 64];
    let n = seal(&K, 1, &[], b"x", &mut rng, &mut blob);
    let mut out = [0u8; 4];
    assert_eq!(
        open(&K, 1, &[], &blob[..SEAL_OVERHEAD - 1], &mut out),
        Err(Unseal::Malformed)
    );
    let mut wrong_fmt = blob;
    wrong_fmt[0] = 2;
    assert_eq!(
        open(&K, 1, &[], &wrong_fmt[..n], &mut out),
        Err(Unseal::Malformed)
    );
    assert_eq!(
        open(&K, 1, &[], &blob[..n], &mut [0u8; 0]),
        Err(Unseal::Malformed),
        "no room for the plaintext"
    );
    assert_eq!(
        open_key(&K, 1, &[], &blob[..n]).err(),
        Some(Unseal::Malformed),
        "not a key's length"
    );
}

#[test]
fn every_seal_draws_a_fresh_nonce() {
    let mut rng = TestRng(1);
    let a = seal_key(&K, 1, &[], &[1; KEY_LEN], &mut rng);
    let b = seal_key(&K, 1, &[], &[1; KEY_LEN], &mut rng);
    assert_ne!(a, b);
    assert_eq!(*open_key(&K, 1, &[], &a).unwrap(), [1; KEY_LEN]);
    assert_eq!(*open_key(&K, 1, &[], &b).unwrap(), [1; KEY_LEN]);
}

#[test]
fn the_device_key_needs_the_root_and_the_unlock_secret() {
    let plain = device_key(&dev(false), None);
    assert_ne!(
        *plain,
        *device_key(&dev(true), None),
        "the OTP root changes it"
    );
    assert_ne!(
        *plain,
        *device_key(&dev(false), Some(&[1; KEY_LEN])),
        "arming changes it"
    );
    assert_ne!(
        *device_key(&dev(false), Some(&[1; KEY_LEN])),
        *device_key(&dev(false), Some(&[2; KEY_LEN]))
    );
    assert_eq!(*plain, *device_key(&dev(false), None));
}

#[test]
fn pin_keys_separate_references_and_pins() {
    let user = pin_key(&K, 0x81, b"123456");
    assert_ne!(*user, *pin_key(&K, 0x88, b"123456"));
    assert_ne!(*user, *pin_key(&K, 0x81, b"1234567"));
    assert_ne!(
        *user,
        *pin_key(&[8; KEY_LEN], 0x81, b"123456"),
        "keyed by DK"
    );
    assert_eq!(*user, *pin_key(&K, 0x81, b"123456"));
}

#[test]
fn the_so_verifier_follows_the_device_root() {
    let pre = so_verifier(&dev(false), b"12345678");
    assert_ne!(pre, so_verifier(&dev(true), b"12345678"));
    assert_ne!(pre, so_verifier(&dev(false), b"12345679"));
}

#[test]
fn object_keys_are_per_fid() {
    assert_ne!(*object_key(&K, 0xA101), *object_key(&K, 0xA102));
    assert_ne!(*object_key(&K, 0xA101), *object_key(&[8; KEY_LEN], 0xA101));
}
