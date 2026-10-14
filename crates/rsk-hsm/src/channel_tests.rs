// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::tests::TestRng;
use rsk_crypto::chacha20poly1305_encrypt;

/// The host's half of an agreement.
struct Host {
    scalar: [u8; 32],
    point: [u8; POINT_LEN],
}

impl Host {
    fn new(scalar: [u8; 32]) -> Host {
        let (x, y) = public_xy(&scalar).unwrap();
        let mut point = [0u8; POINT_LEN];
        point[0] = 0x04;
        point[1..33].copy_from_slice(&x);
        point[33..].copy_from_slice(&y);
        Host { scalar, point }
    }

    /// Box `plain` to the device half `dev_pub`.
    fn seal(&self, dev_pub: &[u8; POINT_LEN], plain: &[u8]) -> Vec<u8> {
        let z = ecdh_raw(
            &self.scalar,
            dev_pub[1..33].try_into().unwrap(),
            dev_pub[33..].try_into().unwrap(),
        )
        .unwrap();
        let mut info = dev_pub.to_vec();
        info.extend_from_slice(&self.point);
        let mut key = [0u8; 32];
        hkdf_sha256(SALT, &z, &info, &mut key).unwrap();
        let nonce = [3u8; NONCE_LEN];
        let mut ct = plain.to_vec();
        let tag = chacha20poly1305_encrypt(&key, &nonce, dev_pub, &mut ct);
        [&nonce[..], &ct, &tag].concat()
    }
}

#[test]
fn a_box_from_the_host_opens_on_its_channel_once() {
    let host = Host::new([0x42; 32]);
    let ch = Channel::agree(&host.point, &mut TestRng(5)).unwrap();
    let blob = host.seal(ch.dev_pub(), b"the unlock secret, thirty-two b!");
    assert_eq!(blob.len(), BOX_OVERHEAD + 32);
    let mut out = [0u8; 32];
    assert!(ch.open(&blob, &mut out));
    assert_eq!(&out, b"the unlock secret, thirty-two b!");
}

#[test]
fn a_box_for_another_agreement_or_altered_does_not_open() {
    let host = Host::new([0x42; 32]);
    let first = Channel::agree(&host.point, &mut TestRng(5)).unwrap();
    let second = Channel::agree(&host.point, &mut TestRng(6)).unwrap();
    assert_ne!(
        first.dev_pub(),
        second.dev_pub(),
        "every agreement is fresh"
    );
    let blob = host.seal(first.dev_pub(), &[1; 8]);
    let mut out = [0u8; 8];
    assert!(!second.open(&blob, &mut out));
    assert_eq!(out, [0; 8]);
    let mut altered = blob.clone();
    altered[NONCE_LEN] ^= 1;
    assert!(!first.open(&altered, &mut out));
    let third = Channel::agree(&host.point, &mut TestRng(5)).unwrap();
    assert!(
        !third.open(&blob[..blob.len() - 1], &mut out),
        "a box of the wrong length"
    );
}

#[test]
fn only_an_uncompressed_point_on_the_curve_agrees() {
    let host_pub = Host::new([0x42; 32]).point;
    let mut rng = TestRng(1);
    assert!(Channel::agree(&host_pub[..64], &mut rng).is_none());
    let mut compressed = host_pub;
    compressed[0] = 0x02;
    assert!(Channel::agree(&compressed, &mut rng).is_none());
    let mut off_curve = host_pub;
    off_curve[64] ^= 1;
    assert!(Channel::agree(&off_curve, &mut rng).is_none());
}
