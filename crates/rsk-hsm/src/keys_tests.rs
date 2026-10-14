// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::domain::{K256, P256, P384, P521};
use crate::seal::Key;
use crate::tests::{TestRng, new_fs};

fn hmk(b: u8) -> Key {
    Key::new([b; KEY_LEN])
}

#[test]
fn a_key_object_round_trips_through_its_seal() {
    let mut fs = new_fs();
    let rsa_blob = [0x5Au8; 5 * 128];
    let cases = [
        KeyObject::new(KeyType::Ec(&P256), COUNTER_UNLIMITED, &[], &[7; 32]).unwrap(),
        KeyObject::new(KeyType::Ec(&P384), 9, &[ALGO_EC_SHA384], &[7; 48]).unwrap(),
        KeyObject::new(KeyType::Ec(&P521), 1, &[], &[1; 66]).unwrap(),
        KeyObject::new(KeyType::Ec(&K256), 3, &[ALGO_EC_RAW, ALGO_EC_DH], &[2; 32]).unwrap(),
        KeyObject::new(
            KeyType::Rsa(RsaSize::R2048),
            5,
            &[ALGO_RSA_DECRYPT],
            &rsa_blob,
        )
        .unwrap(),
    ];
    for (kid, k) in (1u8..).zip(cases.iter()) {
        store(&mut fs, &hmk(1), kid, k, &mut TestRng(kid as u64)).unwrap();
        let back = load(&mut fs, &hmk(1), kid).unwrap().unwrap();
        assert_eq!(back.ty, k.ty);
        assert_eq!(back.counter, k.counter);
        assert_eq!(back.material(), k.material());
        for a in [ALGO_EC_RAW, ALGO_EC_DH, ALGO_EC_SHA384, ALGO_RSA_DECRYPT] {
            assert_eq!(back.allows(a), k.allows(a));
        }
        assert!(exists(&mut fs, kid).unwrap());
    }
    assert!(load(&mut fs, &hmk(1), 200).unwrap().is_none());
    assert!(!exists(&mut fs, 200).unwrap());
}

#[test]
fn a_key_opens_only_under_its_owner_and_only_where_it_was_written() {
    let mut fs = new_fs();
    let k = KeyObject::new(KeyType::Ec(&P256), COUNTER_UNLIMITED, &[], &[7; 32]).unwrap();
    store(&mut fs, &hmk(1), 4, &k, &mut TestRng(1)).unwrap();
    assert_eq!(load(&mut fs, &hmk(2), 4).err(), Some(Sw::MEMORY_FAILURE));
    let mut moved = [0u8; RECORD_MAX];
    let n = fs.read_key(fid(4), &mut moved).unwrap();
    fs.put_key(fid(5), Sealed::wrap(&moved[..n])).unwrap();
    assert_eq!(
        load(&mut fs, &hmk(1), 5).err(),
        Some(Sw::MEMORY_FAILURE),
        "a record copied to another slot does not open there"
    );
}

#[test]
fn decoding_refuses_what_no_build_wrote() {
    let k = KeyObject::new(KeyType::Ec(&P256), 7, &[ALGO_EC_RAW], &[7; 32]).unwrap();
    let mut b = [0u8; PLAIN_MAX];
    let n = k.encode(&mut b);
    assert!(KeyObject::decode(&b[..n]).is_some());
    let mutate = |i: usize, v: u8| {
        let mut c = b;
        c[i] = v;
        KeyObject::decode(&c[..n]).is_none()
    };
    assert!(mutate(0, 2), "version");
    assert!(mutate(1, 9), "kind");
    assert!(
        mutate(3, Curve::Bp256.id()),
        "a curve this applet does not keep"
    );
    assert!(mutate(8, 2), "a list longer than written");
    assert!(
        mutate(9, ALGO_RSA_RAW),
        "an EC key listing an RSA algorithm"
    );
    assert!(KeyObject::decode(&b[..n - 1]).is_none(), "short material");
    assert!(KeyObject::decode(&b[..HEADER_LEN - 1]).is_none());
    let mut rsa = [0u8; PLAIN_MAX];
    let r = KeyObject::new(KeyType::Rsa(RsaSize::R3072), 1, &[], &[1; 5 * 192]).unwrap();
    let m = r.encode(&mut rsa);
    rsa[2..4].copy_from_slice(&1024u16.to_be_bytes());
    assert!(
        KeyObject::decode(&rsa[..m]).is_none(),
        "an RSA size this applet does not make"
    );
    assert!(KeyObject::new(KeyType::Ec(&P256), 1, &[0; ALGOS_MAX + 1], &[7; 32]).is_none());
}

#[test]
fn each_type_serves_its_own_algorithms_only() {
    let ec = KeyType::Ec(&P256);
    let rsa = KeyType::Rsa(RsaSize::R4096);
    for a in [ALGO_EC_RAW, ALGO_EC_SHA224, ALGO_EC_SHA256, ALGO_EC_DH] {
        assert!(ec.serves(a) && !rsa.serves(a), "{a:#04x}");
    }
    for a in [ALGO_RSA_RAW, ALGO_RSA_DECRYPT, ALGO_RSA_PKCS1, ALGO_RSA_PSS] {
        assert!(rsa.serves(a) && !ec.serves(a), "{a:#04x}");
    }
    for sha1 in [0x31, 0x41, 0x71] {
        assert!(!ec.serves(sha1) && !rsa.serves(sha1), "{sha1:#04x}");
    }
    assert_eq!(RsaSize::from_bits(1024), None);
    assert_eq!(RsaSize::R4096.modulus_len(), 512);
}
