// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::keys::COUNTER_UNLIMITED;
use crate::tests::*;
use rsk_rsa::vectors::hex;
use rsk_sdk::Presence;

/// NIST SP 800-38A F.2: the IV, the four plaintext blocks, and per key size the
/// key and the CBC ciphertext.
const IV: &str = "000102030405060708090a0b0c0d0e0f";
const PLAIN: &str = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51\
                     30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";
const CBC: [(&str, &str); 3] = [
    (
        "2b7e151628aed2a6abf7158809cf4f3c",
        "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2\
         73bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7",
    ),
    (
        "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        "4f021db243bc633d7178183a9fa071e8b4d9ada9ad7dedf4e5e738763f69145a\
         571b242012fb7ae07fa9baac3df102e008b0e27988598881d920a9e64f5615cd",
    ),
    (
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d\
         39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b",
    ),
];
/// SP 800-38B D.1: AES-128 CMAC of the first plaintext block.
const CMAC_128_ONE_BLOCK: &str = "070a16b46b4d4144f79bdd9dd04a287c";

fn gen_sym<S: Storage>(app: &mut HsmApplet, fs: &mut Fs<S>, kid: u8, p2: u8, d: &[u8]) -> Sw {
    run(app, fs, CLA_ISO, INS_GENERATE_SYMMETRIC, kid, p2, d).0
}

fn cipher<S: Storage>(
    app: &mut HsmApplet,
    fs: &mut Fs<S>,
    kid: u8,
    algo: u8,
    d: &[u8],
) -> (Sw, Vec<u8>) {
    run(app, fs, CLA_PROPRIETARY, INS_CIPHER_SYMMETRIC, kid, algo, d)
}

/// Seal a known AES key at `kid` the way a generation would.
fn put_aes<S: Storage>(
    app: &mut HsmApplet,
    fs: &mut Fs<S>,
    kid: u8,
    key: &[u8],
    counter: u32,
    algos: &[u8],
) {
    let hmk = app.sess.hmk.clone().unwrap();
    let ty = KeyType::Aes(AesSize::from_len(key.len()).unwrap());
    let obj = KeyObject::new(ty, counter, algos, key).unwrap();
    keys::store(fs, &hmk, kid, &obj, &mut TestRng(5)).unwrap();
}

fn counter<S: Storage>(app: &HsmApplet, fs: &mut Fs<S>, kid: u8) -> u32 {
    let hmk = app.sess.hmk.clone().unwrap();
    keys::load(fs, &hmk, kid).unwrap().unwrap().counter
}

#[test]
fn cbc_under_a_zero_iv_is_the_standard_mode_the_host_chains() {
    let env = Env::new();
    let mut fs = new_fs();
    let mut app = env.applet(None);
    logged_in(&mut app, &mut fs);
    let iv = hex(IV);
    let plain = hex(PLAIN);
    // The host owns the IV: it folds it into the first block itself.
    let mut first = plain.clone();
    for (p, v) in first.iter_mut().zip(&iv) {
        *p ^= v;
    }
    for (kid, (key, ct)) in (1u8..).zip(CBC) {
        put_aes(&mut app, &mut fs, kid, &hex(key), COUNTER_UNLIMITED, &[]);
        let (sw, out) = cipher(&mut app, &mut fs, kid, ALGO_AES_CBC_ENCRYPT, &first);
        assert_eq!((sw, out), (Sw::OK, hex(ct)), "AES-{}", 8 * hex(key).len());
        let (sw, mut back) = cipher(&mut app, &mut fs, kid, ALGO_AES_CBC_DECRYPT, &hex(ct));
        assert_eq!(sw, Sw::OK);
        for (p, v) in back.iter_mut().zip(&iv) {
            *p ^= v;
        }
        assert_eq!(back, plain);
    }
}

#[test]
fn cmac_is_the_standard_mac() {
    let env = Env::new();
    let mut fs = new_fs();
    let mut app = env.applet(None);
    logged_in(&mut app, &mut fs);
    put_aes(&mut app, &mut fs, 1, &hex(CBC[0].0), COUNTER_UNLIMITED, &[]);
    assert_eq!(
        cipher(&mut app, &mut fs, 1, ALGO_AES_CMAC, &hex(PLAIN)[..16]),
        (Sw::OK, hex(CMAC_128_ONE_BLOCK))
    );
    let (sw, empty) = cipher(&mut app, &mut fs, 1, ALGO_AES_CMAC, &[]);
    assert_eq!((sw, empty.len()), (Sw::OK, 16), "any length, none included");
}

#[test]
fn a_generated_key_is_fresh_sized_by_p2_and_works_both_ways() {
    let env = Env::new();
    let mut fs = new_fs();
    let mut app = env.applet(None);
    logged_in(&mut app, &mut fs);
    let hmk = app.sess.hmk.clone().unwrap();
    for (kid, (p2, size)) in (1u8..).zip([
        (AES_128, AesSize::A128),
        (AES_192, AesSize::A192),
        (AES_256, AesSize::A256),
    ]) {
        assert_eq!(gen_sym(&mut app, &mut fs, kid, p2, &[]), Sw::OK);
        let obj = keys::load(&mut fs, &hmk, kid).unwrap().unwrap();
        assert_eq!(
            (obj.ty, obj.counter, obj.algos()),
            (KeyType::Aes(size), COUNTER_UNLIMITED, &[][..])
        );
        assert_ne!(obj.material(), vec![0u8; size.len()]);
        let data = [0x3Cu8; 48];
        let (sw, ct) = cipher(&mut app, &mut fs, kid, ALGO_AES_CBC_ENCRYPT, &data);
        assert_eq!(sw, Sw::OK);
        assert_ne!(ct, data);
        assert_eq!(
            cipher(&mut app, &mut fs, kid, ALGO_AES_CBC_DECRYPT, &ct),
            (Sw::OK, data.to_vec())
        );
    }
    let a = keys::load(&mut fs, &hmk, 3).unwrap().unwrap();
    assert_eq!(gen_sym(&mut app, &mut fs, 4, AES_256, &[]), Sw::OK);
    let b = keys::load(&mut fs, &hmk, 4).unwrap().unwrap();
    assert_ne!(a.material(), b.material());
}

#[test]
fn generation_takes_the_limits_and_nothing_else() {
    let env = Env::new();
    let mut fs = new_fs();
    let mut app = env.applet(None);
    logged_in(&mut app, &mut fs);
    let limits = [0x90, 4, 0, 0, 0, 3, 0x91, 1, ALGO_AES_CMAC, 0x92, 1, 0];
    assert_eq!(gen_sym(&mut app, &mut fs, 1, AES_128, &limits), Sw::OK);
    let hmk = app.sess.hmk.clone().unwrap();
    let obj = keys::load(&mut fs, &hmk, 1).unwrap().unwrap();
    assert_eq!((obj.counter, obj.algos()), (3, &[ALGO_AES_CMAC][..]));
    for bad in [
        &[0x91, 1, ALGO_EC_SHA256][..],
        &[0x91, 0],
        &[0x90, 4, 0, 0, 0, 0],
        &[0x90, 2, 0, 1],
        &[0x92, 1, 1],
        &[0x91, 1, ALGO_AES_CMAC, 0x91, 1, ALGO_AES_CMAC],
        &[0x5F, 0x29, 1, 0],
        &[0x91],
    ] {
        assert_eq!(
            gen_sym(&mut app, &mut fs, 2, AES_128, bad),
            Sw::WRONG_DATA,
            "{bad:02x?}"
        );
    }
    assert!(!keys::exists(&mut fs, 2).unwrap());
}

#[test]
fn generation_needs_a_login_a_size_and_a_free_slot() {
    let env = Env::new();
    let mut fs = new_fs();
    let mut app = env.applet(None);
    select(&mut app, &mut fs);
    assert_eq!(
        gen_sym(&mut app, &mut fs, 1, AES_128, &[]),
        require_init(&mut fs).err().unwrap()
    );
    provision_with(&mut fs, None).unwrap();
    ready(&mut app, &mut fs);
    assert_eq!(
        gen_sym(&mut app, &mut fs, 1, AES_128, &[]),
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    assert_eq!(verify(&mut app, &mut fs, PIN), Sw::OK);
    assert_eq!(
        gen_sym(&mut app, &mut fs, KEY_ID_DEVICE, AES_128, &[]),
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    for p2 in [0x00, 0xAF, 0xB3, 0xFF] {
        assert_eq!(gen_sym(&mut app, &mut fs, 1, p2, &[]), Sw::INCORRECT_P1P2);
    }
    assert_eq!(gen_sym(&mut app, &mut fs, 1, AES_128, &[]), Sw::OK);
    assert_eq!(gen_sym(&mut app, &mut fs, 1, AES_256, &[]), Sw::FILE_EXISTS);
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            CLA_PROPRIETARY,
            INS_GENERATE_SYMMETRIC,
            2,
            AES_128,
            &[]
        )
        .0,
        Sw::CLA_NOT_SUPPORTED
    );
}

#[test]
fn a_symmetric_key_serves_only_cipher_symmetric_and_only_its_algorithms() {
    let env = Env::new();
    let mut fs = new_fs();
    let mut app = env.applet(None);
    logged_in(&mut app, &mut fs);
    put_aes(&mut app, &mut fs, 1, &[7; 16], COUNTER_UNLIMITED, &[]);
    let block = [0u8; 16];
    // Its algorithms through the other instructions, and theirs through this one.
    for algo in [ALGO_AES_CBC_ENCRYPT, ALGO_AES_CMAC] {
        assert_eq!(
            run(
                &mut app,
                &mut fs,
                CLA_PROPRIETARY,
                INS_SIGN,
                1,
                algo,
                &block
            )
            .0,
            Sw::INCORRECT_P1P2
        );
        assert_eq!(
            run(
                &mut app,
                &mut fs,
                CLA_PROPRIETARY,
                INS_DECIPHER,
                1,
                algo,
                &block
            )
            .0,
            Sw::INCORRECT_P1P2
        );
    }
    for algo in [
        ALGO_RSA_RAW,
        ALGO_EC_RAW,
        ALGO_RSA_DECRYPT,
        ALGO_EC_DH,
        ALGO_WRAP,
        0x51,
    ] {
        assert_eq!(
            cipher(&mut app, &mut fs, 1, algo, &block).0,
            Sw::INCORRECT_P1P2
        );
    }
    // An EC key is not an AES key.
    assert_eq!(
        generate(&mut app, &mut fs, 2, &ec_template(&crate::domain::P256)).0,
        Sw::OK
    );
    assert_eq!(
        cipher(&mut app, &mut fs, 2, ALGO_AES_CBC_ENCRYPT, &block).0,
        Sw::INCORRECT_P1P2
    );
    // Its own list narrows it further.
    put_aes(
        &mut app,
        &mut fs,
        3,
        &[7; 16],
        COUNTER_UNLIMITED,
        &[ALGO_AES_CMAC],
    );
    assert_eq!(
        cipher(&mut app, &mut fs, 3, ALGO_AES_CMAC, &block).0,
        Sw::OK
    );
    assert_eq!(
        cipher(&mut app, &mut fs, 3, ALGO_AES_CBC_ENCRYPT, &block).0,
        Sw::CONDITIONS_NOT_SATISFIED
    );
    assert_eq!(
        cipher(&mut app, &mut fs, 9, ALGO_AES_CMAC, &block).0,
        Sw::FILE_NOT_FOUND
    );
    assert_eq!(
        cipher(&mut app, &mut fs, KEY_ID_DEVICE, ALGO_AES_CMAC, &block).0,
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
}

#[test]
fn a_use_is_spent_only_on_input_the_key_can_take() {
    let env = Env::new();
    let mut fs = new_fs();
    let mut app = env.applet(None);
    logged_in(&mut app, &mut fs);
    put_aes(&mut app, &mut fs, 1, &[7; 32], 2, &[]);
    for bad in [&[][..], &[0; 15], &[0; 17]] {
        for algo in [ALGO_AES_CBC_ENCRYPT, ALGO_AES_CBC_DECRYPT] {
            assert_eq!(cipher(&mut app, &mut fs, 1, algo, bad).0, Sw::WRONG_DATA);
        }
    }
    // More than the answer can hold: refused before the key is even opened.
    assert_eq!(
        cipher(&mut app, &mut fs, 1, ALGO_AES_CBC_ENCRYPT, &[0; 2048]).0,
        Sw::WRONG_LENGTH
    );
    assert_eq!(counter(&app, &mut fs, 1), 2);
    assert_eq!(cipher(&mut app, &mut fs, 1, ALGO_AES_CMAC, &[1]).0, Sw::OK);
    assert_eq!(
        cipher(&mut app, &mut fs, 1, ALGO_AES_CBC_ENCRYPT, &[0; 16]).0,
        Sw::OK
    );
    assert_eq!(counter(&app, &mut fs, 1), 0);
    assert_eq!(
        cipher(&mut app, &mut fs, 1, ALGO_AES_CMAC, &[1]).0,
        Sw::FILE_FULL
    );
}

#[test]
fn every_use_asks_for_a_touch_when_the_owner_chose_it() {
    let env = Env::new();
    let mut fs = new_fs();
    let mut app = env.applet(None);
    provision_with(&mut fs, None).unwrap();
    select(&mut app, &mut fs);
    assert_eq!(
        initialize(&mut app, &mut fs, OPT_RRC | OPT_TOUCH_KEY_USE, &SO_PIN),
        Sw::OK
    );
    assert_eq!(verify(&mut app, &mut fs, PIN), Sw::OK);
    assert_eq!(gen_sym(&mut app, &mut fs, 1, AES_128, &[]), Sw::OK);
    let asks = env.asks();
    assert_eq!(cipher(&mut app, &mut fs, 1, ALGO_AES_CMAC, &[1]).0, Sw::OK);
    assert_eq!(env.asks(), asks + 1);
    env.answer(Presence::Declined);
    assert_eq!(
        cipher(&mut app, &mut fs, 1, ALGO_AES_CMAC, &[1]).0,
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
}

#[test]
fn a_locked_device_keeps_its_symmetric_keys_closed() {
    let env = Env::new();
    let mut fs = new_fs();
    let mut app = env.applet(None);
    logged_in(&mut app, &mut fs);
    assert_eq!(gen_sym(&mut app, &mut fs, 1, AES_128, &[]), Sw::OK);
    assert_eq!(arm(&mut app, &mut fs, &SECRET, &SO_PIN), Sw::OK);
    let mut app = env.applet(None);
    select(&mut app, &mut fs);
    // The PIN cannot even be tried, and neither command reaches the store.
    assert_eq!(verify(&mut app, &mut fs, PIN), Sw::CONDITIONS_NOT_SATISFIED);
    assert_eq!(
        cipher(&mut app, &mut fs, 1, ALGO_AES_CMAC, &[1]).0,
        Sw::CONDITIONS_NOT_SATISFIED
    );
    assert_eq!(
        gen_sym(&mut app, &mut fs, 2, AES_128, &[]),
        Sw::CONDITIONS_NOT_SATISFIED
    );
    assert_eq!(unlock(&mut app, &mut fs, &SECRET), Sw::OK);
    assert_eq!(verify(&mut app, &mut fs, PIN), Sw::OK);
    assert_eq!(cipher(&mut app, &mut fs, 1, ALGO_AES_CMAC, &[1]).0, Sw::OK);
}
