// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::domain::{ALL, P256, P384};
use crate::tests::*;
use rsk_crypto::{sha224, sha256, sha384, sha512};
use rsk_fs::storage::faults::{Cut, Op};
use rsk_fs::storage::ram::RamStorage;
use rsk_rsa::vectors::{N_HEX, P_HEX, Q_HEX, hex};

type Applet<'a> = crate::HsmApplet<'a>;

fn sign_cmd<S: Storage>(
    app: &mut Applet,
    fs: &mut Fs<S>,
    kid: u8,
    algo: u8,
    data: &[u8],
) -> (Sw, std::vec::Vec<u8>) {
    run(app, fs, CLA_PROPRIETARY, INS_SIGN, kid, algo, data)
}

fn decipher_cmd<S: Storage>(
    app: &mut Applet,
    fs: &mut Fs<S>,
    kid: u8,
    algo: u8,
    data: &[u8],
) -> (Sw, std::vec::Vec<u8>) {
    run(app, fs, CLA_PROPRIETARY, INS_DECIPHER, kid, algo, data)
}

/// Generate an EC key at `kid` from `tpl`; returns its public point.
fn ec_key<S: Storage>(app: &mut Applet, fs: &mut Fs<S>, kid: u8, tpl: &[u8]) -> std::vec::Vec<u8> {
    let (sw, resp) = generate(app, fs, kid, tpl);
    assert_eq!(sw, Sw::OK);
    let req = get(&resp, TAG_CV_AUTH_REQUEST);
    let body = get(get(req, TAG_CV_CERT), TAG_CV_BODY);
    get(get(body, TAG_CV_PUBKEY), TAG_PK_POINT).to_vec()
}

/// The frozen RSA-2048 key, handed in at `kid` the way the wiring's search would.
fn rsa_key<S: Storage>(app: &mut Applet, fs: &mut Fs<S>, kid: u8, extra: &[u8]) {
    let mut tpl = rsa_template(2048);
    tpl.extend_from_slice(extra);
    let raw = apdu(CLA_ISO, INS_GENERATE_KEYPAIR, kid, 0, &tpl);
    let key = rsk_rsa::rsa_from_pqe(&[1, 0, 1], &hex(P_HEX), &hex(Q_HEX)).unwrap();
    let mut out = [0u8; 2036];
    let mut res = ResBuf::new(&mut out);
    assert_eq!(
        app.rsa_keygen_finish(fs, &Apdu::parse(&raw).unwrap(), &key, &mut res),
        Sw::OK
    );
}

fn mgf1(hash: Hash, seed: &[u8], len: usize) -> std::vec::Vec<u8> {
    let mut out = std::vec::Vec::new();
    let mut counter = 0u32;
    while out.len() < len {
        let mut input = seed.to_vec();
        input.extend_from_slice(&counter.to_be_bytes());
        let mut d = [0u8; MAX_DIGEST];
        let n = hash.digest(&input, &mut d);
        out.extend_from_slice(&d[..n]);
        counter += 1;
    }
    out.truncate(len);
    out
}

/// EMSA-PSS-VERIFY (RFC 8017 §9.1.2) for a salt as long as the hash, written
/// from the RFC rather than from the encoder it checks.
fn pss_verifies(hash: Hash, mhash: &[u8], em: &[u8]) -> bool {
    let h = hash.len();
    let em_len = em.len();
    if em[em_len - 1] != 0xBC || em[0] & 0x80 != 0 {
        return false;
    }
    let (masked, rest) = em.split_at(em_len - h - 1);
    let digest = &rest[..h];
    let mask = mgf1(hash, digest, masked.len());
    let mut db: std::vec::Vec<u8> = masked.iter().zip(mask).map(|(a, b)| a ^ b).collect();
    db[0] &= 0x7F;
    let ps = em_len - 2 * h - 2;
    if db[..ps].iter().any(|&b| b != 0) || db[ps] != 0x01 {
        return false;
    }
    let mut m = std::vec![0u8; 8];
    m.extend_from_slice(mhash);
    m.extend_from_slice(&db[ps + 1..]);
    let mut d = [0u8; MAX_DIGEST];
    let n = hash.digest(&m, &mut d);
    &d[..n] == digest
}

#[test]
fn pss_blocks_verify_and_differ_by_their_salt() {
    for hash in [Hash::Sha256, Hash::Sha384, Hash::Sha512] {
        let mhash = std::vec![0xA5; hash.len()];
        let mut a = [0u8; 256];
        let mut b = [0u8; 256];
        pss_encode(hash, &mhash, &mut TestRng(1), &mut a).unwrap();
        pss_encode(hash, &mhash, &mut TestRng(2), &mut b).unwrap();
        assert!(pss_verifies(hash, &mhash, &a), "{hash:?}");
        assert!(pss_verifies(hash, &mhash, &b));
        assert_ne!(a, b, "a fresh salt per signature");
        let mut flipped = a;
        flipped[100] ^= 1;
        assert!(!pss_verifies(hash, &mhash, &flipped));
    }
    let mut em = [0u8; 256];
    assert_eq!(
        pss_encode(Hash::Sha256, &[0; 31], &mut TestRng(1), &mut em),
        Err(Sw::WRONG_DATA)
    );
    let mut tiny = [0u8; 65];
    assert_eq!(
        pss_encode(Hash::Sha256, &[0; 32], &mut TestRng(1), &mut tiny),
        Err(Sw::WRONG_DATA)
    );
}

#[test]
fn ecdsa_signs_a_given_digest_or_one_it_takes_answering_der() {
    for d in ALL {
        let env = Env::new();
        let mut fs = new_fs();
        let mut app = env.applet(None);
        logged_in(&mut app, &mut fs);
        let point = ec_key(&mut app, &mut fs, 1, &ec_template(d));
        let msg = b"the data a host asks to have signed";
        let w = d.field_len();
        let cases: [(u8, &[u8], std::vec::Vec<u8>); 5] = [
            (ALGO_EC_RAW, &sha256(msg), sha256(msg).to_vec()),
            (ALGO_EC_SHA224, msg, sha224(msg).to_vec()),
            (ALGO_EC_SHA256, msg, sha256(msg).to_vec()),
            (ALGO_EC_SHA384, msg, sha384(msg).to_vec()),
            (ALGO_EC_SHA512, msg, sha512(msg).to_vec()),
        ];
        for (algo, data, digest) in cases {
            if algo == ALGO_EC_RAW && d.field_len() / 2 > data.len() {
                continue;
            }
            let (sw, der) = sign_cmd(&mut app, &mut fs, 1, algo, data);
            assert_eq!(sw, Sw::OK, "{:?} {algo:#04x}", d.curve);
            let raw = der_to_raw(&der, w);
            assert!(
                ecdsa_verifies(d.curve, &point, &digest, &raw),
                "{:?} {algo:#04x}",
                d.curve
            );
        }
    }
}

#[test]
fn rsa_signs_every_padding_the_driver_can_ask_for() {
    let env = Env::new();
    let mut fs = new_fs();
    let mut app = env.applet(None);
    logged_in(&mut app, &mut fs);
    rsa_key(&mut app, &mut fs, 2, &[]);
    let n = hex(N_HEX);
    let msg = b"a certificate to issue";

    // Raw: the host padded the block, the device only exponentiates.
    let mut block = std::vec![0u8; 256];
    block[1] = 0x01;
    block[255] = 0x42;
    let (sw, sig) = sign_cmd(&mut app, &mut fs, 2, ALGO_RSA_RAW, &block);
    assert_eq!(sw, Sw::OK);
    assert_eq!(rsa_public(&n, &sig), block);

    // PKCS#1 v1.5, over a DigestInfo the host built and over a digest the device takes.
    let mut di = DI_SHA256.to_vec();
    di.extend_from_slice(&sha256(msg));
    let (sw, sig) = sign_cmd(&mut app, &mut fs, 2, ALGO_RSA_PKCS1, &di);
    assert_eq!(sw, Sw::OK);
    assert!(rsk_rsa::verify::verify_pkcs1v15(&n, &[1, 0, 1], &di, &sig));
    let (sw, sig2) = sign_cmd(&mut app, &mut fs, 2, ALGO_RSA_PKCS1_SHA256, msg);
    assert_eq!(
        (sw, &sig2),
        (Sw::OK, &sig),
        "deterministic, and the same block"
    );

    // PSS, over a digest either side took.
    for (algo, hash, data) in [
        (ALGO_RSA_PSS, Hash::Sha256, sha256(msg).to_vec()),
        (ALGO_RSA_PSS, Hash::Sha512, sha512(msg).to_vec()),
        (ALGO_RSA_PSS_SHA256, Hash::Sha256, msg.to_vec()),
        (ALGO_RSA_PSS_SHA384, Hash::Sha384, msg.to_vec()),
        (ALGO_RSA_PSS_SHA512, Hash::Sha512, msg.to_vec()),
    ] {
        let (sw, sig) = sign_cmd(&mut app, &mut fs, 2, algo, &data);
        assert_eq!(sw, Sw::OK, "{algo:#04x}");
        let mut d = [0u8; MAX_DIGEST];
        let dn = hash.digest(msg, &mut d);
        assert!(
            pss_verifies(hash, &d[..dn], &rsa_public(&n, &sig)),
            "{algo:#04x}"
        );
    }
}

#[test]
fn malformed_input_is_refused_before_a_use_is_spent() {
    let env = Env::new();
    let mut fs = new_fs();
    let mut app = env.applet(None);
    logged_in(&mut app, &mut fs);
    rsa_key(&mut app, &mut fs, 2, &[0x90, 4, 0, 0, 0, 1]);
    for (algo, data) in [
        (ALGO_RSA_RAW, &[0u8; 255][..]),
        (ALGO_RSA_PKCS1, &[0u8; 40][..]),
        (ALGO_RSA_PSS, &[0u8; 20][..]),
    ] {
        assert_eq!(
            sign_cmd(&mut app, &mut fs, 2, algo, data).0,
            Sw::WRONG_DATA,
            "{algo:#04x}"
        );
    }
    assert_eq!(
        decipher_cmd(&mut app, &mut fs, 2, ALGO_RSA_DECRYPT, &[1; 255]).0,
        Sw::WRONG_DATA
    );
    let point = ec_key(&mut app, &mut fs, 3, &{
        let mut t = ec_template(&P256);
        t.extend_from_slice(&[0x90, 4, 0, 0, 0, 1]);
        t
    });
    assert_eq!(
        sign_cmd(&mut app, &mut fs, 3, ALGO_EC_RAW, &[1; 15]).0,
        Sw::WRONG_DATA
    );
    assert_eq!(
        sign_cmd(&mut app, &mut fs, 3, ALGO_EC_RAW, &[1; 65]).0,
        Sw::WRONG_DATA
    );
    assert_eq!(
        decipher_cmd(&mut app, &mut fs, 3, ALGO_EC_DH, &point[..64]).0,
        Sw::WRONG_DATA
    );
    // The one use each key has is still there.
    assert_eq!(
        sign_cmd(&mut app, &mut fs, 2, ALGO_RSA_PKCS1_SHA256, b"x").0,
        Sw::OK
    );
    assert_eq!(
        sign_cmd(&mut app, &mut fs, 3, ALGO_EC_SHA256, b"x").0,
        Sw::OK
    );
}

#[test]
fn rsa_deciphers_to_the_raw_block_and_ecdh_answers_the_whole_point() {
    let env = Env::new();
    let mut fs = new_fs();
    let mut app = env.applet(None);
    logged_in(&mut app, &mut fs);
    rsa_key(&mut app, &mut fs, 2, &[]);
    let n = hex(N_HEX);
    let mut block = std::vec![0x11u8; 256];
    block[0] = 0x00;
    block[1] = 0x02;
    block[200] = 0x00;
    let ct = rsa_public(&n, &block);
    let (sw, pt) = decipher_cmd(&mut app, &mut fs, 2, ALGO_RSA_DECRYPT, &ct);
    assert_eq!(sw, Sw::OK);
    assert_eq!(pt, block, "unpadded: the host strips it");

    for d in [&P256, &P384] {
        let a = ec_key(&mut app, &mut fs, 5, &ec_template(d));
        let scalar = std::vec![0x0Bu8; d.field_len()];
        let peer = rsk_ec::PrivKey::from_scalar(d.curve, &scalar).unwrap();
        let mut b = [0u8; rsk_ec::MAX_EC_POINT];
        let bn = peer.public_point(&mut b).unwrap();
        let (sw, shared) = decipher_cmd(&mut app, &mut fs, 5, ALGO_EC_DH, &b[..bn]);
        assert_eq!(sw, Sw::OK);
        let mut want = [0u8; rsk_ec::MAX_EC_POINT];
        let wn = peer.ecdh_point(&a, &mut want).unwrap();
        assert_eq!(shared, &want[..wn]);
        let (sw, _) = decipher_cmd(&mut app, &mut fs, 5, ALGO_EC_DH, &a[..]);
        assert_eq!(sw, Sw::OK, "any point on the curve, its own included");
        assert_eq!(
            run(
                &mut app,
                &mut fs,
                CLA_ISO,
                INS_DELETE_FILE,
                0x02,
                0,
                &[PREFIX_KEY, 5]
            )
            .0,
            Sw::OK
        );
    }
    let mut off_curve = std::vec![0x04u8; 65];
    off_curve[64] = 0x01;
    let _ = ec_key(&mut app, &mut fs, 6, &ec_template(&P256));
    assert_eq!(
        decipher_cmd(&mut app, &mut fs, 6, ALGO_EC_DH, &off_curve).0,
        Sw::WRONG_DATA
    );
}

#[test]
fn a_key_is_used_only_as_far_as_the_checks_allow() {
    let env = Env::new();
    let mut fs = new_fs();
    let mut app = env.applet(None);
    logged_in(&mut app, &mut fs);
    let mut tpl = ec_template(&P256);
    tpl.extend_from_slice(&[0x91, 1, ALGO_EC_SHA256]);
    ec_key(&mut app, &mut fs, 1, &tpl);
    assert_eq!(
        sign_cmd(&mut app, &mut fs, 9, ALGO_EC_SHA256, b"x").0,
        Sw::FILE_NOT_FOUND
    );
    assert_eq!(
        sign_cmd(&mut app, &mut fs, KEY_ID_DEVICE, ALGO_EC_SHA256, b"x").0,
        Sw::SECURITY_STATUS_NOT_SATISFIED,
        "the device key signs requests, never for the host"
    );
    assert_eq!(
        sign_cmd(&mut app, &mut fs, 1, ALGO_RSA_RAW, &[0; 256]).0,
        Sw::INCORRECT_P1P2
    );
    assert_eq!(
        sign_cmd(&mut app, &mut fs, 1, 0x71, b"x").0,
        Sw::INCORRECT_P1P2,
        "SHA-1"
    );
    assert_eq!(
        sign_cmd(&mut app, &mut fs, 1, ALGO_EC_DH, b"x").0,
        Sw::INCORRECT_P1P2
    );
    assert_eq!(
        decipher_cmd(&mut app, &mut fs, 1, ALGO_EC_SHA256, b"x").0,
        Sw::INCORRECT_P1P2
    );
    assert_eq!(
        sign_cmd(&mut app, &mut fs, 1, ALGO_EC_SHA384, b"x").0,
        Sw::CONDITIONS_NOT_SATISFIED,
        "not on the key's own list"
    );
    assert_eq!(
        sign_cmd(&mut app, &mut fs, 1, ALGO_EC_SHA256, b"x").0,
        Sw::OK
    );

    // Logged out by a selection, the key is out of reach again.
    select(&mut app, &mut fs);
    assert_eq!(
        sign_cmd(&mut app, &mut fs, 1, ALGO_EC_SHA256, b"x").0,
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
}

#[test]
fn a_use_counter_is_spent_on_flash_before_the_key_runs() {
    let env = Env::new();
    let (cut, medium) = Cut::new();
    let mut fs = Fs::new(cut);
    fs.scan();
    let mut app = env.applet(None);
    logged_in(&mut app, &mut fs);
    let mut tpl = ec_template(&P256);
    tpl.extend_from_slice(&[0x90, 4, 0, 0, 0, 2]);
    ec_key(&mut app, &mut fs, 1, &tpl);
    let at = keys::fid(1).get();

    // A reset as the spent use is written: no signature, and nothing refunded.
    medium.clear_ops();
    medium.arm(0);
    assert_eq!(
        sign_cmd(&mut app, &mut fs, 1, ALGO_EC_SHA256, b"x").0,
        Sw::MEMORY_FAILURE
    );
    medium.arm(u32::MAX);
    assert_eq!(
        sign_cmd(&mut app, &mut fs, 1, ALGO_EC_SHA256, b"x").0,
        Sw::OK
    );
    assert!(matches!(&medium.ops()[..], [Op::Write(f, _)] if *f == at));
    assert_eq!(
        sign_cmd(&mut app, &mut fs, 1, ALGO_EC_SHA256, b"x").0,
        Sw::OK
    );
    assert_eq!(
        sign_cmd(&mut app, &mut fs, 1, ALGO_EC_SHA256, b"x").0,
        Sw::FILE_FULL
    );
    let hmk = app.sess.hmk.clone().unwrap();
    assert_eq!(keys::load(&mut fs, &hmk, 1).unwrap().unwrap().counter, 0);
}

#[test]
fn the_touch_option_asks_before_every_use_and_a_refusal_spends_nothing() {
    let env = Env::new();
    let mut fs = new_fs();
    let mut app = env.applet(None);
    provision_with(&mut fs, None).unwrap();
    select(&mut app, &mut fs);
    assert_eq!(
        initialize(&mut app, &mut fs, OPT_TOUCH_KEY_USE, &SO_PIN),
        Sw::OK
    );
    assert_eq!(verify(&mut app, &mut fs, PIN), Sw::OK);
    let mut tpl = ec_template(&P256);
    tpl.extend_from_slice(&[0x90, 4, 0, 0, 0, 1]);
    let asks = env.asks();
    ec_key(&mut app, &mut fs, 1, &tpl);
    assert_eq!(env.asks(), asks, "making a key needs no touch");
    env.answer(rsk_sdk::Presence::Declined);
    assert_eq!(
        sign_cmd(&mut app, &mut fs, 1, ALGO_EC_SHA256, b"x").0,
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    assert_eq!(env.asks(), asks + 1);
    env.answer(rsk_sdk::Presence::Confirmed);
    assert_eq!(
        sign_cmd(&mut app, &mut fs, 1, ALGO_EC_SHA256, b"x").0,
        Sw::OK
    );
    assert_eq!(env.asks(), asks + 2);
}

#[test]
fn a_closed_lock_refuses_every_key_use() {
    let env = Env::new();
    let mut fs = new_fs();
    let mut app = env.applet(None);
    logged_in(&mut app, &mut fs);
    ec_key(&mut app, &mut fs, 1, &ec_template(&P256));
    assert_eq!(arm(&mut app, &mut fs, &SECRET, &SO_PIN), Sw::OK);
    let mut app = env.applet(None);
    select(&mut app, &mut fs);
    assert_eq!(
        sign_cmd(&mut app, &mut fs, 1, ALGO_EC_SHA256, b"x").0,
        Sw::CONDITIONS_NOT_SATISFIED
    );
    assert_eq!(unlock(&mut app, &mut fs, &SECRET), Sw::OK);
    assert_eq!(verify(&mut app, &mut fs, PIN), Sw::OK);
    assert_eq!(
        sign_cmd(&mut app, &mut fs, 1, ALGO_EC_SHA256, b"x").0,
        Sw::OK
    );
}

#[test]
fn the_device_key_cannot_be_read_written_deleted_or_regenerated() {
    let env = Env::new();
    let mut fs: Fs<RamStorage> = new_fs();
    let mut app = env.applet(None);
    logged_in(&mut app, &mut fs);
    let cc00 = [PREFIX_KEY, KEY_ID_DEVICE];
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            CLA_ISO,
            INS_READ_BINARY_ODD,
            cc00[0],
            cc00[1],
            &[0x54, 2, 0, 0]
        )
        .0,
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    assert_eq!(
        run(&mut app, &mut fs, CLA_ISO, INS_DELETE_FILE, 0x02, 0, &cc00).0,
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    assert_eq!(
        generate(&mut app, &mut fs, KEY_ID_DEVICE, &ec_template(&P256)).0,
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
}
