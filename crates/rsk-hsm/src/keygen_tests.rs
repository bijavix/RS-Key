// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::cvc::OID_LEN;
use crate::domain::{ALL, K256, P256, P384};
use crate::tests::*;
use rsk_crypto::sha256;
use rsk_ec::Curve;
use rsk_fs::storage::ram::RamStorage;

/// The pieces of an authenticated request, each as the bytes it was signed over.
struct Request {
    body: std::vec::Vec<u8>,
    cert: std::vec::Vec<u8>,
    car: std::vec::Vec<u8>,
    inner: std::vec::Vec<u8>,
    outer: std::vec::Vec<u8>,
}

fn tlv_len(v: &[u8]) -> usize {
    rsk_sdk::tlv::format_len_size(v.len() as u16) + v.len()
}

fn split(resp: &[u8]) -> Request {
    let req = get(resp, TAG_CV_AUTH_REQUEST);
    assert_eq!(resp.len(), 1 + tlv_len(req), "nothing after the request");
    let cert = get(req, TAG_CV_CERT);
    let cert_tlv = &req[..2 + tlv_len(cert)];
    let body = get(cert, TAG_CV_BODY);
    let car = get(&req[cert_tlv.len()..], TAG_CV_CAR);
    let car_tlv = &req[cert_tlv.len()..cert_tlv.len() + 1 + tlv_len(car)];
    let mut outer_signed = cert_tlv.to_vec();
    outer_signed.extend_from_slice(car_tlv);
    Request {
        body: cert[..2 + tlv_len(body)].to_vec(),
        cert: outer_signed,
        car: car.to_vec(),
        inner: get(cert, TAG_CV_SIGNATURE).to_vec(),
        outer: get(&req[cert_tlv.len() + car_tlv.len()..], TAG_CV_SIGNATURE).to_vec(),
    }
}

/// The device key's point, from `2F02`'s first certificate.
fn device_point(fs: &mut Fs<RamStorage>) -> std::vec::Vec<u8> {
    let mut buf = [0u8; 1024];
    let n = crate::store::read_plain(fs, crate::store::REC_DEVAUT, &mut buf)
        .unwrap()
        .unwrap();
    let (_, cert) = rsk_sdk::tlv::Tlv::new(&buf[..n]).next().unwrap();
    get(get(get(cert, TAG_CV_BODY), TAG_CV_PUBKEY), TAG_PK_POINT).to_vec()
}

#[test]
fn an_ec_key_comes_back_as_a_request_the_key_and_the_device_both_signed() {
    for d in ALL {
        let env = Env::new();
        let mut fs = new_fs();
        let mut app = env.applet(None);
        logged_in(&mut app, &mut fs);
        let (sw, resp) = generate(&mut app, &mut fs, 1, &ec_template(d));
        assert_eq!(sw, Sw::OK, "{:?}", d.curve);
        let r = split(&resp);

        // The body the driver decodes: profile, its CAR, the key with the curve
        // spelt out in the order it compares them, its CHR.
        let body = get(&r.body, TAG_CV_BODY);
        assert_eq!(get(body, TAG_CV_PROFILE), [CV_PROFILE]);
        assert_eq!(get(body, TAG_CV_CAR), b"UTCA00001");
        assert_eq!(get(body, TAG_CV_CHR), reference(MNEMONIC_DEVICE, SERIAL));
        let pk = get(body, TAG_CV_PUBKEY);
        let tags: std::vec::Vec<u16> = rsk_sdk::tlv::Tlv::new(pk).map(|(t, _)| t).collect();
        assert_eq!(tags, [0x06, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87]);
        assert_eq!(get(pk, TAG_PK_PRIME), d.p);
        assert_eq!(get(pk, TAG_PK_A), d.a);
        let point = get(pk, TAG_PK_POINT);
        assert_eq!(point.len(), d.point_len());

        // Proof of possession by the new key, then the device's vouching.
        assert!(ecdsa_verifies(d.curve, point, &sha256(&r.body), &r.inner));
        assert_eq!(r.car, reference(MNEMONIC_DEVICE, SERIAL));
        assert!(ecdsa_verifies(
            Curve::P256,
            &device_point(&mut fs),
            &sha256(&r.cert),
            &r.outer
        ));
        assert!(keys::exists(&mut fs, 1).unwrap());
    }
}

#[test]
fn an_rsa_key_comes_back_with_its_modulus_and_both_signatures() {
    let env = Env::new();
    let mut fs = new_fs();
    let mut app = env.applet(None);
    logged_in(&mut app, &mut fs);
    let (sw, resp) = generate(&mut app, &mut fs, 2, &rsa_template(2048));
    assert_eq!(sw, Sw::OK);
    let r = split(&resp);
    let pk = get(get(&r.body, TAG_CV_BODY), TAG_CV_PUBKEY);
    let tags: std::vec::Vec<u16> = rsk_sdk::tlv::Tlv::new(pk).map(|(t, _)| t).collect();
    assert_eq!(tags, [0x06, 0x81, 0x82]);
    let n = get(pk, TAG_PK_PRIME);
    assert_eq!(n.len(), 256);
    assert!(n[0] & 0x80 != 0, "a full-width modulus");
    assert_eq!(get(pk, TAG_PK_A), [1, 0, 1]);
    let mut di = DI_SHA256.to_vec();
    di.extend_from_slice(&sha256(&r.body));
    assert!(rsk_rsa::verify::verify_pkcs1v15(
        n,
        &[1, 0, 1],
        &di,
        &r.inner
    ));
    assert!(ecdsa_verifies(
        Curve::P256,
        &device_point(&mut fs),
        &sha256(&r.cert),
        &r.outer
    ));
}

/// The fast path: the wiring finds the primes, the applet finishes — here with a
/// frozen key, so the request carries a modulus known in advance.
#[test]
fn the_wiring_can_hand_in_an_rsa_key_it_found() {
    use rsk_rsa::vectors::{N_HEX, P_HEX, Q_HEX, hex};
    let env = Env::new();
    let mut fs = new_fs();
    let mut app = env.applet(None);
    logged_in(&mut app, &mut fs);
    let raw = apdu(CLA_ISO, INS_GENERATE_KEYPAIR, 3, 0, &rsa_template(2048));
    let cmd = Apdu::parse(&raw).unwrap();
    assert_eq!(app.rsa_keygen_bits(&mut fs, &cmd), Some(2048));
    let ec_raw = apdu(CLA_ISO, INS_GENERATE_KEYPAIR, 3, 0, &ec_template(&P256));
    assert_eq!(
        app.rsa_keygen_bits(&mut fs, &Apdu::parse(&ec_raw).unwrap()),
        None
    );
    let key = rsk_rsa::rsa_from_pqe(&[1, 0, 1], &hex(P_HEX), &hex(Q_HEX)).unwrap();
    let mut out = [0u8; 2036];
    let mut res = ResBuf::new(&mut out);
    assert_eq!(app.rsa_keygen_finish(&mut fs, &cmd, &key, &mut res), Sw::OK);
    let r = split(res.as_slice());
    assert_eq!(
        get(get(get(&r.body, TAG_CV_BODY), TAG_CV_PUBKEY), TAG_PK_PRIME),
        hex(N_HEX)
    );
    // A slot taken since, or a key of another size, is refused and leaves no answer.
    let mut res = ResBuf::new(&mut out);
    assert_eq!(
        app.rsa_keygen_finish(&mut fs, &cmd, &key, &mut res),
        Sw::FILE_EXISTS
    );
    assert!(res.is_empty());
    let raw = apdu(CLA_ISO, INS_GENERATE_KEYPAIR, 4, 0, &rsa_template(3072));
    let mut res = ResBuf::new(&mut out);
    let cmd = Apdu::parse(&raw).unwrap();
    assert_eq!(
        app.rsa_keygen_finish(&mut fs, &cmd, &key, &mut res),
        Sw::EXEC_ERROR
    );
    assert!(!keys::exists(&mut fs, 4).unwrap());
}

#[test]
fn the_largest_request_fits_the_drivers_buffer() {
    // The driver reads a GENERATE KEY PAIR answer into 1200 bytes; RSA-4096 with
    // a sixteen-character CAR is the largest this device writes.
    let env = Env::new();
    let mut fs = new_fs();
    let mut app = env.applet(None);
    logged_in(&mut app, &mut fs);
    let mut tpl = rsa_template(4096);
    let car_at = tpl.windows(9).position(|w| w == b"UTCA00001").unwrap();
    tpl.splice(
        car_at - 1..car_at + 9,
        [16u8].into_iter().chain(*b"UTCA000000000001"),
    );
    let (sw, resp) = generate(&mut app, &mut fs, 1, &tpl);
    assert_eq!(sw, Sw::OK);
    assert!(resp.len() <= 1200, "{} bytes", resp.len());
    assert_eq!(
        get(
            get(get(&split(&resp).body, TAG_CV_BODY), TAG_CV_PUBKEY),
            TAG_PK_PRIME
        )
        .len(),
        512
    );
}

#[test]
fn generating_needs_a_login_a_free_slot_and_a_device_key() {
    let env = Env::new();
    let mut fs = new_fs();
    let mut app = env.applet(None);
    let tpl = ec_template(&P256);
    select(&mut app, &mut fs);
    assert_eq!(
        generate(&mut app, &mut fs, 1, &tpl).0,
        Sw::REFERENCE_NOT_FOUND
    );
    assert_eq!(initialize(&mut app, &mut fs, OPT_RRC, &SO_PIN), Sw::OK);
    assert_eq!(
        generate(&mut app, &mut fs, 1, &tpl).0,
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    assert_eq!(verify(&mut app, &mut fs, PIN), Sw::OK);
    assert_eq!(
        generate(&mut app, &mut fs, 1, &tpl).0,
        Sw::CONDITIONS_NOT_SATISFIED,
        "no device key: nothing could vouch for the key"
    );
    assert!(!keys::exists(&mut fs, 1).unwrap());
    provision_with(&mut fs, None).unwrap();
    assert_eq!(
        generate(&mut app, &mut fs, KEY_ID_DEVICE, &tpl).0,
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    assert_eq!(
        run(&mut app, &mut fs, CLA_ISO, INS_GENERATE_KEYPAIR, 1, 1, &tpl).0,
        Sw::INCORRECT_P1P2
    );
    assert_eq!(generate(&mut app, &mut fs, 1, &tpl).0, Sw::OK);
    assert_eq!(generate(&mut app, &mut fs, 1, &tpl).0, Sw::FILE_EXISTS);
}

#[test]
fn the_template_is_parsed_strictly() {
    let env = Env::new();
    let mut fs = new_fs();
    let mut app = env.applet(None);
    logged_in(&mut app, &mut fs);
    let good = ec_template(&P384);
    let mut kid = 10u8;
    let mut try_tpl = |app: &mut crate::HsmApplet, fs: &mut Fs<RamStorage>, t: &[u8]| {
        kid += 1;
        generate(app, fs, kid, t).0
    };
    assert_eq!(try_tpl(&mut app, &mut fs, &good), Sw::OK);

    let with = |extra: &[u8]| {
        let mut t = good.clone();
        t.extend_from_slice(extra);
        t
    };
    for (what, t) in [
        ("an unknown object", with(&[0x99, 1, 0])),
        ("a second CHR", with(&[0x5F, 0x20, 2, b'A', b'B'])),
        ("a use counter of zero", with(&[0x90, 4, 0, 0, 0, 0])),
        ("a short use counter", with(&[0x90, 2, 0, 1])),
        ("another key domain", with(&[0x92, 1, 1])),
        (
            "an RSA algorithm on an EC key",
            with(&[0x91, 1, ALGO_RSA_RAW]),
        ),
        ("SHA-1 ECDSA", with(&[0x91, 1, 0x71])),
        ("an empty algorithm list", with(&[0x91, 0])),
    ] {
        assert_eq!(try_tpl(&mut app, &mut fs, &t), Sw::WRONG_DATA, "{what}");
    }
    for (what, t) in [
        ("a use counter", with(&[0x90, 4, 0, 0, 0, 5])),
        ("the default key domain", with(&[0x92, 1, 0])),
        (
            "an algorithm list",
            with(&[0x91, 2, ALGO_EC_SHA256, ALGO_EC_DH]),
        ),
    ] {
        assert_eq!(try_tpl(&mut app, &mut fs, &t), Sw::OK, "{what}");
    }

    // The curve: named by p and a; every other parameter given must agree.
    let mut wrong_b = ec_template(&P256);
    let at = wrong_b
        .windows(P256.b.len())
        .position(|w| w == P256.b)
        .unwrap();
    wrong_b[at] ^= 1;
    assert_eq!(try_tpl(&mut app, &mut fs, &wrong_b), Sw::WRONG_DATA);
    let mut brainpool_like = ec_template(&P256);
    let at = brainpool_like
        .windows(P256.a.len())
        .position(|w| w == P256.a)
        .unwrap();
    brainpool_like[at + 31] ^= 1;
    assert_eq!(try_tpl(&mut app, &mut fs, &brainpool_like), Sw::WRONG_DATA);

    // RSA: the sizes this device makes, and only the exponent it makes them with.
    for bits in [1024u16, 2047, 8192] {
        assert_eq!(
            try_tpl(&mut app, &mut fs, &rsa_template(bits)),
            Sw::WRONG_DATA,
            "{bits}"
        );
    }
    let mut e3 = rsa_template(2048);
    let at = e3.windows(5).position(|w| w == [0x82, 3, 1, 0, 1]).unwrap();
    e3.splice(at..at + 5, [0x82, 1, 3]);
    assert_eq!(try_tpl(&mut app, &mut fs, &e3), Sw::WRONG_DATA);
    // An RSA OID over EC parameters, and the other way round.
    let mut mixed = ec_template(&P256);
    let at = mixed
        .windows(OID_LEN)
        .position(|w| w == SigAlg::EcdsaSha256.oid())
        .unwrap();
    mixed[at..at + OID_LEN].copy_from_slice(&SigAlg::RsaV15Sha256.oid());
    assert_eq!(try_tpl(&mut app, &mut fs, &mixed), Sw::WRONG_DATA);
    assert_eq!(
        try_tpl(&mut app, &mut fs, &good[..good.len() - 1]),
        Sw::WRONG_DATA
    );
}

#[test]
fn a_key_limited_by_the_template_carries_the_limits_it_was_made_with() {
    let env = Env::new();
    let mut fs = new_fs();
    let mut app = env.applet(None);
    logged_in(&mut app, &mut fs);
    let mut tpl = ec_template(&K256);
    tpl.extend_from_slice(&[0x90, 4, 0, 0, 0, 2, 0x91, 1, ALGO_EC_SHA256]);
    assert_eq!(generate(&mut app, &mut fs, 7, &tpl).0, Sw::OK);
    let hmk = app.sess.hmk.clone().unwrap();
    let obj = keys::load(&mut fs, &hmk, 7).unwrap().unwrap();
    assert_eq!(obj.counter, 2);
    assert!(obj.allows(ALGO_EC_SHA256) && !obj.allows(ALGO_EC_RAW));
    assert_eq!(obj.ty, KeyType::Ec(&K256));
}
