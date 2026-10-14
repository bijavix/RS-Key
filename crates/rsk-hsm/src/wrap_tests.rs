// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::domain::{ALL, K256, P256, P384, P521};
use crate::tests::*;
use num_bigint_dig::BigUint;
use rsk_fs::storage::ram::RamStorage;
use rsk_rsa::vectors::{N_HEX, N1024_HEX, P_HEX, P1024_HEX, Q_HEX, Q1024_HEX, hex};

const S1: [u8; 32] = [0x13; 32];
const S2: [u8; 32] = [0xC4; 32];

fn dkek_of(shares: &[[u8; 32]]) -> [u8; 32] {
    shares
        .iter()
        .fold([0; 32], |acc, s| core::array::from_fn(|i| acc[i] ^ s[i]))
}

/// A provisioned device initialized for `shares`, each imported, the PIN verified.
fn with_shares<'e>(env: &'e Env, shares: &[[u8; 32]]) -> (HsmApplet<'e>, Fs<RamStorage>) {
    let mut fs = new_fs();
    let mut app = env.applet(None);
    provision_with(&mut fs, None).unwrap();
    select(&mut app, &mut fs);
    let mut d = init_data(OPT_RRC, PIN, &SO_PIN, None);
    d.extend_from_slice(&[0x92, 1, shares.len() as u8]);
    assert_eq!(
        run(&mut app, &mut fs, CLA_PROPRIETARY, INS_INITIALIZE, 0, 0, &d).0,
        Sw::OK
    );
    for s in shares {
        assert_eq!(
            run(&mut app, &mut fs, CLA_PROPRIETARY, INS_KEY_DOMAIN, 0, 0, s).0,
            Sw::OK
        );
    }
    assert_eq!(verify(&mut app, &mut fs, PIN), Sw::OK);
    (app, fs)
}

fn wrap<S: Storage>(app: &mut HsmApplet, fs: &mut Fs<S>, kid: u8) -> (Sw, Vec<u8>) {
    run(
        app,
        fs,
        CLA_PROPRIETARY,
        INS_WRAP_KEY,
        kid,
        WRAP_WITH_DKEK,
        &[],
    )
}

fn unwrap<S: Storage>(app: &mut HsmApplet, fs: &mut Fs<S>, kid: u8) -> Sw {
    run(
        app,
        fs,
        CLA_PROPRIETARY,
        INS_UNWRAP_KEY,
        kid,
        UNWRAP_FROM_STAGING,
        &[],
    )
    .0
}

/// Write `blob` to `2F10` the way the driver does, with UPDATE BINARY.
fn stage<S: Storage>(app: &mut HsmApplet, fs: &mut Fs<S>, blob: &[u8]) {
    let mut d = vec![0x54, 2, 0, 0, 0x53];
    match blob.len() {
        n @ 0..=0x7F => d.push(n as u8),
        n @ 0x80..=0xFF => d.extend_from_slice(&[0x81, n as u8]),
        n => d.extend_from_slice(&[&[0x82][..], &(n as u16).to_be_bytes()].concat()),
    }
    d.extend_from_slice(blob);
    let [hi, lo] = FID_STAGING.to_be_bytes();
    assert_eq!(
        run(app, fs, CLA_ISO, INS_UPDATE_BINARY_ODD, hi, lo, &d).0,
        Sw::OK
    );
}

fn restore<S: Storage>(app: &mut HsmApplet, fs: &mut Fs<S>, blob: &[u8], kid: u8) -> Sw {
    stage(app, fs, blob);
    unwrap(app, fs, kid)
}

fn load<S: Storage>(app: &HsmApplet, fs: &mut Fs<S>, kid: u8) -> KeyObject {
    let hmk = app.sess.hmk.clone().unwrap();
    keys::load(fs, &hmk, kid).unwrap().unwrap()
}

fn put_key<S: Storage>(app: &HsmApplet, fs: &mut Fs<S>, kid: u8, obj: &KeyObject) {
    let hmk = app.sess.hmk.clone().unwrap();
    keys::store(fs, &hmk, kid, obj, &mut TestRng(5)).unwrap();
}

/// An EC key at `kid` on `d`, with `extra` objects; returns its public point.
fn ec_at<S: Storage>(
    app: &mut HsmApplet,
    fs: &mut Fs<S>,
    kid: u8,
    d: &Domain,
    extra: &[u8],
) -> Vec<u8> {
    let mut tpl = ec_template(d);
    tpl.extend_from_slice(extra);
    let (sw, resp) = generate(app, fs, kid, &tpl);
    assert_eq!(sw, Sw::OK);
    let body = get(
        get(get(&resp, TAG_CV_AUTH_REQUEST), TAG_CV_CERT),
        TAG_CV_BODY,
    );
    get(get(body, TAG_CV_PUBKEY), TAG_PK_POINT).to_vec()
}

/// `key` handed in at `kid` the way the wiring's prime search would.
fn rsa_at<S: Storage>(app: &mut HsmApplet, fs: &mut Fs<S>, kid: u8, key: &RsaKey) {
    let raw = apdu(
        CLA_ISO,
        INS_GENERATE_KEYPAIR,
        kid,
        0,
        &rsa_template(8 * key.size() as u16),
    );
    let mut out = [0u8; 2036];
    let mut res = ResBuf::new(&mut out);
    assert_eq!(
        app.rsa_keygen_finish(fs, &Apdu::parse(&raw).unwrap(), key, &mut res),
        Sw::OK
    );
}

fn frozen_rsa() -> RsaKey {
    rsa_from_pqe(&[1, 0, 1], &hex(P_HEX), &hex(Q_HEX)).unwrap()
}

/// Raw RSA with key `kid`: deterministic, so two keys answer alike only if they
/// are the same key.
fn raw_rsa<S: Storage>(app: &mut HsmApplet, fs: &mut Fs<S>, kid: u8, len: usize) -> Vec<u8> {
    let block: Vec<u8> = (0..len).map(|i| if i == 0 { 0 } else { i as u8 }).collect();
    let (sw, out) = run(
        app,
        fs,
        CLA_PROPRIETARY,
        INS_SIGN,
        kid,
        ALGO_RSA_RAW,
        &block,
    );
    assert_eq!(sw, Sw::OK);
    out
}

// ---- The blob, read and written here from the format's own description ----

fn label_key(dkek: &[u8; 32], label: u8) -> [u8; 32] {
    let mut m = dkek.to_vec();
    m.extend_from_slice(&[0, 0, 0, label]);
    sha256(&m)
}

fn field(v: &[u8]) -> Vec<u8> {
    let mut f = (v.len() as u16).to_be_bytes().to_vec();
    f.extend_from_slice(v);
    f
}

/// `size ‖ fields`, each field length-prefixed: the part after the nonce.
fn key_part(size: u16, fields: &[&[u8]]) -> Vec<u8> {
    let mut p = size.to_be_bytes().to_vec();
    for f in fields {
        p.extend(field(f));
    }
    p
}

/// A blob around `part`, sealed under `dkek` as the format says.
fn seal_blob(dkek: &[u8; 32], kind: u8, oid: &[u8], algos: &[u8], part: &[u8]) -> Vec<u8> {
    let mut plain = vec![0xEE; NONCE_LEN];
    plain.extend_from_slice(part);
    if !plain.len().is_multiple_of(16) {
        plain.push(0x80);
        plain.resize(plain.len().next_multiple_of(16), 0);
    }
    aes_encrypt(&label_key(dkek, 1), &[0; 16], Mode::Cbc, &mut plain).unwrap();
    let mut b = sha256(dkek)[..8].to_vec();
    b.push(kind);
    for f in [oid, algos, &[], &[]] {
        b.extend(field(f));
    }
    b.extend(plain);
    let mac = crate::cmac::aes_cmac(&label_key(dkek, 2), &b).unwrap();
    b.extend_from_slice(&mac);
    b
}

/// A blob opened and checked field by field: its type, OID, algorithm list, and
/// the decrypted part after the nonce, padding removed.
struct Opened {
    kind: u8,
    oid: Vec<u8>,
    algos: Vec<u8>,
    part: Vec<u8>,
}

fn open_blob(dkek: &[u8; 32], blob: &[u8]) -> Opened {
    assert_eq!(blob[..8], sha256(dkek)[..8], "KCV");
    let (body, mac) = blob.split_at(blob.len() - 16);
    assert_eq!(
        crate::cmac::aes_cmac(&label_key(dkek, 2), body).unwrap(),
        mac
    );
    let mut at = 9;
    let mut next = || {
        let n = u16::from_be_bytes([body[at], body[at + 1]]) as usize;
        let v = body[at + 2..at + 2 + n].to_vec();
        at += 2 + n;
        v
    };
    let (oid, algos) = (next(), next());
    assert!(
        next().is_empty() && next().is_empty(),
        "access conditions, key OID"
    );
    let mut plain = body[at..].to_vec();
    assert_eq!(plain.len() % 16, 0);
    aes_decrypt(&label_key(dkek, 1), &[0; 16], Mode::Cbc, &mut plain).unwrap();
    Opened {
        kind: body[8],
        oid,
        algos,
        part: plain[NONCE_LEN..].to_vec(),
    }
}

/// The fields of a decrypted part: `size`, then each length-prefixed field, then
/// the padding — `80 00…` exactly when the part was not block-aligned.
fn fields_of(part: &[u8], count: usize) -> (u16, Vec<Vec<u8>>) {
    let size = u16::from_be_bytes([part[0], part[1]]);
    let mut at = 2;
    let mut out = Vec::new();
    for _ in 0..count {
        let n = u16::from_be_bytes([part[at], part[at + 1]]) as usize;
        out.push(part[at + 2..at + 2 + n].to_vec());
        at += 2 + n;
    }
    let pad = &part[at..];
    if (NONCE_LEN + at).is_multiple_of(16) {
        assert!(pad.is_empty());
    } else {
        assert_eq!(pad[0], 0x80);
        assert!(pad[1..].iter().all(|&b| b == 0));
    }
    (size, out)
}

fn strip(v: &[u8]) -> &[u8] {
    &v[v.iter().position(|&b| b != 0).unwrap_or(v.len())..]
}

#[test]
fn every_key_type_survives_a_wrap_and_an_unwrap() {
    let env = Env::new();
    let (mut app, mut fs) = with_shares(&env, &[S1, S2]);
    for (kid, d) in (1u8..).zip(ALL) {
        let point = ec_at(&mut app, &mut fs, kid, d, &[]);
        let (sw, blob) = wrap(&mut app, &mut fs, kid);
        assert_eq!(sw, Sw::OK);
        assert_eq!(restore(&mut app, &mut fs, &blob, kid + 100), Sw::OK);
        let (a, b) = (load(&app, &mut fs, kid), load(&app, &mut fs, kid + 100));
        assert_eq!((a.ty, a.material()), (b.ty, b.material()));
        assert_eq!(b.counter, COUNTER_UNLIMITED);
        // The restored key signs for the original's public point.
        let digest = vec![0x5Au8; d.field_len().min(64)];
        let (sw, der) = run(
            &mut app,
            &mut fs,
            CLA_PROPRIETARY,
            INS_SIGN,
            kid + 100,
            ALGO_EC_RAW,
            &digest,
        );
        assert_eq!(sw, Sw::OK);
        let raw = der_to_raw(&der, d.field_len());
        assert!(
            ecdsa_verifies(d.curve, &point, &digest, &raw),
            "{:?}",
            d.curve
        );
    }
    rsa_at(&mut app, &mut fs, 10, &frozen_rsa());
    let (sw, blob) = wrap(&mut app, &mut fs, 10);
    assert_eq!(sw, Sw::OK);
    assert_eq!(restore(&mut app, &mut fs, &blob, 110), Sw::OK);
    assert_eq!(load(&app, &mut fs, 110).ty, KeyType::Rsa(RsaSize::R2048));
    assert_eq!(
        raw_rsa(&mut app, &mut fs, 110, 256),
        raw_rsa(&mut app, &mut fs, 10, 256)
    );
    for (kid, p2) in [(20u8, AES_128), (21, AES_192), (22, AES_256)] {
        assert_eq!(
            run(
                &mut app,
                &mut fs,
                CLA_ISO,
                INS_GENERATE_SYMMETRIC,
                kid,
                p2,
                &[]
            )
            .0,
            Sw::OK
        );
        let (sw, blob) = wrap(&mut app, &mut fs, kid);
        assert_eq!(sw, Sw::OK);
        assert_eq!(restore(&mut app, &mut fs, &blob, kid + 100), Sw::OK);
        let (a, b) = (load(&app, &mut fs, kid), load(&app, &mut fs, kid + 100));
        assert_eq!((a.ty, a.material()), (b.ty, b.material()));
    }
}

#[test]
fn a_backup_restores_on_another_device_holding_the_same_shares() {
    let env = Env::new();
    let (mut a, mut fs_a) = with_shares(&env, &[S1, S2]);
    let (mut b, mut fs_b) = with_shares(&env, &[S1, S2]);
    let point = ec_at(&mut a, &mut fs_a, 1, &P384, &[]);
    let (_, blob) = wrap(&mut a, &mut fs_a, 1);
    assert_eq!(restore(&mut b, &mut fs_b, &blob, 1), Sw::OK);
    assert_eq!(
        load(&a, &mut fs_a, 1).material(),
        load(&b, &mut fs_b, 1).material()
    );
    let digest = [7u8; 48];
    let (_, der) = run(
        &mut b,
        &mut fs_b,
        CLA_PROPRIETARY,
        INS_SIGN,
        1,
        ALGO_EC_RAW,
        &digest,
    );
    assert!(ecdsa_verifies(
        rsk_ec::Curve::P384,
        &point,
        &digest,
        &der_to_raw(&der, 48)
    ));
    // A device whose shares differ refuses it, and is left without the key.
    let (mut c, mut fs_c) = with_shares(&env, &[S1, S1]);
    assert_eq!(restore(&mut c, &mut fs_c, &blob, 1), Sw::WRONG_DATA);
    assert!(!keys::exists(&mut fs_c, 1).unwrap());
}

#[test]
fn the_blob_is_the_documented_format() {
    let env = Env::new();
    let dkek = dkek_of(&[S1, S2]);
    let (mut app, mut fs) = with_shares(&env, &[S1, S2]);

    let algos = [ALGO_AES_CMAC, ALGO_WRAP];
    let aes = KeyObject::new(KeyType::Aes(AesSize::A128), 9, &algos, &[0x42; 16]).unwrap();
    put_key(&app, &mut fs, 1, &aes);
    let o = open_blob(&dkek, &wrap(&mut app, &mut fs, 1).1);
    assert_eq!(
        (o.kind, &o.oid[..], &o.algos[..]),
        (15, OID_AES, &algos[..])
    );
    // `size ‖ key`, no prefix on the key; 8 + 2 + 16 is not block-aligned.
    assert_eq!(&o.part[..18], &[&[0, 16][..], &[0x42; 16]].concat()[..]);
    assert_eq!(o.part[18], 0x80);
    assert!(o.part[19..].iter().all(|&b| b == 0));

    let point = ec_at(
        &mut app,
        &mut fs,
        2,
        &P256,
        &[0x91, 2, ALGO_EC_SHA256, ALGO_WRAP],
    );
    let o = open_blob(&dkek, &wrap(&mut app, &mut fs, 2).1);
    assert_eq!(
        (o.kind, o.oid, o.algos),
        (
            12,
            SigAlg::EcdsaSha256.oid().to_vec(),
            vec![ALGO_EC_SHA256, ALGO_WRAP]
        )
    );
    let (bits, f) = fields_of(&o.part, 7);
    assert_eq!(bits, 256);
    for (got, want) in f.iter().zip([P256.a, P256.b, P256.p, P256.n]) {
        assert_eq!(&got[..], strip(want));
    }
    assert_eq!(f[4], P256.g);
    assert_eq!(f[5], load(&app, &mut fs, 2).material(), "full width");
    assert_eq!(f[6], point);

    rsa_at(&mut app, &mut fs, 3, &frozen_rsa());
    let blob = wrap(&mut app, &mut fs, 3).1;
    let o = open_blob(&dkek, &blob);
    assert_eq!((o.kind, o.oid), (5, SigAlg::RsaV15Sha256.oid().to_vec()));
    let (bits, f) = fields_of(&o.part, 3);
    assert_eq!(
        (bits, &f[1][..], &f[2][..]),
        (2048, &hex(N_HEX)[..], &[1, 0, 1][..])
    );
    // `d` inverts the public exponent: (m^e)^d = m.
    let n = BigUint::from_bytes_be(&hex(N_HEX));
    let m = BigUint::from(0xC0FFEEu32);
    let c = m.modpow(&BigUint::from(65_537u32), &n);
    assert_eq!(c.modpow(&BigUint::from_bytes_be(&f[0]), &n), m);
    assert_ne!(f[0][0], 0, "minimal");
}

#[test]
fn the_largest_export_fits_the_drivers_buffer() {
    // The driver reads a WRAP KEY answer into 1500 bytes; RSA-4096 is the most.
    let env = Env::new();
    let (mut app, mut fs) = with_shares(&env, &[S1]);
    let key = rsk_rsa::generate_rsa(&mut RsaRng(&mut TestRng(11)), 4096).unwrap();
    rsa_at(&mut app, &mut fs, 1, &key);
    let (sw, blob) = wrap(&mut app, &mut fs, 1);
    assert_eq!(sw, Sw::OK);
    assert!(blob.len() <= 1500, "{} bytes", blob.len());
    assert_eq!(restore(&mut app, &mut fs, &blob, 2), Sw::OK);
    assert_eq!(
        raw_rsa(&mut app, &mut fs, 2, 512),
        raw_rsa(&mut app, &mut fs, 1, 512)
    );
}

#[test]
fn blobs_written_elsewhere_are_restored() {
    let env = Env::new();
    let dkek = dkek_of(&[S1, S2]);
    let (mut app, mut fs) = with_shares(&env, &[S1, S2]);
    let ec_oid = SigAlg::EcdsaSha256.oid();
    let rsa_oid = SigAlg::RsaV15Sha256.oid();

    // EC with no public point, and a list naming SHA-1 this device lacks: the
    // point is derived, and the list keeps what it can honour.
    let scalar = [0x11u8; 32];
    let part = key_part(
        256,
        &[strip(P256.a), P256.b, P256.p, P256.n, P256.g, &scalar, &[]],
    );
    let blob = seal_blob(&dkek, 12, &ec_oid, &[0x71, ALGO_EC_SHA256], &part);
    assert_eq!(restore(&mut app, &mut fs, &blob, 1), Sw::OK);
    let k = load(&app, &mut fs, 1);
    assert_eq!(
        (k.material(), k.algos()),
        (&scalar[..], &[ALGO_EC_SHA256][..])
    );

    // A short scalar, as an encoder writing minimal integers sends it.
    let mut short = [0u8; 32];
    short[31] = 9;
    let part = key_part(256, &[P256.a, P256.b, P256.p, P256.n, P256.g, &[9], &[]]);
    assert_eq!(
        restore(
            &mut app,
            &mut fs,
            &seal_blob(&dkek, 12, &ec_oid, &[], &part),
            2
        ),
        Sw::OK
    );
    assert_eq!(load(&app, &mut fs, 2).material(), short);

    // RSA in the CRT form: dP, dQ, P, qInv, Q, N, E.
    let key = frozen_rsa();
    let (p, q) = (
        BigUint::from_bytes_be(&hex(P_HEX)),
        BigUint::from_bytes_be(&hex(Q_HEX)),
    );
    let d = BigUint::from_bytes_be(&key.d_be());
    let one = BigUint::from(1u8);
    let dp = (&d % (&p - &one)).to_bytes_be();
    let dq = (&d % (&q - &one)).to_bytes_be();
    let qinv = q.modpow(&(&p - BigUint::from(2u8)), &p).to_bytes_be();
    let part = key_part(
        2048,
        &[
            &dp,
            &dq,
            &hex(P_HEX),
            &qinv,
            &hex(Q_HEX),
            &hex(N_HEX),
            &[1, 0, 1],
        ],
    );
    assert_eq!(
        restore(
            &mut app,
            &mut fs,
            &seal_blob(&dkek, 6, &rsa_oid, &[], &part),
            3
        ),
        Sw::OK
    );
    rsa_at(&mut app, &mut fs, 4, &key);
    assert_eq!(
        raw_rsa(&mut app, &mut fs, 3, 256),
        raw_rsa(&mut app, &mut fs, 4, 256)
    );
}

#[test]
fn a_blob_altered_anywhere_is_refused_before_it_is_read() {
    let env = Env::new();
    let (mut app, mut fs) = with_shares(&env, &[S1, S2]);
    ec_at(
        &mut app,
        &mut fs,
        1,
        &K256,
        &[0x91, 2, ALGO_EC_SHA256, ALGO_WRAP],
    );
    let (_, blob) = wrap(&mut app, &mut fs, 1);
    for at in [
        0,
        7,
        8,
        10,
        20,
        24,
        blob.len() - 40,
        blob.len() - 17,
        blob.len() - 1,
    ] {
        let mut bad = blob.clone();
        bad[at] ^= 0x01;
        assert_eq!(
            restore(&mut app, &mut fs, &bad, 2),
            Sw::WRONG_DATA,
            "byte {at}"
        );
    }
    for len in [1, 8, HEAD_LEN + MAC_LEN - 1, blob.len() - 1] {
        assert_eq!(
            restore(&mut app, &mut fs, &blob[..len], 2),
            Sw::WRONG_DATA,
            "{len} bytes"
        );
    }
    let mut longer = blob.clone();
    longer.push(0);
    assert_eq!(restore(&mut app, &mut fs, &longer, 2), Sw::WRONG_DATA);
    assert!(!keys::exists(&mut fs, 2).unwrap());
    assert_eq!(restore(&mut app, &mut fs, &blob, 2), Sw::OK);
}

#[test]
fn a_well_sealed_blob_still_has_to_hold_a_key_this_device_keeps() {
    let env = Env::new();
    let dkek = dkek_of(&[S1, S2]);
    let (mut app, mut fs) = with_shares(&env, &[S1, S2]);
    let ec_oid = SigAlg::EcdsaSha256.oid();
    let rsa_oid = SigAlg::RsaV15Sha256.oid();
    let ec =
        |d: &Domain, scalar: &[u8], q: &[u8]| key_part(256, &[d.a, d.b, d.p, d.n, d.g, scalar, q]);
    let order = P256.n.to_vec();
    // A sound key, but with an exponent other than the one this device keeps.
    let d3 = {
        use num_bigint_dig::ModInverse;
        let one = BigUint::from(1u8);
        let p = BigUint::from_bytes_be(&hex(P_HEX));
        let q = BigUint::from_bytes_be(&hex(Q_HEX));
        let phi = (&p - &one) * (&q - &one);
        let d = BigUint::from(3u8).mod_inverse(&phi).unwrap();
        d.to_biguint().unwrap().to_bytes_be()
    };
    let mut other_point = vec![0x04];
    other_point.extend_from_slice(&[0x01; 64]);
    let bad: Vec<(&str, Vec<u8>)> = vec![
        (
            "unknown type",
            seal_blob(&dkek, 7, &ec_oid, &[], &ec(&P256, &[1], &[])),
        ),
        (
            "EC under the RSA OID",
            seal_blob(&dkek, 12, &rsa_oid, &[], &ec(&P256, &[1], &[])),
        ),
        (
            "AES under the EC OID",
            seal_blob(&dkek, 15, &ec_oid, &[], &key_part(16, &[])),
        ),
        (
            "a curve not kept here",
            seal_blob(
                &dkek,
                12,
                &ec_oid,
                &[],
                &key_part(
                    256,
                    &[P256.a, P256.b, &[0xFF; 32], P256.n, P256.g, &[1], &[]],
                ),
            ),
        ),
        (
            "parameters of two curves",
            seal_blob(
                &dkek,
                12,
                &ec_oid,
                &[],
                &key_part(256, &[P256.a, K256.b, P256.p, P256.n, P256.g, &[1], &[]]),
            ),
        ),
        (
            "a zero scalar",
            seal_blob(&dkek, 12, &ec_oid, &[], &ec(&P256, &[0], &[])),
        ),
        (
            "the order as scalar",
            seal_blob(&dkek, 12, &ec_oid, &[], &ec(&P256, &order, &[])),
        ),
        (
            "a scalar too wide",
            seal_blob(&dkek, 12, &ec_oid, &[], &ec(&P256, &[1; 33], &[])),
        ),
        (
            "someone else's point",
            seal_blob(&dkek, 12, &ec_oid, &[], &ec(&P256, &[1], &other_point)),
        ),
        (
            "only SHA-1 allowed",
            seal_blob(&dkek, 12, &ec_oid, &[0x71], &ec(&P256, &[1], &[])),
        ),
        (
            "too long a list",
            seal_blob(
                &dkek,
                12,
                &ec_oid,
                &[ALGO_EC_SHA256; 17],
                &ec(&P256, &[1], &[]),
            ),
        ),
        (
            "a field cut short",
            seal_blob(
                &dkek,
                12,
                &ec_oid,
                &[],
                &key_part(256, &[P256.a, P256.b])[..40],
            ),
        ),
        (
            "a 512-bit AES key",
            seal_blob(&dkek, 15, OID_AES, &[], &[&[0, 64][..], &[1; 64]].concat()),
        ),
        (
            "an AES key cut short",
            seal_blob(&dkek, 15, OID_AES, &[], &[&[0, 32][..], &[1; 16]].concat()),
        ),
        (
            "RSA with e = 3",
            seal_blob(
                &dkek,
                5,
                &rsa_oid,
                &[],
                &key_part(2048, &[&d3, &hex(N_HEX), &[3]]),
            ),
        ),
        (
            "RSA with e = 3, CRT form",
            seal_blob(
                &dkek,
                6,
                &rsa_oid,
                &[],
                &key_part(
                    2048,
                    &[
                        &[1],
                        &[1],
                        &hex(P_HEX),
                        &[1],
                        &hex(Q_HEX),
                        &hex(N_HEX),
                        &[3],
                    ],
                ),
            ),
        ),
        (
            "RSA with a wrong d",
            seal_blob(
                &dkek,
                5,
                &rsa_oid,
                &[],
                &key_part(2048, &[&[5; 256], &hex(N_HEX), &[1, 0, 1]]),
            ),
        ),
        ("RSA-1024", {
            let k = rsa_from_pqe(&[1, 0, 1], &hex(P1024_HEX), &hex(Q1024_HEX)).unwrap();
            seal_blob(
                &dkek,
                5,
                &rsa_oid,
                &[],
                &key_part(1024, &[&k.d_be(), &hex(N1024_HEX), &[1, 0, 1]]),
            )
        }),
        (
            "CRT primes that are not N's",
            seal_blob(
                &dkek,
                6,
                &rsa_oid,
                &[],
                &key_part(
                    2048,
                    &[
                        &[1],
                        &[1],
                        &hex(P_HEX),
                        &[1],
                        &hex(Q_HEX),
                        &hex(N1024_HEX),
                        &[1, 0, 1],
                    ],
                ),
            ),
        ),
    ];
    for (what, blob) in bad {
        assert_eq!(
            restore(&mut app, &mut fs, &blob, 1),
            Sw::WRONG_DATA,
            "{what}"
        );
    }
    assert!(!keys::exists(&mut fs, 1).unwrap());
    // Sealed by this test's own encoder, a good one opens: the refusals above
    // are the contents', not the encoder's.
    let good = seal_blob(&dkek, 12, &ec_oid, &[], &ec(&P256, &[1], &[]));
    assert_eq!(restore(&mut app, &mut fs, &good, 1), Sw::OK);
}

#[test]
fn a_key_whose_list_leaves_out_wrap_never_leaves() {
    let env = Env::new();
    let (mut app, mut fs) = with_shares(&env, &[S1]);
    ec_at(&mut app, &mut fs, 1, &P256, &[0x91, 1, ALGO_EC_SHA256]);
    assert_eq!(wrap(&mut app, &mut fs, 1).0, Sw::CONDITIONS_NOT_SATISFIED);
    ec_at(
        &mut app,
        &mut fs,
        2,
        &P256,
        &[0x91, 2, ALGO_EC_SHA256, ALGO_WRAP],
    );
    let (sw, blob) = wrap(&mut app, &mut fs, 2);
    assert_eq!(sw, Sw::OK);
    assert_eq!(restore(&mut app, &mut fs, &blob, 3), Sw::OK);
    assert_eq!(load(&app, &mut fs, 3).algos(), [ALGO_EC_SHA256, ALGO_WRAP]);
    // The permission is not an operation.
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            CLA_PROPRIETARY,
            INS_SIGN,
            2,
            ALGO_WRAP,
            &[0; 32]
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
            2,
            ALGO_WRAP,
            &[0; 32]
        )
        .0,
        Sw::INCORRECT_P1P2
    );
}

#[test]
fn wrap_and_unwrap_check_their_framing_and_their_preconditions() {
    let env = Env::new();
    let (mut app, mut fs) = with_shares(&env, &[S1]);
    ec_at(&mut app, &mut fs, 1, &P521, &[]);
    let (_, blob) = wrap(&mut app, &mut fs, 1);
    let cmd = |ins, p1, p2, d: &[u8]| apdu(CLA_PROPRIETARY, ins, p1, p2, d);
    for (raw, sw) in [
        (cmd(INS_WRAP_KEY, 1, 0x93, &[]), Sw::INCORRECT_P1P2),
        (cmd(INS_WRAP_KEY, 1, WRAP_WITH_DKEK, &[1]), Sw::WRONG_LENGTH),
        (
            cmd(INS_WRAP_KEY, KEY_ID_DEVICE, WRAP_WITH_DKEK, &[]),
            Sw::SECURITY_STATUS_NOT_SATISFIED,
        ),
        (
            cmd(INS_WRAP_KEY, 9, WRAP_WITH_DKEK, &[]),
            Sw::FILE_NOT_FOUND,
        ),
        (cmd(INS_UNWRAP_KEY, 2, 0x92, &[]), Sw::INCORRECT_P1P2),
        (
            cmd(INS_UNWRAP_KEY, 2, UNWRAP_FROM_STAGING, &blob),
            Sw::WRONG_LENGTH,
        ),
        (
            cmd(INS_UNWRAP_KEY, KEY_ID_DEVICE, UNWRAP_FROM_STAGING, &[]),
            Sw::SECURITY_STATUS_NOT_SATISFIED,
        ),
        (
            cmd(INS_UNWRAP_KEY, 2, UNWRAP_FROM_STAGING, &[]),
            Sw::FILE_NOT_FOUND,
        ),
        (
            apdu(CLA_ISO, INS_WRAP_KEY, 1, WRAP_WITH_DKEK, &[]),
            Sw::CLA_NOT_SUPPORTED,
        ),
    ] {
        assert_eq!(run_raw(&mut app, &mut fs, &raw).0, sw, "{raw:02x?}");
    }
    stage(&mut app, &mut fs, &blob);
    assert_eq!(unwrap(&mut app, &mut fs, 1), Sw::FILE_EXISTS);
    // Staged but logged out.
    select(&mut app, &mut fs);
    assert_eq!(
        wrap(&mut app, &mut fs, 1).0,
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    assert_eq!(
        unwrap(&mut app, &mut fs, 2),
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    assert_eq!(verify(&mut app, &mut fs, PIN), Sw::OK);
    assert_eq!(unwrap(&mut app, &mut fs, 2), Sw::OK);
}

#[test]
fn a_staged_blob_larger_than_any_key_is_refused_unread() {
    let env = Env::new();
    let (mut app, mut fs) = with_shares(&env, &[S1]);
    assert_eq!(
        restore(&mut app, &mut fs, &[0; BLOB_MAX + 1], 1),
        Sw::WRONG_DATA
    );
}

#[test]
fn without_a_complete_dkek_nothing_is_wrapped_or_unwrapped() {
    let env = Env::new();
    // No DKEK at all: the device was initialized without the `92` object.
    let mut fs = new_fs();
    let mut app = env.applet(None);
    logged_in(&mut app, &mut fs);
    ec_at(&mut app, &mut fs, 1, &P256, &[]);
    assert_eq!(wrap(&mut app, &mut fs, 1).0, Sw::REFERENCE_NOT_FOUND);
    stage(&mut app, &mut fs, &[0; 64]);
    assert_eq!(unwrap(&mut app, &mut fs, 2), Sw::REFERENCE_NOT_FOUND);

    // Shares still owed.
    let mut fs = new_fs();
    let mut app = env.applet(None);
    provision_with(&mut fs, None).unwrap();
    select(&mut app, &mut fs);
    let mut d = init_data(OPT_RRC, PIN, &SO_PIN, None);
    d.extend_from_slice(&[0x92, 1, 2]);
    assert_eq!(
        run(&mut app, &mut fs, CLA_PROPRIETARY, INS_INITIALIZE, 0, 0, &d).0,
        Sw::OK
    );
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            CLA_PROPRIETARY,
            INS_KEY_DOMAIN,
            0,
            0,
            &S1
        )
        .0,
        Sw::OK
    );
    assert_eq!(verify(&mut app, &mut fs, PIN), Sw::OK);
    stage(&mut app, &mut fs, &[0; 64]);
    assert_eq!(unwrap(&mut app, &mut fs, 2), Sw::CONDITIONS_NOT_SATISFIED);
    assert_eq!(wrap(&mut app, &mut fs, 1).0, Sw::CONDITIONS_NOT_SATISFIED);
}

#[test]
fn a_locked_device_neither_wraps_nor_unwraps() {
    let env = Env::new();
    let (mut app, mut fs) = with_shares(&env, &[S1]);
    ec_at(&mut app, &mut fs, 1, &P256, &[]);
    let (_, blob) = wrap(&mut app, &mut fs, 1);
    stage(&mut app, &mut fs, &blob);
    assert_eq!(arm(&mut app, &mut fs, &SECRET, &SO_PIN), Sw::OK);
    let mut app = env.applet(None);
    select(&mut app, &mut fs);
    assert_eq!(wrap(&mut app, &mut fs, 1).0, Sw::CONDITIONS_NOT_SATISFIED);
    assert_eq!(unwrap(&mut app, &mut fs, 2), Sw::CONDITIONS_NOT_SATISFIED);
    assert_eq!(unlock(&mut app, &mut fs, &SECRET), Sw::OK);
    assert_eq!(verify(&mut app, &mut fs, PIN), Sw::OK);
    assert_eq!(unwrap(&mut app, &mut fs, 2), Sw::OK);
}

#[test]
fn a_reinitialization_replaces_the_dkek() {
    let env = Env::new();
    let (mut app, mut fs) = with_shares(&env, &[S1]);
    ec_at(&mut app, &mut fs, 1, &P256, &[]);
    let (_, blob) = wrap(&mut app, &mut fs, 1);
    // Re-initialized with a random DKEK: the old backups no longer open here.
    let mut d = init_data(OPT_RRC, PIN, &SO_PIN, None);
    d.extend_from_slice(&[0x92, 1, 0]);
    assert_eq!(
        run(&mut app, &mut fs, CLA_PROPRIETARY, INS_INITIALIZE, 0, 0, &d).0,
        Sw::OK
    );
    assert_eq!(verify(&mut app, &mut fs, PIN), Sw::OK);
    assert_eq!(restore(&mut app, &mut fs, &blob, 1), Sw::WRONG_DATA);
    // And without the object, there is no DKEK left at all.
    let d = init_data(OPT_RRC, PIN, &SO_PIN, None);
    assert_eq!(
        run(&mut app, &mut fs, CLA_PROPRIETARY, INS_INITIALIZE, 0, 0, &d).0,
        Sw::OK
    );
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            CLA_PROPRIETARY,
            INS_KEY_DOMAIN,
            0,
            0,
            &[]
        )
        .0,
        Sw::REFERENCE_NOT_FOUND
    );
}

#[test]
fn the_family_oids_are_the_ones_a_blob_names() {
    let mut buf = [0u8; OID_LEN];
    assert_eq!(family_oid(BLOB_AES, &mut buf), Some(OID_AES));
    for kind in [BLOB_RSA, BLOB_RSA_CRT] {
        assert_eq!(
            family_oid(kind, &mut buf),
            Some(&[0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x02, 0x01, 0x02][..])
        );
    }
    assert_eq!(
        family_oid(BLOB_EC, &mut buf),
        Some(&[0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x02, 0x02, 0x03][..])
    );
    assert_eq!(family_oid(7, &mut buf), None);
}
