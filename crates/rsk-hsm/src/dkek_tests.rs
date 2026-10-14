// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::store::REC_DKEK;
use crate::tests::*;
use rsk_fs::storage::ram::RamStorage;

const DK: [u8; KEY_LEN] = [0x4D; KEY_LEN];
const SHARE_A: [u8; DKEK_SHARE_LEN] = [0xA5; DKEK_SHARE_LEN];
const SHARE_B: [u8; DKEK_SHARE_LEN] = [0x0F; DKEK_SHARE_LEN];

fn xor(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    core::array::from_fn(|i| a[i] ^ b[i])
}

fn kcv_of(v: &[u8; 32]) -> Vec<u8> {
    sha256(v)[..DKEK_KCV_LEN].to_vec()
}

/// `total ‖ outstanding ‖ KCV`, as MANAGE KEY DOMAIN answers it.
fn status_of(total: u8, outstanding: u8, value: &[u8; 32]) -> Vec<u8> {
    let mut s = vec![total, outstanding];
    s.extend_from_slice(&kcv_of(value));
    s
}

fn manage<S: Storage>(
    app: &mut HsmApplet,
    fs: &mut Fs<S>,
    p1: u8,
    p2: u8,
    d: &[u8],
) -> (Sw, Vec<u8>) {
    run(app, fs, CLA_PROPRIETARY, INS_KEY_DOMAIN, p1, p2, d)
}

/// A device initialized for `shares` DKEK shares (`0`: a random DKEK), the user
/// PIN verified.
fn with_dkek<S: Storage>(app: &mut HsmApplet, fs: &mut Fs<S>, shares: u8) {
    provision_with(fs, None).unwrap();
    select(app, fs);
    let mut d = init_data(OPT_RRC, PIN, &SO_PIN, None);
    d.extend_from_slice(&[0x92, 1, shares]);
    assert_eq!(
        run(app, fs, CLA_PROPRIETARY, INS_INITIALIZE, 0, 0, &d).0,
        Sw::OK
    );
    assert_eq!(verify(app, fs, PIN), Sw::OK);
}

#[test]
fn shares_combine_by_xor_and_the_kcv_follows_the_sum() {
    let mut d = Dkek::awaiting(2);
    assert!(!d.complete() && d.key().is_none());
    assert_eq!(d.kcv().to_vec(), kcv_of(&[0; 32]));
    d.import(&SHARE_A);
    assert!(d.key().is_none());
    assert_eq!(d.kcv().to_vec(), kcv_of(&SHARE_A));
    d.import(&SHARE_B);
    assert_eq!(**d.key().unwrap(), xor(&SHARE_A, &SHARE_B));
    assert_eq!(d.kcv().to_vec(), kcv_of(&xor(&SHARE_A, &SHARE_B)));
}

#[test]
fn a_random_dkek_is_complete_from_the_start() {
    let d = Dkek::random(&mut TestRng(3));
    assert_eq!((d.total, d.imported), (1, 1));
    assert_ne!(**d.key().unwrap(), [0; 32]);
    assert_ne!(
        **d.key().unwrap(),
        **Dkek::random(&mut TestRng(4)).key().unwrap()
    );
}

#[test]
fn the_record_opens_under_its_dk_with_its_header_intact() {
    let mut fs = new_fs();
    assert!(load(&mut fs, &DK).unwrap().is_none());
    assert!(!pending(&mut fs).unwrap());
    let mut d = Dkek::awaiting(3);
    d.import(&SHARE_A);
    store(&mut fs, &DK, &d, &mut TestRng(1)).unwrap();
    assert!(pending(&mut fs).unwrap());
    let back = load(&mut fs, &DK).unwrap().unwrap();
    assert_eq!((back.total, back.imported), (3, 1));
    assert_eq!(back.kcv(), d.kcv());
    assert_eq!(
        load(&mut fs, &[0x4E; KEY_LEN]).err(),
        Some(Sw::MEMORY_FAILURE),
        "another device's DK"
    );

    // The header is bound into the seal: claiming a share imported fails it.
    let mut rec = [0u8; RECORD_LEN];
    let n = read_sealed(&mut fs, REC_DKEK, &mut rec).unwrap().unwrap();
    rec[2] = 3;
    fs.put_key(REC_DKEK, Sealed::wrap(&rec[..n])).unwrap();
    assert!(!pending(&mut fs).unwrap(), "the clear header alone says so");
    assert_eq!(load(&mut fs, &DK).err(), Some(Sw::MEMORY_FAILURE));
}

#[test]
fn a_header_no_build_wrote_is_a_memory_failure() {
    let mut fs = new_fs();
    store(&mut fs, &DK, &Dkek::awaiting(2), &mut TestRng(1)).unwrap();
    let mut good = [0u8; RECORD_LEN];
    read_sealed(&mut fs, REC_DKEK, &mut good).unwrap().unwrap();
    type Edit = fn(&mut Vec<u8>);
    let edits: [(&str, Edit); 4] = [
        ("version", |r| r[0] = 2),
        ("no shares", |r| r[1] = 0),
        ("more imported than owed", |r| r[2] = 3),
        ("truncated", |r| {
            r.pop();
        }),
    ];
    for (what, edit) in edits {
        let mut rec = good.to_vec();
        edit(&mut rec);
        fs.put_key(REC_DKEK, Sealed::wrap(&rec)).unwrap();
        assert_eq!(pending(&mut fs).err(), Some(Sw::MEMORY_FAILURE), "{what}");
        assert_eq!(load(&mut fs, &DK).err(), Some(Sw::MEMORY_FAILURE), "{what}");
    }
}

#[test]
fn shares_are_imported_without_a_login_and_reported_as_they_go() {
    let env = Env::new();
    let mut fs = new_fs();
    let mut app = env.applet(None);
    with_dkek(&mut app, &mut fs, 2);
    // `sc-hsm-tool` imports shares straight after INITIALIZE, logged out.
    select(&mut app, &mut fs);
    assert_eq!(
        manage(&mut app, &mut fs, 0, 0, &[]),
        (Sw::OK, status_of(2, 2, &[0; 32]))
    );
    assert_eq!(
        manage(&mut app, &mut fs, 0, 0, &SHARE_A),
        (Sw::OK, status_of(2, 1, &SHARE_A))
    );
    // A power cycle keeps what is imported.
    let mut app = env.applet(None);
    select(&mut app, &mut fs);
    let both = xor(&SHARE_A, &SHARE_B);
    assert_eq!(
        manage(&mut app, &mut fs, 0, 0, &SHARE_B),
        (Sw::OK, status_of(2, 0, &both))
    );
    assert_eq!(
        manage(&mut app, &mut fs, 0, 0, &SHARE_A).0,
        Sw::COMMAND_NOT_ALLOWED,
        "a complete DKEK takes no more"
    );
    assert_eq!(
        manage(&mut app, &mut fs, 0, 0, &[]),
        (Sw::OK, status_of(2, 0, &both))
    );
}

#[test]
fn a_random_dkek_reports_complete_and_takes_no_share() {
    let env = Env::new();
    let mut fs = new_fs();
    let mut app = env.applet(None);
    with_dkek(&mut app, &mut fs, 0);
    let (sw, s) = manage(&mut app, &mut fs, 0, 0, &[]);
    assert_eq!((sw, &s[..2]), (Sw::OK, &[1, 0][..]));
    assert_eq!(s.len(), 2 + DKEK_KCV_LEN);
    assert_ne!(s[2..], kcv_of(&[0; 32]));
    assert_eq!(
        manage(&mut app, &mut fs, 0, 0, &SHARE_A).0,
        Sw::COMMAND_NOT_ALLOWED
    );
}

#[test]
fn manage_key_domain_checks_its_framing_and_the_device() {
    let env = Env::new();
    let mut fs = new_fs();
    let mut app = env.applet(None);
    select(&mut app, &mut fs);
    assert_eq!(
        manage(&mut app, &mut fs, 0, 1, &[]).0,
        Sw::INCORRECT_P1P2,
        "another key domain: the answer that ends the tool's domain walk"
    );
    assert_eq!(
        manage(&mut app, &mut fs, 0, 0, &[]).0,
        Sw::REFERENCE_NOT_FOUND
    );
    // Initialized without the `92` object: no DKEK, the tool lists it as empty.
    logged_in(&mut app, &mut fs);
    assert_eq!(
        manage(&mut app, &mut fs, 0, 0, &[]).0,
        Sw::REFERENCE_NOT_FOUND
    );
    assert_eq!(
        manage(&mut app, &mut fs, 0, 0, &SHARE_A).0,
        Sw::REFERENCE_NOT_FOUND
    );
    for p1 in [1, 2, 3, 4, 5, 6] {
        assert_eq!(manage(&mut app, &mut fs, p1, 0, &[]).0, Sw::INCORRECT_P1P2);
    }
    assert_eq!(
        manage(&mut app, &mut fs, 0, 0, &SHARE_A[..31]).0,
        Sw::WRONG_LENGTH
    );
    assert_eq!(
        manage(&mut app, &mut fs, 0, 0, &[0; 33]).0,
        Sw::WRONG_LENGTH
    );
    assert_eq!(
        run(&mut app, &mut fs, CLA_ISO, INS_KEY_DOMAIN, 0, 0, &[]).0,
        Sw::CLA_NOT_SUPPORTED
    );
}

#[test]
fn an_uninitialized_device_has_no_key_domain() {
    let env = Env::new();
    let mut fs = new_fs();
    let mut app = env.applet(None);
    select(&mut app, &mut fs);
    let (sw, _) = manage(&mut app, &mut fs, 0, 0, &[]);
    assert_eq!(sw, require_init(&mut fs).err().unwrap());
}

#[test]
fn a_locked_device_neither_reports_nor_takes_shares() {
    let env = Env::new();
    let mut fs = new_fs();
    let mut app = env.applet(None);
    with_dkek(&mut app, &mut fs, 2);
    assert_eq!(arm(&mut app, &mut fs, &SECRET, &SO_PIN), Sw::OK);
    let mut app = env.applet(None);
    select(&mut app, &mut fs);
    for share in [&[][..], &SHARE_A] {
        assert_eq!(
            manage(&mut app, &mut fs, 0, 0, share).0,
            Sw::CONDITIONS_NOT_SATISFIED
        );
    }
    assert_eq!(unlock(&mut app, &mut fs, &SECRET), Sw::OK);
    assert_eq!(
        manage(&mut app, &mut fs, 0, 0, &SHARE_A),
        (Sw::OK, status_of(2, 1, &SHARE_A))
    );
}

#[test]
fn no_key_is_made_while_shares_are_owed() {
    let env = Env::new();
    let mut fs: Fs<RamStorage> = new_fs();
    let mut app = env.applet(None);
    with_dkek(&mut app, &mut fs, 1);
    assert_eq!(
        generate(&mut app, &mut fs, 1, &ec_template(&crate::domain::P256)).0,
        Sw::CONDITIONS_NOT_SATISFIED
    );
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            CLA_ISO,
            INS_GENERATE_SYMMETRIC,
            2,
            AES_256,
            &[]
        )
        .0,
        Sw::CONDITIONS_NOT_SATISFIED
    );
    let raw = apdu(CLA_ISO, INS_GENERATE_KEYPAIR, 3, 0, &rsa_template(2048));
    assert_eq!(
        app.rsa_keygen_bits(&mut fs, &Apdu::parse(&raw).unwrap()),
        None
    );
    assert_eq!(manage(&mut app, &mut fs, 0, 0, &SHARE_A).0, Sw::OK);
    assert_eq!(
        generate(&mut app, &mut fs, 1, &ec_template(&crate::domain::P256)).0,
        Sw::OK
    );
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            CLA_ISO,
            INS_GENERATE_SYMMETRIC,
            2,
            AES_256,
            &[]
        )
        .0,
        Sw::OK
    );
}
