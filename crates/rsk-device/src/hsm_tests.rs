// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::tests::{Env, SERIAL_HASH, SERIAL_ID, TestRng, VendorBoard, apdu, select, sw};
use rsk_fs::storage::ram::RamStorage;
use rsk_hsm::HSM_AID;
use rsk_hsm::consts::*;
use std::vec::Vec;

type Hsm<'a> = HsmApplets<'a, RamStorage, TestRng, VendorBoard>;

const PIN: &[u8] = b"648219";
const SO_PIN: [u8; SO_PIN_LEN] = *b"35762188";
const SECRET: [u8; UNLOCK_SECRET_LEN] = [0xC3; UNLOCK_SECRET_LEN];

/// An APDU with extended lengths and `Le = 65536`, as OpenSC sends to a reader
/// that announces extended APDUs, so nothing is clipped or chained.
fn ext(cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8]) -> Vec<u8> {
    let mut raw = std::vec![cla, ins, p1, p2, 0];
    if !data.is_empty() {
        raw.extend_from_slice(&(data.len() as u16).to_be_bytes());
        raw.extend_from_slice(data);
    }
    raw.extend_from_slice(&[0, 0]);
    raw
}

/// Response body and status word.
fn run(hsm: &mut Hsm<'_>, raw: &[u8]) -> (Vec<u8>, Sw) {
    let res = hsm.handle_apdu(raw);
    (res[..res.len() - 2].to_vec(), sw(res))
}

fn initialize(hsm: &mut Hsm<'_>) {
    let mut d = std::vec![TAG_INIT_OPTIONS as u8, 2];
    d.extend_from_slice(&OPT_RRC.to_be_bytes());
    d.extend_from_slice(&[TAG_INIT_USER_PIN as u8, PIN.len() as u8]);
    d.extend_from_slice(PIN);
    d.extend_from_slice(&[TAG_INIT_SO_PIN as u8, SO_PIN_LEN as u8]);
    d.extend_from_slice(&SO_PIN);
    assert_eq!(sw(hsm.handle_apdu(&select(HSM_AID))), Sw::OK);
    let init = apdu(CLA_PROPRIETARY, INS_INITIALIZE, 0, 0, &d);
    assert_eq!(sw(hsm.handle_apdu(&init)), Sw::OK);
}

fn verify(hsm: &mut Hsm<'_>, pin: &[u8]) -> Sw {
    sw(hsm.handle_apdu(&apdu(CLA_ISO, INS_VERIFY, 0, PIN_USER, pin)))
}

fn lock_state(hsm: &mut Hsm<'_>) -> u8 {
    let (body, status) = run(hsm, &ext(CLA_PROPRIETARY, INS_LOCK, LOCK_STATUS, 0, &[]));
    assert_eq!(status, Sw::OK);
    body[1]
}

/// The host half of the lock channel, spelled from the wire description rather
/// than borrowed from the applet: agree on P-256, derive the box key with HKDF,
/// seal `plain` with ChaCha20-Poly1305 bound to the device's point.
fn boxed(hsm: &mut Hsm<'_>, plain: &[u8]) -> Vec<u8> {
    use rsk_crypto::pinproto::{ecdh_raw, public_xy};
    let host = [0x42u8; 32];
    let (hx, hy) = public_xy(&host).unwrap();
    let mut host_pub = std::vec![0x04];
    host_pub.extend_from_slice(&hx);
    host_pub.extend_from_slice(&hy);
    let channel = apdu(CLA_PROPRIETARY, INS_LOCK, LOCK_CHANNEL, 0, &host_pub);
    let (dev_pub, status) = run(hsm, &channel);
    assert_eq!(status, Sw::OK);
    let z = ecdh_raw(
        &host,
        dev_pub[1..33].try_into().unwrap(),
        dev_pub[33..65].try_into().unwrap(),
    )
    .unwrap();
    let mut info = dev_pub.clone();
    info.extend_from_slice(&host_pub);
    let mut key = [0u8; 32];
    rsk_crypto::hkdf_sha256(b"RSK-HSM/LOCK-CHANNEL", &z, &info, &mut key).unwrap();
    let nonce = [9u8; 12];
    let mut ct = plain.to_vec();
    let tag = rsk_crypto::chacha20poly1305_encrypt(&key, &nonce, &dev_pub, &mut ct);
    let mut blob = nonce.to_vec();
    blob.extend_from_slice(&ct);
    blob.extend_from_slice(&tag);
    blob
}

/// Create the public data object `fid` with a one-byte value.
fn put_object(hsm: &mut Hsm<'_>, fid: u16) -> Sw {
    let [hi, lo] = fid.to_be_bytes();
    let body = [TAG_OFFSET as u8, 2, 0, 0, TAG_DATA as u8, 1, lo];
    sw(hsm.handle_apdu(&apdu(CLA_ISO, INS_UPDATE_BINARY_ODD, hi, lo, &body)))
}

#[test]
fn the_hsm_image_carries_its_applet_and_the_two_recovery_applets_only() {
    let env = Env::new();
    let mut hsm = env.hsm();
    for aid in [rsk_vendor::VENDOR_AID, HSM_AID, rsk_rescue::RESCUE_AID] {
        assert_eq!(sw(hsm.handle_apdu(&select(aid))), Sw::OK, "{aid:02X?}");
    }
    for aid in [
        rsk_openpgp::consts::OPENPGP_AID,
        rsk_mgmt::MANAGEMENT_AID,
        rsk_oath::OATH_AID,
        rsk_otp::OTP_AID,
        rsk_piv::PIV_AID,
        rsk_fido::consts::FIDO_AID,
    ] {
        assert_eq!(
            sw(hsm.handle_apdu(&select(aid))),
            Sw::FILE_NOT_FOUND,
            "{aid:02X?} is the key image's"
        );
    }
}

#[test]
fn selecting_the_hsm_answers_the_fcp_the_driver_matches_on() {
    let env = Env::new();
    let mut hsm = env.hsm();
    let (major, minor, _) = rsk_sdk::FIRMWARE_VERSION;
    let (fcp, status) = run(&mut hsm, &select(HSM_AID));
    assert_eq!(status, Sw::OK);
    assert_eq!(
        fcp,
        [
            TAG_FCP,
            10,
            TAG_FCP_DESCRIPTOR,
            1,
            FD_DF,
            TAG_FCP_PROPRIETARY,
            5,
            0,
            0,
            FCP_TYPE_GENERIC,
            major,
            minor
        ]
    );
}

#[test]
fn a_card_reset_deselects_the_hsm() {
    let env = Env::new();
    let mut hsm = env.hsm();
    initialize(&mut hsm);
    assert_eq!(verify(&mut hsm, PIN), Sw::OK);
    hsm.reset_card();
    assert_eq!(
        verify(&mut hsm, &[]),
        Sw::FILE_NOT_FOUND,
        "nothing selected"
    );
    hsm.handle_apdu(&select(HSM_AID));
    assert_eq!(verify(&mut hsm, &[]), Sw::retries(USER_RETRIES_DEFAULT));
}

#[test]
fn a_full_store_lists_in_one_response_and_in_get_response_chunks() {
    let env = Env::new();
    let mut hsm = env.hsm();
    initialize(&mut hsm);
    assert_eq!(verify(&mut hsm, PIN), Sw::OK);
    let mut want = Vec::new();
    'fill: for prefix in [PREFIX_DATA, PREFIX_EE_CERT, PREFIX_CA_CERT, PREFIX_DCOD] {
        for id in 0..=255u8 {
            if want.len() == MAX_OBJECTS {
                break 'fill;
            }
            let fid = u16::from_be_bytes([prefix, id]);
            assert_eq!(put_object(&mut hsm, fid), Sw::OK, "{fid:04X}");
            want.push(fid);
        }
    }
    let next = want.last().unwrap() + 1;
    assert_eq!(put_object(&mut hsm, next), Sw::FILE_FULL);

    let (whole, status) = run(&mut hsm, &ext(CLA_PROPRIETARY, INS_ENUMERATE, 0, 0, &[]));
    assert_eq!(status, Sw::OK);
    assert_eq!(whole.len(), 2 * MAX_OBJECTS);
    let mut listed: Vec<u16> = whole
        .chunks(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();
    listed.sort_unstable();
    want.sort_unstable();
    assert_eq!(listed, want);

    // A short `Le` gets the same bytes, 256 at a time.
    let (mut chunked, mut status) = run(&mut hsm, &apdu(CLA_PROPRIETARY, INS_ENUMERATE, 0, 0, &[]));
    while status.to_bytes()[0] == 0x61 {
        let (more, s) = run(&mut hsm, &[CLA_ISO, 0xC0, 0, 0, 0]);
        chunked.extend_from_slice(&more);
        status = s;
    }
    assert_eq!(status, Sw::OK);
    assert_eq!(chunked, whole);
}

#[test]
fn the_board_unlocks_the_same_lock_the_host_armed() {
    let env = Env::new();
    assert_eq!(env.hsm().unlock(&SECRET), Err(UnlockError::NotArmed));
    {
        let mut hsm = env.hsm();
        initialize(&mut hsm);
        let mut plain = SECRET.to_vec();
        plain.extend_from_slice(&SO_PIN);
        let blob = boxed(&mut hsm, &plain);
        let arm = apdu(
            CLA_PROPRIETARY,
            INS_LOCK,
            LOCK_ARM,
            LOCK_FACTOR_HOST_KEY,
            &blob,
        );
        assert_eq!(sw(hsm.handle_apdu(&arm)), Sw::OK);
        assert_eq!(lock_state(&mut hsm), LOCK_STATE_UNLOCKED);
    }

    // A power cycle closes it; neither the wire nor the board opens it with
    // anything but the secret.
    let mut hsm = env.hsm();
    hsm.handle_apdu(&select(HSM_AID));
    assert_eq!(lock_state(&mut hsm), LOCK_STATE_LOCKED);
    assert_eq!(verify(&mut hsm, PIN), Sw::CONDITIONS_NOT_SATISFIED);
    assert_eq!(
        hsm.unlock(&[0x11; UNLOCK_SECRET_LEN]),
        Err(UnlockError::Refused)
    );
    assert_eq!(lock_state(&mut hsm), LOCK_STATE_LOCKED);
    assert_eq!(hsm.unlock(&SECRET), Ok(()));
    assert_eq!(lock_state(&mut hsm), LOCK_STATE_UNLOCKED);
    assert_eq!(verify(&mut hsm, PIN), Sw::OK);

    // A card reset ends the login, not the unlock.
    hsm.reset_card();
    hsm.handle_apdu(&select(HSM_AID));
    assert_eq!(lock_state(&mut hsm), LOCK_STATE_UNLOCKED);
    assert_eq!(verify(&mut hsm, &[]), Sw::retries(USER_RETRIES_DEFAULT));
    drop(hsm);
    let mut hsm = env.hsm();
    hsm.handle_apdu(&select(HSM_AID));
    assert_eq!(lock_state(&mut hsm), LOCK_STATE_LOCKED);
}

#[test]
fn the_response_buffer_is_wiped_after_the_hand_off() {
    let env = Env::new();
    let mut hsm = env.hsm();
    hsm.handle_apdu(&select(HSM_AID));
    let challenge = ext(CLA_ISO, INS_GET_CHALLENGE, 0, 0, &[]);
    let n = hsm.handle_apdu(&challenge).len();
    assert!(n > MAX_CHALLENGE);
    hsm.scrub();
    assert!(hsm.resp.iter().all(|&b| b == 0));
}

/// The boot pass over `env`'s store, as the HSM image runs it before USB attaches.
fn boot_env(env: &Env) -> bool {
    let dev = Device {
        serial_hash: &SERIAL_HASH,
        serial_id: &SERIAL_ID,
        otp_key: None,
    };
    let mut fs = env.fs.borrow_mut();
    let mut rng = env.rng.borrow_mut();
    boot(&dev, None, &mut fs, &mut *rng)
}

/// A booted, initialized device with the user PIN verified.
fn logged_in(env: &Env) -> Hsm<'_> {
    assert!(boot_env(env));
    let mut hsm = env.hsm();
    initialize(&mut hsm);
    assert_eq!(verify(&mut hsm, PIN), Sw::OK);
    hsm
}

/// A GENERATE KEY PAIR template for an RSA-2048 key, as the driver builds one.
fn rsa_template() -> Vec<u8> {
    let mut t = std::vec![0x5F, 0x29, 1, 0, 0x42, 9];
    t.extend_from_slice(b"UTCA00001");
    t.extend_from_slice(&[0x7F, 0x49, 21, 0x06, 10]);
    t.extend_from_slice(&[0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x02, 0x01, 0x02]);
    t.extend_from_slice(&[0x82, 3, 1, 0, 1, 0x02, 2, 0x08, 0x00]);
    t.extend_from_slice(&[0x5F, 0x20, 5]);
    t.extend_from_slice(b"RSK01");
    t
}

/// The device certificates in `2F02`, read the way the driver reads them.
fn devaut(hsm: &mut Hsm<'_>) -> Vec<u8> {
    hsm.handle_apdu(&select(HSM_AID));
    let read = ext(CLA_ISO, INS_READ_BINARY_ODD, 0x2F, 0x02, &[0x54, 2, 0, 0]);
    let (body, status) = run(hsm, &read);
    assert_eq!(status, Sw::WARNING_EOF);
    body
}

#[test]
fn the_boot_pass_roots_the_identity_in_the_rescue_device_key() {
    let env = Env::new();
    assert!(boot_env(&env));
    let mut hsm = env.hsm();
    let first = devaut(&mut hsm);
    // The second certificate is the root's, and its key is the one the rescue
    // applet reports as the device attestation key.
    let mut certs = rsk_sdk::tlv::Tlv::new(&first);
    let _ = certs.next().unwrap();
    let (_, root) = certs.next().unwrap();
    let body = rsk_sdk::tlv::find_tag(root, TAG_CV_BODY).unwrap();
    let pk = rsk_sdk::tlv::find_tag(body, TAG_CV_PUBKEY).unwrap();
    let point = rsk_sdk::tlv::find_tag(pk, TAG_PK_POINT).unwrap().to_vec();
    hsm.handle_apdu(&select(rsk_rescue::RESCUE_AID));
    let (keydev, status) = run(&mut hsm, &ext(0x80, 0x10, 0x02, 0, &[]));
    assert_eq!(status, Sw::OK);
    assert_eq!(point, keydev);

    // A later boot over the same store keeps the same identity.
    assert!(boot_env(&env));
    let mut hsm = env.hsm();
    assert_eq!(devaut(&mut hsm), first);
}

#[test]
fn rsa_keygen_runs_on_the_boards_search_when_the_board_has_one() {
    let env = Env::new();
    env.board.borrow_mut().accelerator = true;
    let mut hsm = logged_in(&env);
    let generate = ext(CLA_ISO, INS_GENERATE_KEYPAIR, 1, 0, &rsa_template());
    // The double's accelerator ran and found nothing: only the fast path says so.
    assert_eq!(sw(hsm.handle_apdu(&generate)), Sw::EXEC_ERROR);
    // A chaining segment is a segment, never a command, fast path or not.
    let mut seg = generate.clone();
    seg[0] = 0x10;
    assert_eq!(sw(hsm.handle_apdu(&seg)), Sw::OK);
    drop(hsm);

    // With no accelerator the applet searches on its own core.
    env.board.borrow_mut().accelerator = false;
    let mut hsm = logged_in(&env);
    let (resp, status) = run(&mut hsm, &generate);
    assert_eq!(status, Sw::OK);
    assert_eq!(resp[0], TAG_CV_AUTH_REQUEST as u8);
}
