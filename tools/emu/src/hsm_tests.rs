// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::Duration;

use rsk_crypto::pinproto::{ecdh_raw, public_xy};
use rsk_crypto::{chacha20poly1305_encrypt, hkdf_sha256};
use rsk_hsm::consts::*;

use super::*;
use crate::device::{Jobs, Unplug, job_queue};
use crate::presence::PresenceMode;

const SERIAL: [u8; 8] = *b"RSKEMUH1";
/// `sc-hsm-tool`'s documented default, `3537363231383830`.
const SO_PIN: &[u8] = b"57621880";
const USER_PIN: &[u8] = b"648219";
const SECRET: [u8; UNLOCK_SECRET_LEN] = [0x5C; UNLOCK_SECRET_LEN];
const SW_OK: [u8; 2] = [0x90, 0x00];
const SW_LOCKED: [u8; 2] = rsk_sdk::Sw::CONDITIONS_NOT_SATISFIED.to_bytes();
/// The vendor applet's warm-reboot command (`rsk_vendor`'s crate-private
/// `INS_REBOOT`, P1 = 0: come back up, do not drop to BOOTSEL).
const INS_REBOOT: u8 = 0x1F;

/// The HSM device thread over a memory-only store.
fn bench() -> (Jobs, JoinHandle<()>) {
    let (jobs, requests) = job_queue();
    let cfg = Config {
        store: None,
        presence: PresenceMode::Instant,
        display: false,
        usbip: None,
        seed: Some(vec![0x6d; 32]),
        serial: SERIAL,
        kv_total: crate::KV_TOTAL,
        flash_size: crate::FLASH_SIZE,
        trace: false,
        security_trace: None,
        yubico: false,
        power_cut: None,
        hsm: true,
    };
    let device = std::thread::spawn(move || {
        crate::device::run(cfg, requests, Arc::new(Signals::default()), None, None)
    });
    (jobs, device)
}

fn ask(jobs: &Jobs, job: Job) -> Option<Vec<u8>> {
    let (reply, answer) = mpsc::channel();
    jobs.send(job, reply).expect("the device thread");
    answer
        .recv_timeout(Duration::from_secs(30))
        .expect("the device answered")
}

/// Send one APDU with an extended `Le`; its body and status word.
fn apdu(jobs: &Jobs, cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8]) -> (Vec<u8>, [u8; 2]) {
    let mut raw = vec![cla, ins, p1, p2, 0];
    if !data.is_empty() {
        raw.extend_from_slice(&(data.len() as u16).to_be_bytes());
        raw.extend_from_slice(data);
    }
    raw.extend_from_slice(&[0, 0]);
    let mut res = ask(jobs, Job::Apdu(raw)).expect("an APDU is answered");
    let sw = res.split_off(res.len() - 2);
    (res, [sw[0], sw[1]])
}

fn select(jobs: &Jobs, aid: &[u8]) -> (Vec<u8>, [u8; 2]) {
    apdu(jobs, CLA_ISO, INS_SELECT, SEL_DF_NAME, 0, aid)
}

fn initialize(jobs: &Jobs) {
    let mut d = vec![TAG_INIT_USER_PIN as u8, USER_PIN.len() as u8];
    d.extend_from_slice(USER_PIN);
    d.extend_from_slice(&[TAG_INIT_SO_PIN as u8, SO_PIN.len() as u8]);
    d.extend_from_slice(SO_PIN);
    select(jobs, HSM_AID);
    let (_, sw) = apdu(jobs, CLA_PROPRIETARY, INS_INITIALIZE, 0, 0, &d);
    assert_eq!(sw, SW_OK, "INITIALIZE");
}

fn verify(jobs: &Jobs) -> [u8; 2] {
    apdu(jobs, CLA_ISO, INS_VERIFY, 0, PIN_USER, USER_PIN).1
}

/// LOCK STATUS's state byte.
fn lock_state(jobs: &Jobs) -> u8 {
    let (body, sw) = apdu(jobs, CLA_PROPRIETARY, INS_LOCK, LOCK_STATUS, 0, &[]);
    assert_eq!(sw, SW_OK, "LOCK STATUS");
    body[1]
}

/// The host half of the lock channel: agree on a fresh key, box `plain` under it,
/// and send it as LOCK `p1`.
fn boxed(jobs: &Jobs, p1: u8, p2: u8, plain: &[u8]) -> [u8; 2] {
    let host = [0x37u8; 32];
    let (hx, hy) = public_xy(&host).unwrap();
    let mut host_pub = vec![0x04];
    host_pub.extend_from_slice(&hx);
    host_pub.extend_from_slice(&hy);
    let (dev_pub, sw) = apdu(jobs, CLA_PROPRIETARY, INS_LOCK, LOCK_CHANNEL, 0, &host_pub);
    assert_eq!(sw, SW_OK, "LOCK CHANNEL");
    let z = ecdh_raw(
        &host,
        dev_pub[1..33].try_into().unwrap(),
        dev_pub[33..].try_into().unwrap(),
    )
    .unwrap();
    let mut info = dev_pub.clone();
    info.extend_from_slice(&host_pub);
    let mut key = [0u8; 32];
    hkdf_sha256(b"RSK-HSM/LOCK-CHANNEL", &z, &info, &mut key).unwrap();
    let nonce = [3u8; 12];
    let mut ct = plain.to_vec();
    let tag = chacha20poly1305_encrypt(&key, &nonce, &dev_pub, &mut ct);
    let mut blob = nonce.to_vec();
    blob.extend_from_slice(&ct);
    blob.extend_from_slice(&tag);
    apdu(jobs, CLA_PROPRIETARY, INS_LOCK, p1, p2, &blob).1
}

fn arm(jobs: &Jobs) {
    let mut plain = SECRET.to_vec();
    plain.extend_from_slice(SO_PIN);
    let sw = boxed(jobs, LOCK_ARM, LOCK_FACTOR_HOST_KEY, &plain);
    assert_eq!(sw, SW_OK, "LOCK ARM");
}

fn unlock(jobs: &Jobs) -> [u8; 2] {
    boxed(jobs, LOCK_UNLOCK, 0, &SECRET)
}

fn shut_down(jobs: Jobs, device: JoinHandle<()>) {
    drop(jobs);
    device.join().unwrap();
}

/// `--hsm` serves the HSM image's card and nothing of the key's: the HSM applet
/// answers, an applet only the key image has is not there, and the HID-side jobs
/// no transport of this build sends find nothing to answer them.
#[test]
fn the_card_is_the_hsm_images() {
    let (jobs, device) = bench();
    let (fcp, sw) = select(&jobs, HSM_AID);
    assert_eq!(sw, SW_OK);
    assert_eq!(fcp.first(), Some(&TAG_FCP), "SELECT answers the FCP");
    let (_, sw) = select(&jobs, rsk_openpgp::consts::OPENPGP_AID);
    assert_eq!(sw, rsk_sdk::Sw::FILE_NOT_FOUND.to_bytes());
    let cbor = Job::Cbor {
        cid: 1,
        data: vec![0x04],
    };
    assert_eq!(ask(&jobs, cbor), None);
    shut_down(jobs, device);
}

/// A card reset is not a power cycle: it ends the session — nothing is selected
/// after it, so the login went with the selection — and an unlocked HSM stays
/// unlocked.
#[test]
fn a_card_reset_ends_the_login_and_leaves_the_lock_open() {
    let (jobs, device) = bench();
    initialize(&jobs);
    arm(&jobs);
    assert_eq!(verify(&jobs), SW_OK);
    assert_eq!(ask(&jobs, Job::ResetCard), Some(Vec::new()));
    let (_, sw) = apdu(&jobs, CLA_ISO, INS_VERIFY, 0, PIN_USER, &[]);
    assert_eq!(
        sw,
        rsk_sdk::Sw::FILE_NOT_FOUND.to_bytes(),
        "the reset kept the selection, and the login with it"
    );
    select(&jobs, HSM_AID);
    assert_eq!(lock_state(&jobs), LOCK_STATE_UNLOCKED);
    shut_down(jobs, device);
}

/// A replug is a power cycle: an armed HSM comes back locked, refuses the PIN
/// until it is unlocked again, and opens again with the same secret.
#[test]
fn a_replug_relocks_an_armed_hsm() {
    let (jobs, device) = bench();
    initialize(&jobs);
    arm(&jobs);
    select(&jobs, HSM_AID);
    assert_eq!(lock_state(&jobs), LOCK_STATE_UNLOCKED);
    ask(&jobs, Job::Replug(Unplug::Operator));
    select(&jobs, HSM_AID);
    assert_eq!(lock_state(&jobs), LOCK_STATE_LOCKED);
    assert_eq!(verify(&jobs), SW_LOCKED);
    assert_eq!(unlock(&jobs), SW_OK);
    assert_eq!(verify(&jobs), SW_OK);
    shut_down(jobs, device);
}

/// A warm reboot leaves SRAM powered on a board, so the worker wipes the lock
/// key before it — the emulator must come back locked from one too.
#[test]
fn a_warm_reboot_relocks_it_too() {
    let (jobs, device) = bench();
    initialize(&jobs);
    arm(&jobs);
    let (_, sw) = select(&jobs, rsk_vendor::VENDOR_AID);
    assert_eq!(sw, SW_OK);
    let (_, sw) = apdu(&jobs, CLA_ISO, INS_REBOOT, 0, 0, &[]);
    assert_eq!(sw, SW_OK, "the vendor applet queues the reboot");
    select(&jobs, HSM_AID);
    assert_eq!(lock_state(&jobs), LOCK_STATE_LOCKED);
    shut_down(jobs, device);
}

/// What the flash holds outlives the power cycle: a key made before the replug
/// answers the same after it.
#[test]
fn keys_survive_the_replug() {
    let (jobs, device) = bench();
    initialize(&jobs);
    assert_eq!(verify(&jobs), SW_OK);
    let (_, sw) = apdu(&jobs, CLA_ISO, INS_GENERATE_SYMMETRIC, 1, AES_128, &[]);
    assert_eq!(sw, SW_OK, "GENERATE SYMMETRIC");
    let cmac = |jobs: &Jobs| {
        apdu(
            jobs,
            CLA_PROPRIETARY,
            INS_CIPHER_SYMMETRIC,
            1,
            ALGO_AES_CMAC,
            b"x",
        )
    };
    let (before, sw) = cmac(&jobs);
    assert_eq!(sw, SW_OK);
    ask(&jobs, Job::Replug(Unplug::Operator));
    select(&jobs, HSM_AID);
    assert_eq!(verify(&jobs), SW_OK);
    assert_eq!(cmac(&jobs), (before, SW_OK));
    shut_down(jobs, device);
}
