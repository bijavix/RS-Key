// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Stateful fuzzing of the HSM image's card over the wiring it ships: the same
//! [`rsk_device::HsmApplets`] — vendor, HSM and rescue applets behind one
//! dispatcher — that the firmware and `tools/emu --hsm` run, booted by the same
//! `hsm_boot`. Before the fuzzer's first byte the device is initialized, its DKEK
//! share imported, the user PIN verified and two keys of known value restored, so
//! a sequence starts inside a working token instead of at an INITIALIZE no
//! mutator would ever spell.
//!
//! Each record starts with an opcode byte:
//!
//! | byte | verb |
//! |---|---|
//! | `0x00`–`0x02` | SELECT the vendor, HSM or rescue applet, in registration order |
//! | `0xF0` | VERIFY the user PIN |
//! | `0xF1` | `reset_card()` — the ICC power transition |
//! | `0xF2` | a power cycle: RAM secrets wiped, the wiring rebuilt over the same flash |
//! | `0xF3` | SELECT, then LOCK ARM with a box sealed over a fresh channel |
//! | `0xF4` | SELECT, then LOCK UNLOCK, likewise |
//! | `0xF5` | the board's unlock door, `HsmApplets::unlock` |
//! | `0xF6` | SELECT, then LOCK DISARM with the SO-PIN |
//! | anything else | a raw APDU, framed by `apdu_frame::next_frame` |
//!
//! Raw SELECTs by name are dropped: the opcodes own the selection, which is what
//! lets the harness know which applet a command reached. The dispatcher's own
//! SELECT handling is `cross_applet`'s to fuzz.
//!
//! Beyond not panicking: every reply carries its status word and fits one CCID
//! frame; the key material the harness restored, and the DKEK, never appear in a
//! reply; and while the lock is closed — armed, with no unlock since the power
//! cycle — no command that needs the device key succeeds. The lock verbs are
//! checked against a model of the lock too: ARM only from disarmed, UNLOCK and the
//! board door exactly when armed, DISARM only when open.

use core::cell::RefCell;

use libfuzzer_sys::fuzz_target;
use rsk_crypto::{Device, sha256};
use rsk_device::{Hooks, HsmApplets, UnlockError};
use rsk_fs::Fs;
use rsk_fs::storage::ram::RamStorage;
use rsk_hsm::consts::*;
use rsk_sdk::{Apdu, Sw};

mod apdu_frame;
use apdu_frame::next_frame;
mod hsm_fixture;
use hsm_fixture::*;

const SERIAL_ID: [u8; 8] = [0x12, 0x34, 0x56, 0x78, 1, 2, 3, 4];
const SERIAL_HASH: [u8; 32] = [0x22; 32];
const KV_TOTAL: u32 = 64 * 1024;
const FLASH_SIZE: u32 = 2 * 1024 * 1024;

/// The two keys restored ahead of the fuzzer, with values only the harness knows.
const KID_EC: u8 = 1;
const KID_AES: u8 = 2;
const EC_SCALAR: [u8; 32] = [
    0x3A, 0x91, 0xC4, 0x5E, 0x07, 0xBD, 0x62, 0xF8, 0x1C, 0x83, 0x2F, 0xE6, 0x54, 0x0B, 0x9D, 0x70,
    0xA2, 0x4E, 0x15, 0xC9, 0x68, 0x33, 0xDB, 0x0F, 0x86, 0x5A, 0xE1, 0x27, 0xBC, 0x49, 0x92, 0x6D,
];
const AES_KEY: [u8; 32] = [
    0xE4, 0x17, 0x6B, 0xA0, 0x3D, 0xF2, 0x58, 0x8C, 0x21, 0xC7, 0x0E, 0x95, 0x4A, 0xB3, 0x76, 0x1F,
    0xD8, 0x62, 0x09, 0xAE, 0x35, 0xCB, 0x80, 0x5D, 0xF4, 0x13, 0x6A, 0x97, 0x2C, 0xE5, 0x41, 0xB8,
];

/// Registration order in `HsmApplets`.
const APPLETS: [&[u8]; 3] = [rsk_vendor::VENDOR_AID, HSM_AID, rsk_rescue::RESCUE_AID];
const IDX_HSM: u8 = 1;

const OP_SELECT_MAX: u8 = 2;
const OP_LOGIN: u8 = 0xF0;
const OP_RESET_CARD: u8 = 0xF1;
const OP_POWER_CYCLE: u8 = 0xF2;
const OP_ARM: u8 = 0xF3;
const OP_UNLOCK: u8 = 0xF4;
const OP_UNLOCK_DOOR: u8 = 0xF5;
const OP_DISARM: u8 = 0xF6;

/// The arc every RSA signature algorithm's OID starts with (`id-TA-RSA`).
const ID_TA_RSA: &[u8] = &[0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x02, 0x01];

/// Every `Hooks` method at its default: no dual-core prime search, which is why
/// RSA GENERATE is skipped below.
struct Board;
impl Hooks<RamStorage> for Board {}

/// Confirms every touch, so the touch-gated commands stay reachable.
struct Finger;
impl rsk_sdk::UserPresence for Finger {
    fn request(&mut self, _confirm: rsk_sdk::Confirm<'_>) -> rsk_sdk::Presence {
        rsk_sdk::Presence::Confirmed
    }
}

struct SeqRng(u64);
impl rsk_sdk::Rng for SeqRng {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            *b = (self.0 >> 33) as u8;
        }
    }
}

/// The rescue applet's board: no secure boot, no fuse it may burn.
#[derive(Default)]
struct RescueBoard {
    time: Option<u32>,
}

impl rsk_rescue::Platform for RescueBoard {
    fn secure_boot_status(&self) -> rsk_rescue::SecureBootStatus {
        rsk_rescue::SecureBootStatus {
            enabled: false,
            locked: false,
            bootkey: 0xFF,
        }
    }
    fn now(&self) -> Option<u32> {
        self.time
    }
    fn set_time(&mut self, epoch: u32) {
        self.time = Some(epoch);
    }
    fn request_reboot(&mut self, _bootsel: bool) {}
    fn read_page58_lock_raw(&self) -> Option<u32> {
        Some(0)
    }
    fn lock_page58(&mut self) -> bool {
        false
    }
    fn read_rollback_raw(&self) -> Option<rsk_rescue::rollback::RollbackRaw> {
        None
    }
    fn set_rollback_required(&mut self) -> bool {
        false
    }
}

struct VendorBoard;
impl rsk_vendor::Platform for VendorBoard {}

type Card<'a> = HsmApplets<'a, RamStorage, SeqRng, VendorBoard>;

/// The parts a power cycle keeps: flash, the DRBG, and the board.
struct Bench {
    fs: RefCell<Fs<RamStorage>>,
    rng: RefCell<SeqRng>,
    board: RefCell<Board>,
    finger: RefCell<Finger>,
    rescue: RefCell<RescueBoard>,
}

impl Bench {
    /// Boot as `main.rs` does, then build the wiring: what a power-up is.
    fn power_up(&self) -> Card<'_> {
        let dev = Device {
            serial_hash: &SERIAL_HASH,
            serial_id: &SERIAL_ID,
            otp_key: None,
        };
        assert!(
            rsk_device::hsm_boot(
                &dev,
                None,
                &mut self.fs.borrow_mut(),
                &mut *self.rng.borrow_mut()
            ),
            "the boot pass must bring the device identity into being"
        );
        HsmApplets::new(
            &self.fs,
            &self.rng,
            &self.board,
            &self.finger,
            &self.rescue,
            VendorBoard,
            SERIAL_ID,
            SERIAL_HASH,
            None,
            None,
            KV_TOTAL,
            FLASH_SIZE,
        )
    }
}

/// What the harness knows about the card, to judge its answers by.
struct Model {
    /// The device record names an unlock factor.
    armed: bool,
    /// The key store is reachable this power cycle: disarmed, or unlocked.
    open: bool,
    /// The HSM applet is the one selected.
    hsm: bool,
}

/// A secret, as the leak check looks for it: its first word, which is all a
/// comparison here shows the fuzzer, and its digest.
struct Needle {
    head: [u8; 4],
    digest: [u8; 32],
}

impl Needle {
    fn new(secret: &[u8; 32]) -> Needle {
        Needle {
            head: [secret[0], secret[1], secret[2], secret[3]],
            digest: sha256(secret),
        }
    }
}

/// Whether any 32-byte window of `body` is one of `needles`. Compared by digest,
/// so the fuzzer's comparison tracing learns four bytes of a secret, never the
/// rest — a check that showed it the whole value would teach it to write the value
/// into a file and read it back.
fn leaks(body: &[u8], needles: &[Needle]) -> bool {
    body.windows(32).any(|w| {
        needles
            .iter()
            .any(|n| w[..4] == n.head && sha256(w) == n.digest)
    })
}

/// The status word of a reply, checked on the way past: present, and the reply
/// small enough for one CCID `XfrBlock`.
fn status(res: &[u8]) -> Sw {
    let n = res.len();
    assert!(n >= 2, "a response APDU always carries its status word");
    assert!(
        n + rsk_usb::ccid::HEADER <= rsk_usb::ccid::MAX_CCID_MSG,
        "a {n}-byte response does not fit one CCID frame"
    );
    Sw::new(res[n - 2], res[n - 1])
}

/// A command answered as done: `9000`, or `61xx` with the rest to collect.
fn succeeded(sw: Sw) -> bool {
    sw == Sw::OK || sw.to_bytes()[0] == 0x61
}

/// Whether the HSM may only answer `cmd` with the lock open: everything that needs
/// the device key — a PIN presented, a key made or used, a backup, the DKEK.
fn needs_open_lock(cmd: &Apdu) -> bool {
    match (cmd.cla, cmd.ins) {
        (CLA_ISO, INS_VERIFY) => cmd.nc > 0,
        (
            CLA_ISO,
            INS_CHANGE_REFERENCE | INS_RESET_RETRY | INS_GENERATE_KEYPAIR | INS_GENERATE_SYMMETRIC,
        ) => true,
        (
            CLA_PROPRIETARY,
            INS_KEY_DOMAIN | INS_SIGN | INS_DECIPHER | INS_CIPHER_SYMMETRIC | INS_WRAP_KEY
            | INS_UNWRAP_KEY,
        ) => true,
        _ => false,
    }
}

/// Send one command the harness built; its reply, checked.
fn send(card: &mut Card, raw: &[u8], needles: &[Needle]) -> (Sw, Vec<u8>) {
    let res = card.handle_apdu(raw).to_vec();
    let sw = status(&res);
    let body = &res[..res.len() - 2];
    assert!(
        !leaks(body, needles),
        "a reply carried key material in the clear"
    );
    (sw, body.to_vec())
}

/// SELECT the HSM, open a lock channel and send `p1` with `plain` boxed over it.
fn boxed_lock(card: &mut Card, p1: u8, p2: u8, plain: &[u8], needles: &[Needle]) -> Sw {
    send(card, &select_hsm(), needles);
    let (sw, dev_pub) = send(
        card,
        &apdu(CLA_PROPRIETARY, INS_LOCK, LOCK_CHANNEL, 0, &host_point()),
        needles,
    );
    assert_eq!(sw, Sw::OK, "LOCK CHANNEL refused a valid host point");
    let blob = lock_box(&dev_pub, plain).expect("the device answers a P-256 point");
    send(
        card,
        &apdu(CLA_PROPRIETARY, INS_LOCK, p1, p2, &blob),
        needles,
    )
    .0
}

fuzz_target!(|data: &[u8]| {
    let device = Bench {
        fs: RefCell::new(Fs::new(RamStorage::new())),
        rng: RefCell::new(SeqRng(1)),
        board: RefCell::new(Board),
        finger: RefCell::new(Finger),
        rescue: RefCell::new(RescueBoard::default()),
    };
    device.fs.borrow_mut().scan();
    let needles = [
        Needle::new(&EC_SCALAR),
        Needle::new(&AES_KEY),
        Needle::new(&DKEK),
    ];
    let mut card = device.power_up();

    // Takes no fuzzer input, so these can only fire when the setup itself stops
    // working — which a coverage-less green row would never show.
    let ec = seal_blob(&DKEK, BLOB_EC, &[], &p256_inner(&EC_SCALAR));
    let aes = seal_blob(&DKEK, BLOB_AES, &[], &aes_inner(&AES_KEY));
    for (cmd, what) in [
        (select_hsm(), "SELECT"),
        (initialize(), "INITIALIZE"),
        (import_share(), "importing the DKEK share"),
        (verify_user(), "VERIFY"),
        (update_binary(FID_STAGING, &ec), "staging the EC key"),
        (unwrap_into(KID_EC), "restoring the EC key"),
        (update_binary(FID_STAGING, &aes), "staging the AES key"),
        (unwrap_into(KID_AES), "restoring the AES key"),
    ] {
        assert_eq!(
            send(&mut card, &cmd, &needles).0,
            Sw::OK,
            "{what} must succeed"
        );
    }
    let mut model = Model {
        armed: false,
        open: true,
        hsm: true,
    };

    let mut i = 0;
    while i < data.len() {
        let op = data[i];
        i += 1;
        match op {
            0..=OP_SELECT_MAX => {
                let aid = APPLETS[op as usize];
                let mut sel = vec![CLA_ISO, INS_SELECT, SEL_DF_NAME, 0x00, aid.len() as u8];
                sel.extend_from_slice(aid);
                send(&mut card, &sel, &needles);
                model.hsm = op == IDX_HSM;
            }
            OP_LOGIN => {
                let sw = send(&mut card, &verify_user(), &needles).0;
                // The dispatcher may refuse it first (an open chain answers 6883);
                // what the lock owes is that the PIN is never reached: no login,
                // and no tries-left or blocked answer, which only a PIN check gives.
                let reached = succeeded(sw) || sw.to_bytes()[0] == 0x63 || sw == Sw::PIN_BLOCKED;
                assert!(
                    !(model.hsm && !model.open && reached),
                    "VERIFY reached the PIN with the lock closed: {sw:?}"
                );
            }
            OP_RESET_CARD => {
                card.reset_card();
                model.hsm = false;
            }
            OP_POWER_CYCLE => {
                card.scrub_secrets();
                card = device.power_up();
                model.open = !model.armed;
                model.hsm = false;
            }
            OP_ARM => {
                let mut plain = LOCK_SECRET.to_vec();
                plain.extend_from_slice(&SO_PIN);
                let sw = boxed_lock(&mut card, LOCK_ARM, LOCK_FACTOR_HOST_KEY, &plain, &needles);
                model.hsm = true;
                if model.armed {
                    assert!(!succeeded(sw), "an armed lock was armed again");
                } else if sw == Sw::OK {
                    model.armed = true;
                    model.open = true;
                }
            }
            OP_UNLOCK => {
                let sw = boxed_lock(&mut card, LOCK_UNLOCK, 0, &LOCK_SECRET, &needles);
                model.hsm = true;
                assert_eq!(
                    sw == Sw::OK,
                    model.armed,
                    "UNLOCK with the armed secret answered {sw:?}"
                );
                model.open |= model.armed;
            }
            OP_UNLOCK_DOOR => {
                let r = card.unlock(&LOCK_SECRET);
                let want = if model.armed {
                    Ok(())
                } else {
                    Err(UnlockError::NotArmed)
                };
                assert_eq!(r, want, "the board's unlock door disagrees with the lock");
                model.open |= model.armed;
            }
            OP_DISARM => {
                send(&mut card, &select_hsm(), &needles);
                let cmd = apdu(CLA_PROPRIETARY, INS_LOCK, LOCK_DISARM, 0, &SO_PIN);
                let sw = send(&mut card, &cmd, &needles).0;
                model.hsm = true;
                if !(model.armed && model.open) {
                    assert!(!succeeded(sw), "DISARM ran on a lock that was not open");
                } else if sw == Sw::OK {
                    model.armed = false;
                }
            }
            // A raw APDU, its length a byte of its own after the opcode's: as the
            // opcode's, the reserved values would make every short APDU unreachable.
            _ => {
                let Some((frame, tail)) = next_frame(&data[i..]) else {
                    break;
                };
                i = data.len() - tail.len();
                let raw = frame.as_slice();
                let parsed = Apdu::parse(raw).ok();
                if let Some(cmd) = &parsed {
                    let select_by_name = cmd.ins == INS_SELECT && cmd.p1 == SEL_DF_NAME;
                    let rsa_keygen = cmd.ins == INS_GENERATE_KEYPAIR
                        && cmd.data.windows(ID_TA_RSA.len()).any(|w| w == ID_TA_RSA);
                    if select_by_name || rsa_keygen {
                        continue;
                    }
                }
                let sw = send(&mut card, raw, &needles).0;
                // A chain segment is acknowledged, not run: neither the oracle nor
                // the model learns anything from its `9000`.
                let Some(cmd) = parsed.filter(|c| model.hsm && !c.is_chaining()) else {
                    continue;
                };
                if !model.open && needs_open_lock(&cmd) {
                    assert!(
                        !succeeded(sw),
                        "{:02X} {:02X} succeeded with the lock closed",
                        cmd.cla,
                        cmd.ins
                    );
                }
                if sw != Sw::OK || cmd.cla != CLA_PROPRIETARY {
                    continue;
                }
                match (cmd.ins, cmd.p1) {
                    (INS_INITIALIZE, _) => {
                        model.armed = false;
                        model.open = true;
                    }
                    (INS_LOCK, LOCK_DISARM) => model.armed = false,
                    (INS_LOCK, LOCK_ARM) => {
                        model.armed = true;
                        model.open = true;
                    }
                    (INS_LOCK, LOCK_UNLOCK) => model.open = true,
                    _ => {}
                }
            }
        }
    }
});
