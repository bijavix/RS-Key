// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Fuzz the key-backup decoder at full depth. UNWRAP KEY checks a blob's KCV and
//! its CMAC before it parses a byte, so random bytes never get past the MAC — the
//! `hsm_apdu` target meets exactly that wall. This harness holds the DKEK and seals
//! whatever the fuzzer chose, so every input reaches the key-field parser, the
//! curve match, the scalar and point checks and the RSA rebuild: the surface a
//! share holder with a forged backup would be attacking.
//!
//! Input: `kind ‖ n ‖ algos[n] ‖ template ‖ rest`. On an EC blob an odd
//! `template` writes P-256's parameters ahead of `rest`, so `rest` starts at the
//! scalar — a mutator does not invent 200 bytes of curve; otherwise `rest` is the
//! whole encrypted part after the nonce.
//!
//! Beyond not panicking: a key the device restored is one it must be able to back
//! up again. WRAP answers exactly when the key's list allows it, in a blob the
//! driver's buffer holds; that blob restores; and the restored key wraps to the
//! same fields — a restore lands on one canonical form, whatever form it came in.

use core::cell::RefCell;

use libfuzzer_sys::fuzz_target;
use rsk_fs::Fs;
use rsk_fs::storage::ram::RamStorage;
use rsk_hsm::consts::{ALGO_WRAP, FID_STAGING};
use rsk_hsm::{AlwaysConfirm, HsmApplet};
use rsk_sdk::{Apdu, Applet, ResBuf, Sw};

mod hsm_fixture;
use hsm_fixture::*;

const SERIAL_ID: [u8; 8] = [0x12, 0x34, 0x56, 0x78, 1, 2, 3, 4];
const SERIAL_HASH: [u8; 32] = [0x22; 32];
/// Where the forged blob lands, and where its round trip restores to.
const KID_FORGED: u8 = 1;
const KID_ROUND_TRIP: u8 = 2;

struct SeqRng(u64);

impl rsk_sdk::Rng for SeqRng {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            *b = (self.0 >> 33) as u8;
        }
    }
}

fn run(app: &mut HsmApplet, fs: &mut Fs<RamStorage>, raw: &[u8]) -> (Sw, Vec<u8>) {
    let apdu = Apdu::parse(raw).expect("the harness builds well-formed commands");
    let mut buf = [0u8; 4096];
    let mut res = ResBuf::new(&mut buf);
    let sw = app.process(&apdu, fs, &mut res);
    (sw, res.as_slice().to_vec())
}

/// Stage `blob` and restore it as `kid`.
fn restore(app: &mut HsmApplet, fs: &mut Fs<RamStorage>, blob: &[u8], kid: u8) -> Sw {
    let staged = run(app, fs, &update_binary(FID_STAGING, blob)).0;
    if staged != Sw::OK {
        return staged;
    }
    run(app, fs, &unwrap_into(kid)).0
}

fuzz_target!(|data: &[u8]| {
    let rng = RefCell::new(SeqRng(1));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = HsmApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &touch);
    let mut fs = Fs::new(RamStorage::new());
    fs.scan();
    {
        let mut buf = [0u8; 256];
        let mut res = ResBuf::new(&mut buf);
        assert_eq!(Applet::select(&mut app, false, &mut fs, &mut res), Sw::OK);
    }
    // Takes no fuzzer input, so these can only fire when the setup itself stops
    // working — which a coverage-less green row would never show.
    for (cmd, what) in [
        (initialize(), "INITIALIZE"),
        (import_share(), "importing the DKEK share"),
        (verify_user(), "VERIFY"),
    ] {
        assert_eq!(
            run(&mut app, &mut fs, &cmd).0,
            Sw::OK,
            "{what} must succeed"
        );
    }

    let Some((&kind, rest)) = data.split_first() else {
        return;
    };
    let Some((&n, rest)) = rest.split_first() else {
        return;
    };
    let (algos, rest) = rest.split_at((n as usize).min(rest.len()));
    let Some((&template, rest)) = rest.split_first() else {
        return;
    };
    let mut inner = if kind == BLOB_EC && template & 1 == 1 {
        p256_head()
    } else {
        Vec::new()
    };
    inner.extend_from_slice(rest);
    let blob = seal_blob(&DKEK, kind, algos, &inner);
    if restore(&mut app, &mut fs, &blob, KID_FORGED) != Sw::OK {
        return;
    }

    let (sw, first) = run(&mut app, &mut fs, &wrap_out(KID_FORGED));
    let may_leave = algos.is_empty() || algos.contains(&ALGO_WRAP);
    assert_eq!(
        sw == Sw::OK,
        may_leave,
        "WRAP answered {sw:?} for a key restored with the list {algos:02X?}"
    );
    if !may_leave {
        return;
    }
    assert!(
        first.len() <= DRIVER_WRAP_BUF,
        "a {}-byte backup overflows the driver's {DRIVER_WRAP_BUF}-byte buffer",
        first.len()
    );
    let fields = open_blob(&DKEK, &first).expect("the device's own backup opens under the DKEK");
    assert_eq!(
        restore(&mut app, &mut fs, &first, KID_ROUND_TRIP),
        Sw::OK,
        "the device refused its own backup"
    );
    let (sw, second) = run(&mut app, &mut fs, &wrap_out(KID_ROUND_TRIP));
    assert_eq!(sw, Sw::OK, "the restored copy would not wrap");
    assert_eq!(
        blob_head(&first),
        blob_head(&second),
        "a restored key wrapped to a different type, OID or list"
    );
    assert_eq!(
        open_blob(&DKEK, &second).expect("the device's own backup opens under the DKEK"),
        fields,
        "a restored key wrapped to different key fields"
    );
});
