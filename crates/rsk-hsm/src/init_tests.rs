// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::tests::{PIN, SO_PIN, init_data};

#[test]
fn defaults_fill_what_the_host_left_out() {
    let mut d = vec![0x81, PIN.len() as u8];
    d.extend_from_slice(PIN);
    d.extend_from_slice(&[0x82, 8]);
    d.extend_from_slice(&SO_PIN);
    let p = parse(&d).unwrap();
    assert_eq!((p.options, p.retries), (0, USER_RETRIES_DEFAULT));
    assert_eq!((p.user_pin, p.so_pin), (PIN, &SO_PIN[..]));
}

#[test]
fn every_supported_option_is_accepted_and_nothing_else() {
    for bit in 0..16 {
        let opt = 1u16 << bit;
        let ok = parse(&init_data(opt, PIN, &SO_PIN, Some(3))).is_ok();
        assert_eq!(ok, opt & OPT_SUPPORTED != 0, "{opt:#06x}");
    }
}

#[test]
fn what_opensc_sends_for_c_init_token_parses() {
    // `sc_hsm_init_token`: options 0001, the first six SO-PIN bytes as the user
    // PIN, the SO-PIN as the initialization code, three retries.
    let mut d = vec![0x80, 2, 0x00, 0x01, 0x81, 6];
    d.extend_from_slice(&SO_PIN[..6]);
    d.extend_from_slice(&[0x82, 8]);
    d.extend_from_slice(&SO_PIN);
    d.extend_from_slice(&[0x91, 1, 3]);
    let p = parse(&d).unwrap();
    assert_eq!(
        (p.options, p.retries, p.user_pin),
        (OPT_RRC, 3, &SO_PIN[..6])
    );
}
