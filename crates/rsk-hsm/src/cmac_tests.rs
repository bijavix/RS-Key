// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

fn hex(s: &str) -> std::vec::Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// The message every NIST SP 800-38B example truncates.
const MSG: &str = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";

#[test]
fn the_sp_800_38b_examples() {
    let k128 = hex("2b7e151628aed2a6abf7158809cf4f3c");
    let k256 = hex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
    let m = hex(MSG);
    for (key, len, tag) in [
        (&k128, 0, "bb1d6929e95937287fa37d129b756746"),
        (&k128, 16, "070a16b46b4d4144f79bdd9dd04a287c"),
        (&k128, 40, "dfa66747de9ae63030ca32611497c827"),
        (&k128, 64, "51f0bebf7e3b9d92fc49741779363cfe"),
        (&k256, 0, "028962f61b7bf89efc6b551f4667d983"),
        (&k256, 16, "28a7023f452e8f82bd4bf28d8c37c35c"),
        (&k256, 40, "aaf3d8f1de5640c232f5b169b9c911e6"),
        (&k256, 64, "e1992190549f6ed5696a2c056c315410"),
    ] {
        assert_eq!(
            aes_cmac(key, &m[..len]).unwrap().to_vec(),
            hex(tag),
            "{} bytes",
            len
        );
    }
}

#[test]
fn a_key_of_no_aes_size_is_refused() {
    assert_eq!(aes_cmac(&[0; 20], b"x"), Err(Sw::EXEC_ERROR));
}

#[test]
fn doubling_reduces_by_the_field_polynomial() {
    let mut top = [0u8; BLOCK];
    top[0] = 0x80;
    let mut want = [0u8; BLOCK];
    want[BLOCK - 1] = RB;
    assert_eq!(dbl(&top), want);
    let mut low = [0u8; BLOCK];
    low[BLOCK - 1] = 0x01;
    let mut shifted = [0u8; BLOCK];
    shifted[BLOCK - 1] = 0x02;
    assert_eq!(dbl(&low), shifted);
}
