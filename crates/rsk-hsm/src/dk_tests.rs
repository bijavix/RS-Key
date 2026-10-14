// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::tests::{HASH, MKEK, SERIAL, TestRng, new_fs};
use rsk_fs::storage::faults::Cut;

fn dev(otp: bool) -> Device<'static> {
    Device {
        serial_hash: &HASH,
        serial_id: &SERIAL,
        otp_key: otp.then_some(&MKEK),
    }
}

const DK: [u8; KEY_LEN] = [0x11; KEY_LEN];
const L: [u8; KEY_LEN] = [0x22; KEY_LEN];

fn opened(o: Result<Opened, Sw>) -> Option<[u8; KEY_LEN]> {
    match o.unwrap() {
        Opened::Key(k) => Some(*k),
        Opened::Refused => None,
    }
}

#[test]
fn a_disarmed_record_opens_from_the_root_alone() {
    let mut fs = new_fs();
    let mut rng = TestRng(1);
    assert_eq!(factor(&mut fs), Ok(None));
    write(&mut fs, &dev(false), &mut rng, &DK, Factor::None, None).unwrap();
    assert_eq!(factor(&mut fs), Ok(Some(Factor::None)));
    assert_eq!(
        opened(open_and_migrate(&mut fs, &dev(false), &mut rng, None)),
        Some(DK)
    );
    assert_eq!(
        opened(open_and_migrate(&mut fs, &dev(false), &mut rng, Some(&L))),
        None
    );
}

#[test]
fn an_armed_record_needs_its_secret() {
    let mut fs = new_fs();
    let mut rng = TestRng(1);
    write(
        &mut fs,
        &dev(false),
        &mut rng,
        &DK,
        Factor::HostKey,
        Some(&L),
    )
    .unwrap();
    assert_eq!(factor(&mut fs), Ok(Some(Factor::HostKey)));
    assert_eq!(
        opened(open_and_migrate(&mut fs, &dev(false), &mut rng, None)),
        None
    );
    assert_eq!(
        opened(open_and_migrate(
            &mut fs,
            &dev(false),
            &mut rng,
            Some(&[0x23; KEY_LEN])
        )),
        None
    );
    assert_eq!(
        opened(open_and_migrate(&mut fs, &dev(false), &mut rng, Some(&L))),
        Some(DK)
    );
    assert_eq!(
        opened(open_and_migrate(&mut fs, &dev(true), &mut rng, Some(&L))),
        Some(DK),
        "and migrates"
    );
    assert_eq!(
        opened(open_and_migrate(&mut fs, &dev(false), &mut rng, Some(&L))),
        None,
        "off the old root"
    );
}

#[test]
fn a_factor_without_a_secret_is_refused_before_anything_is_written() {
    let mut fs = new_fs();
    let mut rng = TestRng(1);
    assert_eq!(
        write(&mut fs, &dev(false), &mut rng, &DK, Factor::HostKey, None),
        Err(Sw::UNKNOWN)
    );
    assert_eq!(
        write(&mut fs, &dev(false), &mut rng, &DK, Factor::None, Some(&L)),
        Err(Sw::UNKNOWN)
    );
    assert_eq!(factor(&mut fs), Ok(None));
}

#[test]
fn the_boot_pass_moves_a_disarmed_record_and_re_arms_the_lap_first() {
    let (cut, medium) = Cut::new();
    let mut fs = Fs::new(cut);
    fs.scan();
    let mut rng = TestRng(1);
    write(&mut fs, &dev(false), &mut rng, &DK, Factor::None, None).unwrap();
    fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
    medium.clear_ops();
    migrate_seal(&dev(true), &mut fs, &mut rng);
    medium.assert_re_armed_before(REC_DEV.get(), |_| false, "migrate_seal");
    assert_eq!(
        opened(open_and_migrate(&mut fs, &dev(false), &mut rng, None)),
        None
    );
    medium.clear_ops();
    migrate_seal(&dev(true), &mut fs, &mut rng);
    assert!(
        medium.ops().is_empty(),
        "a record on the current root is left alone"
    );
}

#[test]
fn a_refused_re_arm_skips_the_migration_but_still_opens() {
    let (cut, medium) = Cut::new();
    let mut fs = Fs::new(cut);
    fs.scan();
    let mut rng = TestRng(1);
    write(&mut fs, &dev(false), &mut rng, &DK, Factor::None, None).unwrap();
    fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
    medium.arm(0);
    assert_eq!(
        opened(open_and_migrate(&mut fs, &dev(true), &mut rng, None)),
        Some(DK)
    );
    medium.arm(u32::MAX);
    assert_eq!(
        opened(open_and_migrate(&mut fs, &dev(false), &mut rng, None)),
        Some(DK),
        "still on the old root"
    );
}

#[test]
fn the_boot_pass_leaves_armed_absent_and_pre_otp_devices_alone() {
    let (cut, medium) = Cut::new();
    let mut fs = Fs::new(cut);
    fs.scan();
    let mut rng = TestRng(1);
    migrate_seal(&dev(true), &mut fs, &mut rng);
    write(
        &mut fs,
        &dev(false),
        &mut rng,
        &DK,
        Factor::HostKey,
        Some(&L),
    )
    .unwrap();
    medium.clear_ops();
    migrate_seal(&dev(true), &mut fs, &mut rng);
    migrate_seal(&dev(false), &mut fs, &mut rng);
    assert!(medium.ops().is_empty());
}

#[test]
fn a_record_that_does_not_parse_is_a_memory_failure() {
    let mut fs = new_fs();
    let mut rng = TestRng(1);
    fs.put_key(REC_DEV, Sealed::wrap(&[1, 0, 0, 1, 2, 3]))
        .unwrap();
    assert_eq!(factor(&mut fs), Err(Sw::MEMORY_FAILURE));
    assert!(matches!(
        open_and_migrate(&mut fs, &dev(false), &mut rng, None),
        Err(Sw::MEMORY_FAILURE)
    ));
}
