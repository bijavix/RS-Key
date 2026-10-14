// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::tests::new_fs;
use rsk_fs::storage::faults::ProbeStuck;

#[test]
fn every_class_maps_into_the_range_and_back() {
    for class in Class::ALL {
        for id in [0u8, 1, 0x80, 0xFF] {
            let fid = u16::from_be_bytes([class.prefix(), id]);
            let file = File::from_fid(fid).unwrap();
            assert_eq!(file, File::Object(class, id));
            let at = file.store();
            assert!(
                (RANGE_LO..=RANGE_HI).contains(&at),
                "{fid:#06x} -> {at:#06x}"
            );
            assert_eq!(at & 0xFF, id as u16);
        }
    }
    let bases: Vec<u16> = Class::ALL.iter().map(|c| c.base()).collect();
    let mut sorted = bases.clone();
    sorted.dedup();
    assert_eq!(bases, sorted, "one 256-id page per class, none shared");
    assert_eq!(File::from_fid(FID_DEVAUT), Some(File::DevAut));
    assert_eq!(File::from_fid(FID_TOKENINFO), Some(File::TokenInfo));
    assert_eq!(File::from_fid(FID_STAGING), Some(File::Staging));
    assert_eq!(File::from_fid(0x2F00), None);
    assert_eq!(File::from_fid(0xCB01), None);
}

#[test]
fn no_record_lands_on_a_fid_the_rest_of_the_tree_owns() {
    let records = [
        REC_INIT.get(),
        REC_COUNTERS,
        REC_DEV.get(),
        REC_USER.get(),
        REC_DKEK.get(),
        REC_LABEL,
        REC_DEVAUT,
        REC_STAGING,
    ];
    for fid in records {
        assert!((RANGE_LO..=RANGE_HI).contains(&fid));
        assert!(
            fid < Class::Key.base(),
            "{fid:#06x} is a singleton, under the object pages"
        );
    }
    for fid in [
        rsk_fs::EF_HARDENED,
        rsk_fs::EF_META,
        rsk_fs::EF_SCRUB_FILLER,
    ] {
        assert!(!(RANGE_LO..=RANGE_HI).contains(&fid), "{fid:#06x}");
    }
    assert!(Class::Key.sealed() && Class::ProtData.sealed());
    assert!(!Class::EeCert.sealed() && !Class::Data.sealed());
}

#[test]
fn the_sweep_keeps_only_the_device_identity() {
    let mut fs = new_fs();
    let device_key = File::Object(Class::Key, KEY_ID_DEVICE).store();
    for fid in [
        REC_INIT.get(),
        REC_COUNTERS,
        REC_DEVAUT,
        device_key,
        0xA101,
        0xA8FF,
        0xA9FF,
        0x1234,
    ] {
        fs.put(fid, &[1]).unwrap();
    }
    assert_eq!(sweep(&mut fs), Ok(()));
    for fid in [REC_INIT.get(), REC_COUNTERS, 0xA101, 0xA8FF] {
        assert!(!fs.has_data(fid), "{fid:#06x}");
    }
    for fid in [REC_DEVAUT, device_key, 0xA9FF, 0x1234] {
        assert!(fs.has_data(fid), "{fid:#06x} is not the sweep's");
    }
}

#[test]
fn the_sweep_crosses_its_batch_and_a_truncated_walk_fails_it() {
    let mut fs = new_fs();
    for id in 0..80u16 {
        fs.put(Class::Data.base() | id, &[1]).unwrap();
    }
    assert_eq!(sweep(&mut fs), Ok(()));
    assert!(
        live_objects(&mut fs)
            .unwrap()
            .iter()
            .flatten()
            .all(|b| *b == 0)
    );

    let (stuck, medium) = ProbeStuck::new();
    let mut fs = Fs::new(stuck);
    fs.scan();
    fs.put(0xA101, &[1]).unwrap();
    medium.truncate_walk(true);
    assert_eq!(sweep(&mut fs), Err(Sw::MEMORY_FAILURE));
    assert!(live_objects(&mut fs).is_none());
}

#[test]
fn live_objects_reads_one_walk_into_a_bitmap() {
    let mut fs = new_fs();
    fs.put(Class::EeCert.base() | 3, &[1]).unwrap();
    fs.put(Class::Key.base() | 0xFF, &[1]).unwrap();
    fs.put(REC_LABEL, b"label").unwrap();
    let live = live_objects(&mut fs).unwrap();
    let ee = Class::ALL.iter().position(|c| *c == Class::EeCert).unwrap();
    assert_eq!(live[ee][0], 1 << 3);
    assert_eq!(live[0][31], 0x80);
    assert_eq!(
        live.iter().flatten().map(|b| b.count_ones()).sum::<u32>(),
        2
    );
}

#[test]
fn plain_reads_tell_a_fault_and_an_oversized_value_from_an_absence() {
    let (stuck, medium) = ProbeStuck::new();
    let mut fs = Fs::new(stuck);
    fs.scan();
    fs.put(REC_LABEL, b"0123456789").unwrap();
    let mut small = [0u8; 4];
    assert_eq!(
        read_plain(&mut fs, REC_LABEL, &mut small),
        Err(Sw::MEMORY_FAILURE)
    );
    let mut buf = [0u8; 16];
    assert_eq!(read_plain(&mut fs, REC_LABEL, &mut buf), Ok(Some(10)));
    assert_eq!(read_plain(&mut fs, REC_STAGING, &mut buf), Ok(None));
    assert_eq!(size(&mut fs, REC_LABEL), Ok(Some(10)));
    medium.stick(Some(REC_LABEL));
    assert_eq!(
        read_plain(&mut fs, REC_LABEL, &mut buf),
        Err(Sw::MEMORY_FAILURE)
    );
    assert_eq!(size(&mut fs, REC_LABEL), Err(Sw::MEMORY_FAILURE));
}
