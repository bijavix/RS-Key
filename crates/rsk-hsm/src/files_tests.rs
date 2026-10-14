// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::tests::*;
use rsk_fs::storage::faults::ProbeStuck;

fn write_cmd(fid: u16, offset: Option<u16>, data: &[u8]) -> Vec<u8> {
    let mut d = Vec::new();
    if let Some(o) = offset {
        d.extend_from_slice(&[0x54, 2]);
        d.extend_from_slice(&o.to_be_bytes());
    }
    d.push(0x53);
    // The length forms OpenSC writes: the shortest one that fits.
    match data.len() {
        n @ 0..0x80 => d.push(n as u8),
        n @ 0x80..0x100 => d.extend_from_slice(&[0x81, n as u8]),
        n => {
            d.push(0x82);
            d.extend_from_slice(&(n as u16).to_be_bytes());
        }
    }
    d.extend_from_slice(data);
    let [p1, p2] = fid.to_be_bytes();
    apdu(CLA_ISO, INS_UPDATE_BINARY_ODD, p1, p2, &d)
}

fn read_cmd(fid: u16, offset: u16) -> Vec<u8> {
    let [p1, p2] = fid.to_be_bytes();
    let [o1, o2] = offset.to_be_bytes();
    apdu(CLA_ISO, INS_READ_BINARY_ODD, p1, p2, &[0x54, 2, o1, o2])
}

fn read_le(fid: u16, offset: u16, le: u8) -> Vec<u8> {
    let [p1, p2] = fid.to_be_bytes();
    let [o1, o2] = offset.to_be_bytes();
    vec![CLA_ISO, INS_READ_BINARY_ODD, p1, p2, 4, 0x54, 2, o1, o2, le]
}

fn select_ef(app: &mut HsmApplet, fs: &mut Fs<RamStorage>, fid: u16) -> (Sw, Vec<u8>) {
    run(app, fs, CLA_ISO, INS_SELECT, SEL_FID, 0, &fid.to_be_bytes())
}

use rsk_fs::storage::ram::RamStorage;

#[test]
fn public_objects_read_freely_and_write_with_the_pin() {
    let env = Env::new();
    let mut fs = new_fs();
    let mut app = env.applet(None);
    ready(&mut app, &mut fs);
    let fid = 0xCE01;
    assert_eq!(
        run_raw(&mut app, &mut fs, &write_cmd(fid, Some(0), b"cert")).0,
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    assert_eq!(verify(&mut app, &mut fs, PIN), Sw::OK);
    assert_eq!(
        run_raw(&mut app, &mut fs, &write_cmd(fid, Some(0), b"")).0,
        Sw::OK,
        "an empty file is created"
    );
    assert_eq!(
        run_raw(&mut app, &mut fs, &write_cmd(fid, Some(0), b"0123456789")).0,
        Sw::OK
    );
    assert_eq!(
        run_raw(&mut app, &mut fs, &write_cmd(fid, Some(10), b"abc")).0,
        Sw::OK,
        "a chunk appends"
    );
    select(&mut app, &mut fs);
    assert_eq!(
        run_raw(&mut app, &mut fs, &read_cmd(fid, 0)),
        (Sw::WARNING_EOF, b"0123456789abc".to_vec())
    );
    assert_eq!(
        run_raw(&mut app, &mut fs, &read_le(fid, 2, 4)),
        (Sw::OK, b"2345".to_vec())
    );
    assert_eq!(
        run_raw(&mut app, &mut fs, &read_le(fid, 11, 4)),
        (Sw::WARNING_EOF, b"bc".to_vec())
    );
    assert_eq!(
        run_raw(&mut app, &mut fs, &read_cmd(fid, 13)),
        (Sw::WARNING_EOF, vec![]),
        "at the end"
    );
    assert_eq!(
        run_raw(&mut app, &mut fs, &read_cmd(fid, 14)).0,
        Sw::WRONG_P1P2,
        "past the end"
    );
    // The plain READ BINARY reads the current EF, which the odd one selected.
    let (sw, r) = run(&mut app, &mut fs, CLA_ISO, INS_READ_BINARY, 0, 4, &[]);
    assert_eq!((sw, r), (Sw::WARNING_EOF, b"456789abc".to_vec()));
    assert_eq!(
        run(&mut app, &mut fs, CLA_ISO, INS_READ_BINARY, 0x81, 0, &[]).0,
        Sw::INCORRECT_P1P2,
        "no SFI"
    );
    // A rewrite from the start drops the old tail.
    assert_eq!(verify(&mut app, &mut fs, PIN), Sw::OK);
    assert_eq!(
        run_raw(&mut app, &mut fs, &write_cmd(fid, None, b"xy")).0,
        Sw::OK
    );
    assert_eq!(
        run_raw(&mut app, &mut fs, &read_cmd(fid, 0)),
        (Sw::WARNING_EOF, b"xy".to_vec())
    );
    assert_eq!(
        run_raw(&mut app, &mut fs, &write_cmd(fid, Some(3), b"z")).0,
        Sw::WRONG_P1P2,
        "no gaps"
    );
}

#[test]
fn the_current_ef_backs_the_zero_identifier() {
    let env = Env::new();
    let mut fs = new_fs();
    let mut app = env.applet(None);
    ready(&mut app, &mut fs);
    assert_eq!(
        run_raw(&mut app, &mut fs, &read_cmd(0, 0)).0,
        Sw::COMMAND_NOT_ALLOWED,
        "nothing selected"
    );
    assert_eq!(verify(&mut app, &mut fs, PIN), Sw::OK);
    assert_eq!(
        run_raw(&mut app, &mut fs, &write_cmd(0xCF07, Some(0), b"data")).0,
        Sw::OK
    );
    assert_eq!(
        run_raw(&mut app, &mut fs, &write_cmd(0, Some(4), b"!")).0,
        Sw::OK
    );
    assert_eq!(
        run_raw(&mut app, &mut fs, &read_cmd(0, 0)),
        (Sw::WARNING_EOF, b"data!".to_vec())
    );
}

#[test]
fn protected_data_is_sealed_and_needs_the_pin_both_ways() {
    let env = Env::new();
    let mut fs = new_fs();
    let mut app = env.applet(None);
    ready(&mut app, &mut fs);
    let fid = 0xCD02;
    let secret = [0x5Au8; 300];
    assert_eq!(verify(&mut app, &mut fs, PIN), Sw::OK);
    assert_eq!(
        run_raw(&mut app, &mut fs, &write_cmd(fid, Some(0), &secret[..200])).0,
        Sw::OK
    );
    assert_eq!(
        run_raw(
            &mut app,
            &mut fs,
            &write_cmd(fid, Some(200), &secret[200..])
        )
        .0,
        Sw::OK
    );
    let at = store::File::Object(Class::ProtData, 2).store();
    let mut raw = [0u8; 400];
    let n = fs.read(at, &mut raw).unwrap();
    assert_eq!(n, 300 + SEAL_OVERHEAD);
    assert!(
        !raw[..n].windows(16).any(|w| w == &secret[..16]),
        "no plaintext at rest"
    );
    assert_eq!(
        run_raw(&mut app, &mut fs, &read_cmd(fid, 0)),
        (Sw::WARNING_EOF, secret.to_vec())
    );
    let (sw, fcp) = select_ef(&mut app, &mut fs, fid);
    assert_eq!(sw, Sw::OK);
    assert_eq!(
        &fcp[2..6],
        &[TAG_FCP_SIZE, 2, 0x01, 0x2C],
        "the size is the plaintext's"
    );
    select(&mut app, &mut fs);
    assert_eq!(
        run_raw(&mut app, &mut fs, &read_cmd(fid, 0)).0,
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    // Sealed per object: moved to another identifier, it does not open.
    let other = store::File::Object(Class::ProtData, 3).store();
    fs.put(other, &raw[..n]).unwrap();
    assert_eq!(verify(&mut app, &mut fs, PIN), Sw::OK);
    assert_eq!(
        run_raw(&mut app, &mut fs, &read_cmd(0xCD03, 0)).0,
        Sw::MEMORY_FAILURE
    );
}

#[test]
fn key_objects_and_the_device_files_refuse_hosts() {
    let env = Env::new();
    let mut fs = new_fs();
    let mut app = env.applet(None);
    ready(&mut app, &mut fs);
    let key = store::File::Object(Class::Key, 1).store();
    fs.put(key, &[1, 2, 3]).unwrap();
    fs.put(store::REC_DEVAUT, &[0x7F, 0x21, 0]).unwrap();
    assert_eq!(verify(&mut app, &mut fs, PIN), Sw::OK);
    assert_eq!(
        run_raw(&mut app, &mut fs, &read_cmd(0xCC01, 0)).0,
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    assert_eq!(
        run_raw(&mut app, &mut fs, &write_cmd(0xCC01, Some(0), b"k")).0,
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    assert_eq!(
        run_raw(&mut app, &mut fs, &write_cmd(FID_DEVAUT, Some(0), b"k")).0,
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    assert_eq!(
        run_raw(&mut app, &mut fs, &read_cmd(FID_DEVAUT, 0)),
        (Sw::WARNING_EOF, vec![0x7F, 0x21, 0])
    );
    let del = |fid: u16| apdu(CLA_ISO, INS_DELETE_FILE, 2, 0, &fid.to_be_bytes());
    assert_eq!(
        run_raw(&mut app, &mut fs, &del(FID_DEVAUT)).0,
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    assert_eq!(
        run_raw(&mut app, &mut fs, &del(0xCC00)).0,
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    assert_eq!(
        run_raw(&mut app, &mut fs, &del(0x2F01)).0,
        Sw::FILE_NOT_FOUND
    );
    assert_eq!(run_raw(&mut app, &mut fs, &del(0xCC01)).0, Sw::OK);
    assert!(!fs.has_data(key));
    assert_eq!(
        run_raw(&mut app, &mut fs, &del(0xCC01)).0,
        Sw::FILE_NOT_FOUND
    );
}

#[test]
fn delete_needs_the_pin_and_a_two_byte_identifier() {
    let env = Env::new();
    let mut fs = new_fs();
    let mut app = env.applet(None);
    ready(&mut app, &mut fs);
    fs.put(store::File::Object(Class::Data, 9).store(), b"x")
        .unwrap();
    let del = apdu(CLA_ISO, INS_DELETE_FILE, 2, 0, &[0xCF, 0x09]);
    assert_eq!(
        run_raw(&mut app, &mut fs, &del).0,
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    assert_eq!(verify(&mut app, &mut fs, PIN), Sw::OK);
    assert_eq!(
        run(&mut app, &mut fs, CLA_ISO, INS_DELETE_FILE, 2, 0, &[0xCF]).0,
        Sw::WRONG_LENGTH
    );
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            CLA_ISO,
            INS_DELETE_FILE,
            1,
            0,
            &[0xCF, 9]
        )
        .0,
        Sw::INCORRECT_P1P2
    );
    assert_eq!(run_raw(&mut app, &mut fs, &del).0, Sw::OK);
}

#[test]
fn select_answers_an_fcp_for_each_file_and_6a82_otherwise() {
    let env = Env::new();
    let mut fs = new_fs();
    let mut app = env.applet(None);
    ready(&mut app, &mut fs);
    fs.put(store::File::Object(Class::CaCert, 4).store(), &[0u8; 300])
        .unwrap();
    let (sw, fcp) = select_ef(&mut app, &mut fs, 0xCA04);
    assert_eq!(sw, Sw::OK);
    assert_eq!(
        fcp,
        [
            0x62, 0x0B, 0x80, 2, 0x01, 0x2C, 0x82, 1, 0x01, 0x83, 2, 0xCA, 0x04
        ]
    );
    assert_eq!(select_ef(&mut app, &mut fs, 0xCA05).0, Sw::FILE_NOT_FOUND);
    assert_eq!(select_ef(&mut app, &mut fs, 0x1234).0, Sw::FILE_NOT_FOUND);
    assert_eq!(
        select_ef(&mut app, &mut fs, FID_TOKENINFO).0,
        Sw::OK,
        "EF.TokenInfo always exists"
    );
    // Every path form the driver can send, and no response data on request.
    for p1 in [
        SEL_FID,
        SEL_CHILD_EF,
        SEL_PATH_FROM_MF,
        SEL_PATH_FROM_CURRENT,
    ] {
        assert_eq!(
            run(
                &mut app,
                &mut fs,
                CLA_ISO,
                INS_SELECT,
                p1,
                0x0C,
                &[0xCA, 0x04]
            ),
            (Sw::OK, vec![])
        );
    }
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            CLA_ISO,
            INS_SELECT,
            SEL_FID,
            0x01,
            &[0xCA, 0x04]
        )
        .0,
        Sw::INCORRECT_P1P2
    );
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            CLA_ISO,
            INS_SELECT,
            0x01,
            0,
            &[0xCA, 0x04]
        )
        .0,
        Sw::INCORRECT_P1P2
    );
    assert_eq!(
        run(&mut app, &mut fs, CLA_ISO, INS_SELECT, SEL_FID, 0, &[0xCA]).0,
        Sw::WRONG_LENGTH
    );
    let (sw, fcp) = select_ef(&mut app, &mut fs, FID_MF);
    assert_eq!((sw, fcp[0]), (Sw::OK, TAG_FCP));
}

#[test]
fn selecting_the_application_by_name_ends_the_session() {
    let env = Env::new();
    let mut fs = new_fs();
    let mut app = env.applet(None);
    ready(&mut app, &mut fs);
    assert_eq!(verify(&mut app, &mut fs, PIN), Sw::OK);
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            CLA_ISO,
            INS_SELECT,
            SEL_DF_NAME,
            0x0C,
            HSM_AID
        ),
        (Sw::OK, vec![])
    );
    assert_eq!(status(&mut app, &mut fs, PIN_USER), Sw::retries(3));
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            CLA_ISO,
            INS_SELECT,
            SEL_DF_NAME,
            0,
            &[0xA0, 0]
        )
        .0,
        Sw::FILE_NOT_FOUND
    );
}

#[test]
fn enumerate_lists_every_live_object() {
    let env = Env::new();
    let mut fs = new_fs();
    let mut app = env.applet(None);
    ready(&mut app, &mut fs);
    assert_eq!(
        run(&mut app, &mut fs, CLA_PROPRIETARY, INS_ENUMERATE, 0, 0, &[]),
        (Sw::OK, vec![])
    );
    for (class, id) in [
        (Class::EeCert, 1),
        (Class::Key, 0),
        (Class::Key, 1),
        (Class::Prkd, 1),
        (Class::ProtData, 0xFF),
    ] {
        fs.put(store::File::Object(class, id).store(), &[1])
            .unwrap();
    }
    fs.put(store::REC_DEVAUT, &[1]).unwrap();
    let (sw, list) = run(&mut app, &mut fs, CLA_PROPRIETARY, INS_ENUMERATE, 0, 0, &[]);
    assert_eq!(sw, Sw::OK);
    assert_eq!(list, [0xCC, 0, 0xCC, 1, 0xC4, 1, 0xCD, 0xFF, 0xCE, 1]);
    assert_eq!(
        run(&mut app, &mut fs, CLA_PROPRIETARY, INS_ENUMERATE, 1, 0, &[]).0,
        Sw::INCORRECT_P1P2
    );
}

#[test]
fn enumerate_and_object_creation_fail_on_a_walk_cut_short() {
    let env = Env::new();
    let (stuck, medium) = ProbeStuck::new();
    let mut fs = Fs::new(stuck);
    fs.scan();
    let mut app = env.applet(None);
    ready(&mut app, &mut fs);
    assert_eq!(verify(&mut app, &mut fs, PIN), Sw::OK);
    medium.truncate_walk(true);
    assert_eq!(
        run(&mut app, &mut fs, CLA_PROPRIETARY, INS_ENUMERATE, 0, 0, &[]).0,
        Sw::MEMORY_FAILURE
    );
    assert_eq!(
        run_raw(&mut app, &mut fs, &write_cmd(0xCF01, Some(0), b"x")).0,
        Sw::MEMORY_FAILURE
    );
}

#[test]
fn object_creation_stops_where_enumerate_could_no_longer_list_them() {
    let env = Env::new();
    let mut fs = new_fs();
    let mut app = env.applet(None);
    ready(&mut app, &mut fs);
    assert_eq!(verify(&mut app, &mut fs, PIN), Sw::OK);
    let mut n = 0;
    'fill: for class in [Class::Data, Class::EeCert, Class::CaCert, Class::Cd] {
        for id in 0..=255u8 {
            if n == MAX_OBJECTS {
                break 'fill;
            }
            fs.put(store::File::Object(class, id).store(), &[1])
                .unwrap();
            n += 1;
        }
    }
    assert_eq!(
        run_raw(&mut app, &mut fs, &write_cmd(0xC901, Some(0), b"x")).0,
        Sw::FILE_FULL
    );
    assert_eq!(
        run_raw(&mut app, &mut fs, &write_cmd(0xCF00, Some(0), b"overwrite")).0,
        Sw::OK
    );
    let (sw, list) = run(&mut app, &mut fs, CLA_PROPRIETARY, INS_ENUMERATE, 0, 0, &[]);
    assert_eq!((sw, list.len()), (Sw::OK, 2 * MAX_OBJECTS));
}

#[test]
fn token_info_is_the_devices_around_the_label_the_host_names() {
    let mut out = [0u8; TOKENINFO_MAX];
    let n = token_info(DEFAULT_LABEL, &mut out);
    assert_eq!(label_of(&out[..n]), Ok(Some(DEFAULT_LABEL)));
    assert_eq!(
        &out[..n],
        b"\x30\x1B\x02\x01\x00\x0C\x06RS-Key\x80\x0ARS-Key HSM\x03\x02\x05\x20"
    );
    let n = token_info(&[b'x'; LABEL_MAX], &mut out);
    assert_eq!(n, TOKENINFO_MAX);
    // What OpenSC writes after an INITIALIZE: version, label, flags.
    let host = b"\x30\x10\x02\x01\x00\x80\x07my-labl\x03\x02\x05\x20";
    assert_eq!(label_of(host), Ok(Some(&b"my-labl"[..])));
    assert_eq!(label_of(b"\x30\x05\x02\x01\x00\x03\x00"), Ok(None));
    assert_eq!(label_of(b"\x31\x03\x02\x01\x00"), Err(Sw::WRONG_DATA));
    assert_eq!(
        label_of(b"\x30\x03\x02\x01\x00\x00"),
        Err(Sw::WRONG_DATA),
        "trailing bytes"
    );
    assert_eq!(
        label_of(b"\x30\x04\x02\x05\x00\x00"),
        Err(Sw::WRONG_DATA),
        "an object overrunning the body"
    );
    let mut long = vec![0x30, 35, 0x80, 33];
    long.extend_from_slice(&[b'y'; 33]);
    assert_eq!(label_of(&long), Err(Sw::WRONG_DATA));
}

#[test]
fn the_label_is_written_after_an_initialize_or_with_the_pin() {
    let env = Env::new();
    let mut fs = new_fs();
    let mut app = env.applet(None);
    select(&mut app, &mut fs);
    let host = b"\x30\x10\x02\x01\x00\x80\x07my-labl\x03\x02\x05\x20";
    assert_eq!(
        run_raw(&mut app, &mut fs, &write_cmd(FID_TOKENINFO, Some(0), host)).0,
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    assert_eq!(initialize(&mut app, &mut fs, OPT_RRC, &SO_PIN), Sw::OK);
    assert_eq!(
        run_raw(&mut app, &mut fs, &write_cmd(FID_TOKENINFO, Some(0), host)).0,
        Sw::OK
    );
    let (sw, ti) = run_raw(&mut app, &mut fs, &read_cmd(FID_TOKENINFO, 0));
    assert_eq!(sw, Sw::WARNING_EOF);
    assert_eq!(label_of(&ti), Ok(Some(&b"my-labl"[..])));
    assert!(ti.windows(MANUFACTURER.len()).any(|w| w == MANUFACTURER));
    // The grant ends with the selection that follows.
    select(&mut app, &mut fs);
    assert_eq!(
        run_raw(&mut app, &mut fs, &write_cmd(FID_TOKENINFO, Some(0), host)).0,
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    assert_eq!(verify(&mut app, &mut fs, PIN), Sw::OK);
    assert_eq!(
        run_raw(&mut app, &mut fs, &write_cmd(FID_TOKENINFO, Some(1), host)).0,
        Sw::WRONG_P1P2
    );
    let none = b"\x30\x05\x02\x01\x00\x03\x00";
    assert_eq!(
        run_raw(&mut app, &mut fs, &write_cmd(FID_TOKENINFO, Some(0), none)).0,
        Sw::OK
    );
    let (_, ti) = run_raw(&mut app, &mut fs, &read_cmd(FID_TOKENINFO, 0));
    assert_eq!(
        label_of(&ti),
        Ok(Some(DEFAULT_LABEL)),
        "no label is the default one"
    );
    let del = apdu(CLA_ISO, INS_DELETE_FILE, 2, 0, &FID_TOKENINFO.to_be_bytes());
    assert_eq!(
        run_raw(&mut app, &mut fs, &del).0,
        Sw::OK,
        "deleting the default is a no-op"
    );
}

#[test]
fn update_binary_parses_its_data_objects_strictly() {
    let env = Env::new();
    let mut fs = new_fs();
    let mut app = env.applet(None);
    ready(&mut app, &mut fs);
    assert_eq!(verify(&mut app, &mut fs, PIN), Sw::OK);
    let up = |d: &[u8]| apdu(CLA_ISO, INS_UPDATE_BINARY_ODD, 0xCF, 0x01, d);
    for bad in [
        &[0x54, 2, 0, 0][..],
        &[0x53, 1, 1, 0x53, 1, 2],
        &[0x54, 2, 0, 0, 0x54, 2, 0, 0, 0x53, 0],
        &[0x54, 3, 0, 0, 0, 0x53, 0],
        &[0x55, 1, 0, 0x53, 0],
        &[0x53, 3, 1],
    ] {
        assert_eq!(
            run_raw(&mut app, &mut fs, &up(bad)).0,
            Sw::WRONG_DATA,
            "{bad:02x?}"
        );
    }
    assert_eq!(
        run_raw(&mut app, &mut fs, &up(&[0x54, 1, 0, 0x53, 1, 7])).0,
        Sw::OK,
        "a one-byte offset"
    );
    let big = vec![1u8; MAX_PLAIN + 1];
    let mut d = vec![0x53, 0x82];
    d.extend_from_slice(&(big.len() as u16).to_be_bytes());
    d.extend_from_slice(&big);
    assert_eq!(run_raw(&mut app, &mut fs, &up(&d)).0, Sw::FILE_FULL);
}

#[test]
fn splice_writes_in_place_and_drops_the_tail() {
    let mut buf = *b"abcdef";
    assert_eq!(splice(&mut buf, 6, 2, b"XY"), Ok(4));
    assert_eq!(&buf[..4], b"abXY");
    assert_eq!(splice(&mut buf, 4, 5, b"Z"), Err(Sw::WRONG_P1P2));
    assert_eq!(splice(&mut buf, 4, 4, b"123"), Err(Sw::FILE_FULL));
}
