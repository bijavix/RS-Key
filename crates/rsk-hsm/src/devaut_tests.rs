// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::tests::*;
use rsk_crypto::read_fused;
use rsk_fs::storage::faults::{Cut, Op};

/// `2F02` as the driver reads it: SELECT, then READ BINARY until it ends.
fn read_devaut<S: Storage>(app: &mut crate::HsmApplet, fs: &mut Fs<S>) -> std::vec::Vec<u8> {
    select(app, fs);
    let (sw, data) = run(
        app,
        fs,
        CLA_ISO,
        INS_READ_BINARY_ODD,
        0x2F,
        0x02,
        &[0x54, 2, 0, 0],
    );
    assert_eq!(
        sw,
        Sw::WARNING_EOF,
        "the whole file in one read, short of Le"
    );
    data
}

#[test]
fn provisioning_mints_the_device_key_and_the_certificates_the_driver_binds_by() {
    let env = Env::new();
    let mut fs = new_fs();
    provision_with(&mut fs, None).unwrap();
    let mut app = env.applet(None);
    let devaut = read_devaut(&mut app, &mut fs);
    assert!(devaut.len() <= DEVAUT_MAX);

    // The first certificate: the device key, held by `RSK<serial>00001` — the
    // driver drops the last five characters and calls the rest the token serial.
    let mut objs = rsk_sdk::tlv::Tlv::new(&devaut);
    let (t1, device_cert) = objs.next().unwrap();
    let (t2, root_cert) = objs.next().unwrap();
    assert!(objs.next().is_none());
    assert_eq!((t1, t2), (TAG_CV_CERT, TAG_CV_CERT));
    let body = get(device_cert, TAG_CV_BODY);
    assert_eq!(get(body, TAG_CV_PROFILE), [CV_PROFILE]);
    let chr = reference(MNEMONIC_DEVICE, SERIAL);
    let root_chr = reference(MNEMONIC_ROOT, SERIAL);
    assert_eq!(get(body, TAG_CV_CHR), chr);
    assert_eq!(get(body, TAG_CV_CAR), root_chr);
    let pk = get(body, TAG_CV_PUBKEY);
    assert_eq!(get(pk, TAG_PK_OID), SigAlg::EcdsaSha256.oid());
    assert_eq!(get(pk, TAG_PK_PRIME), P256.p);
    assert_eq!(get(pk, TAG_PK_A), P256.a);
    let device_point = get(pk, TAG_PK_POINT).to_vec();

    // Signed by the root, over the body as it stands, tag and length included.
    let tlv_len = |v: &[u8]| 2 + rsk_sdk::tlv::format_len_size(v.len() as u16) + v.len();
    let signed = &device_cert[..tlv_len(body)];
    let sig = get(device_cert, TAG_CV_SIGNATURE);
    assert!(ecdsa_verifies(
        Curve::K256,
        &root_point(),
        &sha256(signed),
        sig
    ));

    // The second: the root, self-signed, with its curve written out.
    let rbody = get(root_cert, TAG_CV_BODY);
    assert_eq!(get(rbody, TAG_CV_CHR), root_chr);
    assert_eq!(get(rbody, TAG_CV_CAR), root_chr);
    let rpk = get(rbody, TAG_CV_PUBKEY);
    assert_eq!(get(rpk, TAG_PK_PRIME), K256.p);
    assert_eq!(get(rpk, TAG_PK_POINT), root_point());
    let rsig = get(root_cert, TAG_CV_SIGNATURE);
    assert!(ecdsa_verifies(
        Curve::K256,
        &root_point(),
        &sha256(&root_cert[..tlv_len(rbody)]),
        rsig
    ));

    // The device key is listed — so a host never picks `CC00` for a key of its
    // own — and it is the one the certificate names.
    let (_, list) = run(&mut app, &mut fs, CLA_PROPRIETARY, INS_ENUMERATE, 0, 0, &[]);
    assert!(list.chunks(2).any(|c| c == [PREFIX_KEY, KEY_ID_DEVICE]));
    let fused = read_fused(None);
    let dev = Device {
        serial_hash: &HASH,
        serial_id: &SERIAL,
        otp_key: fused.as_deref(),
    };
    let obj = keys::load_device(&mut fs, &dev, &mut TestRng(1))
        .unwrap()
        .unwrap();
    let key = PrivKey::from_scalar(Curve::P256, obj.material()).unwrap();
    let mut point = [0u8; MAX_EC_POINT];
    let n = key.public_point(&mut point).unwrap();
    assert_eq!(&point[..n], &device_point[..]);
}

#[test]
fn provisioning_again_writes_nothing_and_a_new_root_rewrites_the_certificates() {
    let (cut, medium) = Cut::new();
    let mut fs = Fs::new(cut);
    fs.scan();
    provision_with(&mut fs, None).unwrap();
    let first = medium.value(REC_DEVAUT).unwrap();
    medium.clear_ops();
    provision_with(&mut fs, None).unwrap();
    assert_eq!(
        medium.ops(),
        [],
        "deterministic signatures: nothing to rewrite"
    );

    // Another root (the OTP device key fused later): same device key, new chain.
    let fused = read_fused(None);
    let dev = Device {
        serial_hash: &HASH,
        serial_id: &SERIAL,
        otp_key: fused.as_deref(),
    };
    let other = k256::ecdsa::SigningKey::from_bytes(&[0x44; 32].into()).unwrap();
    let point: [u8; ROOT_POINT_LEN] = other
        .verifying_key()
        .to_sec1_point(false)
        .as_bytes()
        .try_into()
        .unwrap();
    let mut sign = |d: &[u8; 32]| {
        use k256::ecdsa::signature::hazmat::PrehashSigner;
        let s: k256::ecdsa::Signature = other.sign_prehash(d).ok()?;
        s.to_bytes().as_slice().try_into().ok()
    };
    provision(&dev, &mut fs, &mut TestRng(3), &point, &mut sign).unwrap();
    let ops = medium.ops();
    assert!(
        matches!(&ops[..], [Op::Write(f, _)] if *f == REC_DEVAUT),
        "{ops:?}"
    );
    let second = medium.value(REC_DEVAUT).unwrap();
    assert_ne!(first, second);
    let pk = |v: &[u8]| {
        let (_, cert) = rsk_sdk::tlv::Tlv::new(v).next().unwrap();
        get(get(get(cert, TAG_CV_BODY), TAG_CV_PUBKEY), TAG_PK_POINT).to_vec()
    };
    assert_eq!(pk(&first), pk(&second), "the device key stood");
}

#[test]
fn a_root_that_cannot_sign_or_a_store_that_cannot_write_leaves_what_was_there() {
    let mut fs = new_fs();
    let fused = read_fused(None);
    let dev = Device {
        serial_hash: &HASH,
        serial_id: &SERIAL,
        otp_key: fused.as_deref(),
    };
    let mut refuse = |_: &[u8; 32]| None;
    assert_eq!(
        provision(&dev, &mut fs, &mut TestRng(3), &root_point(), &mut refuse),
        Err(Sw::EXEC_ERROR)
    );
    assert!(!fs.has_data(REC_DEVAUT));

    let (cut, medium) = Cut::new();
    let mut fs = Fs::new(cut);
    fs.scan();
    provision_with(&mut fs, None).unwrap();
    let before = medium.value(REC_DEVAUT);
    medium.arm(0);
    let other = k256::ecdsa::SigningKey::from_bytes(&[0x44; 32].into()).unwrap();
    let point: [u8; ROOT_POINT_LEN] = other
        .verifying_key()
        .to_sec1_point(false)
        .as_bytes()
        .try_into()
        .unwrap();
    let mut sign = |d: &[u8; 32]| {
        use k256::ecdsa::signature::hazmat::PrehashSigner;
        let s: k256::ecdsa::Signature = other.sign_prehash(d).ok()?;
        s.to_bytes().as_slice().try_into().ok()
    };
    assert_eq!(
        provision(&dev, &mut fs, &mut TestRng(3), &point, &mut sign),
        Err(Sw::MEMORY_FAILURE)
    );
    assert_eq!(medium.value(REC_DEVAUT), before);
}

#[test]
fn burning_the_otp_root_carries_the_device_key_forward() {
    let (cut, medium) = Cut::new();
    let mut fs = Fs::new(cut);
    fs.scan();
    provision_with(&mut fs, None).unwrap();
    let before = medium.value(keys::fid(KEY_ID_DEVICE).get()).unwrap();
    fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
    medium.clear_ops();
    provision_with(&mut fs, OTP).unwrap();
    medium.assert_re_armed_before(keys::fid(KEY_ID_DEVICE).get(), |_| false, "OTP carry");
    assert_ne!(
        medium.value(keys::fid(KEY_ID_DEVICE).get()).unwrap(),
        before
    );
    // The carried key is the same key: the certificates did not change.
    let ops = medium.ops();
    assert!(
        !ops.iter()
            .any(|o| matches!(o, Op::Write(f, _) if *f == REC_DEVAUT)),
        "{ops:?}"
    );
    // And it now opens under the fused root alone.
    let fused = read_fused(OTP);
    let dev = Device {
        serial_hash: &HASH,
        serial_id: &SERIAL,
        otp_key: fused.as_deref(),
    };
    let at = keys::fid(KEY_ID_DEVICE);
    let mut sealed = [0u8; 200];
    let n = fs.read_key(at, &mut sealed).unwrap();
    let mut plain = [0u8; 200];
    assert!(
        crate::seal::open(
            &crate::seal::device_auth_key(&dev),
            at.get(),
            &[],
            &sealed[..n],
            &mut plain
        )
        .is_ok()
    );
}
