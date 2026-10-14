// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn objects_close_to_the_shortest_length_that_holds_them() {
    for (content, header) in [
        (0usize, &[0x30u8, 0x00][..]),
        (0x7F, &[0x30, 0x7F]),
        (0x80, &[0x30, 0x81, 0x80]),
        (0xFF, &[0x30, 0x81, 0xFF]),
        (0x100, &[0x30, 0x82, 0x01, 0x00]),
        (0x4A0, &[0x30, 0x82, 0x04, 0xA0]),
    ] {
        let mut buf = [0u8; 0x500];
        let mut w = Writer::new(&mut buf);
        let o = w.open(0x30).unwrap();
        w.raw(&std::vec![0xAB; content]).unwrap();
        w.close(o).unwrap();
        assert_eq!(&w.as_slice()[..header.len()], header, "{content:#x}");
        assert_eq!(w.len(), header.len() + content);
        assert!(w.as_slice()[header.len()..].iter().all(|&b| b == 0xAB));
    }
}

#[test]
fn nested_objects_keep_every_range_contiguous() {
    let mut buf = [0u8; 600];
    let mut w = Writer::new(&mut buf);
    let outer = w.open(TAG_CV_AUTH_REQUEST).unwrap();
    let inner = w.open(TAG_CV_CERT).unwrap();
    w.put(TAG_CV_SIGNATURE, &[0x55; 300]).unwrap();
    w.close(inner).unwrap();
    w.put(TAG_CV_CAR, b"CAR").unwrap();
    w.close(outer).unwrap();
    let out = w.as_slice();
    let mut want = std::vec![0x67, 0x82, 0x01, 0x3B, 0x7F, 0x21, 0x82, 0x01, 0x31];
    want.extend_from_slice(&[0x5F, 0x37, 0x82, 0x01, 0x2C]);
    want.extend_from_slice(&[0x55; 300]);
    want.extend_from_slice(&[0x42, 0x03, b'C', b'A', b'R']);
    assert_eq!(out, &want[..]);
}

#[test]
fn a_full_buffer_is_an_error_not_a_truncation() {
    let mut buf = [0u8; 8];
    let mut w = Writer::new(&mut buf);
    assert_eq!(w.put(0x42, &[0; 6]), Ok(()));
    assert_eq!(w.put(0x42, &[0; 1]), Err(Sw::EXEC_ERROR));
    let mut small = [0u8; 4];
    let mut w = Writer::new(&mut small);
    assert!(w.open(0x7F49).is_err());
}

#[test]
fn signature_algorithms_are_the_tr_03110_identifiers() {
    // id-TA-ECDSA-SHA-256 and id-TA-RSA-v1-5-SHA-256: the two the driver sends.
    assert_eq!(
        SigAlg::EcdsaSha256.oid(),
        [0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x02, 0x02, 0x03]
    );
    assert_eq!(
        SigAlg::RsaV15Sha256.oid(),
        [0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x02, 0x01, 0x02]
    );
    for a in SigAlg::ALL {
        assert_eq!(SigAlg::from_oid(&a.oid()), Some(a));
    }
    let mut sha1 = SigAlg::EcdsaSha256.oid();
    sha1[OID_LEN - 1] = 0x01;
    assert_eq!(SigAlg::from_oid(&sha1), None, "ECDSA-SHA-1 is not accepted");
    assert_eq!(SigAlg::from_oid(&sha1[..OID_LEN - 1]), None);
}

#[test]
fn references_spell_the_reported_serial() {
    // serial4 clears the top six bits of the first chip-id byte.
    let id = [0xFF, 0xBC, 0x61, 0x4E, 0, 0, 0, 0];
    let want = u32::from_be_bytes([0x03, 0xBC, 0x61, 0x4E]);
    let r = reference(MNEMONIC_DEVICE, id);
    assert_eq!(&r[..3], b"RSK");
    assert_eq!(
        core::str::from_utf8(&r[3..11]).unwrap(),
        std::format!("{want:08}")
    );
    assert_eq!(&r[11..], b"00001");
    assert!(is_reference(&r));
    assert!(!is_reference(&[]));
    assert!(!is_reference(&[b'A'; CV_REF_MAX + 1]));
    assert!(!is_reference(b"A\x00B"));
}

#[test]
fn ecdsa_signatures_are_minimal_der_integers() {
    let mut buf = [0u8; 80];
    let mut w = Writer::new(&mut buf);
    let mut raw = [0u8; 64];
    raw[0] = 0x00;
    raw[1] = 0x00;
    raw[2] = 0x12;
    raw[32] = 0x80;
    put_ecdsa_der(&mut w, &raw).unwrap();
    let out = w.as_slice();
    // r drops its two leading zeros; s keeps all 32 bytes behind a sign byte.
    assert_eq!(&out[..4], &[0x30, 0x43, 0x02, 0x1E]);
    assert_eq!(out[4], 0x12);
    assert_eq!(&out[34..37], &[0x02, 0x21, 0x00]);
    assert_eq!(out[37], 0x80);
    assert_eq!(out.len(), 2 + 0x43);

    let mut w = Writer::new(&mut buf);
    put_ecdsa_der(&mut w, &[0u8; 64]).unwrap();
    assert_eq!(
        w.as_slice(),
        &[0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00]
    );
    let mut w = Writer::new(&mut buf);
    assert_eq!(put_ecdsa_der(&mut w, &[1, 2, 3]), Err(Sw::EXEC_ERROR));
}
