// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

fn init() -> Init {
    Init {
        options: 0x0121,
        retry_max: 3,
        so_verifier: [0xAB; KEY_LEN],
        so_envelope: [0xCD; SEALED_KEY_LEN],
    }
}

#[test]
fn the_initialization_record_round_trips_and_binds_only_its_header() {
    let b = init().encode();
    let back = Init::decode(&b).unwrap();
    assert_eq!((back.options, back.retry_max), (0x0121, 3));
    assert_eq!(back.so_verifier, [0xAB; KEY_LEN]);
    assert_eq!(back.so_envelope, [0xCD; SEALED_KEY_LEN]);
    assert_eq!(&b[..INIT_HDR_LEN], &Init::header(0x0121, 3));
}

#[test]
fn the_initialization_record_refuses_what_no_build_wrote() {
    let good = init().encode();
    assert!(Init::decode(&good[..good.len() - 1]).is_none());
    let mut longer = good.to_vec();
    longer.push(0);
    assert!(Init::decode(&longer).is_none());
    for (i, v) in [(0, 2u8), (3, 0), (3, USER_RETRIES_MAX + 1)] {
        let mut b = good;
        b[i] = v;
        assert!(Init::decode(&b).is_none(), "byte {i} = {v}");
    }
}

#[test]
fn counters_round_trip_within_their_bounds() {
    let c = Counters { user: 2, so: 15 };
    assert_eq!(Counters::decode(&c.encode()), Some(c));
    assert_eq!(Counters::decode(&[1, USER_RETRIES_MAX + 1, 1]), None);
    assert_eq!(Counters::decode(&[1, 1, SO_RETRIES + 1]), None);
    assert_eq!(Counters::decode(&[2, 1, 1]), None);
    assert_eq!(Counters::decode(&[1, 1]), None);
}

#[test]
fn factor_ids_are_frozen() {
    for f in [Factor::None, Factor::HostKey, Factor::Fido2HmacSecret] {
        assert_eq!(Factor::from_id(f.id()), Some(f));
    }
    assert_eq!(
        [
            Factor::None.id(),
            Factor::HostKey.id(),
            Factor::Fido2HmacSecret.id()
        ],
        [0, 1, 2]
    );
    assert_eq!(Factor::from_id(3), None);
}

#[test]
fn the_device_record_carries_its_lock_in_the_bound_header() {
    let mut hdr = [0u8; DEV_HDR_MAX];
    let params = [9u8; 5];
    let h = DevRecord::header(Factor::Fido2HmacSecret, &params, &mut hdr);
    let mut rec = hdr[..h].to_vec();
    rec.extend_from_slice(&[0xEE; SEALED_KEY_LEN]);
    let d = DevRecord::decode(&rec).unwrap();
    assert_eq!(d.factor, Factor::Fido2HmacSecret);
    assert_eq!(d.bind, &hdr[..h]);
    assert_eq!(d.envelope, &[0xEE; SEALED_KEY_LEN]);
    assert!(rec.len() <= DEV_MAX_LEN);

    let mut short = rec.clone();
    short.pop();
    assert!(DevRecord::decode(&short).is_none());
    let mut bad_factor = rec.clone();
    bad_factor[1] = 9;
    assert!(DevRecord::decode(&bad_factor).is_none());
    let mut bad_len = rec.clone();
    bad_len[2] = 6;
    assert!(DevRecord::decode(&bad_len).is_none());
    let mut bad_ver = rec;
    bad_ver[0] = 0;
    assert!(DevRecord::decode(&bad_ver).is_none());
}
