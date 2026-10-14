// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use num_bigint_dig::BigUint;
use rsk_ec::{EcError, MAX_EC_POINT, PrivKey};

fn int(b: &[u8]) -> BigUint {
    BigUint::from_bytes_be(b)
}

/// The scalar `k` as a big-endian field-width string.
fn scalar(d: &Domain, k: &BigUint) -> std::vec::Vec<u8> {
    let b = k.to_bytes_be();
    let mut out = std::vec![0u8; d.field_len()];
    out[d.field_len() - b.len()..].copy_from_slice(&b);
    out
}

fn point_of(d: &Domain, k: &BigUint) -> Result<std::vec::Vec<u8>, EcError> {
    let key = PrivKey::from_scalar(d.curve, &scalar(d, k)).unwrap();
    let mut pt = [0u8; MAX_EC_POINT];
    let n = key.public_point(&mut pt)?;
    Ok(pt[..n].to_vec())
}

/// Each table entry is checked against the arithmetic it claims, not against a
/// second copy of itself: `G` is on `y² = x³ + ax + b (mod p)` and is what the
/// curve library calls `1·G`; `n − 1` is the largest scalar it accepts and `n`
/// the first it refuses, with `(n − 1)·G = −G`.
#[test]
fn every_curve_is_the_curve_its_parameters_say() {
    for d in ALL {
        let w = d.field_len();
        assert_eq!(d.p.len(), w);
        assert_eq!(d.a.len(), w);
        assert_eq!(d.b.len(), w);
        assert_eq!(d.n.len(), w);
        assert_eq!(d.g.len(), d.point_len());
        assert_eq!(d.h, [1]);
        let p = int(d.p);
        let (x, y) = (int(&d.g[1..1 + w]), int(&d.g[1 + w..]));
        let rhs = (&x * &x * &x + int(d.a) * &x + int(d.b)) % &p;
        assert_eq!((&y * &y) % &p, rhs, "{:?}: G is not on the curve", d.curve);

        let one = BigUint::from(1u8);
        assert_eq!(point_of(d, &one).unwrap(), d.g, "{:?}: 1·G", d.curve);
        let n = int(d.n);
        let minus_g = point_of(d, &(&n - &one)).unwrap();
        assert_eq!(&minus_g[1..1 + w], &d.g[1..1 + w]);
        assert_eq!(
            int(&minus_g[1 + w..]),
            &p - &y,
            "{:?}: (n−1)·G = −G",
            d.curve
        );
        assert_eq!(point_of(d, &n), Err(EcError::Failed), "{:?}: n", d.curve);
    }
}

#[test]
fn a_curve_is_found_by_its_prime_and_first_coefficient_only() {
    for d in ALL {
        assert_eq!(by_prime(d.p, d.a).map(|f| f.curve), Some(d.curve));
        assert_eq!(of(d.curve).map(|f| f.curve), Some(d.curve));
    }
    assert!(by_prime(P256.p, P384.a).is_none());
    assert!(by_prime(&P256.p[1..], &P256.a[1..]).is_none());
    assert!(of(Curve::Bp256).is_none());
}
