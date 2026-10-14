// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Card-verifiable certificates (BSI TR-03110 part 3): the body a GENERATE KEY
//! PAIR answers inside an authenticated request, and the two certificates of
//! `2F02`. Written forward into one buffer with lengths filled in as each object
//! closes, so every range that gets signed is contiguous where it is sent.

use rsk_sdk::Sw;

use crate::consts::*;
use crate::digest::Hash;
use crate::domain::Domain;

/// A forward BER-TLV writer over a fixed buffer.
pub(crate) struct Writer<'b> {
    buf: &'b mut [u8],
    n: usize,
}

/// A constructed object still open: where its length goes.
pub(crate) struct Open {
    at: usize,
}

/// A length field is at most `82 hi lo`.
const LEN_MAX_BYTES: usize = 3;

/// The definite-length encoding of `len`, and how many of its bytes are used.
fn length(len: usize) -> Result<([u8; LEN_MAX_BYTES], usize), Sw> {
    Ok(match len {
        0..=0x7F => ([len as u8, 0, 0], 1),
        0x80..=0xFF => ([0x81, len as u8, 0], 2),
        0x100..=0xFFFF => {
            let [hi, lo] = (len as u16).to_be_bytes();
            ([0x82, hi, lo], 3)
        }
        _ => return Err(Sw::EXEC_ERROR),
    })
}

impl<'b> Writer<'b> {
    pub(crate) fn new(buf: &'b mut [u8]) -> Self {
        Writer { buf, n: 0 }
    }

    pub(crate) fn len(&self) -> usize {
        self.n
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.buf[..self.n]
    }

    pub(crate) fn raw(&mut self, b: &[u8]) -> Result<(), Sw> {
        let end = self.n + b.len();
        self.buf
            .get_mut(self.n..end)
            .ok_or(Sw::EXEC_ERROR)?
            .copy_from_slice(b);
        self.n = end;
        Ok(())
    }

    fn tag(&mut self, tag: u16) -> Result<(), Sw> {
        let [hi, lo] = tag.to_be_bytes();
        if hi == 0 {
            self.raw(&[lo])
        } else {
            self.raw(&[hi, lo])
        }
    }

    /// One primitive object.
    pub(crate) fn put(&mut self, tag: u16, value: &[u8]) -> Result<(), Sw> {
        self.tag(tag)?;
        let (l, ln) = length(value.len())?;
        self.raw(&l[..ln])?;
        self.raw(value)
    }

    /// Start a constructed object; its content follows until [`Self::close`].
    pub(crate) fn open(&mut self, tag: u16) -> Result<Open, Sw> {
        self.tag(tag)?;
        let at = self.n;
        self.raw(&[0; LEN_MAX_BYTES])?;
        Ok(Open { at })
    }

    /// Write the object's length and move its content up against it.
    pub(crate) fn close(&mut self, o: Open) -> Result<(), Sw> {
        let start = o.at + LEN_MAX_BYTES;
        let (l, ln) = length(self.n - start)?;
        self.buf.copy_within(start..self.n, o.at + ln);
        self.buf[o.at..o.at + ln].copy_from_slice(&l[..ln]);
        self.n -= LEN_MAX_BYTES - ln;
        Ok(())
    }
}

/// How a certificate or a request is signed: the TR-03110 terminal-authentication
/// object identifiers this device writes and accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SigAlg {
    EcdsaSha256,
    EcdsaSha384,
    EcdsaSha512,
    RsaV15Sha256,
    RsaV15Sha512,
    RsaPssSha256,
    RsaPssSha512,
}

/// `id-TA` (0.4.0.127.0.7.2.2.2); the last two arcs name the algorithm.
const ID_TA: [u8; 8] = [0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x02];
/// The length of every OID below.
pub(crate) const OID_LEN: usize = ID_TA.len() + 2;

impl SigAlg {
    const ALL: [SigAlg; 7] = [
        SigAlg::EcdsaSha256,
        SigAlg::EcdsaSha384,
        SigAlg::EcdsaSha512,
        SigAlg::RsaV15Sha256,
        SigAlg::RsaV15Sha512,
        SigAlg::RsaPssSha256,
        SigAlg::RsaPssSha512,
    ];

    /// The arcs after `id-TA`: `1.x` for RSA, `2.x` for ECDSA.
    const fn arcs(self) -> [u8; 2] {
        match self {
            SigAlg::RsaV15Sha256 => [1, 2],
            SigAlg::RsaPssSha256 => [1, 4],
            SigAlg::RsaV15Sha512 => [1, 5],
            SigAlg::RsaPssSha512 => [1, 6],
            SigAlg::EcdsaSha256 => [2, 3],
            SigAlg::EcdsaSha384 => [2, 4],
            SigAlg::EcdsaSha512 => [2, 5],
        }
    }

    pub(crate) fn oid(self) -> [u8; OID_LEN] {
        let mut o = [0u8; OID_LEN];
        o[..ID_TA.len()].copy_from_slice(&ID_TA);
        o[ID_TA.len()..].copy_from_slice(&self.arcs());
        o
    }

    pub(crate) fn from_oid(oid: &[u8]) -> Option<SigAlg> {
        SigAlg::ALL.into_iter().find(|a| a.oid() == oid)
    }

    pub(crate) const fn is_ec(self) -> bool {
        matches!(
            self,
            SigAlg::EcdsaSha256 | SigAlg::EcdsaSha384 | SigAlg::EcdsaSha512
        )
    }

    pub(crate) const fn hash(self) -> Hash {
        match self {
            SigAlg::EcdsaSha256 | SigAlg::RsaV15Sha256 | SigAlg::RsaPssSha256 => Hash::Sha256,
            SigAlg::EcdsaSha384 => Hash::Sha384,
            SigAlg::EcdsaSha512 | SigAlg::RsaV15Sha512 | SigAlg::RsaPssSha512 => Hash::Sha512,
        }
    }
}

/// The public half a body carries.
pub(crate) enum PublicKey<'k> {
    /// An uncompressed point, with its curve written out in full.
    Ec {
        domain: &'static Domain,
        point: &'k [u8],
    },
    Rsa {
        modulus: &'k [u8],
        exponent: &'k [u8],
    },
}

/// The public key object, `7F49`: the algorithm, then the key's own objects in
/// the order a body lists them.
pub(crate) fn put_public_key(w: &mut Writer, alg: SigAlg, key: &PublicKey) -> Result<(), Sw> {
    let o = w.open(TAG_CV_PUBKEY)?;
    w.put(TAG_PK_OID, &alg.oid())?;
    match key {
        PublicKey::Ec { domain, point } => {
            w.put(TAG_PK_PRIME, domain.p)?;
            w.put(TAG_PK_A, domain.a)?;
            w.put(TAG_PK_B, domain.b)?;
            w.put(TAG_PK_BASE, domain.g)?;
            w.put(TAG_PK_ORDER, domain.n)?;
            w.put(TAG_PK_POINT, point)?;
            w.put(TAG_PK_COFACTOR, domain.h)?;
        }
        PublicKey::Rsa { modulus, exponent } => {
            w.put(TAG_PK_PRIME, modulus)?;
            w.put(TAG_PK_A, exponent)?;
        }
    }
    w.close(o)
}

/// A certificate body, `7F4E`. Returns where it starts, so the caller can sign
/// the whole object once it is written.
pub(crate) fn put_body(
    w: &mut Writer,
    car: Option<&[u8]>,
    alg: SigAlg,
    key: &PublicKey,
    chr: &[u8],
) -> Result<usize, Sw> {
    let start = w.len();
    let o = w.open(TAG_CV_BODY)?;
    w.put(TAG_CV_PROFILE, &[CV_PROFILE])?;
    if let Some(car) = car {
        w.put(TAG_CV_CAR, car)?;
    }
    put_public_key(w, alg, key)?;
    w.put(TAG_CV_CHR, chr)?;
    w.close(o)?;
    Ok(start)
}

/// Whether `r` can be a certification authority or holder reference: one to
/// sixteen printable characters.
pub(crate) fn is_reference(r: &[u8]) -> bool {
    (1..=CV_REF_MAX).contains(&r.len()) && r.iter().all(|b| (0x20..=0x7E).contains(b))
}

/// The serial every applet reports, as the eight decimal digits a reference
/// carries.
fn serial_digits(serial_id: [u8; 8]) -> [u8; 8] {
    let mut v = u32::from_be_bytes(rsk_sdk::serial4(serial_id));
    let mut d = [b'0'; 8];
    for c in d.iter_mut().rev() {
        *c = b'0' + (v % 10) as u8;
        v /= 10;
    }
    d
}

/// The sequence number every reference here ends in. The driver drops the last
/// five characters of the device's holder reference to get the token serial.
const SEQUENCE: &[u8; 5] = b"00001";
/// The device's own key: its holder reference reads `RSK` and the serial.
pub(crate) const MNEMONIC_DEVICE: &[u8; 3] = b"RSK";
/// The device root, the key the device certificate is signed with.
pub(crate) const MNEMONIC_ROOT: &[u8; 3] = b"RSD";

/// A reference: mnemonic, serial, sequence number — sixteen characters.
pub(crate) fn reference(mnemonic: &[u8; 3], serial_id: [u8; 8]) -> [u8; CV_REF_MAX] {
    let mut r = [0u8; CV_REF_MAX];
    r[..3].copy_from_slice(mnemonic);
    r[3..11].copy_from_slice(&serial_digits(serial_id));
    r[11..].copy_from_slice(SEQUENCE);
    r
}

/// A DER INTEGER from big-endian magnitude bytes: leading zeros dropped, one put
/// back when the top bit would read as a sign.
fn put_der_uint(w: &mut Writer, v: &[u8]) -> Result<(), Sw> {
    let first = v.iter().position(|&b| b != 0).unwrap_or(v.len() - 1);
    let v = &v[first..];
    let o = w.open(0x02)?;
    if v[0] & 0x80 != 0 {
        w.raw(&[0])?;
    }
    w.raw(v)?;
    w.close(o)
}

/// Raw `r ‖ s` as the DER `SEQUENCE { INTEGER r, INTEGER s }` the driver reads.
pub(crate) fn put_ecdsa_der(w: &mut Writer, raw: &[u8]) -> Result<(), Sw> {
    if raw.is_empty() || !raw.len().is_multiple_of(2) {
        return Err(Sw::EXEC_ERROR);
    }
    let (r, s) = raw.split_at(raw.len() / 2);
    let o = w.open(0x30)?;
    put_der_uint(w, r)?;
    put_der_uint(w, s)?;
    w.close(o)
}

#[cfg(test)]
#[path = "cvc_tests.rs"]
mod tests;
