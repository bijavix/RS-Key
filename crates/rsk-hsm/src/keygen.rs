// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! GENERATE KEY PAIR (`00 46 kid 00`). The data is the body of the CV request the
//! host wants back, less the public key it cannot know yet; the answer is that
//! request completed — signed by the new key, as proof of possession, and
//! wrapped in an authenticated request the device key signs, as proof the key
//! was made here.

use rsk_crypto::Device;
use rsk_ec::{MAX_EC_POINT, PrivKey};
use rsk_fs::{Fs, Storage};
use rsk_rsa::crt::{crt_from_plain, crt_plaintext};
use rsk_rsa::{MAX_CRT_PLAIN, RsaKey, generate_rsa, modulus_be};
use rsk_sdk::{Apdu, ResBuf, Rng, Sw};

use crate::HsmApplet;
use crate::auth::require_init;
use crate::consts::*;
use crate::cvc::{MNEMONIC_DEVICE, PublicKey, SigAlg, Writer, is_reference, put_body, reference};
use crate::domain::{self, Domain};
use crate::files::walk;
use crate::keyops::{EcRng, MAX_OUT, Private, RsaRng, device_key, ec_sw, sign_cv};
use crate::keys::{self, ALGOS_MAX, COUNTER_UNLIMITED, KeyObject, KeyType, RsaSize};
use crate::seal::{Key, Wiped};

/// The only public exponent this device makes keys with.
const RSA_EXPONENT: &[u8] = rsk_rsa::RSA_PUB_EXP_BE;

/// What a GENERATE KEY PAIR asks for.
struct Template<'d> {
    car: Option<&'d [u8]>,
    chr: &'d [u8],
    alg: SigAlg,
    ty: KeyType,
    counter: u32,
    algos: &'d [u8],
}

/// The curve a request's explicit parameters name. Every parameter it does give
/// must be that curve's; `p` and `a` must be given.
fn ec_domain(objs: &[(u16, &[u8])]) -> Result<&'static Domain, Sw> {
    let get = |t: u16| objs.iter().find(|(tag, _)| *tag == t).map(|(_, v)| *v);
    let (p, a) = (
        get(TAG_PK_PRIME).ok_or(Sw::WRONG_DATA)?,
        get(TAG_PK_A).ok_or(Sw::WRONG_DATA)?,
    );
    let d = domain::by_prime(p, a).ok_or(Sw::WRONG_DATA)?;
    let given = [
        (TAG_PK_B, d.b),
        (TAG_PK_BASE, d.g),
        (TAG_PK_ORDER, d.n),
        (TAG_PK_COFACTOR, d.h),
    ];
    if given
        .iter()
        .all(|(t, want)| get(*t).is_none_or(|v| v == *want))
    {
        Ok(d)
    } else {
        Err(Sw::WRONG_DATA)
    }
}

/// The public key template: the algorithm, then what the key is to be.
fn parse_public_key(v: &[u8]) -> Result<(SigAlg, KeyType), Sw> {
    let mut objs: [(u16, &[u8]); 8] = [(0, &[]); 8];
    let mut n = 0usize;
    walk(v, |tag, val| {
        let allowed = matches!(
            tag,
            TAG_PK_OID
                | TAG_PK_PRIME
                | TAG_PK_A
                | TAG_PK_B
                | TAG_PK_BASE
                | TAG_PK_ORDER
                | TAG_PK_COFACTOR
                | TAG_PK_MODULUS_BITS
        );
        if !allowed || n == objs.len() || objs[..n].iter().any(|(t, _)| *t == tag) {
            return Err(Sw::WRONG_DATA);
        }
        objs[n] = (tag, val);
        n += 1;
        Ok(())
    })?;
    let objs = &objs[..n];
    let get = |t: u16| objs.iter().find(|(tag, _)| *tag == t).map(|(_, v)| *v);
    let alg = get(TAG_PK_OID)
        .and_then(SigAlg::from_oid)
        .ok_or(Sw::WRONG_DATA)?;
    let ty = if alg.is_ec() {
        if get(TAG_PK_MODULUS_BITS).is_some() {
            return Err(Sw::WRONG_DATA);
        }
        KeyType::Ec(ec_domain(objs)?)
    } else {
        let only_rsa = objs
            .iter()
            .all(|(t, _)| matches!(*t, TAG_PK_OID | TAG_PK_A | TAG_PK_MODULUS_BITS));
        if !only_rsa || get(TAG_PK_A).is_some_and(|e| e != RSA_EXPONENT) {
            return Err(Sw::WRONG_DATA);
        }
        let bits = match get(TAG_PK_MODULUS_BITS).ok_or(Sw::WRONG_DATA)? {
            [b] => *b as usize,
            [hi, lo] => u16::from_be_bytes([*hi, *lo]) as usize,
            _ => return Err(Sw::WRONG_DATA),
        };
        KeyType::Rsa(RsaSize::from_bits(bits).ok_or(Sw::WRONG_DATA)?)
    };
    Ok((alg, ty))
}

/// Parse the request template strictly: each object once, nothing this build
/// would quietly ignore.
fn parse(data: &[u8]) -> Result<Template<'_>, Sw> {
    let mut profile = None;
    let mut car = None;
    let mut chr = None;
    let mut pk = None;
    let mut counter = None;
    let mut algos = None;
    let mut domain_seen = false;
    walk(data, |tag, v| {
        let fresh = match tag {
            TAG_CV_PROFILE if v == [CV_PROFILE] => profile.replace(()).is_none(),
            TAG_CV_CAR if is_reference(v) => car.replace(v).is_none(),
            TAG_CV_CHR if is_reference(v) => chr.replace(v).is_none(),
            TAG_CV_PUBKEY => pk.replace(v).is_none(),
            TAG_KEY_USE_COUNTER => match *v {
                [a, b, c, d] if u32::from_be_bytes([a, b, c, d]) != 0 => {
                    counter.replace(u32::from_be_bytes([a, b, c, d])).is_none()
                }
                _ => false,
            },
            TAG_KEY_ALGORITHMS if (1..=ALGOS_MAX).contains(&v.len()) => algos.replace(v).is_none(),
            TAG_KEY_DOMAIN if v == [KEY_DOMAIN_DEFAULT] => {
                !core::mem::replace(&mut domain_seen, true)
            }
            _ => false,
        };
        if fresh { Ok(()) } else { Err(Sw::WRONG_DATA) }
    })?;
    if profile.is_none() {
        return Err(Sw::WRONG_DATA);
    }
    let (alg, ty) = parse_public_key(pk.ok_or(Sw::WRONG_DATA)?)?;
    let algos: &[u8] = algos.unwrap_or(&[]);
    if !algos.iter().all(|&a| ty.serves(a)) {
        return Err(Sw::WRONG_DATA);
    }
    Ok(Template {
        car,
        chr: chr.ok_or(Sw::WRONG_DATA)?,
        alg,
        ty,
        counter: counter.unwrap_or(COUNTER_UNLIMITED),
        algos,
    })
}

/// Write the authenticated request around a new key: the body with its public
/// half, the key's own signature over the body, then the device key's over both
/// and its own reference.
#[allow(clippy::too_many_arguments)] // one assembly, every piece named
fn write_request(
    w: &mut Writer,
    tpl: &Template,
    public: &PublicKey,
    key: &Private,
    device: &Private,
    outer_car: &[u8],
    rng: &mut dyn Rng,
) -> Result<(), Sw> {
    let mut sig = Wiped::<MAX_OUT>::zeroed();
    let req = w.open(TAG_CV_AUTH_REQUEST)?;
    let cert_start = w.len();
    let cert = w.open(TAG_CV_CERT)?;
    let body_start = put_body(w, tpl.car, tpl.alg, public, tpl.chr)?;
    let body_end = w.len();
    let n = sign_cv(
        key,
        tpl.alg,
        &w.as_slice()[body_start..body_end],
        rng,
        &mut sig[..],
    )?;
    w.put(TAG_CV_SIGNATURE, &sig[..n])?;
    w.close(cert)?;
    w.put(TAG_CV_CAR, outer_car)?;
    let outer_end = w.len();
    let n = sign_cv(
        device,
        SigAlg::EcdsaSha256,
        &w.as_slice()[cert_start..outer_end],
        rng,
        &mut sig[..],
    )?;
    w.put(TAG_CV_SIGNATURE, &sig[..n])?;
    w.close(req)
}

impl HsmApplet<'_> {
    /// Everything a GENERATE KEY PAIR checks before a key is made: the login, the
    /// key reference, the template, a free slot with room, and a device key to
    /// vouch for the result. Writes nothing.
    fn keygen_checks<'d, S: Storage>(
        &mut self,
        fs: &mut Fs<S>,
        apdu: &Apdu<'d>,
    ) -> Result<(Template<'d>, Key), Sw> {
        if apdu.p2 != 0 {
            return Err(Sw::INCORRECT_P1P2);
        }
        require_init(fs)?;
        self.require_open(fs)?;
        let hmk = self
            .sess
            .hmk
            .clone()
            .ok_or(Sw::SECURITY_STATUS_NOT_SATISFIED)?;
        if apdu.p1 == KEY_ID_DEVICE {
            return Err(Sw::SECURITY_STATUS_NOT_SATISFIED);
        }
        let tpl = parse(apdu.data)?;
        if keys::exists(fs, apdu.p1)? {
            return Err(Sw::FILE_EXISTS);
        }
        crate::files::room_for_object(fs)?;
        Ok((tpl, hmk))
    }

    /// GENERATE KEY PAIR, run here in full — an EC key, or an RSA key on this
    /// core's own prime search.
    pub(crate) fn generate_keypair<S: Storage>(
        &mut self,
        dev: &Device,
        fs: &mut Fs<S>,
        apdu: &Apdu,
        res: &mut ResBuf,
    ) -> Sw {
        let (tpl, hmk) = match self.keygen_checks(fs, apdu) {
            Ok(t) => t,
            Err(sw) => return sw,
        };
        let r = match tpl.ty {
            KeyType::Ec(d) => self.finish_ec(dev, fs, apdu.p1, &tpl, &hmk, d, res),
            KeyType::Rsa(size) => {
                let key = generate_rsa(&mut RsaRng(&mut *self.rng.borrow_mut()), size.bits());
                match key {
                    Ok(key) => self.finish_rsa(dev, fs, apdu.p1, &tpl, &hmk, &key, res),
                    Err(_) => Err(Sw::EXEC_ERROR),
                }
            }
        };
        match r {
            Ok(()) => Sw::OK,
            Err(sw) => {
                res.clear();
                sw
            }
        }
    }

    /// The size of the RSA key `apdu` would generate, when it is a GENERATE KEY
    /// PAIR this applet would carry out: the wiring then runs the prime search on
    /// both cores and hands the key to [`Self::rsa_keygen_finish`]. `None` for
    /// anything else, including a request that would be refused — the ordinary
    /// dispatch answers that one.
    pub fn rsa_keygen_bits<S: Storage>(&mut self, fs: &mut Fs<S>, apdu: &Apdu) -> Option<usize> {
        if apdu.cla != CLA_ISO || apdu.ins != INS_GENERATE_KEYPAIR {
            return None;
        }
        match self.keygen_checks(fs, apdu).ok()?.0.ty {
            KeyType::Rsa(size) => Some(size.bits()),
            KeyType::Ec(_) => None,
        }
    }

    /// Finish the GENERATE KEY PAIR [`Self::rsa_keygen_bits`] accepted, around the
    /// key the wiring found. Everything is checked again: nothing the search did
    /// can have changed the answer, but a check skipped is a check that can drift.
    pub fn rsa_keygen_finish<S: Storage>(
        &mut self,
        fs: &mut Fs<S>,
        apdu: &Apdu,
        key: &RsaKey,
        res: &mut ResBuf,
    ) -> Sw {
        let (serial_hash, serial_id, mkek) = self.device_ids();
        let dev = Device {
            serial_hash: &serial_hash,
            serial_id: &serial_id,
            otp_key: mkek.as_deref(),
        };
        let r = self
            .keygen_checks(fs, apdu)
            .and_then(|(tpl, hmk)| match tpl.ty {
                KeyType::Rsa(size) if size.bits() == 8 * key.size() => {
                    self.finish_rsa(&dev, fs, apdu.p1, &tpl, &hmk, key, res)
                }
                _ => Err(Sw::EXEC_ERROR),
            });
        match r {
            Ok(()) => Sw::OK,
            Err(sw) => {
                res.clear();
                sw
            }
        }
    }

    #[allow(clippy::too_many_arguments)] // the two finishes share one shape
    fn finish_ec<S: Storage>(
        &mut self,
        dev: &Device,
        fs: &mut Fs<S>,
        kid: u8,
        tpl: &Template,
        hmk: &Key,
        d: &'static Domain,
        res: &mut ResBuf,
    ) -> Result<(), Sw> {
        let key = PrivKey::generate(d.curve, &mut EcRng(&mut *self.rng.borrow_mut()))
            .ok_or(Sw::EXEC_ERROR)?;
        let mut point = [0u8; MAX_EC_POINT];
        let pn = key.public_point(&mut point).map_err(ec_sw)?;
        let obj =
            KeyObject::new(tpl.ty, tpl.counter, tpl.algos, key.scalar()).ok_or(Sw::EXEC_ERROR)?;
        let public = PublicKey::Ec {
            domain: d,
            point: &point[..pn],
        };
        self.answer_and_store(
            dev,
            fs,
            kid,
            tpl,
            hmk,
            &public,
            &Private::Ec(key),
            &obj,
            res,
        )
    }

    #[allow(clippy::too_many_arguments)] // the two finishes share one shape
    fn finish_rsa<S: Storage>(
        &mut self,
        dev: &Device,
        fs: &mut Fs<S>,
        kid: u8,
        tpl: &Template,
        hmk: &Key,
        key: &RsaKey,
        res: &mut ResBuf,
    ) -> Result<(), Sw> {
        let mut plain = Wiped::<MAX_CRT_PLAIN>::zeroed();
        let n = crt_plaintext(key, &mut plain[..]).map_err(|_| Sw::EXEC_ERROR)?;
        let half = n / 5;
        let mut modulus = [0u8; MAX_OUT];
        let mn = modulus_be(&plain[..half], &plain[half..2 * half], &mut modulus)
            .map_err(|_| Sw::EXEC_ERROR)?;
        let crt = crt_from_plain(&plain[..n]).map_err(|_| Sw::EXEC_ERROR)?;
        let obj =
            KeyObject::new(tpl.ty, tpl.counter, tpl.algos, &plain[..n]).ok_or(Sw::EXEC_ERROR)?;
        let public = PublicKey::Rsa {
            modulus: &modulus[..mn],
            exponent: RSA_EXPONENT,
        };
        self.answer_and_store(
            dev,
            fs,
            kid,
            tpl,
            hmk,
            &public,
            &Private::Rsa(crt),
            &obj,
            res,
        )
    }

    /// The answer is written before the key is: a key the host never heard about
    /// would be a key nobody can name. A store that fails discards the answer.
    #[allow(clippy::too_many_arguments)] // one assembly, every piece named
    fn answer_and_store<S: Storage>(
        &mut self,
        dev: &Device,
        fs: &mut Fs<S>,
        kid: u8,
        tpl: &Template,
        hmk: &Key,
        public: &PublicKey,
        key: &Private,
        obj: &KeyObject,
        res: &mut ResBuf,
    ) -> Result<(), Sw> {
        let mut rng = self.rng.borrow_mut();
        let device = device_key(fs, dev, &mut *rng)?;
        let outer_car = reference(MNEMONIC_DEVICE, self.serial_id);
        let mut w = Writer::new(res.spare_mut());
        write_request(&mut w, tpl, public, key, &device, &outer_car, &mut *rng)?;
        let len = w.len();
        res.commit(len);
        keys::store(fs, hmk, kid, obj, &mut *rng)
    }
}

#[cfg(test)]
#[path = "keygen_tests.rs"]
mod tests;
