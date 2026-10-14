// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Whole-applet tests over the APDU surface, and the fixture every module's tests
//! share.

use super::*;
use rsk_crypto::chacha20poly1305_encrypt;
use rsk_crypto::pinproto::{ecdh_raw, public_xy};
use rsk_fs::storage::faults::{Cut, ProbeMedium, ProbeStuck};
use rsk_fs::storage::ram::RamStorage;

pub(crate) const SERIAL: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
pub(crate) const HASH: [u8; 32] = [0x22; 32];
/// `sc-hsm-tool`'s documented default, `3537363231383830`.
pub(crate) const SO_PIN: [u8; 8] = [0x35, 0x37, 0x36, 0x32, 0x31, 0x38, 0x38, 0x30];
pub(crate) const OTHER_SO: [u8; 8] = [0x11; 8];
pub(crate) const PIN: &[u8] = b"648219";
pub(crate) const MKEK: [u8; 32] = [0x5A; 32];

fn read_mkek() -> Option<[u8; 32]> {
    Some(MKEK)
}
/// The fused-key reader of a device whose OTP root is provisioned.
pub(crate) const OTP: Option<FusedKey> = Some(read_mkek);

/// Deterministic LCG randomness.
pub(crate) struct TestRng(pub u64);
impl Rng for TestRng {
    fn fill(&mut self, b: &mut [u8]) {
        for x in b.iter_mut() {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *x = (self.0 >> 33) as u8;
        }
    }
}

/// A touch whose answer a test sets, counting the asks.
pub(crate) struct Touch {
    pub answer: Presence,
    pub asks: u32,
}
impl UserPresence for Touch {
    fn request(&mut self, _confirm: Confirm<'_>) -> Presence {
        self.asks += 1;
        self.answer
    }
}

/// The randomness and the touch an applet borrows, outliving every applet a test
/// builds over them — a new applet is a power cycle.
pub(crate) struct Env {
    pub rng: RefCell<TestRng>,
    pub touch: RefCell<Touch>,
}

impl Env {
    pub(crate) fn new() -> Env {
        Env {
            rng: RefCell::new(TestRng(7)),
            touch: RefCell::new(Touch {
                answer: Presence::Confirmed,
                asks: 0,
            }),
        }
    }

    pub(crate) fn applet(&self, mkek: Option<FusedKey>) -> HsmApplet<'_> {
        HsmApplet::new(SERIAL, HASH, mkek, &self.rng, &self.touch)
    }

    pub(crate) fn answer(&self, p: Presence) {
        self.touch.borrow_mut().answer = p;
    }

    pub(crate) fn asks(&self) -> u32 {
        self.touch.borrow().asks
    }
}

pub(crate) fn new_fs() -> Fs<RamStorage> {
    let mut fs = Fs::new(RamStorage::new());
    fs.scan();
    fs
}

/// An APDU with extended lengths and `Le = 65536`, so no response is clipped.
pub(crate) fn apdu(cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8]) -> Vec<u8> {
    let mut raw = vec![cla, ins, p1, p2, 0];
    if !data.is_empty() {
        raw.extend_from_slice(&(data.len() as u16).to_be_bytes());
        raw.extend_from_slice(data);
    }
    raw.extend_from_slice(&[0, 0]);
    raw
}

pub(crate) fn run_raw<S: Storage>(
    app: &mut HsmApplet,
    fs: &mut Fs<S>,
    raw: &[u8],
) -> (Sw, Vec<u8>) {
    let apdu = Apdu::parse(raw).unwrap();
    let mut out = [0u8; 2036];
    let mut res = ResBuf::new(&mut out);
    let sw = Applet::process(app, &apdu, fs, &mut res);
    (sw, res.as_slice().to_vec())
}

pub(crate) fn run<S: Storage>(
    app: &mut HsmApplet,
    fs: &mut Fs<S>,
    cla: u8,
    ins: u8,
    p1: u8,
    p2: u8,
    data: &[u8],
) -> (Sw, Vec<u8>) {
    run_raw(app, fs, &apdu(cla, ins, p1, p2, data))
}

pub(crate) fn select<S: Storage>(app: &mut HsmApplet, fs: &mut Fs<S>) -> Vec<u8> {
    let mut out = [0u8; 256];
    let mut res = ResBuf::new(&mut out);
    assert_eq!(Applet::select(app, false, fs, &mut res), Sw::OK);
    res.as_slice().to_vec()
}

pub(crate) fn init_data(options: u16, pin: &[u8], so: &[u8], retries: Option<u8>) -> Vec<u8> {
    let mut d = vec![0x80, 2];
    d.extend_from_slice(&options.to_be_bytes());
    d.extend_from_slice(&[0x81, pin.len() as u8]);
    d.extend_from_slice(pin);
    d.extend_from_slice(&[0x82, so.len() as u8]);
    d.extend_from_slice(so);
    if let Some(r) = retries {
        d.extend_from_slice(&[0x91, 1, r]);
    }
    d
}

pub(crate) fn initialize<S: Storage>(
    app: &mut HsmApplet,
    fs: &mut Fs<S>,
    options: u16,
    so: &[u8],
) -> Sw {
    let data = init_data(options, PIN, so, None);
    run(app, fs, CLA_PROPRIETARY, INS_INITIALIZE, 0, 0, &data).0
}

pub(crate) fn verify<S: Storage>(app: &mut HsmApplet, fs: &mut Fs<S>, pin: &[u8]) -> Sw {
    run(app, fs, CLA_ISO, INS_VERIFY, 0, PIN_USER, pin).0
}

pub(crate) fn status<S: Storage>(app: &mut HsmApplet, fs: &mut Fs<S>, reference: u8) -> Sw {
    run(app, fs, CLA_ISO, INS_VERIFY, 0, reference, &[]).0
}

/// A fresh device, initialized with [`PIN`] and [`SO_PIN`], RESET RETRY COUNTER on.
pub(crate) fn ready<S: Storage>(app: &mut HsmApplet, fs: &mut Fs<S>) {
    select(app, fs);
    assert_eq!(initialize(app, fs, OPT_RRC, &SO_PIN), Sw::OK);
}

pub(crate) fn lock_status<S: Storage>(app: &mut HsmApplet, fs: &mut Fs<S>) -> [u8; 4] {
    let (sw, r) = run(app, fs, CLA_PROPRIETARY, INS_LOCK, LOCK_STATUS, 0, &[]);
    assert_eq!(sw, Sw::OK);
    r.try_into().unwrap()
}

/// The host half of the lock channel: agree, then box `plain` to the device.
pub(crate) fn boxed<S: Storage>(app: &mut HsmApplet, fs: &mut Fs<S>, plain: &[u8]) -> Vec<u8> {
    let host = [0x42u8; 32];
    let (hx, hy) = public_xy(&host).unwrap();
    let mut host_pub = vec![0x04];
    host_pub.extend_from_slice(&hx);
    host_pub.extend_from_slice(&hy);
    let (sw, dev_pub) = run(
        app,
        fs,
        CLA_PROPRIETARY,
        INS_LOCK,
        LOCK_CHANNEL,
        0,
        &host_pub,
    );
    assert_eq!(sw, Sw::OK);
    assert_eq!(dev_pub.len(), 65);
    let z = ecdh_raw(
        &host,
        dev_pub[1..33].try_into().unwrap(),
        dev_pub[33..].try_into().unwrap(),
    )
    .unwrap();
    let mut info = dev_pub.clone();
    info.extend_from_slice(&host_pub);
    let mut key = [0u8; 32];
    rsk_crypto::hkdf_sha256(b"RSK-HSM/LOCK-CHANNEL", &z, &info, &mut key).unwrap();
    let nonce = [9u8; 12];
    let mut ct = plain.to_vec();
    let tag = chacha20poly1305_encrypt(&key, &nonce, &dev_pub, &mut ct);
    let mut blob = nonce.to_vec();
    blob.extend_from_slice(&ct);
    blob.extend_from_slice(&tag);
    blob
}

pub(crate) const SECRET: [u8; 32] = [0xC3; 32];

pub(crate) fn arm<S: Storage>(
    app: &mut HsmApplet,
    fs: &mut Fs<S>,
    secret: &[u8; 32],
    so: &[u8],
) -> Sw {
    let mut plain = secret.to_vec();
    plain.extend_from_slice(so);
    let blob = boxed(app, fs, &plain);
    run(
        app,
        fs,
        CLA_PROPRIETARY,
        INS_LOCK,
        LOCK_ARM,
        records::Factor::HostKey.id(),
        &blob,
    )
    .0
}

pub(crate) fn unlock<S: Storage>(app: &mut HsmApplet, fs: &mut Fs<S>, secret: &[u8; 32]) -> Sw {
    let blob = boxed(app, fs, secret);
    run(app, fs, CLA_PROPRIETARY, INS_LOCK, LOCK_UNLOCK, 0, &blob).0
}

// ---- Keys: a device root, request templates, and a verifier of our own ----

/// The stand-in for the rescue applet's device key: a fixed secp256k1 root.
pub(crate) fn root_key() -> k256::ecdsa::SigningKey {
    k256::ecdsa::SigningKey::from_bytes(&[0x3C; 32].into()).unwrap()
}

pub(crate) fn root_point() -> [u8; ROOT_POINT_LEN] {
    let p = root_key().verifying_key().to_sec1_point(false);
    p.as_bytes().try_into().unwrap()
}

/// Provision the device identity under `mkek` with the test root.
pub(crate) fn provision_with<S: Storage>(fs: &mut Fs<S>, mkek: Option<FusedKey>) -> Result<(), Sw> {
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    let fused = read_fused(mkek);
    let dev = Device {
        serial_hash: &HASH,
        serial_id: &SERIAL,
        otp_key: fused.as_deref(),
    };
    let key = root_key();
    let mut sign = |d: &[u8; 32]| -> Option<[u8; ROOT_SIG_LEN]> {
        let s: k256::ecdsa::Signature = key.sign_prehash(d).ok()?;
        s.to_bytes().as_slice().try_into().ok()
    };
    provision(&dev, fs, &mut TestRng(9), &root_point(), &mut sign)
}

/// A fresh, initialized, provisioned device with the user PIN verified.
pub(crate) fn logged_in<S: Storage>(app: &mut HsmApplet, fs: &mut Fs<S>) {
    provision_with(fs, None).unwrap();
    ready(app, fs);
    assert_eq!(verify(app, fs, PIN), Sw::OK);
}

/// The request template the driver sends for a key on curve `d`.
pub(crate) fn ec_template(d: &domain::Domain) -> Vec<u8> {
    let mut pk = vec![0x06, 10];
    pk.extend_from_slice(&cvc::SigAlg::EcdsaSha256.oid());
    for (tag, v) in [
        (0x81, d.p),
        (0x82, d.a),
        (0x83, d.b),
        (0x84, d.g),
        (0x85, d.n),
        (0x87, d.h),
    ] {
        pk.push(tag);
        if v.len() > 127 {
            pk.push(0x81);
        }
        pk.push(v.len() as u8);
        pk.extend_from_slice(v);
    }
    template(&pk)
}

/// The request template the driver sends for an RSA key of `bits`.
pub(crate) fn rsa_template(bits: u16) -> Vec<u8> {
    let mut pk = vec![0x06, 10];
    pk.extend_from_slice(&cvc::SigAlg::RsaV15Sha256.oid());
    pk.extend_from_slice(&[0x82, 3, 1, 0, 1, 0x02, 2]);
    pk.extend_from_slice(&bits.to_be_bytes());
    template(&pk)
}

/// `5F29 00, 42 CAR, 7F49 { pk }, 5F20 CHR` — the driver's CAR, our serial's CHR.
fn template(pk: &[u8]) -> Vec<u8> {
    let mut t = vec![0x5F, 0x29, 1, 0, 0x42, 9];
    t.extend_from_slice(b"UTCA00001");
    t.extend_from_slice(&[0x7F, 0x49]);
    if pk.len() > 255 {
        t.extend_from_slice(&[0x82, (pk.len() >> 8) as u8, pk.len() as u8]);
    } else if pk.len() > 127 {
        t.extend_from_slice(&[0x81, pk.len() as u8]);
    } else {
        t.push(pk.len() as u8);
    }
    t.extend_from_slice(pk);
    let chr = cvc::reference(cvc::MNEMONIC_DEVICE, SERIAL);
    t.extend_from_slice(&[0x5F, 0x20, chr.len() as u8]);
    t.extend_from_slice(&chr);
    t
}

pub(crate) fn generate<S: Storage>(
    app: &mut HsmApplet,
    fs: &mut Fs<S>,
    kid: u8,
    tpl: &[u8],
) -> (Sw, Vec<u8>) {
    run(app, fs, CLA_ISO, INS_GENERATE_KEYPAIR, kid, 0, tpl)
}

/// The value of the first `tag` in `data`.
pub(crate) fn get(data: &[u8], tag: u16) -> &[u8] {
    rsk_sdk::tlv::find_tag(data, tag).unwrap_or_else(|| panic!("no {tag:#06x}"))
}

/// Whether raw `r ‖ s` is an ECDSA signature over `digest` by `point`.
pub(crate) fn ecdsa_verifies(
    curve: rsk_ec::Curve,
    point: &[u8],
    digest: &[u8],
    raw: &[u8],
) -> bool {
    macro_rules! check {
        ($c:ident) => {{
            use $c::ecdsa::signature::hazmat::PrehashVerifier;
            let (Ok(vk), Ok(sig)) = (
                $c::ecdsa::VerifyingKey::from_sec1_bytes(point),
                $c::ecdsa::Signature::from_slice(raw),
            ) else {
                return false;
            };
            vk.verify_prehash(digest, &sig).is_ok()
        }};
    }
    match curve {
        rsk_ec::Curve::P256 => check!(p256),
        rsk_ec::Curve::P384 => check!(p384),
        rsk_ec::Curve::P521 => check!(p521),
        rsk_ec::Curve::K256 => check!(k256),
        _ => unreachable!(),
    }
}

/// A DER ECDSA signature back to fixed-width `r ‖ s`.
pub(crate) fn der_to_raw(der: &[u8], width: usize) -> Vec<u8> {
    assert_eq!(der[0], 0x30);
    let body = if der[1] == 0x81 { &der[3..] } else { &der[2..] };
    let mut out = Vec::new();
    let mut rest = body;
    for _ in 0..2 {
        assert_eq!(rest[0], 0x02);
        let n = rest[1] as usize;
        let v = &rest[2..2 + n];
        assert!(
            v.len() == 1 || v[0] != 0 || v[1] & 0x80 != 0,
            "minimal INTEGER"
        );
        let v = &v[v.iter().position(|&b| b != 0).unwrap_or(v.len())..];
        out.extend(core::iter::repeat_n(0, width - v.len()));
        out.extend_from_slice(v);
        rest = &rest[2 + n..];
    }
    assert!(rest.is_empty());
    out
}

/// The SHA-256 DigestInfo prefix (RFC 8017 §9.2 note 1), spelt out here rather
/// than borrowed from the layer whose output it checks.
pub(crate) const DI_SHA256: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

/// `s^65537 mod n`, as wide as `n`: the RSA public operation, recomputed.
pub(crate) fn rsa_public(n: &[u8], s: &[u8]) -> Vec<u8> {
    use num_bigint_dig::BigUint;
    let n_ = BigUint::from_bytes_be(n);
    let m = BigUint::from_bytes_be(s).modpow(&BigUint::from(65_537u32), &n_);
    let b = m.to_bytes_be();
    let mut out = vec![0u8; n.len() - b.len()];
    out.extend_from_slice(&b);
    out
}

fn counters<S: Storage>(fs: &mut Fs<S>) -> records::Counters {
    auth::load_counters(fs).unwrap()
}

// ---- SELECT and the application FCP ----

#[test]
fn select_answers_the_fcp_the_driver_matches_on() {
    let env = Env::new();
    let mut fs = new_fs();
    let mut app = env.applet(None);
    let fcp = select(&mut app, &mut fs);
    let (major, minor, _) = rsk_sdk::FIRMWARE_VERSION;
    // `62 { 82 01 38, 85 05 opt opt FF major minor }`: the driver needs `85`
    // to be at least two bytes, and reads the version from its last two.
    assert_eq!(
        fcp,
        [
            0x62, 0x0A, 0x82, 0x01, 0x38, 0x85, 0x05, 0x00, 0x00, 0xFF, major, minor
        ]
    );
    assert_eq!(
        initialize(&mut app, &mut fs, OPT_RRC | OPT_RRC_UNBLOCK_ONLY, &SO_PIN),
        Sw::OK
    );
    let fcp = select(&mut app, &mut fs);
    assert_eq!(&fcp[7..9], &[0x00, 0x21], "the options are reported back");
}

#[test]
fn class_bytes_are_checked_and_unknown_instructions_refused() {
    let env = Env::new();
    let mut fs = new_fs();
    let mut app = env.applet(None);
    select(&mut app, &mut fs);
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            CLA_PROPRIETARY,
            INS_VERIFY,
            0,
            PIN_USER,
            &[]
        )
        .0,
        Sw::CLA_NOT_SUPPORTED
    );
    assert_eq!(
        run(&mut app, &mut fs, CLA_ISO, INS_ENUMERATE, 0, 0, &[]).0,
        Sw::CLA_NOT_SUPPORTED
    );
    assert_eq!(
        run(&mut app, &mut fs, CLA_ISO, 0x2A, 0, 0, &[]).0,
        Sw::INS_NOT_SUPPORTED
    );
    assert_eq!(
        run(&mut app, &mut fs, CLA_PROPRIETARY, 0x5A, 0, 0, &[]).0,
        Sw::INS_NOT_SUPPORTED
    );
}

#[test]
fn get_challenge_serves_le_bytes_up_to_the_ceiling() {
    let env = Env::new();
    let mut fs = new_fs();
    let mut app = env.applet(None);
    let short = [0x00, INS_GET_CHALLENGE, 0, 0, 0x10];
    let (sw, r) = run_raw(&mut app, &mut fs, &short);
    assert_eq!((sw, r.len()), (Sw::OK, 16));
    let (sw, r) = run(&mut app, &mut fs, CLA_ISO, INS_GET_CHALLENGE, 0, 0, &[]);
    assert_eq!((sw, r.len()), (Sw::OK, MAX_CHALLENGE));
    let (sw, a) = run_raw(&mut app, &mut fs, &short);
    let (_, b) = run_raw(&mut app, &mut fs, &short);
    assert_eq!(sw, Sw::OK);
    assert_ne!(a, b);
    assert_eq!(
        run(&mut app, &mut fs, CLA_ISO, INS_GET_CHALLENGE, 1, 0, &[]).0,
        Sw::INCORRECT_P1P2
    );
    assert_eq!(
        run(&mut app, &mut fs, CLA_ISO, INS_GET_CHALLENGE, 0, 0, &[1]).0,
        Sw::WRONG_LENGTH
    );
}

// ---- PIN status, VERIFY ----

#[test]
fn an_uninitialized_device_has_no_pins() {
    let env = Env::new();
    let mut fs = new_fs();
    let mut app = env.applet(None);
    select(&mut app, &mut fs);
    for reference in [PIN_USER, PIN_SO, PIN_BIO_1, PIN_BIO_2, 0x01] {
        assert_eq!(
            status(&mut app, &mut fs, reference),
            Sw::REFERENCE_NOT_FOUND,
            "{reference:#x}"
        );
    }
    assert_eq!(verify(&mut app, &mut fs, PIN), Sw::REFERENCE_NOT_FOUND);
}

#[test]
fn verify_reports_tries_and_blocks_at_zero() {
    let env = Env::new();
    let mut fs = new_fs();
    let mut app = env.applet(None);
    ready(&mut app, &mut fs);
    assert_eq!(status(&mut app, &mut fs, PIN_USER), Sw::retries(3));
    assert_eq!(status(&mut app, &mut fs, PIN_SO), Sw::retries(15));
    assert_eq!(verify(&mut app, &mut fs, b"000000"), Sw::retries(2));
    assert_eq!(verify(&mut app, &mut fs, PIN), Sw::OK);
    assert_eq!(status(&mut app, &mut fs, PIN_USER), Sw::OK, "verified");
    assert_eq!(counters(&mut fs).user, 3, "a match gives the try back");
    for left in [2, 1] {
        assert_eq!(verify(&mut app, &mut fs, b"000000"), Sw::retries(left));
    }
    assert_eq!(
        status(&mut app, &mut fs, PIN_USER),
        Sw::retries(1),
        "a failure ends the login"
    );
    assert_eq!(verify(&mut app, &mut fs, b"000000"), Sw::PIN_BLOCKED);
    assert_eq!(
        verify(&mut app, &mut fs, PIN),
        Sw::PIN_BLOCKED,
        "blocked means blocked"
    );
    assert_eq!(status(&mut app, &mut fs, PIN_USER), Sw::PIN_BLOCKED);
}

#[test]
fn verify_refuses_pin_lengths_that_cannot_exist_without_spending_a_try() {
    let env = Env::new();
    let mut fs = new_fs();
    let mut app = env.applet(None);
    ready(&mut app, &mut fs);
    assert_eq!(verify(&mut app, &mut fs, b"12345"), Sw::WRONG_LENGTH);
    assert_eq!(verify(&mut app, &mut fs, &[b'1'; 17]), Sw::WRONG_LENGTH);
    assert_eq!(counters(&mut fs).user, 3);
    assert_eq!(
        run(&mut app, &mut fs, CLA_ISO, INS_VERIFY, 1, PIN_USER, PIN).0,
        Sw::INCORRECT_P1P2
    );
    assert_eq!(
        run(&mut app, &mut fs, CLA_ISO, INS_VERIFY, 0, PIN_SO, &SO_PIN).0,
        Sw::COMMAND_NOT_ALLOWED
    );
    assert_eq!(
        status(&mut app, &mut fs, PIN_BIO_1),
        Sw::REFERENCE_NOT_FOUND
    );
}

#[test]
fn the_try_is_spent_before_the_pin_is_checked() {
    let env = Env::new();
    let (cut, medium) = Cut::new();
    let mut fs = Fs::new(cut);
    fs.scan();
    let mut app = env.applet(None);
    ready(&mut app, &mut fs);
    // Serve exactly one append — the decrement — and cut the power after it.
    medium.arm(1);
    assert_eq!(verify(&mut app, &mut fs, PIN), Sw::MEMORY_FAILURE);
    medium.arm(u32::MAX);
    let left = medium.value(store::REC_COUNTERS).unwrap()[1];
    assert_eq!(
        left, 2,
        "the decrement landed and a correct PIN after the cut did not refund it"
    );
    // And a medium that refuses the decrement refuses the check with it.
    medium.arm(0);
    assert_eq!(verify(&mut app, &mut fs, PIN), Sw::MEMORY_FAILURE);
    medium.arm(u32::MAX);
    assert_eq!(
        status(&mut app, &mut fs, PIN_USER),
        Sw::retries(2),
        "nothing was checked"
    );
}

#[test]
fn a_faulted_record_read_is_a_memory_failure_not_a_wrong_pin() {
    let env = Env::new();
    let (stuck, medium): (ProbeStuck, ProbeMedium) = ProbeStuck::new();
    let mut fs = Fs::new(stuck);
    fs.scan();
    let mut app = env.applet(None);
    ready(&mut app, &mut fs);
    for fid in [
        store::REC_USER.get(),
        store::REC_COUNTERS,
        store::REC_INIT.get(),
        store::REC_DEV.get(),
    ] {
        medium.stick(Some(fid));
        assert_eq!(
            verify(&mut app, &mut fs, PIN),
            Sw::MEMORY_FAILURE,
            "{fid:#06x}"
        );
        medium.stick(None);
        assert_eq!(
            status(&mut app, &mut fs, PIN_USER),
            Sw::retries(3),
            "{fid:#06x} cost a try"
        );
    }
    // An absent initialization record reads "never initialized"; an unreadable
    // one must not.
    medium.stick(Some(store::REC_INIT.get()));
    assert_eq!(status(&mut app, &mut fs, PIN_USER), Sw::MEMORY_FAILURE);
}

#[test]
fn select_and_a_card_reset_end_the_login() {
    let env = Env::new();
    let mut fs = new_fs();
    let mut app = env.applet(None);
    ready(&mut app, &mut fs);
    assert_eq!(verify(&mut app, &mut fs, PIN), Sw::OK);
    select(&mut app, &mut fs);
    assert_eq!(status(&mut app, &mut fs, PIN_USER), Sw::retries(3));
    assert_eq!(verify(&mut app, &mut fs, PIN), Sw::OK);
    Applet::deselect(&mut app, &mut fs);
    assert_eq!(status(&mut app, &mut fs, PIN_USER), Sw::retries(3));
}

// ---- INITIALIZE ----

#[test]
fn initialize_parses_strictly() {
    let env = Env::new();
    let mut fs = new_fs();
    let mut app = env.applet(None);
    select(&mut app, &mut fs);
    let mut bad: Vec<Vec<u8>> = vec![
        init_data(0, b"12345", &SO_PIN, None),
        init_data(0, &[b'1'; 17], &SO_PIN, None),
        init_data(0, PIN, &SO_PIN[..7], None),
        init_data(0, PIN, &SO_PIN, Some(0)),
        init_data(0, PIN, &SO_PIN, Some(11)),
        init_data(0x0002, PIN, &SO_PIN, None),
        init_data(0x0004, PIN, &SO_PIN, None),
    ];
    // Key domains and public-key authentication are not offered, and the DKEK
    // share count is one byte, given once.
    for extra in [
        &[0x97, 1, 1][..],
        &[0x93, 2, 2, 1],
        &[0x95, 1, 0],
        &[0x92, 0],
        &[0x92, 2, 0, 1],
        &[0x92, 1, 1, 0x92, 1, 1],
    ] {
        let mut d = init_data(0, PIN, &SO_PIN, None);
        d.extend_from_slice(extra);
        bad.push(d);
    }
    let mut dup = init_data(0, PIN, &SO_PIN, None);
    dup.extend_from_slice(&[0x81, 6]);
    dup.extend_from_slice(PIN);
    bad.push(dup);
    let mut trailing = init_data(0, PIN, &SO_PIN, None);
    trailing.push(0x81);
    bad.push(trailing);
    bad.push(vec![0x80, 2, 0, 1, 0x82, 8, 1, 2, 3, 4, 5, 6, 7, 8]);
    bad.push(vec![
        0x80, 2, 0, 1, 0x81, 6, b'1', b'2', b'3', b'4', b'5', b'6',
    ]);
    for d in bad {
        assert_eq!(
            run(&mut app, &mut fs, CLA_PROPRIETARY, INS_INITIALIZE, 0, 0, &d).0,
            Sw::WRONG_DATA,
            "{d:02x?}"
        );
    }
    assert!(matches!(auth::load_init(&mut fs), Ok(None)));
    let good = init_data(0, PIN, &SO_PIN, Some(5));
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            CLA_PROPRIETARY,
            INS_INITIALIZE,
            0,
            1,
            &good
        )
        .0,
        Sw::INCORRECT_P1P2
    );
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            CLA_PROPRIETARY,
            INS_INITIALIZE,
            0,
            0,
            &good
        )
        .0,
        Sw::OK
    );
    assert_eq!(status(&mut app, &mut fs, PIN_USER), Sw::retries(5));
}

#[test]
fn reinitialize_needs_the_so_pin_and_a_touch_and_wipes_every_object() {
    let env = Env::new();
    let mut fs = new_fs();
    let mut app = env.applet(None);
    ready(&mut app, &mut fs);
    assert_eq!(verify(&mut app, &mut fs, PIN), Sw::OK);
    let write = apdu(
        CLA_ISO,
        INS_UPDATE_BINARY_ODD,
        PREFIX_DATA,
        0x01,
        &[0x54, 2, 0, 0, 0x53, 3, 1, 2, 3],
    );
    assert_eq!(run_raw(&mut app, &mut fs, &write).0, Sw::OK);
    // The device's own identity is kept: a stand-in for the key the next milestone puts there.
    let device_key = store::File::Object(store::Class::Key, KEY_ID_DEVICE).store();
    fs.put(device_key, &[0xDE, 0xAD]).unwrap();

    assert_eq!(
        initialize(&mut app, &mut fs, OPT_RRC, &OTHER_SO),
        Sw::retries(14)
    );
    let asks = env.asks();
    env.answer(Presence::Timeout);
    assert_eq!(
        initialize(&mut app, &mut fs, OPT_RRC, &SO_PIN),
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    assert_eq!(env.asks(), asks + 1);
    assert!(
        fs.has_data(store::File::Object(store::Class::Data, 1).store()),
        "a refused touch wiped nothing"
    );
    assert_eq!(
        counters(&mut fs).so,
        15,
        "the SO-PIN was right, so its try came back"
    );

    env.answer(Presence::Confirmed);
    let data = init_data(0, b"222222", &SO_PIN, Some(4));
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            CLA_PROPRIETARY,
            INS_INITIALIZE,
            0,
            0,
            &data
        )
        .0,
        Sw::OK
    );
    assert!(!fs.has_data(store::File::Object(store::Class::Data, 1).store()));
    assert_eq!(fs.read(device_key, &mut [0u8; 2]), Some(2));
    assert_eq!(verify(&mut app, &mut fs, PIN), Sw::retries(3));
    assert_eq!(verify(&mut app, &mut fs, b"222222"), Sw::OK);
    assert_eq!(counters(&mut fs), records::Counters { user: 4, so: 15 });
}

#[test]
fn a_blocked_so_pin_can_never_reinitialize() {
    let env = Env::new();
    let mut fs = new_fs();
    let mut app = env.applet(None);
    ready(&mut app, &mut fs);
    for left in (0..15).rev() {
        let sw = initialize(&mut app, &mut fs, 0, &OTHER_SO);
        assert_eq!(
            sw,
            if left == 0 {
                Sw::PIN_BLOCKED
            } else {
                Sw::retries(left)
            }
        );
    }
    assert_eq!(initialize(&mut app, &mut fs, 0, &SO_PIN), Sw::PIN_BLOCKED);
    assert_eq!(status(&mut app, &mut fs, PIN_SO), Sw::PIN_BLOCKED);
    assert_eq!(
        verify(&mut app, &mut fs, PIN),
        Sw::OK,
        "the user PIN still works"
    );
}

#[test]
fn a_torn_first_initialization_reads_as_never_initialized() {
    let env = Env::new();
    // Find how many appends a whole first initialization takes.
    let mut appends = 0;
    loop {
        let (cut, medium) = Cut::new();
        let mut fs = Fs::new(cut);
        fs.scan();
        let mut app = env.applet(None);
        select(&mut app, &mut fs);
        medium.arm(appends);
        let sw = initialize(&mut app, &mut fs, OPT_RRC, &SO_PIN);
        medium.arm(u32::MAX);
        if sw == Sw::OK {
            break;
        }
        assert_eq!(sw, Sw::MEMORY_FAILURE, "after {appends} appends");
        assert_eq!(
            auth::load_init(&mut fs).map(|i| i.is_some()),
            Ok(false),
            "after {appends} appends"
        );
        assert_eq!(status(&mut app, &mut fs, PIN_USER), Sw::REFERENCE_NOT_FOUND);
        // Nothing protects the half-written records, so anyone may finish it — with
        // their own SO-PIN, over a sweep of what the torn one left.
        assert_eq!(initialize(&mut app, &mut fs, OPT_RRC, &OTHER_SO), Sw::OK);
        assert_eq!(verify(&mut app, &mut fs, PIN), Sw::OK);
        appends += 1;
    }
    assert!(
        appends >= 4,
        "the device record, the user envelope, the counters and the initialization record"
    );
}

// ---- CHANGE REFERENCE DATA, RESET RETRY COUNTER ----

#[test]
fn change_user_pin_finds_the_split_and_logs_in() {
    let env = Env::new();
    let mut fs = new_fs();
    let mut app = env.applet(None);
    ready(&mut app, &mut fs);
    for (old, new) in [
        (PIN, &b"0123456789abcdef"[..]),
        (b"0123456789abcdef", b"777777"),
        (b"777777", b"8888888"),
    ] {
        let mut d = old.to_vec();
        d.extend_from_slice(new);
        assert_eq!(
            run(
                &mut app,
                &mut fs,
                CLA_ISO,
                INS_CHANGE_REFERENCE,
                0,
                PIN_USER,
                &d
            )
            .0,
            Sw::OK
        );
        assert_eq!(
            status(&mut app, &mut fs, PIN_USER),
            Sw::OK,
            "a change leaves the PIN verified"
        );
        select(&mut app, &mut fs);
        assert_eq!(verify(&mut app, &mut fs, old), Sw::retries(2));
        assert_eq!(verify(&mut app, &mut fs, new), Sw::OK);
    }
    let mut wrong = b"999999".to_vec();
    wrong.extend_from_slice(b"111111");
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            CLA_ISO,
            INS_CHANGE_REFERENCE,
            0,
            PIN_USER,
            &wrong
        )
        .0,
        Sw::retries(2)
    );
    assert_eq!(verify(&mut app, &mut fs, b"111111"), Sw::retries(1));
    for len in [11, 33] {
        let d = vec![b'1'; len];
        assert_eq!(
            run(
                &mut app,
                &mut fs,
                CLA_ISO,
                INS_CHANGE_REFERENCE,
                0,
                PIN_USER,
                &d
            )
            .0,
            Sw::WRONG_LENGTH
        );
    }
}

#[test]
fn change_user_pin_re_arms_the_at_rest_lap_before_the_new_envelope() {
    let env = Env::new();
    let (cut, medium) = Cut::new();
    let mut fs = Fs::new(cut);
    fs.scan();
    let mut app = env.applet(None);
    ready(&mut app, &mut fs);
    // As if the lap had already run: the re-arm is then a removal the log can show.
    fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
    medium.clear_ops();
    let mut d = PIN.to_vec();
    d.extend_from_slice(b"313131");
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            CLA_ISO,
            INS_CHANGE_REFERENCE,
            0,
            PIN_USER,
            &d
        )
        .0,
        Sw::OK
    );
    medium.assert_re_armed_before(store::REC_USER.get(), |_| false, "CHANGE REFERENCE DATA");
}

#[test]
fn change_so_pin_replaces_the_verifier_and_the_envelope() {
    let env = Env::new();
    let mut fs = new_fs();
    let mut app = env.applet(None);
    ready(&mut app, &mut fs);
    let mut d = SO_PIN.to_vec();
    d.extend_from_slice(&OTHER_SO);
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            CLA_ISO,
            INS_CHANGE_REFERENCE,
            0,
            PIN_SO,
            &d
        )
        .0,
        Sw::OK
    );
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            CLA_ISO,
            INS_CHANGE_REFERENCE,
            0,
            PIN_SO,
            &d
        )
        .0,
        Sw::retries(14)
    );
    // The new SO-PIN opens the SO envelope: it can set a new user PIN.
    let mut rrc = OTHER_SO.to_vec();
    rrc.extend_from_slice(b"454545");
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            CLA_ISO,
            INS_RESET_RETRY,
            0,
            PIN_USER,
            &rrc
        )
        .0,
        Sw::OK
    );
    assert_eq!(verify(&mut app, &mut fs, b"454545"), Sw::OK);
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            CLA_ISO,
            INS_CHANGE_REFERENCE,
            0,
            PIN_SO,
            &d[..15]
        )
        .0,
        Sw::WRONG_LENGTH
    );
}

#[test]
fn reset_retry_counter_follows_the_options() {
    let env = Env::new();
    let mut fs = new_fs();
    let mut app = env.applet(None);
    ready(&mut app, &mut fs);
    for _ in 0..3 {
        verify(&mut app, &mut fs, b"000000");
    }
    assert_eq!(status(&mut app, &mut fs, PIN_USER), Sw::PIN_BLOCKED);
    let unblock = |app: &mut HsmApplet, fs: &mut Fs<RamStorage>, so: &[u8]| {
        run(app, fs, CLA_ISO, INS_RESET_RETRY, 0x01, PIN_USER, so).0
    };
    assert_eq!(unblock(&mut app, &mut fs, &OTHER_SO), Sw::retries(14));
    assert_eq!(unblock(&mut app, &mut fs, &SO_PIN), Sw::OK);
    assert_eq!(
        verify(&mut app, &mut fs, PIN),
        Sw::OK,
        "unblocking keeps the PIN"
    );
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            CLA_ISO,
            INS_RESET_RETRY,
            0x02,
            PIN_USER,
            &SO_PIN
        )
        .0,
        Sw::INCORRECT_P1P2
    );
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            CLA_ISO,
            INS_RESET_RETRY,
            0x01,
            PIN_SO,
            &SO_PIN
        )
        .0,
        Sw::REFERENCE_NOT_FOUND
    );
    let mut short = SO_PIN.to_vec();
    short.extend_from_slice(b"12345");
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            CLA_ISO,
            INS_RESET_RETRY,
            0,
            PIN_USER,
            &short
        )
        .0,
        Sw::WRONG_LENGTH
    );

    // Unblock-only refuses a new PIN; no RRC refuses both.
    for (options, set_ok, unblock_ok) in [
        (OPT_RRC | OPT_RRC_UNBLOCK_ONLY, false, true),
        (0, false, false),
    ] {
        let mut app = env.applet(None);
        let mut fs = new_fs();
        select(&mut app, &mut fs);
        assert_eq!(initialize(&mut app, &mut fs, options, &SO_PIN), Sw::OK);
        let mut set = SO_PIN.to_vec();
        set.extend_from_slice(b"565656");
        let sw = run(
            &mut app,
            &mut fs,
            CLA_ISO,
            INS_RESET_RETRY,
            0,
            PIN_USER,
            &set,
        )
        .0;
        assert_eq!(sw == Sw::OK, set_ok, "{options:#x} set");
        assert_eq!(sw == Sw::CONDITIONS_NOT_SATISFIED, !set_ok);
        let sw = unblock(&mut app, &mut fs, &SO_PIN);
        assert_eq!(sw == Sw::OK, unblock_ok, "{options:#x} unblock");
        assert_eq!(
            counters(&mut fs).so,
            15,
            "{options:#x}: a refused option spends no SO try"
        );
    }
}

// ---- The lock ----

#[test]
fn arming_needs_the_so_pin_a_touch_and_a_fresh_channel() {
    let env = Env::new();
    let mut fs = new_fs();
    let mut app = env.applet(None);
    ready(&mut app, &mut fs);
    assert_eq!(
        lock_status(&mut app, &mut fs),
        [1, LOCK_STATE_DISARMED, 0, LOCK_FLAG_INITIALIZED]
    );

    assert_eq!(arm(&mut app, &mut fs, &SECRET, &OTHER_SO), Sw::retries(14));
    env.answer(Presence::Declined);
    assert_eq!(
        arm(&mut app, &mut fs, &SECRET, &SO_PIN),
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    env.answer(Presence::Confirmed);
    assert_eq!(lock_status(&mut app, &mut fs)[1], LOCK_STATE_DISARMED);

    // No channel, a spent channel, a box sealed to another channel.
    let mut plain = SECRET.to_vec();
    plain.extend_from_slice(&SO_PIN);
    let blob = boxed(&mut app, &mut fs, &plain);
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            CLA_PROPRIETARY,
            INS_LOCK,
            LOCK_ARM,
            2,
            &blob
        )
        .0,
        Sw::INCORRECT_P1P2
    );
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            CLA_PROPRIETARY,
            INS_LOCK,
            LOCK_ARM,
            1,
            &blob
        )
        .0,
        Sw::OK
    );
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            CLA_PROPRIETARY,
            INS_LOCK,
            LOCK_ARM,
            1,
            &blob
        )
        .0,
        Sw::CONDITIONS_NOT_SATISFIED
    );
    assert_eq!(
        lock_status(&mut app, &mut fs)[..3],
        [1, LOCK_STATE_UNLOCKED, 1]
    );
    assert_eq!(
        arm(&mut app, &mut fs, &SECRET, &SO_PIN),
        Sw::CONDITIONS_NOT_SATISFIED,
        "armed once"
    );
}

#[test]
fn an_armed_device_relocks_on_every_power_cycle() {
    let env = Env::new();
    let mut fs = new_fs();
    {
        let mut app = env.applet(None);
        ready(&mut app, &mut fs);
        assert_eq!(arm(&mut app, &mut fs, &SECRET, &SO_PIN), Sw::OK);
        assert_eq!(
            verify(&mut app, &mut fs, PIN),
            Sw::OK,
            "the arming session stays open"
        );
        let write = apdu(
            CLA_ISO,
            INS_UPDATE_BINARY_ODD,
            PREFIX_DATA,
            0x02,
            &[0x53, 2, 0xAB, 0xCD],
        );
        assert_eq!(run_raw(&mut app, &mut fs, &write).0, Sw::OK);
    }
    let mut app = env.applet(None);
    select(&mut app, &mut fs);
    assert_eq!(lock_status(&mut app, &mut fs)[1], LOCK_STATE_LOCKED);
    // Closed: no PIN can be tried, and none is spent; status and public reads work.
    assert_eq!(verify(&mut app, &mut fs, PIN), Sw::CONDITIONS_NOT_SATISFIED);
    assert_eq!(
        verify(&mut app, &mut fs, b"000000"),
        Sw::CONDITIONS_NOT_SATISFIED
    );
    assert_eq!(status(&mut app, &mut fs, PIN_USER), Sw::retries(3));
    let read = apdu(
        CLA_ISO,
        INS_READ_BINARY_ODD,
        PREFIX_DATA,
        0x02,
        &[0x54, 2, 0, 0],
    );
    assert_eq!(
        run_raw(&mut app, &mut fs, &read),
        (Sw::WARNING_EOF, vec![0xAB, 0xCD])
    );
    let mut change = PIN.to_vec();
    change.extend_from_slice(b"121212");
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            CLA_ISO,
            INS_CHANGE_REFERENCE,
            0,
            PIN_USER,
            &change
        )
        .0,
        Sw::CONDITIONS_NOT_SATISFIED
    );
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            CLA_ISO,
            INS_RESET_RETRY,
            1,
            PIN_USER,
            &SO_PIN
        )
        .0,
        Sw::CONDITIONS_NOT_SATISFIED
    );
    assert_eq!(counters(&mut fs), records::Counters { user: 3, so: 15 });

    assert_eq!(
        unlock(&mut app, &mut fs, &[0x3C; 32]),
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    assert_eq!(lock_status(&mut app, &mut fs)[1], LOCK_STATE_LOCKED);
    assert_eq!(unlock(&mut app, &mut fs, &SECRET), Sw::OK);
    assert_eq!(lock_status(&mut app, &mut fs)[1], LOCK_STATE_UNLOCKED);
    assert_eq!(verify(&mut app, &mut fs, PIN), Sw::OK);
    // SELECT ends the login, not the unlock.
    select(&mut app, &mut fs);
    assert_eq!(lock_status(&mut app, &mut fs)[1], LOCK_STATE_UNLOCKED);
    assert_eq!(verify(&mut app, &mut fs, PIN), Sw::OK);

    let mut app = env.applet(None);
    assert_eq!(
        lock_status(&mut app, &mut fs)[1],
        LOCK_STATE_LOCKED,
        "and the next power cycle relocks it"
    );
}

#[test]
fn the_unlock_seam_takes_the_secret_from_any_source() {
    let env = Env::new();
    let mut fs = new_fs();
    let mut app = env.applet(None);
    ready(&mut app, &mut fs);
    assert_eq!(app.unlock(&mut fs, &SECRET), Err(UnlockError::NotArmed));
    assert_eq!(arm(&mut app, &mut fs, &SECRET, &SO_PIN), Sw::OK);
    let mut app = env.applet(None);
    assert_eq!(app.unlock(&mut fs, &[0u8; 32]), Err(UnlockError::Refused));
    assert_eq!(app.unlock(&mut fs, &SECRET), Ok(()));
    select(&mut app, &mut fs);
    assert_eq!(verify(&mut app, &mut fs, PIN), Sw::OK);
}

#[test]
fn arming_re_arms_the_at_rest_lap_before_it_supersedes_the_disarmed_record() {
    let env = Env::new();
    let (cut, medium) = Cut::new();
    let mut fs = Fs::new(cut);
    fs.scan();
    let mut app = env.applet(None);
    ready(&mut app, &mut fs);
    fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
    medium.clear_ops();
    assert_eq!(arm(&mut app, &mut fs, &SECRET, &SO_PIN), Sw::OK);
    medium.assert_re_armed_before(store::REC_DEV.get(), |_| false, "ARM");
}

#[test]
fn a_torn_arm_leaves_the_device_disarmed() {
    let env = Env::new();
    let (cut, medium) = Cut::new();
    let mut fs = Fs::new(cut);
    fs.scan();
    let mut app = env.applet(None);
    ready(&mut app, &mut fs);
    // Two appends land — the SO counter and its refund — and the record write does not.
    medium.arm(2);
    assert_eq!(arm(&mut app, &mut fs, &SECRET, &SO_PIN), Sw::MEMORY_FAILURE);
    medium.arm(u32::MAX);
    let mut app = env.applet(None);
    select(&mut app, &mut fs);
    assert_eq!(lock_status(&mut app, &mut fs)[1], LOCK_STATE_DISARMED);
    assert_eq!(verify(&mut app, &mut fs, PIN), Sw::OK);
}

#[test]
fn disarming_needs_the_device_unlocked_the_so_pin_and_a_touch() {
    let env = Env::new();
    let mut fs = new_fs();
    let mut app = env.applet(None);
    ready(&mut app, &mut fs);
    let disarm = |app: &mut HsmApplet, fs: &mut Fs<RamStorage>, so: &[u8]| {
        run(app, fs, CLA_PROPRIETARY, INS_LOCK, LOCK_DISARM, 0, so).0
    };
    assert_eq!(
        disarm(&mut app, &mut fs, &SO_PIN),
        Sw::CONDITIONS_NOT_SATISFIED,
        "not armed"
    );
    assert_eq!(arm(&mut app, &mut fs, &SECRET, &SO_PIN), Sw::OK);
    let mut app = env.applet(None);
    assert_eq!(
        disarm(&mut app, &mut fs, &SO_PIN),
        Sw::CONDITIONS_NOT_SATISFIED,
        "locked"
    );
    assert_eq!(counters(&mut fs).so, 15, "a closed lock spends no SO try");
    assert_eq!(unlock(&mut app, &mut fs, &SECRET), Sw::OK);
    assert_eq!(disarm(&mut app, &mut fs, &SO_PIN[..7]), Sw::WRONG_LENGTH);
    assert_eq!(disarm(&mut app, &mut fs, &OTHER_SO), Sw::retries(14));
    env.answer(Presence::Timeout);
    assert_eq!(
        disarm(&mut app, &mut fs, &SO_PIN),
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    env.answer(Presence::Confirmed);
    assert_eq!(disarm(&mut app, &mut fs, &SO_PIN), Sw::OK);
    let mut app = env.applet(None);
    assert_eq!(
        lock_status(&mut app, &mut fs)[..3],
        [1, LOCK_STATE_DISARMED, 0]
    );
    assert_eq!(verify(&mut app, &mut fs, PIN), Sw::OK);
}

#[test]
fn the_so_can_reinitialize_a_locked_device_and_that_disarms_it() {
    let env = Env::new();
    let mut fs = new_fs();
    let mut app = env.applet(None);
    ready(&mut app, &mut fs);
    assert_eq!(arm(&mut app, &mut fs, &SECRET, &SO_PIN), Sw::OK);
    let mut app = env.applet(None);
    select(&mut app, &mut fs);
    assert_eq!(initialize(&mut app, &mut fs, OPT_RRC, &SO_PIN), Sw::OK);
    assert_eq!(lock_status(&mut app, &mut fs)[1], LOCK_STATE_DISARMED);
    let mut app = env.applet(None);
    assert_eq!(lock_status(&mut app, &mut fs)[1], LOCK_STATE_DISARMED);
    select(&mut app, &mut fs);
    assert_eq!(verify(&mut app, &mut fs, PIN), Sw::OK);
}

#[test]
fn lock_commands_check_their_framing() {
    let env = Env::new();
    let mut fs = new_fs();
    let mut app = env.applet(None);
    ready(&mut app, &mut fs);
    let lock = |app: &mut HsmApplet, fs: &mut Fs<RamStorage>, p1: u8, p2: u8, d: &[u8]| {
        run(app, fs, CLA_PROPRIETARY, INS_LOCK, p1, p2, d).0
    };
    assert_eq!(
        lock(&mut app, &mut fs, LOCK_STATUS, 1, &[]),
        Sw::INCORRECT_P1P2
    );
    assert_eq!(
        lock(&mut app, &mut fs, LOCK_STATUS, 0, &[0]),
        Sw::WRONG_LENGTH
    );
    assert_eq!(lock(&mut app, &mut fs, 0x05, 0, &[]), Sw::INCORRECT_P1P2);
    assert_eq!(
        lock(&mut app, &mut fs, LOCK_CHANNEL, 0, &[0x04; 64]),
        Sw::WRONG_DATA
    );
    let mut off_curve = vec![0x04];
    off_curve.extend_from_slice(&[0x01; 64]);
    assert_eq!(
        lock(&mut app, &mut fs, LOCK_CHANNEL, 0, &off_curve),
        Sw::WRONG_DATA
    );
    assert_eq!(
        lock(&mut app, &mut fs, LOCK_UNLOCK, 0, &[0; 60]),
        Sw::CONDITIONS_NOT_SATISFIED,
        "no channel"
    );
    // A tampered box fails, and spends the channel.
    let mut blob = boxed(&mut app, &mut fs, &SECRET);
    blob[20] ^= 1;
    assert_eq!(
        lock(&mut app, &mut fs, LOCK_UNLOCK, 0, &blob),
        Sw::WRONG_DATA
    );
    blob[20] ^= 1;
    assert_eq!(
        lock(&mut app, &mut fs, LOCK_UNLOCK, 0, &blob),
        Sw::CONDITIONS_NOT_SATISFIED
    );
    let blob = boxed(&mut app, &mut fs, &SECRET);
    assert_eq!(
        lock(&mut app, &mut fs, LOCK_UNLOCK, 0, &blob[..59]),
        Sw::WRONG_LENGTH
    );
    let blob = boxed(&mut app, &mut fs, &SECRET);
    assert_eq!(
        lock(&mut app, &mut fs, LOCK_UNLOCK, 0, &blob),
        Sw::CONDITIONS_NOT_SATISFIED,
        "not armed"
    );
}

#[test]
fn a_selection_drops_an_unused_channel() {
    let env = Env::new();
    let mut fs = new_fs();
    let mut app = env.applet(None);
    ready(&mut app, &mut fs);
    assert_eq!(arm(&mut app, &mut fs, &SECRET, &SO_PIN), Sw::OK);
    let mut app = env.applet(None);
    let blob = boxed(&mut app, &mut fs, &SECRET);
    select(&mut app, &mut fs);
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            CLA_PROPRIETARY,
            INS_LOCK,
            LOCK_UNLOCK,
            0,
            &blob
        )
        .0,
        Sw::CONDITIONS_NOT_SATISFIED
    );
}

// ---- The OTP root ----

#[test]
fn burning_the_otp_root_carries_dk_and_the_so_verifier_forward() {
    let env = Env::new();
    let mut fs = new_fs();
    let mut app = env.applet(None);
    ready(&mut app, &mut fs);
    let before_dev = fs.read(store::REC_DEV.get(), &mut [0u8; 128]).unwrap();
    let mut old_dev = vec![0u8; before_dev];
    fs.read(store::REC_DEV.get(), &mut old_dev);

    fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
    let mut app = env.applet(OTP);
    select(&mut app, &mut fs);
    assert_eq!(
        lock_status(&mut app, &mut fs)[3] & LOCK_FLAG_OTP_ROOT,
        LOCK_FLAG_OTP_ROOT
    );
    assert_eq!(
        verify(&mut app, &mut fs, PIN),
        Sw::OK,
        "DK opened under the old root"
    );
    let mut new_dev = vec![0u8; before_dev];
    fs.read(store::REC_DEV.get(), &mut new_dev);
    assert_ne!(old_dev, new_dev, "and was re-sealed under the new one");
    assert!(
        !fs.has_data(rsk_fs::EF_HARDENED),
        "with the at-rest lap re-armed"
    );

    let init_before = auth::load_init(&mut fs).unwrap().unwrap().so_verifier;
    let mut rrc = SO_PIN.to_vec();
    rrc.extend_from_slice(b"343434");
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            CLA_ISO,
            INS_RESET_RETRY,
            0,
            PIN_USER,
            &rrc
        )
        .0,
        Sw::OK
    );
    let init_after = auth::load_init(&mut fs).unwrap().unwrap().so_verifier;
    assert_ne!(
        init_before, init_after,
        "the SO verifier moved at its first presentation"
    );

    // A pre-OTP image no longer opens either: they live on the OTP root now.
    let mut app = env.applet(None);
    select(&mut app, &mut fs);
    assert_eq!(verify(&mut app, &mut fs, b"343434"), Sw::MEMORY_FAILURE);
    assert_eq!(initialize(&mut app, &mut fs, 0, &SO_PIN), Sw::retries(14));
    let mut app = env.applet(OTP);
    select(&mut app, &mut fs);
    assert_eq!(verify(&mut app, &mut fs, b"343434"), Sw::OK);
}

#[test]
fn an_armed_device_carries_dk_forward_at_its_next_unlock() {
    let env = Env::new();
    let mut fs = new_fs();
    let mut app = env.applet(None);
    ready(&mut app, &mut fs);
    assert_eq!(arm(&mut app, &mut fs, &SECRET, &SO_PIN), Sw::OK);
    migrate_seal(
        &Device {
            serial_hash: &HASH,
            serial_id: &SERIAL,
            otp_key: Some(&MKEK),
        },
        &mut fs,
        &mut TestRng(3),
    );
    let mut app = env.applet(OTP);
    assert_eq!(unlock(&mut app, &mut fs, &SECRET), Sw::OK);
    let mut app = env.applet(None);
    assert_eq!(
        unlock(&mut app, &mut fs, &SECRET),
        Sw::SECURITY_STATUS_NOT_SATISFIED,
        "moved off the old root"
    );
    let mut app = env.applet(OTP);
    assert_eq!(unlock(&mut app, &mut fs, &SECRET), Sw::OK);
    select(&mut app, &mut fs);
    assert_eq!(verify(&mut app, &mut fs, PIN), Sw::OK);
}
