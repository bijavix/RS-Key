// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The HSM image's CCID wiring: the HSM applet between the two recovery applets
//! every image carries, behind one dispatcher. A type of its own rather than a
//! mode of [`crate::CcidApplets`]: the two images share no other applet, and the
//! enabled-applications mask only gates applets this image does not have.

use core::cell::RefCell;

use rsk_crypto::{Device, FusedKey};
use rsk_fs::{Fs, Storage};
use rsk_hsm::HsmApplet;
use rsk_hsm::consts::{MAX_OBJECTS, UNLOCK_SECRET_LEN};
use rsk_rescue::RescueApplet;
use rsk_rescue::keydev;
use rsk_sdk::{Apdu, Applet, Dispatcher, ResBuf, Sw};
use rsk_vendor::VendorApplet;

pub use rsk_hsm::UnlockError;

use crate::Hooks;
use crate::ccid::RESP_CAP;

// ENUMERATE lists every object in one response, two bytes each. The applet caps
// the count; only this crate sees the body that response has to fit.
const _: () = assert!(2 * MAX_OBJECTS <= RESP_CAP - 2);

/// Registration-order index of the HSM applet, whose RSA keygen is fast-pathed.
const IDX_HSM: usize = 1;

/// The HSM image's boot pass over the store, before USB attaches: carry what an
/// OTP burn left under the old root onto the new one, then bring the device's
/// attestation identity into being, rooted in the rescue applet's device key.
/// `false` when that identity could not be made — the token then cannot be bound,
/// rather than presenting an identity nothing vouched for.
pub fn boot<S: Storage>(
    dev: &Device,
    devk: Option<&[u8; 32]>,
    fs: &mut Fs<S>,
    rng: &mut dyn rsk_sdk::Rng,
) -> bool {
    keydev::migrate_kbase(dev, fs, rng);
    rsk_hsm::migrate_seal(dev, fs, rng);
    let Some(root) = keydev::load_or_generate(dev, devk, fs, rng) else {
        return false;
    };
    let point = keydev::public_uncompressed(&root);
    let mut sign = |d: &[u8; 32]| keydev::sign_digest(&root, d);
    rsk_hsm::provision(dev, fs, rng, &point, &mut sign).is_ok()
}

pub struct HsmApplets<'a, S: Storage, R: rsk_sdk::Rng + 'static, VP: rsk_vendor::Platform> {
    fs: &'a RefCell<Fs<S>>,
    rng: &'a RefCell<R>,
    hooks: &'a RefCell<dyn Hooks<S>>,
    disp: Dispatcher,
    vendor: VendorApplet<'a, VP>,
    hsm: HsmApplet<'a>,
    rescue: RescueApplet<'a>,
    resp: [u8; RESP_CAP],
}

impl<'a, S: Storage, R: rsk_sdk::Rng + 'static, VP: rsk_vendor::Platform> HsmApplets<'a, S, R, VP> {
    /// The parameters of [`crate::CcidApplets::new`] that the three applets here
    /// use; what they mean is documented there.
    #[allow(clippy::too_many_arguments)] // one-time wiring from the worker
    pub fn new<PR: rsk_sdk::UserPresence + 'static>(
        fs: &'a RefCell<Fs<S>>,
        rng: &'a RefCell<R>,
        hooks: &'a RefCell<dyn Hooks<S>>,
        presence: &'a RefCell<PR>,
        platform: &'a RefCell<dyn rsk_rescue::Platform>,
        vendor_platform: VP,
        serial_id: [u8; 8],
        serial_hash: [u8; 32],
        mkek_source: Option<FusedKey>,
        devk: Option<FusedKey>,
        kv_total: u32,
        flash_size: u32,
    ) -> Self {
        Self {
            fs,
            rng,
            hooks,
            disp: Dispatcher::new(),
            vendor: VendorApplet::new(vendor_platform, presence),
            hsm: HsmApplet::new(serial_id, serial_hash, mkek_source, rng, presence),
            rescue: RescueApplet::new(
                serial_id,
                serial_hash,
                mkek_source,
                devk,
                rng,
                platform,
                presence,
                kv_total,
                flash_size,
            ),
            resp: [0; RESP_CAP],
        }
    }

    /// Dispatch one CCID APDU, returning the response APDU (body + SW1 SW2). An
    /// RSA key generation runs its prime search here, on both cores.
    pub fn handle_apdu(&mut self, apdu: &[u8]) -> &[u8] {
        // As in the key image's wiring: the fast path bypasses the dispatcher, so
        // the class byte it would judge is judged first, and the stale response
        // tail and command chain a dispatch would drop are dropped here.
        let dispatchable =
            Apdu::parse(apdu).is_ok_and(|p| !p.is_chaining() && !p.is_secure_messaging());
        if dispatchable && let Some(n) = self.try_rsa_keygen(apdu) {
            self.disp.clear_pending();
            self.disp.clear_chaining();
            return &self.resp[..n];
        }
        let (sw, n) = {
            let mut res = ResBuf::new(&mut self.resp[..RESP_CAP - 2]);
            let mut applets: [&mut dyn Applet<Fs<S>>; 3] =
                [&mut self.vendor, &mut self.hsm, &mut self.rescue];
            let mut fsb = self.fs.borrow_mut();
            let sw = self.disp.process(apdu, &mut applets, &mut *fsb, &mut res);
            (sw, res.len())
        };
        self.resp[n..n + 2].copy_from_slice(&sw.to_bytes());
        &self.resp[..n + 2]
    }

    /// An RSA GENERATE KEY PAIR with the board's prime search: the applet vets the
    /// request and finishes it, the search in between is [`Hooks::rsa_search`].
    /// `None` hands the APDU to the ordinary dispatch — anything else, a request
    /// the applet would refuse, or a board with no accelerator.
    fn try_rsa_keygen(&mut self, apdu: &[u8]) -> Option<usize> {
        if self.disp.current() != Some(IDX_HSM) {
            return None;
        }
        let p = Apdu::parse(apdu).ok()?;
        let nbits = self.hsm.rsa_keygen_bits(&mut *self.fs.borrow_mut(), &p)?;
        let key = {
            let mut rng = self.rng.borrow_mut();
            self.hooks.borrow_mut().rsa_search(nbits, &mut *rng)?
        };
        let Some(key) = key else {
            self.resp[..2].copy_from_slice(&Sw::EXEC_ERROR.to_bytes());
            return Some(2);
        };
        let (sw, n) = {
            let mut res = ResBuf::new(&mut self.resp[..RESP_CAP - 2]);
            let mut fsb = self.fs.borrow_mut();
            let sw = self.hsm.rsa_keygen_finish(&mut *fsb, &p, &key, &mut res);
            (sw, res.len())
        };
        self.resp[n..n + 2].copy_from_slice(&sw.to_bytes());
        Some(n + 2)
    }

    /// Drop the selected applet's security status on an ICC power transition: for
    /// the HSM, the verified user PIN and any unused lock channel. The lock itself
    /// is the power cycle's, not the reader's — a card reset leaves it as it was.
    pub fn reset_card(&mut self) {
        let mut applets: [&mut dyn Applet<Fs<S>>; 3] =
            [&mut self.vendor, &mut self.hsm, &mut self.rescue];
        let mut fsb = self.fs.borrow_mut();
        self.disp.reset_card(&mut applets, &mut *fsb);
    }

    /// Wipe the response buffer — it can hold a deciphered key or an ECDH secret
    /// after a dispatch. Called by the worker after the hand-off.
    pub fn scrub(&mut self) {
        use zeroize::Zeroize;
        self.resp.zeroize();
    }

    /// Unlock an armed HSM with a secret the board obtained itself, rather than
    /// one a host boxed over the lock channel — the door a token on the USB-A
    /// port comes in by. Same check, same state, as the host's UNLOCK.
    pub fn unlock(&mut self, secret: &[u8; UNLOCK_SECRET_LEN]) -> Result<(), UnlockError> {
        let mut fsb = self.fs.borrow_mut();
        self.hsm.unlock(&mut *fsb, secret)
    }
}

#[cfg(test)]
#[path = "hsm_tests.rs"]
mod tests;
