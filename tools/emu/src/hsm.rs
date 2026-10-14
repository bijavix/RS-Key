// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The HSM image's device thread: the card the firmware's `hsm` feature builds —
//! the vendor, HSM and rescue applets behind `rsk_device::HsmApplets` — booted by
//! the same `hsm_boot` and answering one job at a time.
//!
//! The sequencing is `firmware/src/hsm_worker.rs`'s, mirrored: the response is
//! wiped once handed off, a queued reboot runs only after its reply is out, and a
//! power cycle or a warm reboot wipes the RAM secrets before the card comes back.
//! That last step is what relocks an armed HSM, so it is the one to get right
//! here: an emulator that kept the unlocked state across a replug would pass a
//! suite the device fails.

use std::cell::RefCell;
use std::sync::Arc;
use std::sync::mpsc::Receiver;

use rsk_crypto::Device;
use rsk_device::{Hooks, HsmApplets};
use rsk_fs::Fs;

use crate::device::{Config, EmuVendorPlatform, Job, JobSource, hex};
use crate::platform::EmuPlatform;
use crate::presence::EmuPresence;
use crate::rng::EmuRng;
use crate::signals::{self, Signals};
use crate::store::EmuStore;

/// The board the HSM wiring reaches back into only for the dual-core prime
/// search, which the emulator does not have: the applet's own search runs.
struct HsmHooks;

impl Hooks<EmuStore> for HsmHooks {}

/// Build the HSM card over `fs` and answer jobs until every sender is gone.
pub fn serve(
    cfg: Config,
    jobs: JobSource,
    signals: Arc<Signals>,
    fs: &RefCell<Fs<EmuStore>>,
    rng: &RefCell<EmuRng>,
    lines: Option<Receiver<String>>,
) {
    let presence = RefCell::new(EmuPresence::new(cfg.presence, lines, signals.clone()));
    let platform = RefCell::new(EmuPlatform::new());
    let hooks = RefCell::new(HsmHooks);
    let vendor = EmuVendorPlatform::default();
    let serial_id = cfg.serial;
    let serial_hash = rsk_crypto::sha256(&serial_id);

    // `main.rs`'s HSM boot block, at every power-up. No OTP block and no fused
    // device key: the store is sealed under the chip-serial root and the
    // attestation identity is minted into flash, as on a board never provisioned.
    let boot = || {
        let dev = Device {
            serial_hash: &serial_hash,
            serial_id: &serial_id,
            otp_key: None,
        };
        if !rsk_device::hsm_boot(&dev, None, &mut fs.borrow_mut(), &mut *rng.borrow_mut()) {
            eprintln!("emu: no device identity this boot — key generation will refuse");
        }
    };
    let power_up = || {
        boot();
        HsmApplets::new(
            fs,
            rng,
            &hooks,
            &presence,
            &platform,
            vendor.clone(),
            serial_id,
            serial_hash,
            None,
            None,
            cfg.kv_total,
            cfg.flash_size,
        )
    };
    let mut card = power_up();
    eprintln!("emu: device ready (HSM image) — serial {}", hex(&serial_id));

    while let Ok(req) = jobs.next() {
        let card_job = matches!(req.job, Job::Apdu(_) | Job::ResetCard);
        signals.set_wait_scope(if card_job {
            signals::SCOPE_CCID
        } else {
            signals::SCOPE_NONE
        });
        let out = match req.job {
            Job::Apdu(data) => {
                let body = card.handle_apdu(&data).to_vec();
                card.scrub();
                if cfg.trace {
                    eprintln!(
                        "emu: apdu {} B -> sw={:02x}{:02x} ({} B)",
                        data.len(),
                        body[body.len() - 2],
                        body[body.len() - 1],
                        body.len() - 2
                    );
                }
                Some(body)
            }
            Job::ResetCard => {
                card.reset_card();
                Some(Vec::new())
            }
            Job::Replug(_) => {
                card.scrub_secrets();
                card = power_up();
                eprintln!("emu: replugged — RAM state dropped, an armed HSM is locked again");
                Some(Vec::new())
            }
            // The HSM image has no HID interface, so no transport this build
            // starts queues these.
            Job::Cbor { .. }
            | Job::Msg { .. }
            | Job::Vendor { .. }
            | Job::OtpHid { .. }
            | Job::OtpStatus
            | Job::DeselectMsg => None,
        };
        signals.set_wait_scope(signals::SCOPE_NONE);
        // A disconnected client is not an error: it just stopped listening.
        let _ = req.reply.send(out);

        // Both reboot paths — the vendor applet's INS_REBOOT and the rescue
        // applet's twin — run only once the reply is out, as on the device.
        let rescue = platform.borrow_mut().reboot_requested.take();
        if rescue == Some(true) {
            eprintln!("emu: host asked for BOOTSEL; there is no bootloader to fall into");
        }
        if vendor.take_reboot() || rescue == Some(false) {
            card.scrub_secrets();
            card = power_up();
            eprintln!("emu: warm reboot — RAM state dropped, an armed HSM is locked again");
        }
    }
}

#[cfg(test)]
#[path = "hsm_tests.rs"]
mod tests;
