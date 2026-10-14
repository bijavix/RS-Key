// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The HSM image's compute worker: the security key's hand-off with one transport.
//! The CCID task, on the high-priority executor, fills [`EXCHANGE`], signals
//! [`REQ`] and streams time extensions until [`DONE`]; this task runs the APDU to
//! completion on the thread executor and is the single point of flash access. One
//! transport sends one request at a time, so nothing else needs serializing.

use core::cell::RefCell;

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;
use embassy_sync::signal::Signal;
use embassy_time::{Duration, Timer};
use zeroize::Zeroize;

use rsk_crypto::FusedKey;
use rsk_usb::ccid::{ApduHandler, MAX_CCID_MSG};

use crate::handler::{DeviceHooks, FidoRng, Hsm, Store};
use crate::presence::Presence;
use crate::rescue_platform::RescuePlatform;
use crate::vendor::REBOOT_BOOTSEL;

/// Time for the reboot command's own reply to reach the host before the reset.
const REBOOT_FLUSH_MS: u64 = 200;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Apdu,
    /// An ICC power transition: drop the selection and the login. No payload.
    ResetCard,
}

/// The request the transport fills and the response the worker writes back.
struct Exchange {
    kind: Kind,
    req_len: usize,
    req: [u8; MAX_CCID_MSG],
    resp_len: usize,
    resp: [u8; MAX_CCID_MSG],
}

type Cs = CriticalSectionRawMutex;

static EXCHANGE: Mutex<Cs, Exchange> = Mutex::new(Exchange {
    kind: Kind::Apdu,
    req_len: 0,
    req: [0; MAX_CCID_MSG],
    resp_len: 0,
    resp: [0; MAX_CCID_MSG],
});
/// Transport → worker: a request is ready in [`EXCHANGE`].
static REQ: Signal<Cs, ()> = Signal::new();
/// Worker → transport: the response is ready in [`EXCHANGE`].
static DONE: Signal<Cs, ()> = Signal::new();

/// Hand `data` to the worker as `kind`, await its response, copy it into `out`.
async fn roundtrip(kind: Kind, data: &[u8], out: &mut [u8]) -> usize {
    {
        let mut ex = EXCHANGE.lock().await;
        let n = data.len().min(MAX_CCID_MSG);
        ex.kind = kind;
        ex.req_len = n;
        ex.req[..n].copy_from_slice(&data[..n]);
    }
    REQ.signal(());
    DONE.wait().await;
    let mut ex = EXCHANGE.lock().await;
    let n = ex.resp_len.min(out.len());
    out[..n].copy_from_slice(&ex.resp[..n]);
    // The response can carry a deciphered key or an ECDH secret.
    let m = ex.resp_len;
    ex.resp[..m].zeroize();
    ex.resp_len = 0;
    n
}

/// CCID client handler (high-priority executor): forwards to the worker. There is
/// no on-device PIN pad, so `PC_to_RDR_Secure` keeps the trait's refusal.
pub struct ClientCcid;

impl ApduHandler for ClientCcid {
    async fn handle_apdu(&mut self, apdu: &[u8], out: &mut [u8]) -> usize {
        roundtrip(Kind::Apdu, apdu, out).await
    }
    async fn reset_card(&mut self) {
        let mut sink = [0u8; 2];
        roundtrip(Kind::ResetCard, &[], &mut sink).await;
    }
}

/// The compute worker (low-priority thread executor): owns the HSM applet set and
/// runs each request to completion while the CCID task streams time extensions.
pub struct Worker<'a> {
    applets: Hsm<'a>,
    /// The DRBG, kept for the reboot wipe: the one long-lived RAM secret outside
    /// the applets.
    rng: &'a RefCell<FidoRng>,
}

impl<'a> Worker<'a> {
    #[allow(clippy::too_many_arguments)] // one-time wiring from main
    pub fn new(
        fs: &'a RefCell<Store>,
        rng: &'a RefCell<FidoRng>,
        presence: &'a RefCell<Presence>,
        platform: &'a RefCell<RescuePlatform>,
        hooks: &'a RefCell<DeviceHooks>,
        serial_id: [u8; 8],
        serial_hash: [u8; 32],
        mkek_source: Option<FusedKey>,
        devk_source: Option<FusedKey>,
        kv_total: u32,
    ) -> Self {
        Self {
            applets: Hsm::new(
                fs,
                rng,
                hooks,
                presence,
                platform,
                crate::vendor::VendorPlatform,
                serial_id,
                serial_hash,
                mkek_source,
                devk_source,
                kv_total,
                crate::flash_storage::FLASH_SIZE as u32,
            ),
            rng,
        }
    }

    /// Process requests forever. A reboot the vendor or rescue applet queued runs
    /// once its reply is on the wire.
    pub async fn run(&mut self) -> ! {
        loop {
            REQ.wait().await;
            self.handle_transport().await;
            if let Some(mode) = crate::vendor::take_reboot() {
                self.reboot(mode).await;
            }
        }
    }

    /// One CCID request: dispatch it, wipe the request, signal the response.
    async fn handle_transport(&mut self) {
        crate::led::set_status(crate::led::STATUS_PROCESSING);
        {
            let mut ex = EXCHANGE.lock().await;
            crate::presence::set_wait_scope(crate::presence::SCOPE_CCID);
            let Exchange {
                kind,
                req_len,
                req,
                resp_len,
                resp,
            } = &mut *ex;
            let r: &[u8] = match *kind {
                Kind::Apdu => self.applets.handle_apdu(&req[..*req_len]),
                Kind::ResetCard => {
                    self.applets.reset_card();
                    &[]
                }
            };
            let n = r.len().min(resp.len());
            resp[..n].copy_from_slice(&r[..n]);
            *resp_len = n;
            // The request can carry a PIN or a share of the DKEK.
            req[..*req_len].zeroize();
            *req_len = 0;
            self.applets.scrub();
        }
        crate::presence::set_wait_scope(crate::presence::SCOPE_NONE);
        crate::led::set_status(crate::led::STATUS_IDLE);
        DONE.signal(());
    }

    /// Reset once the reply has flushed, wiping first what a warm reset would
    /// leave in SRAM: the HSM's session and lock keys, the DRBG, and core1's last
    /// RSA prime. `REBOOT_BOOTSEL` drops to the bootloader, anything else is warm.
    async fn reboot(&mut self, mode: u8) -> ! {
        Timer::after(Duration::from_millis(REBOOT_FLUSH_MS)).await;
        self.applets.scrub_secrets();
        self.rng.borrow_mut().scrub();
        crate::core1::scrub();
        if mode == REBOOT_BOOTSEL {
            embassy_rp::rom_data::reset_to_usb_boot(0, 0);
        } else {
            cortex_m::peripheral::SCB::sys_reset();
        }
        // reset_to_usb_boot returns only on failure; park.
        loop {
            cortex_m::asm::nop();
        }
    }
}
