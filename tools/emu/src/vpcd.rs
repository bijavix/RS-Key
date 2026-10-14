// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The card in `vpcd`, the virtual smart-card reader vsmartcard adds to `pcscd`:
//! the emulator connects to the reader as its card, so everything on top of PC/SC
//! — OpenSC, `pkcs11-tool`, `systemd-cryptenroll` — sees an inserted card, with no
//! USB stack, no kernel module and no root. It is how the HSM image's interop
//! runs on a host with no board.
//!
//! The wire is vsmartcard's, each message prefixed by its length:
//!
//! ```text
//! message   len:u16 BE | payload
//! ```
//!
//! A one-byte payload from the reader is a control code — power off, power on,
//! reset, or "send the ATR", which alone is answered — and anything longer is a
//! command APDU, answered with its response APDU.
//!
//! A power transition is a card reset, as `PC_to_RDR_IccPowerOn`/`Off` are on the
//! CCID path: it ends the selected applet's session. It is not a power cycle — an
//! unlocked HSM stays unlocked across it; the card socket's replug is the power
//! cycle, and a suite that needs one sends it there.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::ccid::run;
use crate::device::{Job, Jobs};

/// vpcd's control codes (vsmartcard's `vpcd.h`).
const CTRL_OFF: u8 = 0x00;
const CTRL_ON: u8 = 0x01;
const CTRL_RESET: u8 = 0x02;
const CTRL_ATR: u8 = 0x04;

/// vpcd's port as the packaged `reader.conf.d/vpcd` configures it (`0x8C7B`).
pub const PORT: u16 = 0x8C7B;

/// How long to wait before knocking again on a reader that is not there.
const RETRY: Duration = Duration::from_secs(1);

/// Stay inserted in the vpcd reader at `addr` for the life of the process:
/// reconnect whenever `pcscd` restarts, and wait for it while it is down.
pub fn run_forever(addr: &str, jobs: Jobs, atr: &'static [u8]) {
    let mut waiting = false;
    loop {
        match TcpStream::connect(addr) {
            Ok(stream) => {
                eprintln!("emu: card inserted in the vpcd reader at {addr}");
                waiting = false;
                match serve(stream, &jobs, atr) {
                    Ok(()) => eprintln!("emu: vpcd hung up — waiting for it to come back"),
                    Err(e) => eprintln!("emu: vpcd: {e} — reconnecting"),
                }
            }
            Err(e) if !waiting => {
                eprintln!("emu: no vpcd reader at {addr} ({e}); is pcscd running? retrying");
                waiting = true;
            }
            Err(_) => {}
        }
        std::thread::sleep(RETRY);
    }
}

/// Answer one reader connection until it closes. `Ok` when the reader hung up
/// between messages; `Err` on a broken message or a device thread that is gone.
pub fn serve(mut stream: TcpStream, jobs: &Jobs, atr: &[u8]) -> io::Result<()> {
    stream.set_nodelay(true)?;
    loop {
        let mut len = [0u8; 2];
        match stream.read_exact(&mut len) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        }
        let mut msg = vec![0u8; u16::from_be_bytes(len) as usize];
        stream.read_exact(&mut msg)?;
        match msg.as_slice() {
            [] => return Err(io::Error::other("an empty message from the reader")),
            [CTRL_ATR] => send(&mut stream, atr)?,
            [CTRL_OFF | CTRL_ON | CTRL_RESET] => {
                run(jobs, Job::ResetCard)?;
            }
            // vicc, vsmartcard's own card, logs these and carries on; so does this.
            [code] => eprintln!("emu: vpcd sent an unknown control code {code:#04x}"),
            apdu => {
                let body = run(jobs, Job::Apdu(apdu.to_vec()))?;
                send(&mut stream, &body)?;
            }
        }
    }
}

fn send(stream: &mut TcpStream, payload: &[u8]) -> io::Result<()> {
    let len = u16::try_from(payload.len())
        .map_err(|_| io::Error::other("a response longer than a vpcd message"))?;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(payload)?;
    stream.flush()
}

#[cfg(test)]
#[path = "vpcd_tests.rs"]
mod tests;
