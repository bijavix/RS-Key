// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use std::net::TcpListener;
use std::sync::mpsc;
use std::thread::JoinHandle;

use super::*;
use crate::device::job_queue;

const ATR: &[u8] = &[0x3B, 0x80, 0x80, 0x01, 0x01];

/// What the stub device was asked, in order.
#[derive(Debug, PartialEq, Eq)]
enum Seen {
    Apdu(Vec<u8>),
    ResetCard,
}

/// A device thread that answers an APDU with its bytes reversed and `9000`, and
/// reports every job it takes.
fn stub() -> (Jobs, mpsc::Receiver<Seen>, JoinHandle<()>) {
    let (jobs, source) = job_queue();
    let (seen, log) = mpsc::channel();
    let device = std::thread::spawn(move || {
        while let Ok(req) = source.next() {
            let out = match req.job {
                Job::Apdu(cmd) => {
                    let mut body: Vec<u8> = cmd.iter().rev().copied().collect();
                    body.extend_from_slice(&[0x90, 0x00]);
                    let _ = seen.send(Seen::Apdu(cmd));
                    body
                }
                Job::ResetCard => {
                    let _ = seen.send(Seen::ResetCard);
                    Vec::new()
                }
                _ => panic!("vpcd queued a job that is not the card's"),
            };
            let _ = req.reply.send(Some(out));
        }
    });
    (jobs, log, device)
}

/// The reader's end of one connection, and the card side serving the other.
fn connect(jobs: &Jobs) -> (TcpStream, JoinHandle<io::Result<()>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let card = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (reader, _) = listener.accept().unwrap();
    let jobs = jobs.clone();
    (reader, std::thread::spawn(move || serve(card, &jobs, ATR)))
}

fn put(reader: &mut TcpStream, payload: &[u8]) {
    reader
        .write_all(&(payload.len() as u16).to_be_bytes())
        .unwrap();
    reader.write_all(payload).unwrap();
}

fn get(reader: &mut TcpStream) -> Vec<u8> {
    let mut len = [0u8; 2];
    reader.read_exact(&mut len).unwrap();
    let mut msg = vec![0u8; u16::from_be_bytes(len) as usize];
    reader.read_exact(&mut msg).unwrap();
    msg
}

/// pcscd's power-up: the power code resets the card, and the ATR request alone
/// is answered.
#[test]
fn power_on_resets_the_card_and_the_atr_is_answered() {
    let (jobs, log, _device) = stub();
    let (mut reader, card) = connect(&jobs);
    put(&mut reader, &[CTRL_ON]);
    put(&mut reader, &[CTRL_ATR]);
    assert_eq!(get(&mut reader), ATR);
    assert_eq!(log.recv().unwrap(), Seen::ResetCard);
    drop(reader);
    assert!(
        card.join().unwrap().is_ok(),
        "a hang-up between messages is not an error"
    );
}

/// Every power transition is a card reset, whichever way it goes.
#[test]
fn every_power_code_resets_the_card() {
    let (jobs, log, _device) = stub();
    let (mut reader, card) = connect(&jobs);
    for code in [CTRL_OFF, CTRL_ON, CTRL_RESET] {
        put(&mut reader, &[code]);
        assert_eq!(log.recv().unwrap(), Seen::ResetCard, "code {code:#04x}");
    }
    drop(reader);
    card.join().unwrap().unwrap();
}

#[test]
fn an_apdu_is_answered_with_its_response() {
    let (jobs, log, _device) = stub();
    let (mut reader, card) = connect(&jobs);
    put(&mut reader, &[0x00, 0xA4, 0x04, 0x00]);
    assert_eq!(get(&mut reader), [0x00, 0x04, 0xA4, 0x00, 0x90, 0x00]);
    assert_eq!(
        log.recv().unwrap(),
        Seen::Apdu(vec![0x00, 0xA4, 0x04, 0x00])
    );
    drop(reader);
    card.join().unwrap().unwrap();
}

/// A control code this side does not know is passed over, as vicc passes it: no
/// job, no reply, and the next message is served as usual.
#[test]
fn an_unknown_control_code_is_passed_over() {
    let (jobs, log, _device) = stub();
    let (mut reader, card) = connect(&jobs);
    put(&mut reader, &[0x07]);
    put(&mut reader, &[0x80, 0x58, 0x00, 0x00]);
    assert_eq!(get(&mut reader), [0x00, 0x00, 0x58, 0x80, 0x90, 0x00]);
    assert_eq!(
        log.recv().unwrap(),
        Seen::Apdu(vec![0x80, 0x58, 0x00, 0x00])
    );
    drop(reader);
    card.join().unwrap().unwrap();
}

/// A message with no payload is not one the protocol has: the connection is
/// dropped rather than guessed at.
#[test]
fn an_empty_message_drops_the_connection() {
    let (jobs, log, _device) = stub();
    let (mut reader, card) = connect(&jobs);
    put(&mut reader, &[]);
    assert!(card.join().unwrap().is_err());
    assert!(log.try_recv().is_err(), "nothing reached the device");
}
