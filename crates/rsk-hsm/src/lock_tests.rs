// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

fn dk() -> Key {
    Key::new([7; 32])
}

fn states() -> [(&'static str, Lock); 4] {
    [
        ("unknown", Lock::Unknown),
        ("disarmed", Lock::Disarmed),
        ("locked", Lock::Locked),
        ("unlocked", Lock::Unlocked(dk())),
    ]
}

/// The whole transition table: every state against every event, refusals named.
#[test]
fn every_event_in_every_state() {
    use Event::*;
    let expect: [(&str, [Result<(), Refusal>; 3]); 4] = [
        ("unknown", [Err(Refusal::Unknown); 3]),
        (
            "disarmed",
            [Ok(()), Err(Refusal::NotArmed), Err(Refusal::NotArmed)],
        ),
        (
            "locked",
            [Err(Refusal::Armed), Ok(()), Err(Refusal::Closed)],
        ),
        ("unlocked", [Err(Refusal::Armed), Ok(()), Ok(())]),
    ];
    for ((name, lock), (ename, row)) in states().iter().zip(expect) {
        assert_eq!(*name, ename);
        for (ev, want) in [Arm, Unlock, Disarm].into_iter().zip(row) {
            assert_eq!(lock.admits(ev), want, "{name} {ev:?}");
        }
    }
}

#[test]
fn power_up_follows_the_record() {
    assert!(matches!(Lock::at_power_up(Factor::None), Lock::Disarmed));
    assert!(matches!(Lock::at_power_up(Factor::HostKey), Lock::Locked));
    assert!(matches!(
        Lock::at_power_up(Factor::Fido2HmacSecret),
        Lock::Locked
    ));
}

#[test]
fn only_a_disarmed_or_unlocked_lock_is_open() {
    let open: Vec<bool> = states().iter().map(|(_, l)| l.is_open()).collect();
    assert_eq!(open, [false, true, false, true]);
    let held: Vec<bool> = states().iter().map(|(_, l)| l.held().is_some()).collect();
    assert_eq!(held, [false, false, false, true]);
}

#[test]
fn the_admitted_transitions_land_where_they_say() {
    let mut l = Lock::Disarmed;
    l.armed(dk());
    assert!(matches!(&l, Lock::Unlocked(k) if **k == [7; 32]));
    l.disarmed();
    assert!(matches!(l, Lock::Disarmed));
    let mut l = Lock::Locked;
    l.unlocked(dk());
    assert!(matches!(l, Lock::Unlocked(_)));
    for (_, mut l) in states() {
        l.reinitialized();
        assert!(matches!(l, Lock::Disarmed));
    }
}

#[test]
fn the_status_byte_is_frozen() {
    let wire: Vec<u8> = states().iter().map(|(_, l)| l.wire()).collect();
    assert_eq!(wire, [0xFF, 0, 1, 2]);
}
