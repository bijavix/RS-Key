<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 RS-Key contributors -->

# Roadmap

Where RS-Key is going, and where it is deliberately not going. Directions, not
dates: this is a single-maintainer project, and a schedule would be a promise
nobody here can keep. What has already happened is in
[CHANGELOG.md](https://github.com/TheMaxMur/RS-Key/blob/main/CHANGELOG.md); why
some things will never happen is argued in [limitations.md](limitations.md).
This page is the middle.

Everything below is a direction, which means it can be abandoned. A direction
that stops being true gets deleted from this page rather than quietly left to
rot — if you find one that no longer matches the tree, that is a bug worth an
issue.

## Where the work is going

**Post-quantum, at the speed of the protocol.** ML-DSA-44, -65 and -87
credentials work today, checked against the NIST ACVP vectors. ML-KEM-768 is
compiled in and reached by nothing, because no CTAP PIN/UV protocol uses it
yet. The direction is to follow that standardisation rather than run ahead of
it: shipping a key-exchange no host speaks would be motion, not progress.

**Formal verification, from pilots to coverage.** The models and their
harnesses already run in CI, with three refinement pilots — the PIN token, the
cross-reset state, the store — tying a model to the code it claims to abstract
([formal.md](formal.md)). The direction is more of the security-relevant state
under models that actually run, and keeping the checks-of-the-checks honest:
a proof nobody executes is documentation with a false badge on it.

**Conformance parity.** The bar is a real YubiKey and the specification, in
that order when they disagree and the spec is on our side, and the other order
when it is not — matching a behaviour real hosts depend on beats being right
alone ([interop.md](interop.md)). The direction is closing divergences one at a
time, each with the measurement that found it.

**The trusted display.** The variant with a screen is where the anti-phishing
promise lives: what you are approving, shown by something the host cannot
repaint ([guides/display.md](guides/display.md)). The direction is to make that
path as boring and as well-tested as the headless one, because a display that
is occasionally wrong is worse than no display.

**Host tooling.** Fewer steps between a fresh board and a working key — the
`rsk` CLI, the TUI cockpit, and the platform notes for Linux and Windows. Most
of the friction people actually hit is here, not in the firmware.

**Supply chain.** Releases are signed and carry build provenance; the direction
is that every artifact can be verified without taking this repository's word
for anything ([supply-chain.md](supply-chain.md)).

**The HSM image, on boards and with a second factor.** The HSM image has run
against OpenSC, GnuTLS and LUKS on the emulator; the direction is the same run on
the boards it is sized for, then an unlock that needs no host: a FIDO2 token in
the Waveshare RP2350-USB-A's USB-A port whose `hmac-secret` opens the lock. The
lock's record already names the factor and its state machine does not change
for it ([hsm-design.md](hsm-design.md#pin-and-lock-state-machine)).

## What this project will not do

Some of these are settled and argued elsewhere; they are listed here so the
absence is a decision rather than an omission.

- **Pursue certification.** Not certified by the FIDO Alliance and not seeking
  it: certification needs a legal entity and fees a hobby project does not
  have. If your threat model requires a certified key, buy one.
- **Maintain release branches.** The tip of `main` is what is supported; a fix
  is a commit there plus an advisory
  ([SECURITY.md](https://github.com/TheMaxMur/RS-Key/blob/main/SECURITY.md)).
- **Promise dates.** See the top of this page.

## How this page changes

By pull request, like everything else, and the maintainer decides
([GOVERNANCE.md](https://github.com/TheMaxMur/RS-Key/blob/main/GOVERNANCE.md)).
Proposals belong in an issue first — the cheapest moment to hear that something
is out of scope is before it is written.
