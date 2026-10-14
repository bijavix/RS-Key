# tests/interop — real-world consumer sweep

The layer above protocol conformance: does the device work with the actual
software a user runs (`gpg`, `ssh`, `ykman`, `fido2-token`, OpenSC), not with
our own APDU/CBOR scripts. This is the executable companion to
[../../docs/interop.md](../../docs/interop.md) — read that for the full matrix,
the status legend, and the touch-vs-no-touch build split.

```sh
nix develop -c python tests/interop/run.py            # read-only CLI cells
nix develop -c python tests/interop/run.py --touch    # also touch cells (need a press)
nix develop -c python tests/interop/run.py --json      # machine-readable
```

- Discovers the device via `fido2-token -L` (HID) and `ykman info` (CCID); a
  missing transport or tool is a **SKIP**, not a failure.
- Every default probe is **read-only**. Touch cells (`--touch`) need a finger
  on the BOOTSEL button and the touch firmware build. `--destructive` is
  reserved for future enrol/keygen cells (none yet).
- Exit status is non-zero iff a probe that actually ran FAILED.

Adding a probe: append to the `PROBES` table in `run.py` with a small
`p_*(env)` function returning `(status, detail)`. Keep it read-only unless it
is gated behind `--destructive`.

## Differential against a real YubiKey

`run.py` sweeps one device. The differential harness compares RS-Key **against a
physically-present YubiKey** and flags anything that isn't a documented, expected
divergence — so a fidelity gap stands out from the ~160 fields that legitimately
differ (serial, AAGUID, form factor, the capacity constants, …).

Both keys can stay plugged: the RS-Key `VIDPID=Yubikey5` build carries an `RSK`
marker in its USB product string, FIDO HID descriptor and PC/SC reader name that
a genuine YubiKey never has, and ykman cells target by `--device <serial>`.

```sh
# capture each device (read-only); an identity guard refuses a mislabeled snapshot
nix develop -c python tests/interop/capture.py --label real --serial <yk-serial>  --out real.json
nix develop -c python tests/interop/capture.py --label rsk  --serial <rsk-serial> --out rsk.json

# classify every field: MATCH / ALLOWED / RULE_VIOLATION / UNEXPECTED
nix develop -c python tests/interop/diff.py real.json rsk.json            # human report
nix develop -c python tests/interop/diff.py real.json rsk.json --markdown # docs/interop.md block

# crypto-parity: RS-Key's OATH engine vs the RFC 4226 known-answer (755224…)
nix develop -c python tests/interop/parity.py --serial <serial>
```

- `divergences.py` is the allow-list: rules keyed by canonical field path
  (`Ignore` / `Tolerance` / `ExpectDiff` / `Superset`), each with a reason. A
  field that differs with **no** rule is an `UNEXPECTED` fidelity gap; a field a
  rule matched but whose value drifted outside it is a `RULE_VIOLATION`.
- `normalize.py` turns each tool's output into canonical dotted keys — precise
  for the CTAP2 getInfo CBOR map and the mgmt DeviceInfo TLV, generic
  `Label: value` scraping for ykman/gpg prose.
- `test_diff.py` unit-tests the engine and the precise parsers with no hardware
  (`python -m pytest tests/interop/test_diff.py`).

macOS 27 note: the harness runs under the nix python (for `hid`/`pyscard`) but
shells out to **Homebrew** `ykman`/`fido2-token`/`gpg`/`pkcs11-tool` — the nix
ykman aborts under the macOS 27 libffi JIT, and the nix `PYTHONPATH` would
otherwise sabotage Homebrew ykman's own interpreter. `capture.py` handles both
(`_bin()` prefers `/opt/homebrew/bin`; every child runs with `PYTHONPATH`/`DYLD_*`
scrubbed).

Other platforms (move the two keys there and re-run the same three commands):

- **Linux** — the nix `ykman` works, so `nix develop -c python
  tests/interop/capture.py …` runs as-is. Needs `pcscd` + hidraw (both in the
  dev shell); install `fido2-token`/OpenSC if you want those cells.
- **Windows** — no nix: `pip install ykman pyscard hidapi cryptography`, then run
  `python tests\interop\capture.py …`. PIV/WebAuthn ride the OS minidriver /
  Windows Hello; those are the GUI stage, out of scope for this read-only sweep.

## The HSM image

`hsm.py` is the HSM image's consumer sweep, and unlike `run.py` it writes: it
initializes the token (`--wipe` for one already initialized), so point it at an
HSM you mean to erase. Each result is checked by another tool than the one that
made it — `sc-hsm-tool` (initialize, a DKEK share, wrap → delete → unwrap),
`pkcs11-tool` (EC and RSA keygen, `--test`, ECDSA, ECDH, RSA sign and decrypt,
all checked by OpenSSL), `rsk hsm attest`, GnuTLS `certtool`/`p11tool` (a
certificate self-signed on the token, verified by OpenSSL), and LUKS
(`systemd-cryptenroll` binds a keyslot, `cryptsetup`'s token plugin opens it,
and refuses to while the HSM's lock is closed).

```sh
python tests/interop/hsm.py --wipe                  # a board in reader 0
HOST_TARGET=x86_64-unknown-linux-gnu ./scripts/hsm-interop.sh   # no board
```

`scripts/hsm-interop.sh` builds `tools/emu`, inserts its `--hsm` card in
vsmartcard's `vpcd` reader and runs `tests/86_hsm.py` and this sweep against it.
It needs `pcscd` with `vsmartcard-vpcd`, OpenSC, and for the LUKS steps
`cryptsetup`, `systemd-cryptenroll`, GnuTLS and root; a missing tool skips its
steps. On a board the lock step asks for an unplug and two touches.
