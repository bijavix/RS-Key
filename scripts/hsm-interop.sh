#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

# The HSM image against real PC/SC, with no board: `tools/emu --hsm` inserted in
# vsmartcard's vpcd reader, then `tests/86_hsm.py` over pyscard and pcscd, and
# `tests/interop/hsm.py` over OpenSC, GnuTLS, OpenSSL and LUKS.
#
#   HOST_TARGET=x86_64-unknown-linux-gnu ./scripts/hsm-interop.sh
#
# Needs pcscd running with the vpcd driver (Debian/Ubuntu: `pcscd
# vsmartcard-vpcd`; in a container with no polkit, `pcscd --disable-polkit`),
# OpenSC, pyscard and cryptography — and for the LUKS steps cryptsetup,
# systemd-cryptenroll, GnuTLS's certtool and root. A tool that is missing skips
# the steps that need it; a vpcd reader that is missing stops the run.
set -euo pipefail
cd "$(dirname "$0")/.."

HOST="${HOST_TARGET:-x86_64-unknown-linux-gnu}"
EMU="tools/emu/target/$HOST/release/rsk-emu"
CCID_PORT="${HSM_INTEROP_CCID_PORT:-7841}"
VPCD="${HSM_INTEROP_VPCD:-127.0.0.1:35963}"
WORK="$(mktemp -d)"
emu=""
trap '[ -n "$emu" ] && kill "$emu" 2>/dev/null; rm -rf "$WORK"' EXIT

command -v opensc-tool >/dev/null || { echo "FAIL: OpenSC is not installed" >&2; exit 1; }
if ! opensc-tool -l 2>/dev/null | grep -q "Virtual PCD"; then
  echo "FAIL: pcscd shows no vpcd reader — install vsmartcard-vpcd and start pcscd" >&2
  exit 1
fi

echo "== building the emulator"
cargo build --release --manifest-path tools/emu/Cargo.toml --target "$HOST"

"$EMU" --hsm --store "$WORK/hsm.store" --ccid-port "$CCID_PORT" --vpcd "$VPCD" \
  >"$WORK/emu.log" 2>&1 &
emu=$!
for _ in $(seq 50); do
  grep -q "card inserted" "$WORK/emu.log" && break
  sleep 0.2
done
if ! grep -q "card inserted" "$WORK/emu.log"; then
  echo "FAIL: the emulator never reached the vpcd reader at $VPCD:" >&2
  cat "$WORK/emu.log" >&2
  exit 1
fi

# The reader the card went into: vpcd adds two, and pcscd's poll marks the one
# with a card. Its index is what OpenSC's tools take, its name what pyscard does.
for _ in $(seq 25); do
  line="$(opensc-tool -l 2>/dev/null | awk '/Virtual PCD/ && $2 == "Yes" {print; exit}')"
  [ -n "$line" ] && break
  sleep 0.2
done
if [ -z "$line" ]; then
  echo "FAIL: no vpcd reader reports the card" >&2
  exit 1
fi
index="$(awk '{print $1}' <<<"$line")"
name="$(sed -E 's/^[0-9]+ +Yes +//' <<<"$line")"
echo "== the HSM is in reader $index ($name)"

rc=0
echo
echo "== tests/86_hsm.py over pyscard"
RSK_EMU_CCID="127.0.0.1:$CCID_PORT" RSK_TEST_READER="$name" python3 tests/86_hsm.py || rc=1
echo
echo "== tests/interop/hsm.py over OpenSC, GnuTLS, OpenSSL and LUKS"
python3 tests/interop/hsm.py --wipe --reader-index "$index" --emu-ccid "127.0.0.1:$CCID_PORT" \
  || rc=1

[ "$rc" -eq 0 ] && echo && echo "HSM INTEROP PASSED"
exit "$rc"
