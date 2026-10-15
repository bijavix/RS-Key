#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""The HSM image against the software a homelab runs on it, each result checked
by another tool than the one that produced it:

  OpenSC      `sc-hsm-tool` initializes, imports a DKEK share, wraps a key,
              deletes it and unwraps it back; `pkcs11-tool` generates EC and RSA
              keys, signs, derives and decrypts — PKCS#1 v1.5 and the OAEP that
              systemd 261 enrolls with — and runs its own self-test: every
              signature verified by OpenSSL, the ECDH secret and the RSA
              plaintexts compared with OpenSSL's
  GnuTLS      `certtool` self-signs a certificate with a token key and `p11tool`
              stores it; OpenSSL verifies it
  rsk         `rsk hsm attest` checks a generated key's request against the device
  LUKS        `systemd-cryptenroll` binds a LUKS2 keyslot to the token's RSA key and
              `cryptsetup`'s token plugin opens it — then the HSM's lock is armed,
              a power cycle closes it, the same unlock is refused until
              `rsk hsm lock unlock` opens it again, and the lock is disarmed

DESTRUCTIVE: `sc-hsm-tool --initialize` erases the token; an initialized one is
left alone unless --wipe is given.

    python tests/interop/hsm.py [--wipe] [--reader-index N] [--emu-ccid HOST:PORT]

Needs one PC/SC reader with the HSM in it: a board, or `tools/emu --hsm --vpcd` in
vsmartcard's vpcd reader — `scripts/hsm-interop.sh` sets that up and runs this
with `tests/86_hsm.py`. A missing tool skips the steps that need it. The lock
step needs a power cycle: --emu-ccid names the emulator's card socket and the
replug goes there; without it the suite asks for an unplug.
"""
import argparse
import hashlib
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time

REPO = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tests"))

PIN = "648219"
SO_PIN_HEX = "3537363231383830"  # sc-hsm-tool's documented default
LABEL = "RS-Key HSM"
TOKEN = f"{LABEL} (UserPIN)"  # OpenSC's sc-hsm label: the token label and its PIN
SHARE_PASSWORD = "rs-key interop share password"
LUKS_PASSPHRASE = "rs-key interop passphrase"
ID_EC, ID_RSA = "10", "11"
TIMEOUT_S = 600  # an on-card RSA-2048 keygen on a board, with room to spare
MODULES = (
    "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
    "/usr/lib/aarch64-linux-gnu/opensc-pkcs11.so",
    "/usr/lib64/opensc-pkcs11.so",
    "/usr/lib/opensc-pkcs11.so",
    "/opt/homebrew/lib/opensc-pkcs11.so",
)
EXIT_SKIP = 77

results = []


def report(status, step, detail=""):
    results.append(status)
    print(f"{status:<4} {step}" + (f" — {detail}" if detail else ""), flush=True)


def run(cmd, *, stdin=None, env=None, check=True):
    """One tool invocation, its output kept for the failure message."""
    done = subprocess.run(cmd, input=stdin, capture_output=True, text=True,
                          timeout=TIMEOUT_S, env={**os.environ, **(env or {})})
    out = (done.stdout + done.stderr).strip()
    if check and done.returncode != 0:
        raise StepFailed(f"`{' '.join(cmd[:3])}…` exited {done.returncode}: {out[-400:]}")
    return done.returncode, out


class StepFailed(Exception):
    pass


def step(name, needs=()):
    """Run the decorated step, a SKIP when a tool it needs is missing."""
    def wrap(fn):
        def go(*a):
            missing = [t for t in needs if shutil.which(t) is None]
            if missing:
                report("SKIP", name, f"needs {', '.join(missing)}")
                return None
            try:
                value = fn(*a)
            except StepFailed as e:
                report("FAIL", name, str(e))
                return None
            report("PASS", name, value if isinstance(value, str) else "")
            return value if value is not None else True
        return go
    return wrap


class Suite:
    def __init__(self, args, work):
        self.args = args
        self.work = pathlib.Path(work)
        self.reader = str(args.reader_index)
        self.module = next((m for m in MODULES if os.path.exists(m)), None)
        self.rsk_env = {"PYTHONPATH": str(REPO / "tools")}

    def p11(self, *cmd, login=False, check=True):
        base = ["pkcs11-tool", "--module", self.module, "--token-label", TOKEN]
        if login:
            base += ["--login", "--pin", PIN]
        return run(base + list(cmd), check=check)

    def rsk(self, *cmd, stdin=None, check=True):
        return run([sys.executable, "-m", "rsk", "hsm", "--reader", self.reader_name, *cmd],
                   stdin=stdin, env=self.rsk_env, check=check)

    def file(self, name):
        return str(self.work / name)

    # ---- OpenSC -------------------------------------------------------------

    @step("OpenSC binds the sc-hsm driver", needs=("opensc-tool",))
    def driver(self):
        _, readers = run(["opensc-tool", "-l"])
        line = next((ln for ln in readers.splitlines()
                     if ln.strip().startswith(self.reader) and "Yes" in ln), None)
        if line is None:
            raise StepFailed(f"reader {self.reader} holds no card:\n{readers}")
        self.reader_name = line.split(None, 3)[-1].strip()
        _, name = run(["opensc-tool", "-r", self.reader, "-n"])
        if "SmartCard-HSM" not in name:
            raise StepFailed(f"OpenSC calls the card {name!r}")
        return name.splitlines()[-1]

    @step("sc-hsm-tool initializes the token", needs=("sc-hsm-tool",))
    def initialize(self):
        _, info = run(["sc-hsm-tool", "-r", self.reader])
        if "never been initialized" not in info and not self.args.wipe:
            raise StepFailed("the token is initialized and INITIALIZE erases it — rerun with --wipe")
        run(["sc-hsm-tool", "-r", self.reader, "--initialize", "--so-pin", SO_PIN_HEX,
             "--pin", PIN, "--dkek-shares", "1", "--label", LABEL])
        _, info = run(["sc-hsm-tool", "-r", self.reader])
        if "User PIN tries left  : 3" not in info:
            raise StepFailed(f"after INITIALIZE:\n{info}")

    @step("sc-hsm-tool imports a DKEK share", needs=("sc-hsm-tool",))
    def dkek(self):
        share = self.file("share.pbe")
        run(["sc-hsm-tool", "--create-dkek-share", share, "--password", SHARE_PASSWORD])
        _, out = run(["sc-hsm-tool", "-r", self.reader, "--import-dkek-share", share,
                      "--password", SHARE_PASSWORD])
        kcv = next((ln.split(":")[1].strip() for ln in out.splitlines()
                    if "key check value" in ln), "")
        if not kcv or kcv == "0000000000000000":
            raise StepFailed(f"no DKEK after the import:\n{out}")
        return f"KCV {kcv}"

    @step("pkcs11-tool generates EC P-256 and RSA-2048 keys", needs=("pkcs11-tool",))
    def keygen(self):
        self.p11("--keypairgen", "--key-type", "EC:prime256v1", "--label", "interop-ec",
                 "--id", ID_EC, login=True)
        self.p11("--keypairgen", "--key-type", "rsa:2048", "--label", "interop-rsa",
                 "--id", ID_RSA, login=True)
        for kid, name in ((ID_EC, "ec"), (ID_RSA, "rsa")):
            der = self.file(f"{name}-pub.der")
            self.p11("--read-object", "--type", "pubkey", "--id", kid, "-o", der)
            run(["openssl", "pkey", "-pubin", "-inform", "DER", "-in", der,
                 "-out", self.file(f"{name}-pub.pem")])

    @step("pkcs11-tool --test", needs=("pkcs11-tool",))
    def selftest(self):
        _, out = self.p11("--test", login=True)
        if "No errors" not in out:
            raise StepFailed(out[-600:])

    @step("ECDSA by pkcs11-tool, verified by OpenSSL", needs=("pkcs11-tool", "openssl"))
    def ecdsa(self):
        data, sig = self.file("data.bin"), self.file("ec.sig")
        pathlib.Path(data).write_bytes(b"rs-key interop: ecdsa")
        self.p11("--sign", "--mechanism", "ECDSA-SHA256", "--id", ID_EC, "-i", data,
                 "-o", sig, "--signature-format", "openssl", login=True)
        run(["openssl", "dgst", "-sha256", "-verify", self.file("ec-pub.pem"),
             "-signature", sig, data])

    @step("ECDH by pkcs11-tool equals OpenSSL's", needs=("pkcs11-tool", "openssl"))
    def ecdh(self):
        peer, peer_pub = self.file("peer.pem"), self.file("peer-pub.der")
        run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
             "-out", peer])
        run(["openssl", "pkey", "-in", peer, "-pubout", "-outform", "DER", "-out", peer_pub])
        card, host = self.file("shared.card"), self.file("shared.host")
        self.p11("--derive", "--mechanism", "ECDH1-DERIVE", "--id", ID_EC, "-i", peer_pub,
                 "-o", card, login=True)
        run(["openssl", "pkeyutl", "-derive", "-inkey", peer, "-peerkey",
             self.file("ec-pub.pem"), "-out", host])
        if pathlib.Path(card).read_bytes() != pathlib.Path(host).read_bytes():
            raise StepFailed("the token and OpenSSL derived different secrets")

    @step("RSA by pkcs11-tool: OpenSSL verifies the signature, PKCS#1 and OAEP decrypt",
          needs=("pkcs11-tool", "openssl"))
    def rsa(self):
        data, sig = self.file("data.bin"), self.file("rsa.sig")
        self.p11("--sign", "--mechanism", "SHA256-RSA-PKCS", "--id", ID_RSA, "-i", data,
                 "-o", sig, login=True)
        run(["openssl", "dgst", "-sha256", "-verify", self.file("rsa-pub.pem"),
             "-signature", sig, data])
        # OpenSC strips either padding on the host over the card's raw RSA; OAEP
        # with SHA-256 is what systemd 261's cryptenroll seals a LUKS key with.
        for name, enc, dec in (
            ("PKCS#1", [], ["--mechanism", "RSA-PKCS"]),
            ("OAEP", ["-pkeyopt", "rsa_padding_mode:oaep", "-pkeyopt", "rsa_oaep_md:sha256",
                      "-pkeyopt", "rsa_mgf1_md:sha256"],
             ["--mechanism", "RSA-PKCS-OAEP", "--hash-algorithm", "SHA256",
              "--mgf", "MGF1-SHA256"]),
        ):
            tag = name.lower().replace("#", "")
            secret, ct, pt = (self.file(f"secret-{tag}.{x}") for x in ("bin", "ct", "pt"))
            pathlib.Path(secret).write_bytes(os.urandom(32))
            run(["openssl", "pkeyutl", "-encrypt", "-pubin", "-inkey", self.file("rsa-pub.pem"),
                 *enc, "-in", secret, "-out", ct])
            self.p11("--decrypt", *dec, "--id", ID_RSA, "-i", ct, "-o", pt, login=True)
            if pathlib.Path(pt).read_bytes() != pathlib.Path(secret).read_bytes():
                raise StepFailed(f"{name}: the token decrypted something else")

    @step("rsk hsm attest: the EC key was generated on this device")
    def attest(self):
        _, out = self.rsk("attest", "--key", "1")
        line = next((ln for ln in out.splitlines() if "generated on this device" in ln), None)
        if line is None:
            raise StepFailed(out)
        return " ".join(line.split(":", 1)[1].split())

    @step("sc-hsm-tool wraps a key, deletes it, unwraps it back; it still signs",
          needs=("sc-hsm-tool", "pkcs11-tool", "openssl"))
    def backup(self):
        wrapped = self.file("wrapped.bin")
        run(["sc-hsm-tool", "-r", self.reader, "--wrap-key", wrapped, "--key-reference", "1",
             "--pin", PIN])
        self.p11("--delete-object", "--type", "privkey", "--id", ID_EC, login=True)
        rc, _ = self.p11("--sign", "--mechanism", "ECDSA-SHA256", "--id", ID_EC,
                         "-i", self.file("data.bin"), "-o", self.file("gone.sig"),
                         login=True, check=False)
        if rc == 0:
            raise StepFailed("the deleted key still signed")
        run(["sc-hsm-tool", "-r", self.reader, "--unwrap-key", wrapped, "--key-reference", "1",
             "--pin", PIN, "--force"])
        sig = self.file("restored.sig")
        self.p11("--sign", "--mechanism", "ECDSA-SHA256", "--id", ID_EC,
                 "-i", self.file("data.bin"), "-o", sig, "--signature-format", "openssl",
                 login=True)
        run(["openssl", "dgst", "-sha256", "-verify", self.file("ec-pub.pem"),
             "-signature", sig, self.file("data.bin")])
        return f"{os.path.getsize(wrapped)}-byte backup"

    # ---- GnuTLS -------------------------------------------------------------

    @step("certtool self-signs on the token, p11tool stores it, OpenSSL verifies it",
          needs=("certtool", "p11tool", "openssl"))
    def certificate(self):
        _, tokens = run(["p11tool", "--list-tokens"])
        url = next((ln.split("URL:", 1)[1].strip() for ln in tokens.splitlines()
                    if "URL:" in ln and "RS-Key" in ln), None)
        if url is None:
            raise StepFailed("p11tool lists no RS-Key token")
        tmpl, cert = self.file("cert.cfg"), self.file("rsa-cert.pem")
        pathlib.Path(tmpl).write_text('cn = "RS-Key HSM interop"\nserial = 1\n'
                                      "expiration_days = 30\nsigning_key\nencryption_key\n")
        env = {"GNUTLS_PIN": PIN}
        run(["certtool", "--generate-self-signed",
             "--load-privkey", f"{url};object=interop-rsa;type=private",
             "--load-pubkey", f"{url};object=interop-rsa;type=public",
             "--template", tmpl, "--outfile", cert], env=env)
        run(["openssl", "verify", "-CAfile", cert, cert])
        run(["p11tool", "--login", "--write", "--load-certificate", cert, "--label",
             "interop-rsa", "--id", ID_RSA, url], env=env)
        _, objects = self.p11("-O")
        if "Certificate Object" not in objects:
            raise StepFailed("the certificate is not on the token")

    # ---- LUKS ---------------------------------------------------------------

    @step("systemd-cryptenroll binds a LUKS2 keyslot to the token",
          needs=("cryptsetup", "systemd-cryptenroll"))
    def enroll(self):
        image = self.file("luks.img")
        with open(image, "wb") as f:
            f.truncate(32 * 1024 * 1024)
        run(["cryptsetup", "luksFormat", "--batch-mode", "--type", "luks2", "--pbkdf", "pbkdf2",
             "--pbkdf-force-iterations", "1000", "--key-file", "-", image],
            stdin=LUKS_PASSPHRASE)
        _, out = run(["systemd-cryptenroll", f"--pkcs11-token-uri={self.token_uri()}", image],
                     env={"PASSWORD": LUKS_PASSPHRASE, "PIN": PIN})
        _, dump = run(["cryptsetup", "luksDump", image])
        if "systemd-pkcs11" not in dump:
            raise StepFailed(f"no systemd-pkcs11 token in the header:\n{out}")

    def token_uri(self):
        _, tokens = run(["p11tool", "--list-tokens"]) if shutil.which("p11tool") else (0, "")
        url = next((ln.split("URL:", 1)[1].strip() for ln in tokens.splitlines()
                    if "URL:" in ln and "RS-Key" in ln), None)
        return url or "auto"

    def luks_open(self):
        """Open the keyslot through the token, with no device-mapper needed."""
        return run(["cryptsetup", "open", "--test-passphrase", "--token-only",
                    self.file("luks.img")], stdin=PIN, check=False)

    @step("cryptsetup opens the keyslot through the token", needs=("cryptsetup",))
    def unlock_luks(self):
        rc, out = self.luks_open()
        if rc != 0:
            raise StepFailed(out[-400:])

    @step("the lock: armed, closed by a power cycle, LUKS refused until unlocked",
          needs=("cryptsetup",))
    def lock(self):
        secret = self.file("unlock.key")
        if not self.args.emu_ccid:
            print("👉 touch the button when the HSM asks — to arm the lock, then to disarm it")
        self.rsk("lock", "arm", "--scheme", "hex", "--so-pin", SO_PIN_HEX, "--secret-out", secret,
                 stdin="ARM-HSM\n")
        self.power_cycle()
        _, status = self.rsk("status")
        if "LOCKED" not in status:
            raise StepFailed(f"after the power cycle:\n{status}")
        rc, out = self.luks_open()
        if rc == 0:
            raise StepFailed("LUKS opened through a locked HSM")
        self.rsk("lock", "unlock", "--secret-file", secret)
        rc, out = self.luks_open()
        if rc != 0:
            raise StepFailed(f"the unlocked HSM did not open LUKS: {out[-300:]}")
        self.rsk("lock", "disarm", "--so-pin", SO_PIN_HEX)
        self.power_cycle()
        _, status = self.rsk("status")
        if "disarmed" not in status:
            raise StepFailed(f"after disarming and a power cycle:\n{status}")

    def power_cycle(self):
        if self.args.emu_ccid:
            os.environ["RSK_EMU_CCID"] = self.args.emu_ccid
            import emu
            emu.power_cycle()
            return
        print("\n👉 UNPLUG the HSM, then plug it straight back in — then press Enter.")
        input()
        time.sleep(2)  # pcscd's hotplug poll


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--wipe", action="store_true", help="re-initialize an initialized token")
    p.add_argument("--reader-index", type=int, default=0, help="opensc-tool reader number")
    p.add_argument("--emu-ccid", help="the emulator's card socket, HOST:PORT, for power cycles")
    args = p.parse_args()
    if shutil.which("pkcs11-tool") is None or shutil.which("opensc-tool") is None:
        print("SKIP: OpenSC is not installed (pkcs11-tool, opensc-tool)")
        sys.exit(EXIT_SKIP)
    with tempfile.TemporaryDirectory(prefix="rsk-hsm-interop-") as work:
        suite = Suite(args, work)
        if suite.module is None:
            print("SKIP: no opensc-pkcs11.so found")
            sys.exit(EXIT_SKIP)
        if not suite.driver():
            sys.exit(1)
        for s in (suite.initialize, suite.dkek, suite.keygen, suite.selftest, suite.ecdsa,
                  suite.ecdh, suite.rsa, suite.attest, suite.backup, suite.certificate,
                  suite.enroll, suite.unlock_luks, suite.lock):
            s()
            if results[-1] == "FAIL" and s in (suite.initialize, suite.keygen):
                break  # nothing after these has a token to work on
    fails = results.count("FAIL")
    print(f"\n{results.count('PASS')} passed, {fails} failed, {results.count('SKIP')} skipped")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
