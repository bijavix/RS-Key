# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""rsk hsm — the HSM image: its status, its attestation, its lock, its DKEK.

  status            version, serial, PIN tries, the lock and the DKEK
  attest            check 2F02's chain to the device root, and that root against
                    the rescue applet's device key; with --key, that key's
                    attested request, as OpenSC stored it at generation
  lock arm          arm the lock with a fresh 32-byte unlock secret, shown ONCE
                    (SO-PIN + touch; typed confirm)
  lock unlock       present the secret: the key store opens until power-off
  lock disarm       back to no lock (SO-PIN + touch; unlock first)
  dkek create       draw a DKEK share, show it as SLIP-39 T-of-N shares, import it
  dkek import       rebuild a share from SLIP-39 shares and import it

Keys are PKCS#11's business: generate, use and back them up with OpenSC
(`pkcs11-tool`, `sc-hsm-tool`) — see docs/guides/hsm.md.
"""
import getpass
import hashlib
import os
import sys

from . import ccid
from .backup import from_bip39, from_slip39, to_bip39, to_slip39
from .common import die, sanitize

from cryptography.exceptions import InvalidSignature  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305  # noqa: E402
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # noqa: E402

HSM_AID = bytes.fromhex("E82B0601040181C31F0201")
RESCUE_AID = bytes.fromhex("A0583FC19B7E4F21")

CLA_ISO, CLA_PROPRIETARY = 0x00, 0x80
INS_VERIFY, INS_KEY_DOMAIN, INS_READ_ODD, INS_LOCK, INS_GET_RESPONSE = 0x20, 0x52, 0xB1, 0xE8, 0xC0
INS_KEYDEV = 0x10  # the rescue applet's device-key instruction; P1 02 answers its point
PIN_USER, PIN_SO = 0x81, 0x88
LOCK_STATUS, LOCK_CHANNEL, LOCK_UNLOCK, LOCK_ARM, LOCK_DISARM = 0, 1, 2, 3, 4
FACTOR_NONE, FACTOR_HOST_KEY, FACTOR_FIDO2 = 0, 1, 2
STATE_DISARMED, STATE_LOCKED, STATE_UNLOCKED, STATE_UNKNOWN = 0, 1, 2, 0xFF
FLAG_INITIALIZED, FLAG_OTP_ROOT, FLAG_USER_VERIFIED, FLAG_RESCRUB_REFUSED = 1, 2, 4, 8
FID_DEVAUT = 0x2F02
PREFIX_EE_CERT = 0xCE
SO_PIN_LEN = 8
SECRET_LEN = 32
DKEK_SHARE_LEN = 32
KCV_LEN = 8
CHANNEL_SALT = b"RSK-HSM/LOCK-CHANNEL"  # must match rsk-hsm's channel.rs
CHUNK = 0xFF  # what one short READ BINARY asks for

SW_OK = 0x9000
SW_EOF = 0x6282
SW_SECURITY = 0x6982
SW_BLOCKED = 0x6983
SW_CONDITIONS = 0x6985
SW_NOT_ALLOWED = 0x6986
SW_REF_NOT_FOUND = 0x6A88

STATES = {
    STATE_DISARMED: "disarmed",
    STATE_LOCKED: "LOCKED — `rsk hsm lock unlock` opens it",
    STATE_UNLOCKED: "armed, unlocked until power-off",
    STATE_UNKNOWN: "unknown — the device record could not be read",
}
FACTORS = {FACTOR_NONE: "none", FACTOR_HOST_KEY: "host key", FACTOR_FIDO2: "FIDO2 token"}

# id-TA (0.4.0.127.0.7.2.2.2) and the two arcs after it that name a CV
# signature algorithm (BSI TR-03110).
ID_TA = bytes.fromhex("04007F0007020202")
CV_ALGS = {
    b"\x01\x02": ("rsa-v15", hashes.SHA256),
    b"\x01\x04": ("rsa-pss", hashes.SHA256),
    b"\x01\x05": ("rsa-v15", hashes.SHA512),
    b"\x01\x06": ("rsa-pss", hashes.SHA512),
    b"\x02\x03": ("ecdsa", hashes.SHA256),
    b"\x02\x04": ("ecdsa", hashes.SHA384),
    b"\x02\x05": ("ecdsa", hashes.SHA512),
}
# The curves a CV public key names by its field prime (SEC 2, FIPS 186-4).
CURVES = {
    2**256 - 2**224 + 2**192 + 2**96 - 1: ec.SECP256R1,
    2**384 - 2**128 - 2**96 + 2**32 - 1: ec.SECP384R1,
    2**521 - 1: ec.SECP521R1,
    2**256 - 2**32 - 977: ec.SECP256K1,
}


class CardError(Exception):
    """A status word a command did not want."""

    def __init__(self, what, sw):
        super().__init__(f"{what}: SW {sw:04X}")
        self.sw = sw


# ---- BER-TLV ---------------------------------------------------------------


def tlv(tag, value):
    head = tag.to_bytes(2 if tag > 0xFF else 1, "big")
    n = len(value)
    if n < 0x80:
        ln = bytes([n])
    elif n < 0x100:
        ln = bytes([0x81, n])
    else:
        ln = bytes([0x82, n >> 8, n & 0xFF])
    return head + ln + bytes(value)


def objects(data):
    """Every top-level BER-TLV object in `data` as (tag, value, encoding). A
    length that runs past the data is the device's error, reported, not followed."""
    out, i = [], 0
    while i < len(data):
        start = i
        tag = data[i]
        i += 1
        if tag & 0x1F == 0x1F:
            if i >= len(data):
                raise ValueError("a tag cut short")
            tag = (tag << 8) | data[i]
            i += 1
        if i >= len(data):
            raise ValueError(f"TLV {tag:X} has no length")
        n = data[i]
        i += 1
        if n & 0x80:
            k = n & 0x7F
            if k == 0 or k > 3 or i + k > len(data):
                raise ValueError(f"TLV {tag:X} has a malformed length")
            n = int.from_bytes(data[i:i + k], "big")
            i += k
        if i + n > len(data):
            raise ValueError(f"TLV {tag:X} runs past its container")
        out.append((tag, data[i:i + n], data[start:i + n]))
        i += n
    return out


def child(data, tag):
    """The first object tagged `tag` in `data`: (value, encoding)."""
    for t, value, raw in objects(data):
        if t == tag:
            return value, raw
    raise ValueError(f"no TLV {tag:X}")


# ---- the card --------------------------------------------------------------


class Hsm:
    """The HSM applet over one PC/SC connection, short APDUs only — every reader
    carries them."""

    def __init__(self, conn):
        self.conn = conn

    def raw(self, cla, ins, p1, p2, data=b""):
        cmd = [cla, ins, p1, p2]
        if data:
            if len(data) > 255:
                raise ValueError("a command longer than a short APDU")
            cmd += [len(data)] + list(data)
        cmd += [0x00]
        body, sw1, sw2 = ccid.transmit(self.conn, cmd)
        while sw1 == 0x61:
            more, sw1, sw2 = ccid.transmit(self.conn, [0x00, INS_GET_RESPONSE, 0x00, 0x00, sw2])
            body += more
        return body, (sw1 << 8) | sw2

    def cmd(self, what, cla, ins, p1, p2, data=b""):
        body, sw = self.raw(cla, ins, p1, p2, data)
        if sw != SW_OK:
            raise CardError(what, sw)
        return body

    def select(self, aid=HSM_AID):
        """SELECT an applet — for the HSM, which ends its login session — and
        answer its FCP."""
        body, sw = self.raw(CLA_ISO, 0xA4, 0x04, 0x00, aid)
        if sw != SW_OK:
            die("no HSM applet on this card — is it the HSM image?" if aid == HSM_AID
                else f"SELECT {aid.hex()}: SW {sw:04X}")
        return body

    def read(self, fid):
        """A whole EF, a short READ BINARY at a time, as OpenSC reads one."""
        out = b""
        while True:
            offset = tlv(0x54, len(out).to_bytes(2, "big"))
            body, sw = self.raw(CLA_ISO, INS_READ_ODD, fid >> 8, fid & 0xFF, offset)
            if sw not in (SW_OK, SW_EOF):
                raise CardError(f"READ BINARY {fid:04X}", sw)
            out += body
            if sw == SW_EOF or not body:
                return out

    def pin_status(self, ref):
        return self.raw(CLA_ISO, INS_VERIFY, 0x00, ref)[1]

    def lock_status(self):
        body = self.cmd("LOCK STATUS", CLA_PROPRIETARY, INS_LOCK, LOCK_STATUS, 0)
        if len(body) != 4:
            die(f"LOCK STATUS answered {body.hex()}")
        return body

    def key_domain(self, share=b""):
        """MANAGE KEY DOMAIN: (shares in total, still owed, KCV) — `share` imports
        one first. None when no DKEK is configured."""
        body, sw = self.raw(CLA_PROPRIETARY, INS_KEY_DOMAIN, 0x00, 0x00, share)
        if sw == SW_REF_NOT_FOUND:
            return None
        if sw != SW_OK:
            raise CardError("MANAGE KEY DOMAIN", sw)
        if len(body) < 2 + KCV_LEN:
            die(f"MANAGE KEY DOMAIN answered {body.hex()}")
        return body[0], body[1], body[2:2 + KCV_LEN]

    def lock_box(self, p1, p2, plain):
        """Send `plain` boxed over a fresh lock channel — an ephemeral P-256
        agreement whose key opens exactly one ChaCha20-Poly1305 box."""
        host = ec.generate_private_key(ec.SECP256R1())
        host_pub = host.public_key().public_bytes(serialization.Encoding.X962,
                                                  serialization.PublicFormat.UncompressedPoint)
        dev_pub = self.cmd("LOCK CHANNEL", CLA_PROPRIETARY, INS_LOCK, LOCK_CHANNEL, 0, host_pub)
        blob = seal_box(host, host_pub, dev_pub, plain, os.urandom(12))
        return self.raw(CLA_PROPRIETARY, INS_LOCK, p1, p2, blob)[1]


def seal_box(host, host_pub, dev_pub, plain, nonce):
    """`nonce ‖ ChaCha20-Poly1305(k, nonce, plain, aad = dev_pub)`, where k is
    HKDF-SHA256 of the P-256 agreement, salted, over both points."""
    if len(dev_pub) != 65 or dev_pub[0] != 0x04:
        die(f"LOCK CHANNEL answered {dev_pub.hex()}, not a P-256 point")
    peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), dev_pub)
    z = host.exchange(ec.ECDH(), peer)
    key = HKDF(hashes.SHA256(), 32, CHANNEL_SALT, dev_pub + host_pub).derive(z)
    return nonce + ChaCha20Poly1305(key).encrypt(nonce, plain, dev_pub)


def connect(args, exclusive=False):
    """The HSM, selected, and its FCP. Every command that changes the device —
    or hands it a secret — asks for `exclusive`: one RS-Key reader, or none."""
    hsm = Hsm(ccid.connect(getattr(args, "reader", None), exclusive=exclusive))
    return hsm, hsm.select()


# ---- attestation -----------------------------------------------------------


def ecdsa_der(raw):
    half = len(raw) // 2
    return encode_dss_signature(int.from_bytes(raw[:half], "big"),
                                int.from_bytes(raw[half:], "big"))


def cv_key(pk):
    """The public key a CV `7F49` carries, and the algorithm it names."""
    oid = child(pk, 0x06)[0]
    if oid[:len(ID_TA)] != ID_TA or oid[len(ID_TA):] not in CV_ALGS:
        raise ValueError(f"an algorithm this tool does not know: {oid.hex()}")
    kind, digest = CV_ALGS[oid[len(ID_TA):]]
    if kind == "ecdsa":
        curve = CURVES.get(int.from_bytes(child(pk, 0x81)[0], "big"))
        if curve is None:
            raise ValueError("a curve this tool does not know")
        key = ec.EllipticCurvePublicKey.from_encoded_point(curve(), child(pk, 0x86)[0])
    else:
        n = int.from_bytes(child(pk, 0x81)[0], "big")
        e = int.from_bytes(child(pk, 0x82)[0], "big")
        key = rsa.RSAPublicNumbers(e, n).public_key()
    return key, kind, digest


def cv_verify(key, kind, digest, sig, signed):
    """Whether `sig` is `key`'s CV signature over `signed`."""
    try:
        if kind == "ecdsa":
            key.verify(ecdsa_der(sig), signed, ec.ECDSA(digest()))
        elif kind == "rsa-v15":
            key.verify(sig, signed, padding.PKCS1v15(), digest())
        else:
            pss = padding.PSS(mgf=padding.MGF1(digest()), salt_length=digest().digest_size)
            key.verify(sig, signed, pss, digest())
        return True
    except InvalidSignature:
        return False


def device_chain(devaut, keydev):
    """2F02's two certificates checked: the device key's, signed by the root, and
    the root's own — and the root is the rescue applet's device key `keydev`.
    Returns (device public key, device holder reference, root point)."""
    certs = [value for tag, value, _ in objects(devaut) if tag == 0x7F21]
    if len(certs) != 2:
        raise ValueError(f"2F02 holds {len(certs)} certificate(s), not 2")
    dev_cert, root_cert = certs
    root_body = child(root_cert, 0x7F4E)[0]
    root, rkind, rdigest = cv_key(child(root_body, 0x7F49)[0])
    root_point = child(child(root_body, 0x7F49)[0], 0x86)[0]
    if root_point != keydev:
        raise ValueError("2F02's root is not the rescue applet's device key")
    for cert, what in ((root_cert, "root"), (dev_cert, "device")):
        _, body_raw = child(cert, 0x7F4E)
        if not cv_verify(root, rkind, rdigest, child(cert, 0x5F37)[0], body_raw):
            raise ValueError(f"the {what} certificate does not verify under the root")
    dev_body = child(dev_cert, 0x7F4E)[0]
    device, _, _ = cv_key(child(dev_body, 0x7F49)[0])
    return device, child(dev_body, 0x5F20)[0], root_point


def check_request(req, device, holder):
    """A GENERATE KEY PAIR answer, `67 { 7F21 { 7F4E, 5F37 }, 42, 5F37 }`: signed by
    its own key over the body and by the device key over the certificate and the
    reference naming it. Returns the attested public key."""
    inner = child(req, 0x67)[0]
    cert, cert_raw = child(inner, 0x7F21)
    body, body_raw = child(cert, 0x7F4E)
    key, kind, digest = cv_key(child(body, 0x7F49)[0])
    if not cv_verify(key, kind, digest, child(cert, 0x5F37)[0], body_raw):
        raise ValueError("the request is not signed by the key it carries")
    car, car_raw = child(inner, 0x42)
    if car != holder:
        raise ValueError(f"the request is vouched for by {car!r}, not this device ({holder!r})")
    if not cv_verify(device, "ecdsa", hashes.SHA256, child(inner, 0x5F37)[0], cert_raw + car_raw):
        raise ValueError("the device key's signature over the request does not verify")
    return key


def describe(key):
    if isinstance(key, rsa.RSAPublicKey):
        return f"RSA-{key.key_size}"
    return f"EC {key.curve.name}"


# ---- secrets ---------------------------------------------------------------


def parse_so_pin(text):
    """The SO-PIN as `sc-hsm-tool` takes it: sixteen hex digits."""
    text = text.strip()
    try:
        pin = bytes.fromhex(text)
    except ValueError:
        pin = b""
    if len(pin) != SO_PIN_LEN:
        die("the SO-PIN is 16 hex digits, as sc-hsm-tool takes it (e.g. 3537363231383830)")
    return pin


def resolve_so_pin(args):
    return parse_so_pin(args.so_pin if args.so_pin else getpass.getpass("SO-PIN (16 hex digits): "))


def read_secret(args):
    """The unlock secret from --secret-file (32 raw bytes or 64 hex digits),
    --key-hex, --mnemonic, or a prompt per --scheme."""
    if args.secret_file:
        with open(args.secret_file, "rb") as f:
            raw = f.read()
        secret = raw if len(raw) == SECRET_LEN else _hex_secret(raw.decode(errors="replace"))
    elif args.key_hex:
        secret = _hex_secret(args.key_hex)
    elif args.scheme == "bip39":
        secret = from_bip39(args.mnemonic or getpass.getpass("BIP-39 phrase: "))
    elif args.scheme == "slip39":
        print("Enter SLIP-39 shares, one per line, blank line to finish:")
        lines = []
        while (ln := input()).strip():
            lines.append(ln)
        secret = from_slip39(lines)
    else:
        secret = _hex_secret(getpass.getpass("unlock secret (64 hex digits): "))
    if len(secret) != SECRET_LEN:
        die(f"the unlock secret is {SECRET_LEN} bytes, this is {len(secret)}")
    return secret


def _hex_secret(text):
    try:
        return bytes.fromhex(text.strip())
    except ValueError:
        die("the unlock secret is 64 hex digits")


def write_private(path, data):
    """Create `path` 0600 and write `data`, refusing to replace a file — it may be
    the only copy of the secret it holds."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        die(f"{path} exists — refusing to overwrite what may be the only copy of a secret")
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def show_secret(secret, args):
    """Render a secret ONCE in the chosen scheme."""
    if args.scheme == "bip39":
        rendered = to_bip39(secret)
    elif args.scheme == "slip39":
        rendered = to_slip39(secret, args.threshold, args.shares)
    else:
        rendered = [secret.hex()]
    for i, line in enumerate(rendered, 1):
        label = f"share {i}/{len(rendered)}" if len(rendered) > 1 else args.scheme
        print(f"\n[{label}]\n{line}")
    if args.scheme == "slip39":
        print(f"\n(any {args.threshold} of {args.shares} shares rebuild it)")


# ---- commands --------------------------------------------------------------


def _tries(sw):
    if sw == SW_OK:
        return "verified this session"
    if sw == SW_BLOCKED:
        return "BLOCKED"
    if sw & 0xFFF0 == 0x63C0:
        return f"{sw & 0x0F} tries left"
    return f"unreadable (SW {sw:04X})"


def cmd_status(args):
    hsm, fcp = connect(args)
    props = child(child(fcp, 0x62)[0], 0x85)[0]
    print(f"HSM applet       : version {props[-2]}.{props[-1]}")
    try:
        holder = device_chain_holder(hsm)
        print(f"device           : {sanitize(holder.decode(errors='replace'))}")
    except (CardError, ValueError) as e:
        print(f"device           : no readable identity ({e})")
    status = hsm.lock_status()
    if not status[3] & FLAG_INITIALIZED:
        print("initialized      : no — `sc-hsm-tool --initialize` sets the PINs")
        return
    print(f"user PIN         : {_tries(hsm.pin_status(PIN_USER))}")
    print(f"SO-PIN           : {_tries(hsm.pin_status(PIN_SO))}")
    print(f"lock             : {STATES.get(status[1], f'state {status[1]:#04x}')}"
          f" (factor: {FACTORS.get(status[2], f'{status[2]:#04x}')})")
    print(f"device root      : {'OTP-fused' if status[3] & FLAG_OTP_ROOT else 'chip serial only (not provisioned)'}")
    if status[3] & FLAG_RESCRUB_REFUSED:
        print("WARNING          : the flash refused to re-arm its at-rest scrub this power cycle")
    try:
        dkek = hsm.key_domain()
    except CardError as e:
        print(f"DKEK             : unreadable while locked ({e})" if e.sw == SW_CONDITIONS
              else f"DKEK             : {e}")
        return
    if dkek is None:
        print("DKEK             : none — keys can never leave this device")
    else:
        total, owed, kcv = dkek
        print(f"DKEK             : {total - owed} of {total} share(s) imported, KCV {kcv.hex()}"
              + ("" if owed == 0 else " — no key can be made until the rest are in"))


def device_chain_holder(hsm):
    certs = [value for tag, value, _ in objects(hsm.read(FID_DEVAUT)) if tag == 0x7F21]
    if not certs:
        raise ValueError("2F02 is empty")
    return child(child(certs[0], 0x7F4E)[0], 0x5F20)[0]


def cmd_attest(args):
    hsm, _ = connect(args)
    devaut = hsm.read(FID_DEVAUT)
    hsm.select(RESCUE_AID)
    keydev = hsm.cmd("rescue KEYDEV public key", CLA_PROPRIETARY, INS_KEYDEV, 0x02, 0x00)
    hsm.select()
    try:
        device, holder, root_point = device_chain(devaut, keydev)
    except ValueError as e:
        die(f"attestation FAILED: {e}")
    fingerprint = hashlib.sha256(root_point).hexdigest()
    print(f"device           : {sanitize(holder.decode(errors='replace'))}")
    print(f"device root      : secp256k1, SHA-256 {fingerprint}")
    print("chain            : device certificate ← root ← the rescue applet's device key ✓")
    if args.expect_root and args.expect_root.lower() != fingerprint:
        die("the device root is NOT the one you pinned — this is another device, or it was re-keyed")
    if args.key is not None:
        try:
            stored = hsm.read(PREFIX_EE_CERT << 8 | args.key)
        except CardError as e:
            die(f"key {args.key}: nothing stored at CE{args.key:02X} ({e})")
        if not stored.startswith(b"\x67"):
            die(f"key {args.key}: its request was replaced by a certificate, so the token no "
                "longer carries proof of where the key was made")
        try:
            key = check_request(stored, device, holder)
        except ValueError as e:
            die(f"key {args.key}: attestation FAILED: {e}")
        print(f"key {args.key:<12} : {describe(key)}, generated on this device ✓")
    if not args.expect_root:
        print("\nPin this root: pass --expect-root next time, so a swapped device cannot pass.")


def cmd_lock_arm(args):
    hsm, _ = connect(args, exclusive=True)
    status = hsm.lock_status()
    if not status[3] & FLAG_INITIALIZED:
        die("initialize the HSM first (sc-hsm-tool --initialize)")
    if status[1] != STATE_DISARMED:
        die("the lock is already armed")
    so_pin = resolve_so_pin(args)
    print("""Arming the lock means:
  * EVERY power-up leaves the key store shut until the unlock secret is
    presented (`rsk hsm lock unlock`) — a LUKS volume behind it waits too.
  * Lose the secret and the keys are reachable only from their backups; the
    SO-PIN can re-initialize the device, which erases them.""")
    if input("\nType ARM-HSM to arm the lock: ").strip() != "ARM-HSM":
        die("aborted")
    secret = os.urandom(SECRET_LEN)
    # Shown before the arm, not after: a run that dies once the device holds the
    # secret must not have been the only thing that ever saw it.
    print("\n=== WRITE THIS DOWN — the HSM's unlock secret ===")
    show_secret(secret, args)
    if args.secret_out:
        write_private(args.secret_out, secret.hex().encode() + b"\n")
    print("\ntouch the device to authorise…", file=sys.stderr)
    sw = hsm.lock_box(LOCK_ARM, FACTOR_HOST_KEY, secret + so_pin)
    if sw != SW_OK:
        if args.secret_out:
            os.remove(args.secret_out)
        die(_lock_refusal("arm", sw) + " — nothing was armed; discard the secret above")
    print("\nlock armed ✓ — unlocked until power-off; every power-up from now on needs"
          " `rsk hsm lock unlock`")


def cmd_lock_unlock(args):
    secret = read_secret(args)
    hsm, _ = connect(args, exclusive=True)
    sw = hsm.lock_box(LOCK_UNLOCK, 0, secret)
    if sw != SW_OK:
        die(_lock_refusal("unlock", sw))
    print("unlocked ✓ — the key store is open until power-off")


def cmd_lock_disarm(args):
    hsm, _ = connect(args, exclusive=True)
    so_pin = resolve_so_pin(args)
    print("touch the device to authorise…", file=sys.stderr)
    _, sw = hsm.raw(CLA_PROPRIETARY, INS_LOCK, LOCK_DISARM, 0, so_pin)
    if sw != SW_OK:
        die(_lock_refusal("disarm", sw))
    print("lock disarmed ✓ — power-ups no longer need the secret")


def _lock_refusal(what, sw):
    if sw == SW_CONDITIONS:
        return {
            "arm": f"{what} refused: the lock is not disarmed",
            "unlock": f"{what} refused: the lock is not armed",
            "disarm": f"{what} refused: the lock is not armed, or not unlocked yet",
        }[what]
    if sw == SW_SECURITY:
        return (f"{what} refused: wrong secret" if what == "unlock"
                else f"{what} refused: the touch was declined")
    if sw & 0xFFF0 == 0x63C0:
        return f"{what} refused: wrong SO-PIN, {sw & 0x0F} tries left"
    if sw == SW_BLOCKED:
        return f"{what} refused: the SO-PIN is blocked"
    return f"{what} failed: SW {sw:04X}"


def _owed(hsm):
    try:
        dkek = hsm.key_domain()
    except CardError as e:
        die(f"the key domain is unreadable ({e}) — unlocked?")
    if dkek is None:
        die("this device keeps no DKEK — initialize it with --dkek-shares N to back keys up")
    total, owed, _ = dkek
    if owed == 0:
        die(f"all {total} DKEK share(s) are already in")
    return total, owed


def _import(hsm, share):
    try:
        total, owed, kcv = hsm.key_domain(share)
    except CardError as e:
        die(f"import refused ({e})")
    print(f"share imported ✓ — {total - owed} of {total} in, DKEK KCV {kcv.hex()}"
          + ("" if owed == 0 else f"; {owed} still owed"))


def cmd_dkek_create(args):
    hsm, _ = connect(args, exclusive=True)
    _owed(hsm)
    share = os.urandom(DKEK_SHARE_LEN)
    print("\n=== WRITE THESE DOWN — one DKEK share, as SLIP-39 shares ===")
    print("Every backup this device makes is encrypted under the DKEK; without the\n"
          "share, no backup restores anywhere.")
    for i, line in enumerate(to_slip39(share, args.threshold, args.shares), 1):
        print(f"\n[share {i}/{args.shares}]\n{line}")
    print(f"\n(any {args.threshold} of {args.shares} rebuild the DKEK share; its check value is"
          f" {hashlib.sha256(share).hexdigest()[:2 * KCV_LEN]})")
    if input("\nType IMPORT once the shares are written down: ").strip() != "IMPORT":
        die("aborted — nothing was imported")
    _import(hsm, share)


def cmd_dkek_import(args):
    print("Enter SLIP-39 shares of one DKEK share, one per line, blank line to finish:")
    lines = []
    while (ln := input()).strip():
        lines.append(ln)
    share = from_slip39(lines)
    if len(share) != DKEK_SHARE_LEN:
        die(f"the rebuilt share is {len(share)} bytes, a DKEK share is {DKEK_SHARE_LEN}")
    hsm, _ = connect(args, exclusive=True)
    _owed(hsm)
    _import(hsm, share)


def register(sub):
    p = sub.add_parser("hsm", help="the HSM image: status, attestation, lock, DKEK shares")
    p.add_argument("--reader", help="PC/SC reader name substring (default: the RS-Key reader)")
    g = p.add_subparsers(dest="cmd", required=True)
    g.add_parser("status", help="version, serial, PIN tries, lock, DKEK").set_defaults(func=cmd_status)

    a = g.add_parser("attest", help="check the device's attestation chain (and a key's)")
    a.add_argument("--key", type=lambda s: int(s, 0), help="key reference to check (1-255)")
    a.add_argument("--expect-root", help="SHA-256 of the device root you pinned")
    a.set_defaults(func=cmd_attest)

    lk = g.add_parser("lock", help="arm, unlock or disarm the HSM lock")
    lg = lk.add_subparsers(dest="lock_cmd", required=True)

    def scheme(sp):
        sp.add_argument("--scheme", choices=["bip39", "slip39", "hex"], default="bip39")

    arm = lg.add_parser("arm", help="arm the lock (shows the unlock secret ONCE)")
    scheme(arm)
    arm.add_argument("--threshold", type=int, default=2, help="SLIP-39 shares needed (default 2)")
    arm.add_argument("--shares", type=int, default=3, help="SLIP-39 total shares (default 3)")
    arm.add_argument("--so-pin", help="SO-PIN, 16 hex digits (prompted if omitted)")
    arm.add_argument("--secret-out", help="also write the secret (hex) to this new 0600 file")
    arm.set_defaults(func=cmd_lock_arm)

    un = lg.add_parser("unlock", help="present the unlock secret until power-off")
    scheme(un)
    un.add_argument("--secret-file", help="the secret: 32 raw bytes or 64 hex digits")
    un.add_argument("--key-hex", help="the secret as 64 hex digits")
    un.add_argument("--mnemonic", help="the secret as a BIP-39 phrase")
    un.set_defaults(func=cmd_lock_unlock)

    dis = lg.add_parser("disarm", help="disarm the lock (unlock first)")
    dis.add_argument("--so-pin", help="SO-PIN, 16 hex digits (prompted if omitted)")
    dis.set_defaults(func=cmd_lock_disarm)

    dk = g.add_parser("dkek", help="DKEK shares as SLIP-39 T-of-N")
    dg = dk.add_subparsers(dest="dkek_cmd", required=True)
    cr = dg.add_parser("create", help="draw a share, show it as SLIP-39 shares, import it")
    cr.add_argument("--threshold", type=int, default=2, help="SLIP-39 shares needed (default 2)")
    cr.add_argument("--shares", type=int, default=3, help="SLIP-39 total shares (default 3)")
    cr.set_defaults(func=cmd_dkek_create)
    dg.add_parser("import", help="rebuild a share from SLIP-39 shares and import it") \
        .set_defaults(func=cmd_dkek_import)
