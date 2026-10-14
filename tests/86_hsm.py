#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""HSM image test — the SmartCard-HSM-compatible applet over PC/SC, every answer
checked host-side with an independent implementation (`cryptography`).

Covers: SELECT and its FCP, INITIALIZE, the user PIN and SO-PIN with their retry
counters (wrong tries, CHANGE, block, RESET RETRY COUNTER), the device
certificate chain in 2F02 and its root against the rescue applet's device key,
EC P-256 and RSA keys generated with an attested request, SIGN (card-hashed and
host-hashed), ECDH, RSA decryption, AES keys with CBC and CMAC, a DKEK share,
WRAP opened host-side and UNWRAP of the result, a forged backup refused, DELETE,
and the lock: armed, relocked by a power cycle, unlocked, disarmed.

DESTRUCTIVE: INITIALIZE erases every key on the device. A device that is already
initialized is left alone unless --wipe is given.

    nix develop -c python tests/86_hsm.py [--wipe] [--rsa-bits 2048|3072|4096]
    python tests/emu.py tests/86_hsm.py      # against `tools/emu --hsm`

The lock needs a power cycle: on a board the suite asks for an unplug, on the
emulator it is the card socket's replug. A re-initialization, ARM and DISARM
each ask for a touch.
"""
import hashlib
import os
import struct
import sys

try:
    from smartcard.Exceptions import NoCardException
except ImportError:
    sys.exit("missing dependency: pip install pyscard")
try:
    from cryptography.hazmat.primitives import cmac, hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, encode_dss_signature
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
except ImportError:
    sys.exit("missing dependency: pip install cryptography")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _device import find_reader  # noqa: E402
import replug  # noqa: E402

HSM_AID = bytes.fromhex("E82B0601040181C31F0201")
RESCUE_AID = bytes.fromhex("A0583FC19B7E4F21")

INS_VERIFY, INS_CHANGE, INS_RESET_RETRY = 0x20, 0x24, 0x2C
INS_INITIALIZE, INS_KEY_DOMAIN = 0x50, 0x52
INS_GENERATE, INS_GENERATE_SYM = 0x46, 0x48
INS_DECIPHER, INS_SIGN, INS_WRAP, INS_UNWRAP, INS_CIPHER = 0x62, 0x68, 0x72, 0x74, 0x78
INS_SELECT, INS_READ_ODD, INS_UPDATE_ODD, INS_DELETE = 0xA4, 0xB1, 0xD7, 0xE4
INS_LOCK, INS_GET_RESPONSE = 0xE8, 0xC0
INS_KEYDEV = 0x10  # the rescue applet's device-key instruction; P1 02 answers the point

PIN_USER, PIN_SO = 0x81, 0x88
ALGO_RSA_RAW, ALGO_RSA_DECRYPT, ALGO_RSA_PKCS1_SHA256 = 0x20, 0x21, 0x33
ALGO_EC_RAW, ALGO_EC_SHA256, ALGO_EC_DH = 0x70, 0x73, 0x80
ALGO_AES_ENC, ALGO_AES_DEC, ALGO_AES_CMAC = 0x10, 0x11, 0x18
AES_256 = 0xB2
LOCK_STATUS, LOCK_CHANNEL, LOCK_UNLOCK, LOCK_ARM, LOCK_DISARM = 0, 1, 2, 3, 4
FACTOR_HOST_KEY = 0x01
STATE_DISARMED, STATE_LOCKED, STATE_UNLOCKED = 0, 1, 2
FLAG_INITIALIZED, FLAG_USER_VERIFIED = 0x01, 0x04

SW_OK, SW_EOF = 0x9000, 0x6282
SW_SECURITY, SW_BLOCKED, SW_CONDITIONS = 0x6982, 0x6983, 0x6985
SW_WRONG_DATA, SW_NOT_FOUND, SW_REF_NOT_FOUND = 0x6A80, 0x6A82, 0x6A88

USER_PIN = b"648219"
OTHER_PIN = b"20261014"
# `sc-hsm-tool`'s documented default SO-PIN, `3537363231383830`.
SO_PIN = b"57621880"
RETRIES = 3
SO_RETRIES = 15
DKEK_SHARE = bytes(range(0x40, 0x60))
UNLOCK_SECRET = hashlib.sha256(b"rs-key 86_hsm unlock secret").digest()

KID_EC, KID_RSA, KID_AES, KID_RESTORED = 1, 2, 3, 4
STAGING = 0x2F10
DEVAUT = 0x2F02
PREFIX_KEY = 0xCC
DRIVER_WRAP_BUF = 1500  # the buffer OpenSC's driver reads WRAP KEY into

# The SmartCard-HSM algorithm OIDs: id-TA-ECDSA-SHA-256, id-TA-RSA-v1-5-SHA-256.
OID_ECDSA_SHA256 = bytes.fromhex("04007F00070202020203")
OID_RSA_V15_SHA256 = bytes.fromhex("04007F00070202020102")
# NIST P-256 (FIPS 186-4 D.1.2.3), sent as the driver sends it: every parameter.
P256 = {
    0x81: bytes.fromhex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"),
    0x82: bytes.fromhex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC"),
    0x83: bytes.fromhex("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"),
    0x84: bytes.fromhex("046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
                        "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"),
    0x85: bytes.fromhex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"),
    0x87: b"\x01",
}


def fail(msg):
    print("FAIL:", msg)
    sys.exit(1)


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
    """Every top-level BER-TLV object in `data` as (tag, value, encoding)."""
    out, i = [], 0
    while i < len(data):
        start = i
        tag = data[i]
        i += 1
        if tag & 0x1F == 0x1F:
            tag = (tag << 8) | data[i]
            i += 1
        n = data[i]
        i += 1
        if n & 0x80:
            k = n & 0x7F
            n = int.from_bytes(data[i:i + k], "big")
            i += k
        if i + n > len(data):
            fail(f"TLV {tag:X} runs past its container")
        out.append((tag, data[i:i + n], data[start:i + n]))
        i += n
    return out


def child(data, tag):
    """The first object tagged `tag` in `data` as (value, encoding)."""
    for t, value, raw in objects(data):
        if t == tag:
            return value, raw
    fail(f"no TLV {tag:X} in {data[:16].hex()}…")


# ---- the card --------------------------------------------------------------


class Hsm:
    def __init__(self, conn):
        self.conn = conn

    def raw(self, cla, ins, p1, p2, data=b"", extended=False):
        """One command, its 61xx continuation collected. Extended lengths when the
        data or the answer may not fit a short APDU."""
        cmd = [cla, ins, p1, p2]
        if extended or len(data) > 255:
            cmd += [0x00]
            if data:
                cmd += [len(data) >> 8, len(data) & 0xFF] + list(data)
            cmd += [0x00, 0x00]
        else:
            if data:
                cmd += [len(data)] + list(data)
            cmd += [0x00]
        resp, sw1, sw2 = self.conn.transmit(cmd)
        body = bytes(resp)
        while sw1 == 0x61:
            more, sw1, sw2 = self.conn.transmit([0x00, INS_GET_RESPONSE, 0x00, 0x00, sw2])
            body += bytes(more)
        return body, (sw1 << 8) | sw2

    def cmd(self, cla, ins, p1, p2, data=b"", want=SW_OK, what=None, extended=False):
        body, sw = self.raw(cla, ins, p1, p2, data, extended)
        if want is not None and sw != want:
            fail(f"{what or f'{cla:02X} {ins:02X} {p1:02X} {p2:02X}'}: SW {sw:04X}, want {want:04X}")
        return body, sw

    def select(self, aid=HSM_AID):
        body, sw = self.raw(0x00, INS_SELECT, 0x04, 0x00, aid)
        if sw == SW_NOT_FOUND and aid == HSM_AID:
            fail("no HSM applet — this is not the HSM image (build with --features hsm)")
        if sw != SW_OK:
            fail(f"SELECT {aid.hex()}: SW {sw:04X}")
        return body

    def verify(self, pin=USER_PIN, want=SW_OK):
        return self.cmd(0x00, INS_VERIFY, 0x00, PIN_USER, pin, want, "VERIFY")[1]

    def pin_status(self, ref=PIN_USER):
        return self.raw(0x00, INS_VERIFY, 0x00, ref)[1]

    def read(self, fid):
        """A whole EF: one extended READ BINARY, which ends at end of file."""
        body, sw = self.raw(0x00, INS_READ_ODD, fid >> 8, fid & 0xFF,
                            tlv(0x54, b"\x00\x00"), extended=True)
        if sw not in (SW_OK, SW_EOF):
            fail(f"READ BINARY {fid:04X}: SW {sw:04X}")
        return body

    def write(self, fid, data, want=SW_OK):
        payload = tlv(0x54, b"\x00\x00") + tlv(0x53, data)
        return self.cmd(0x00, INS_UPDATE_ODD, fid >> 8, fid & 0xFF, payload, want,
                        f"UPDATE BINARY {fid:04X}")[1]

    def sign(self, kid, algo, data, want=SW_OK):
        return self.cmd(0x80, INS_SIGN, kid, algo, data, want, f"SIGN key {kid} algo {algo:02X}",
                        extended=True)

    def lock_status(self):
        body, _ = self.cmd(0x80, INS_LOCK, LOCK_STATUS, 0, what="LOCK STATUS")
        if len(body) != 4:
            fail(f"LOCK STATUS answered {body.hex()}")
        return body

    def lock_box(self, p1, p2, plain, want=SW_OK, what="LOCK"):
        """Agree on a fresh lock channel and send `plain` boxed over it — the host
        half of the protocol `rsk hsm lock` speaks."""
        host = ec.generate_private_key(ec.SECP256R1())
        host_pub = host.public_key().public_bytes(serialization.Encoding.X962,
                                                  serialization.PublicFormat.UncompressedPoint)
        dev_pub, _ = self.cmd(0x80, INS_LOCK, LOCK_CHANNEL, 0, host_pub, what="LOCK CHANNEL")
        if len(dev_pub) != 65 or dev_pub[0] != 0x04:
            fail(f"LOCK CHANNEL answered {dev_pub.hex()}")
        peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), dev_pub)
        z = host.exchange(ec.ECDH(), peer)
        key = HKDF(hashes.SHA256(), 32, b"RSK-HSM/LOCK-CHANNEL", dev_pub + host_pub).derive(z)
        nonce = os.urandom(12)
        boxed = nonce + ChaCha20Poly1305(key).encrypt(nonce, plain, dev_pub)
        return self.cmd(0x80, INS_LOCK, p1, p2, boxed, want, what)[1]


def connect():
    target = find_reader(require_marker=True)
    if target is None:
        fail("no RS-Key reader found (pin one with RSK_TEST_READER)")
    try:
        conn = target.createConnection()
        conn.connect()
    except NoCardException:
        fail(f"{target} has no card powered on")
    return Hsm(conn)


def power_cycle(hsm, why):
    """Real power, then the card again with the HSM selected: whatever the session
    held is gone, and an armed lock is closed."""
    try:
        hsm.conn.disconnect()
    except Exception:
        pass  # the card is going away regardless
    replug.power_cycle_card(why)
    hsm = connect()
    hsm.select()
    return hsm


# ---- the suites ------------------------------------------------------------


def initialize(hsm, wipe):
    status = hsm.pin_status()
    if status != SW_REF_NOT_FOUND:
        if not wipe:
            fail("this HSM is already initialized and INITIALIZE erases every key on it — "
                 "rerun with --wipe if that is what you want")
        print("👉 touch the button to confirm the erase")
    data = (tlv(0x80, b"\x00\x01") + tlv(0x81, USER_PIN) + tlv(0x82, SO_PIN)
            + tlv(0x91, bytes([RETRIES])) + tlv(0x92, b"\x01"))
    hsm.cmd(0x80, INS_INITIALIZE, 0, 0, data, what="INITIALIZE")
    status = hsm.lock_status()
    if status[1] != STATE_DISARMED or not status[3] & FLAG_INITIALIZED:
        fail(f"LOCK STATUS after INITIALIZE: {status.hex()}")
    print("INITIALIZE OK (one DKEK share awaited, lock disarmed)")


def pins(hsm):
    if hsm.pin_status() != 0x63C0 | RETRIES:
        fail(f"user PIN status {hsm.pin_status():04X}, want 63C{RETRIES}")
    if hsm.pin_status(PIN_SO) != 0x63C0 | SO_RETRIES:
        fail(f"SO-PIN status {hsm.pin_status(PIN_SO):04X}, want 63CF")
    hsm.verify(b"000000", want=0x63C0 | (RETRIES - 1))
    hsm.verify()
    if hsm.pin_status() != SW_OK:
        fail("a verified PIN does not read as verified")
    hsm.cmd(0x00, INS_CHANGE, 0, PIN_USER, USER_PIN + OTHER_PIN, what="CHANGE REFERENCE DATA")
    hsm.verify(USER_PIN, want=0x63C0 | (RETRIES - 1))
    hsm.verify(OTHER_PIN)
    hsm.cmd(0x00, INS_CHANGE, 0, PIN_USER, OTHER_PIN + USER_PIN, what="CHANGE back")
    print("  user PIN: tries counted, a right PIN restores them, CHANGE works")
    for left in range(RETRIES - 1, 0, -1):
        hsm.verify(b"999999", want=0x63C0 | left)
    hsm.verify(b"999999", want=SW_BLOCKED)
    hsm.verify(want=SW_BLOCKED)
    hsm.cmd(0x00, INS_RESET_RETRY, 0x01, PIN_USER, b"00000000", want=0x63C0 | (SO_RETRIES - 1),
            what="RESET RETRY COUNTER (wrong SO-PIN)")
    hsm.cmd(0x00, INS_RESET_RETRY, 0x01, PIN_USER, SO_PIN, what="RESET RETRY COUNTER")
    if hsm.pin_status(PIN_SO) != 0x63C0 | SO_RETRIES:
        fail("a right SO-PIN did not restore its own tries")
    hsm.verify()
    print("  blocked after the last try, unblocked by the SO-PIN")


def ecdsa_der(raw):
    half = len(raw) // 2
    return encode_dss_signature(int.from_bytes(raw[:half], "big"), int.from_bytes(raw[half:], "big"))


def device_chain(hsm):
    """2F02: the device certificate, signed by the root, then the root's own. The
    root must be the device key the rescue applet reports."""
    certs = [value for tag, value, _ in objects(hsm.read(DEVAUT)) if tag == 0x7F21]
    if len(certs) != 2:
        fail(f"2F02 holds {len(certs)} certificates, want 2")
    dev_cert, root_cert = certs
    root_point = child(child(child(root_cert, 0x7F4E)[0], 0x7F49)[0], 0x86)[0]
    root = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), root_point)
    for cert, what in ((dev_cert, "device"), (root_cert, "root")):
        body_raw = child(cert, 0x7F4E)[1]
        sig = child(cert, 0x5F37)[0]
        root.verify(ecdsa_der(sig), body_raw, ec.ECDSA(hashes.SHA256()))
        print(f"  {what} certificate verifies under the root")
    dev_body = child(dev_cert, 0x7F4E)[0]
    holder = child(dev_body, 0x5F20)[0]
    device_point = child(child(dev_body, 0x7F49)[0], 0x86)[0]
    device = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), device_point)
    hsm.select(RESCUE_AID)
    keydev, _ = hsm.cmd(0x80, INS_KEYDEV, 0x02, 0x00, what="rescue KEYDEV public key")
    if keydev != root_point:
        fail("the HSM's root is not the rescue applet's device key")
    hsm.select()
    hsm.verify()
    print(f"device chain OK: {holder.decode(errors='replace')} ← root = the rescue applet's key")
    return device, holder


def keygen_template(public):
    return (tlv(0x5F29, b"\x00") + tlv(0x42, b"UTCA00001") + tlv(0x7F49, public)
            + tlv(0x5F20, b"UTTM00001"))


def check_request(resp, device, holder, key_of, verify):
    """GENERATE KEY PAIR's answer, `67 { 7F21 { 7F4E, 5F37 }, 42, 5F37 }`: the
    inner signature by the new key over the body, the outer by the device key over
    the certificate and the reference that names it. Returns the new public key,
    which `key_of` reads out of the body's `7F49`."""
    req = child(resp, 0x67)[0]
    cert, cert_raw = child(req, 0x7F21)
    body, body_raw = child(cert, 0x7F4E)
    key = key_of(child(body, 0x7F49)[0])
    verify(key, child(cert, 0x5F37)[0], body_raw)
    outer_car, car_raw = child(req, 0x42)
    if outer_car != holder:
        fail(f"the request is vouched for by {outer_car!r}, not the device {holder!r}")
    device.verify(ecdsa_der(child(req, 0x5F37)[0]), cert_raw + car_raw, ec.ECDSA(hashes.SHA256()))
    return key


def ec_key(hsm, device, holder):
    public = tlv(0x06, OID_ECDSA_SHA256) + b"".join(tlv(t, v) for t, v in P256.items())
    resp, _ = hsm.cmd(0x00, INS_GENERATE, KID_EC, 0, keygen_template(public),
                      what="GENERATE KEY PAIR (P-256)", extended=True)
    key = check_request(
        resp, device, holder,
        lambda pk: ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), child(pk, 0x86)[0]),
        lambda key, sig, signed: key.verify(ecdsa_der(sig), signed, ec.ECDSA(hashes.SHA256())),
    )
    msg = b"rs-key 86_hsm ecdsa"
    digest = hashlib.sha256(msg).digest()
    sig, _ = hsm.sign(KID_EC, ALGO_EC_RAW, digest)
    key.verify(sig, digest, ec.ECDSA(Prehashed(hashes.SHA256())))
    sig, _ = hsm.sign(KID_EC, ALGO_EC_SHA256, msg)
    key.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
    peer = ec.generate_private_key(ec.SECP256R1())
    peer_pub = peer.public_key().public_bytes(serialization.Encoding.X962,
                                              serialization.PublicFormat.UncompressedPoint)
    shared, _ = hsm.cmd(0x80, INS_DECIPHER, KID_EC, ALGO_EC_DH, peer_pub, what="ECDH")
    if len(shared) != 65 or shared[1:33] != peer.exchange(ec.ECDH(), key):
        fail("ECDH disagrees with the host's agreement")
    print("P-256: request attested, both ECDSA forms verify, ECDH agrees")
    return key


def rsa_key(hsm, device, holder, bits):
    public = tlv(0x06, OID_RSA_V15_SHA256) + tlv(0x82, b"\x01\x00\x01") + tlv(0x02, struct.pack(">H", bits))
    print(f"  generating RSA-{bits} on the card (tens of seconds on a board)…")
    resp, _ = hsm.cmd(0x00, INS_GENERATE, KID_RSA, 0, keygen_template(public),
                      what=f"GENERATE KEY PAIR (RSA-{bits})", extended=True)
    key = check_request(
        resp, device, holder,
        lambda pk: rsa.RSAPublicNumbers(int.from_bytes(child(pk, 0x82)[0], "big"),
                                        int.from_bytes(child(pk, 0x81)[0], "big")).public_key(),
        lambda key, sig, signed: key.verify(sig, signed, padding.PKCS1v15(), hashes.SHA256()),
    )
    if key.key_size != bits:
        fail(f"asked for RSA-{bits}, got {key.key_size}")
    msg = b"rs-key 86_hsm rsa"
    sig, _ = hsm.sign(KID_RSA, ALGO_RSA_PKCS1_SHA256, msg)
    key.verify(sig, msg, padding.PKCS1v15(), hashes.SHA256())
    # What OpenSC sends: the host pads, the card runs the raw private operation.
    di = bytes.fromhex("3031300d060960864801650304020105000420") + hashlib.sha256(msg).digest()
    k = bits // 8
    block = b"\x00\x01" + b"\xff" * (k - 3 - len(di)) + b"\x00" + di
    sig, _ = hsm.sign(KID_RSA, ALGO_RSA_RAW, block)
    key.verify(sig, msg, padding.PKCS1v15(), hashes.SHA256())
    secret = b"rs-key 86_hsm session key"
    ct = key.encrypt(secret, padding.PKCS1v15())
    plain, _ = hsm.cmd(0x80, INS_DECIPHER, KID_RSA, ALGO_RSA_DECRYPT, ct, what="RSA DECIPHER",
                       extended=True)
    if len(plain) != k or plain[:2] != b"\x00\x02" or plain[plain.index(b"\x00", 2) + 1:] != secret:
        fail("raw RSA decryption did not return the padded block of the message")
    print(f"RSA-{bits}: request attested, PKCS#1 (card- and host-padded) verify, decryption OK")


def derive(dkek, label):
    return hashlib.sha256(dkek + bytes([0, 0, 0, label])).digest()


def aes_cmac(key, data):
    c = cmac.CMAC(algorithms.AES(key))
    c.update(data)
    return c.finalize()


def open_backup(blob):
    """A WRAP KEY blob opened as a share holder would, once its KCV names our DKEK
    and its CMAC is right: `(type, size, the part after the size, its fields)` —
    an AES key follows the size bare, an EC or RSA key as length-prefixed fields."""
    if len(blob) > DRIVER_WRAP_BUF:
        fail(f"a {len(blob)}-byte backup overflows the driver's buffer")
    dkek = DKEK_SHARE  # one share: the DKEK is the share
    if blob[:8] != hashlib.sha256(dkek).digest()[:8]:
        fail("the backup names another DKEK")
    if aes_cmac(derive(dkek, 2), blob[:-16]) != blob[-16:]:
        fail("the backup's MAC does not verify under the DKEK")
    kind, at = blob[8], 9
    for _ in range(4):
        (n,) = struct.unpack(">H", blob[at:at + 2])
        at += 2 + n
    dec = Cipher(algorithms.AES(derive(dkek, 1)), modes.CBC(bytes(16))).decryptor()
    inner = dec.update(blob[at:-16]) + dec.finalize()
    fields, at = [], 10  # nonce, size
    while at + 2 <= len(inner):
        (n,) = struct.unpack(">H", inner[at:at + 2])
        if at + 2 + n > len(inner):
            break
        fields.append(inner[at + 2:at + 2 + n])
        at += 2 + n
    return kind, struct.unpack(">H", inner[8:10])[0], inner[10:], fields


def dkek(hsm):
    status, _ = hsm.cmd(0x80, INS_KEY_DOMAIN, 0, 0, what="MANAGE KEY DOMAIN")
    if status[:2] != b"\x01\x01":
        fail(f"key domain status {status.hex()}, want one share of one outstanding")
    status, _ = hsm.cmd(0x80, INS_KEY_DOMAIN, 0, 0, DKEK_SHARE, what="import the DKEK share")
    if status[:2] != b"\x01\x00" or status[2:10] != hashlib.sha256(DKEK_SHARE).digest()[:8]:
        fail(f"after the import the domain reads {status.hex()}")
    hsm.cmd(0x80, INS_KEY_DOMAIN, 0, 0, DKEK_SHARE, want=0x6986, what="a share too many")
    print("DKEK: one share imported, its KCV matches, a second refused")


def aes(hsm):
    hsm.cmd(0x00, INS_GENERATE_SYM, KID_AES, AES_256, what="GENERATE SYMMETRIC KEY")
    data = os.urandom(32)
    ct, _ = hsm.cmd(0x80, INS_CIPHER, KID_AES, ALGO_AES_ENC, data, what="AES-CBC encrypt")
    pt, _ = hsm.cmd(0x80, INS_CIPHER, KID_AES, ALGO_AES_DEC, ct, what="AES-CBC decrypt")
    if pt != data:
        fail("AES-CBC did not round-trip")
    tag, _ = hsm.cmd(0x80, INS_CIPHER, KID_AES, ALGO_AES_CMAC, data, what="AES-CMAC")
    blob, _ = hsm.cmd(0x80, INS_WRAP, KID_AES, 0x92, what="WRAP KEY (AES)", extended=True)
    kind, size, rest, _ = open_backup(blob)
    inner_key = rest[:size]
    if kind != 15 or size != 32:
        fail(f"an AES-256 key wrapped as type {kind}, size {size}")
    enc = Cipher(algorithms.AES(inner_key), modes.CBC(bytes(16))).encryptor()
    if enc.update(data) + enc.finalize() != ct or aes_cmac(inner_key, data) != tag:
        fail("the wrapped AES key does not compute what the card computed")
    print("AES-256: CBC round trip and CMAC match the key its backup carries")


def backup(hsm, ec_pub):
    blob, _ = hsm.cmd(0x80, INS_WRAP, KID_EC, 0x92, what="WRAP KEY (P-256)", extended=True)
    kind, size, _, fields = open_backup(blob)
    if kind != 12 or size != 256 or len(fields) < 6:
        fail(f"a P-256 key wrapped as type {kind}, size {size}, {len(fields)} fields")
    d = int.from_bytes(fields[5], "big")
    derived = ec.derive_private_key(d, ec.SECP256R1()).public_key()
    if derived.public_numbers() != ec_pub.public_numbers():
        fail("the backup's scalar is not the key's")
    hsm.write(STAGING, blob)
    hsm.cmd(0x80, INS_UNWRAP, KID_RESTORED, 0x93, what="UNWRAP KEY")
    digest = hashlib.sha256(b"restored").digest()
    sig, _ = hsm.sign(KID_RESTORED, ALGO_EC_RAW, digest)
    ec_pub.verify(sig, digest, ec.ECDSA(Prehashed(hashes.SHA256())))
    forged = bytearray(blob)
    forged[-1] ^= 0x01
    hsm.write(STAGING, bytes(forged))
    hsm.cmd(0x80, INS_UNWRAP, KID_RESTORED + 1, 0x93, want=SW_WRONG_DATA, what="UNWRAP (bad MAC)")
    print("backup: the blob opens under the DKEK, restores, and a forged MAC is refused")


def lock(hsm, ec_pub):
    status = hsm.lock_status()
    if status[1:3] != bytes([STATE_DISARMED, 0]):
        fail(f"LOCK STATUS {status.hex()}, want disarmed")
    print("👉 touch the button to arm the lock")
    hsm.lock_box(LOCK_ARM, FACTOR_HOST_KEY, UNLOCK_SECRET + SO_PIN, what="LOCK ARM")
    status = hsm.lock_status()
    if status[1:3] != bytes([STATE_UNLOCKED, FACTOR_HOST_KEY]):
        fail(f"armed, LOCK STATUS reads {status.hex()}")
    hsm = power_cycle(hsm, "relocking the armed HSM")
    status = hsm.lock_status()
    if status[1] != STATE_LOCKED:
        fail(f"after a power cycle an armed HSM reads {status.hex()}, not locked")
    hsm.verify(want=SW_CONDITIONS)
    if hsm.pin_status() != 0x63C0 | RETRIES:
        fail("the refused VERIFY spent a try")
    digest = hashlib.sha256(b"locked").digest()
    _, sw = hsm.raw(0x80, INS_SIGN, KID_EC, ALGO_EC_RAW, digest)
    if sw == SW_OK:
        fail("a locked HSM signed")
    hsm.lock_box(LOCK_UNLOCK, 0, bytes(32), want=SW_SECURITY, what="UNLOCK (wrong secret)")
    hsm.lock_box(LOCK_UNLOCK, 0, UNLOCK_SECRET, what="UNLOCK")
    hsm.verify()
    sig, _ = hsm.sign(KID_EC, ALGO_EC_RAW, digest)
    ec_pub.verify(sig, digest, ec.ECDSA(Prehashed(hashes.SHA256())))
    print("lock: armed, locked by the power cycle, PIN refused without a try spent, unlocked")
    print("👉 touch the button to disarm the lock")
    hsm.cmd(0x80, INS_LOCK, LOCK_DISARM, 0, SO_PIN, what="LOCK DISARM")
    hsm = power_cycle(hsm, "checking the disarmed HSM opens alone")
    if hsm.lock_status()[1] != STATE_DISARMED:
        fail("a disarmed HSM came back locked")
    hsm.verify()
    print("  disarmed: the next power-up needs no unlock")
    return hsm


def delete(hsm):
    fid = PREFIX_KEY << 8 | KID_RESTORED
    hsm.cmd(0x00, INS_DELETE, 0x02, 0x00, fid.to_bytes(2, "big"), what="DELETE FILE")
    _, sw = hsm.raw(0x80, INS_SIGN, KID_RESTORED, ALGO_EC_RAW, bytes(32))
    if sw != SW_NOT_FOUND:
        fail(f"a deleted key answered SIGN with {sw:04X}")
    _, sw = hsm.raw(0x00, INS_READ_ODD, PREFIX_KEY, KID_EC, tlv(0x54, b"\x00\x00"))
    if sw != SW_SECURITY:
        fail(f"READ BINARY of a key answered {sw:04X}")
    print("DELETE removes a key; a key object is never readable")


def main():
    wipe = "--wipe" in sys.argv
    bits = 2048
    if "--rsa-bits" in sys.argv:
        bits = int(sys.argv[sys.argv.index("--rsa-bits") + 1])
        if bits not in (2048, 3072, 4096):
            fail("--rsa-bits takes 2048, 3072 or 4096")
    hsm = connect()
    fcp = hsm.select()
    if len(child(child(fcp, 0x62)[0], 0x85)[0]) < 2:
        fail(f"SELECT answered {fcp.hex()}: the driver wants a tag 85 of two bytes or more")
    print(f"SELECT HSM OK (FCP {fcp.hex()})")
    initialize(hsm, wipe)
    pins(hsm)
    device, holder = device_chain(hsm)
    dkek(hsm)
    ec_pub = ec_key(hsm, device, holder)
    rsa_key(hsm, device, holder, bits)
    aes(hsm)
    backup(hsm, ec_pub)
    hsm = lock(hsm, ec_pub)
    delete(hsm)
    print("\nALL HSM TESTS PASSED")


if __name__ == "__main__":
    main()
