# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""`rsk hsm` without a device: the attestation checks, the secrets, the prompts.

Run from tools/:  python -m pytest rsk/test_hsm.py
The attestation half is the one that must say no: a chain built here the way the
device builds it has to pass, and every way of swapping a piece of it — a root
that is not the rescue applet's key, a certificate signed by another key, a
request vouched for under another name — has to fail. A checker that only ever
saw good chains is one that could be deleted with this file green.

The end-to-end half — the lock box opening on a real applet — is
`tests/86_hsm.py` and the interop suite, against `tools/emu --hsm`.
"""
import os
import stat
import sys
import types

# Nothing here touches a device; the PC/SC import stays a stub.
sys.modules.setdefault("hid", types.ModuleType("hid"))

import pytest  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305  # noqa: E402
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # noqa: E402

from rsk import hsm  # noqa: E402

OID_ECDSA_SHA256 = hsm.ID_TA + b"\x02\x03"
P256_PRIME = (2**256 - 2**224 + 2**192 + 2**96 - 1).to_bytes(32, "big")
K256_PRIME = (2**256 - 2**32 - 977).to_bytes(32, "big")


def _point(key):
    return key.public_key().public_bytes(serialization.Encoding.X962,
                                         serialization.PublicFormat.UncompressedPoint)


def _raw_sig(key, data, digest=hashes.SHA256):
    r, s = decode_dss_signature(key.sign(data, ec.ECDSA(digest())))
    width = (key.curve.key_size + 7) // 8
    return r.to_bytes(width, "big") + s.to_bytes(width, "big")


def _body(holder, key, prime, car=b"RSKROOT"):
    pk = hsm.tlv(0x06, OID_ECDSA_SHA256) + hsm.tlv(0x81, prime) + hsm.tlv(0x86, _point(key))
    return hsm.tlv(0x7F4E, hsm.tlv(0x5F29, b"\x00") + hsm.tlv(0x42, car)
                   + hsm.tlv(0x7F49, pk) + hsm.tlv(0x5F20, holder))


def _cert(holder, key, prime, signer):
    body = _body(holder, key, prime)
    return hsm.tlv(0x7F21, body + hsm.tlv(0x5F37, _raw_sig(signer, body)))


class Chain:
    """A 2F02 the way the device writes one: the device key's certificate signed
    by the root, then the root's own."""

    def __init__(self):
        self.root = ec.generate_private_key(ec.SECP256K1())
        self.device = ec.generate_private_key(ec.SECP256R1())
        self.holder = b"RSK3901318900001"

    def devaut(self, signer=None):
        signer = signer or self.root
        return (_cert(self.holder, self.device, P256_PRIME, signer)
                + _cert(b"RSKROOT", self.root, K256_PRIME, self.root))

    def keydev(self):
        return _point(self.root)

    def request(self, key=None, car=None, outer_signer=None, inner_signer=None):
        """A GENERATE KEY PAIR answer for `key`, countersigned by the device."""
        key = key or ec.generate_private_key(ec.SECP256R1())
        body = _body(b"UTTM00001", key, P256_PRIME, car=b"UTCA00001")
        cert = hsm.tlv(0x7F21, body + hsm.tlv(0x5F37, _raw_sig(inner_signer or key, body)))
        outer_car = hsm.tlv(0x42, car or self.holder)
        sig = _raw_sig(outer_signer or self.device, cert + outer_car)
        return hsm.tlv(0x67, cert + outer_car + hsm.tlv(0x5F37, sig)), key


def test_the_device_chain_passes():
    chain = Chain()
    device, holder, root = hsm.device_chain(chain.devaut(), chain.keydev())
    assert holder == chain.holder
    assert root == chain.keydev()
    assert device.public_numbers() == chain.device.public_key().public_numbers()


def test_a_root_that_is_not_the_rescue_applets_key_fails():
    chain = Chain()
    other = _point(ec.generate_private_key(ec.SECP256K1()))
    with pytest.raises(ValueError, match="not the rescue applet's device key"):
        hsm.device_chain(chain.devaut(), other)


def test_a_device_certificate_signed_by_another_key_fails():
    chain = Chain()
    forged = chain.devaut(signer=ec.generate_private_key(ec.SECP256K1()))
    with pytest.raises(ValueError, match="does not verify under the root"):
        hsm.device_chain(forged, chain.keydev())


def test_a_2f02_with_one_certificate_fails():
    chain = Chain()
    first = hsm.objects(chain.devaut())[0][2]
    with pytest.raises(ValueError, match="1 certificate"):
        hsm.device_chain(first, chain.keydev())


def test_a_key_request_passes_and_names_its_key():
    chain = Chain()
    device, holder, _ = hsm.device_chain(chain.devaut(), chain.keydev())
    req, key = chain.request()
    got = hsm.check_request(req, device, holder)
    assert got.public_numbers() == key.public_key().public_numbers()


def test_a_request_vouched_for_under_another_name_fails():
    chain = Chain()
    device, holder, _ = hsm.device_chain(chain.devaut(), chain.keydev())
    req, _ = chain.request(car=b"RSK0000000000001")
    with pytest.raises(ValueError, match="not this device"):
        hsm.check_request(req, device, holder)


def test_a_request_another_device_countersigned_fails():
    chain = Chain()
    device, holder, _ = hsm.device_chain(chain.devaut(), chain.keydev())
    req, _ = chain.request(outer_signer=ec.generate_private_key(ec.SECP256R1()))
    with pytest.raises(ValueError, match="device key's signature"):
        hsm.check_request(req, device, holder)


def test_a_request_its_key_did_not_sign_fails():
    """Countersigned all the same: the device's signature does not stand in for
    the key's own."""
    chain = Chain()
    device, holder, _ = hsm.device_chain(chain.devaut(), chain.keydev())
    req, _ = chain.request(inner_signer=ec.generate_private_key(ec.SECP256R1()))
    with pytest.raises(ValueError, match="not signed by the key it carries"):
        hsm.check_request(req, device, holder)


@pytest.mark.parametrize("data", [b"\x7F", b"\x7F\x21", b"\x80\x05ab", b"\x80\x84\x00\x00\x00\x01"])
def test_a_malformed_tlv_is_refused_not_followed(data):
    with pytest.raises(ValueError):
        hsm.objects(data)


def test_the_lock_box_is_what_the_device_opens():
    """The device's half of `channel.rs`, here from its description: the same
    agreement, the same salt and info, the device point as the AAD."""
    host = ec.generate_private_key(ec.SECP256R1())
    device = ec.generate_private_key(ec.SECP256R1())
    host_pub, dev_pub = _point(host), _point(device)
    nonce = os.urandom(12)
    blob = hsm.seal_box(host, host_pub, dev_pub, b"secret" * 6, nonce)
    z = device.exchange(ec.ECDH(), host.public_key())
    key = HKDF(hashes.SHA256(), 32, b"RSK-HSM/LOCK-CHANNEL", dev_pub + host_pub).derive(z)
    assert ChaCha20Poly1305(key).decrypt(blob[:12], blob[12:], dev_pub) == b"secret" * 6


@pytest.mark.parametrize("text", ["3537363231383830", " 3537363231383830\n"])
def test_the_so_pin_is_sixteen_hex_digits(text):
    assert hsm.parse_so_pin(text) == b"57621880"


@pytest.mark.parametrize("text", ["57621880", "35373632313838", "35373632313838303030", "zz37363231383830"])
def test_anything_else_is_not_an_so_pin(text):
    with pytest.raises(SystemExit):
        hsm.parse_so_pin(text)


def _secret_args(**kw):
    base = {"secret_file": None, "key_hex": None, "mnemonic": None, "scheme": "hex"}
    return types.SimpleNamespace(**{**base, **kw})


def test_a_secret_file_holds_raw_bytes_or_hex(tmp_path):
    secret = os.urandom(32)
    raw = tmp_path / "raw.key"
    raw.write_bytes(secret)
    text = tmp_path / "hex.key"
    text.write_text(secret.hex() + "\n")
    assert hsm.read_secret(_secret_args(secret_file=str(raw))) == secret
    assert hsm.read_secret(_secret_args(secret_file=str(text))) == secret


def test_a_secret_of_the_wrong_length_is_refused():
    with pytest.raises(SystemExit):
        hsm.read_secret(_secret_args(key_hex="00" * 31))


def test_a_secret_file_is_private_and_never_replaced(tmp_path):
    out = tmp_path / "unlock.key"
    hsm.write_private(str(out), b"first")
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    with pytest.raises(SystemExit):
        hsm.write_private(str(out), b"second")
    assert out.read_bytes() == b"first"


def test_arm_does_nothing_without_the_typed_phrase(monkeypatch):
    calls = []

    class Card:
        def lock_status(self):
            return bytes([1, hsm.STATE_DISARMED, 0, hsm.FLAG_INITIALIZED])

        def lock_box(self, *a):
            calls.append(a)
            return hsm.SW_OK

    monkeypatch.setattr(hsm, "connect", lambda args, exclusive=False: (Card(), b""))
    monkeypatch.setattr("builtins.input", lambda prompt="": "arm-hsm")
    args = types.SimpleNamespace(so_pin="3537363231383830", scheme="hex", threshold=2,
                                 shares=3, secret_out=None)
    with pytest.raises(SystemExit):
        hsm.cmd_lock_arm(args)
    assert calls == []


def test_arm_refuses_a_lock_that_is_already_armed(monkeypatch, capsys):
    class Card:
        def lock_status(self):
            return bytes([1, hsm.STATE_LOCKED, hsm.FACTOR_HOST_KEY, hsm.FLAG_INITIALIZED])

    monkeypatch.setattr(hsm, "connect", lambda args, exclusive=False: (Card(), b""))
    args = types.SimpleNamespace(so_pin="3537363231383830", scheme="hex", threshold=2,
                                 shares=3, secret_out=None)
    with pytest.raises(SystemExit):
        hsm.cmd_lock_arm(args)
    assert "already armed" in capsys.readouterr().err
