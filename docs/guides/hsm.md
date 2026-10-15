<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 RS-Key contributors -->

# The HSM image — a PKCS#11 key store for a server

The HSM image turns an RP2350 board into a small key store for one server. Keys
are generated on the board and used there; the server reaches them through
OpenSC's PKCS#11 module. That is enough for the jobs a homelab has:

- **LUKS unlock** with `systemd-cryptenroll --pkcs11-token-uri` and `/etc/crypttab`
- **SSH** host keys and an SSH certificate authority
- **a small internal TLS CA** with OpenSSL or GnuTLS

It is a separate image built from the same tree as the security key
([build.md](../build.md#the-hsm-image)), and it is *not* a security key: no
FIDO2, OpenPGP, PIV or OATH. What it speaks is a subset of the CardContact
SmartCard-HSM's command set, which OpenSC has a built-in driver for, so there is
no driver to install — `opensc-tool` calls it a SmartCard-HSM, and `sc-hsm-tool`,
`pkcs11-tool` and anything that loads `opensc-pkcs11.so` work with it.

**The RP2350 is not a secure element.** Software on the server can use a key on
this device while it is unlocked and the PIN is known, but cannot copy it out;
with the OTP root and secure boot provisioned a flash dump does not open it
either. A funded lab is another matter. Read
[what it does not defend against](../threat-model.md#the-hsm-image) and
[what it does not do](../limitations.md#hsm-image) before you put a key on it
that matters.

## What you need

| Image | Board |
|---|---|
| `rs-key-<tag>-hsm.uf2` | 4 MB RP2350 boards — most of them |
| `rs-key-<tag>-hsm-2mb.uf2` | 2 MB: the Waveshare RP2350-USB-A |
| `rs-key-<tag>-hsm-16mb.uf2` | 16 MB, e.g. the TenStar RP2350-USB |

On the server: `pcscd` and OpenSC (Debian/Ubuntu: `pcscd opensc`), and the `rsk`
CLI for the HSM's status, attestation and lock ([cli.md](cli.md)). The
walkthroughs below also use `cryptsetup` and `systemd-cryptenroll`, OpenSSH, and
OpenSSL with `pkcs11-provider` (or GnuTLS's `certtool` and `p11tool`).

The PKCS#11 module's path depends on the distribution; the commands below call it
`$P11`:

```sh
P11=/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so   # Debian/Ubuntu on x86-64
P11=/usr/lib64/opensc-pkcs11.so                  # Fedora
```

The commands on this page were run against the HSM image on the emulator
([below](#try-it-without-a-board)) with OpenSC 0.25, systemd 255,
cryptsetup 2.7, OpenSSH 9.6, OpenSSL 3.0 with pkcs11-provider 0.3 and GnuTLS
3.8, except where a step says otherwise. None has run on a board yet.

## Flash it

Hold **BOOT** while plugging the board in and copy the `.uf2` onto the `RP2350`
drive, as for the security key ([quickstart](../quickstart.md#2-flash)). To build
it yourself, [build.md](../build.md#the-hsm-image) has the flavors;
`nix build .#firmware-hsm-2mb` (or `.#firmware-hsm`, `.#firmware-hsm-16mb`)
includes the partition table step a bare `cargo build` leaves out.

Reflashing between the HSM image and the security-key image loses nothing: they
keep their records in disjoint parts of the store. The production steps — the
OTP master key, then secure boot — are the security key's
([production.md](../production.md)); `rsk otp` and `rsk secure-boot` talk to the
rescue applet, which the HSM image keeps, though neither has been run against an
HSM board yet. Until the OTP master key is fused, everything the HSM stores is
sealed under a key derived from the chip serial.

Check that the server sees it:

```sh
opensc-tool -l          # a reader whose name carries "RS-Key HSM", "Yes" under Card
opensc-tool -n          # SmartCard-HSM version 5.8
rsk hsm status
```

`rsk hsm` finds the reader by its `RS-Key` name; `rsk hsm --reader <name> …`
picks another one.

## Initialize

Initializing sets the two PINs and decides whether keys can ever be backed up.
Decide all three before you start: changing the backup decision later means
initializing again, which erases every key.

- **SO-PIN**: 16 hexadecimal digits. It re-initializes the device (erasing every
  key), unblocks the user PIN — and, with the options `sc-hsm-tool` sets, gives
  the user PIN a new value, which makes it as good as the user PIN for using
  keys. Draw a random one and keep it offline: `openssl rand -hex 8`. Not the
  SmartCard-HSM documentation's `3537363231383830`. 15 tries.
- **User PIN**: 6 to 16 characters. 3 tries unless `--pin-retry` says otherwise
  (up to 10).
- **DKEK shares**: how many shares make up the key every backup is encrypted
  under (next section). Leave `--dkek-shares` out and the device has no DKEK at
  all: no key can ever leave it, not even encrypted.

```sh
sc-hsm-tool --initialize --dkek-shares 1 --label homelab   # asks for the SO-PIN and the PIN
```

It asks for each once, with no second entry to catch a typo, so type them with
care. The PKCS#11 token is then called `homelab (UserPIN)`; OpenSC appends the PIN's
name, and URIs carry it as `token=homelab%20%28UserPIN%29`. Running
`--initialize` on an initialized device needs the current SO-PIN and a touch, and
erases every key.

## Backups: the DKEK

A backup is a key exported by the HSM itself, encrypted and MACed under the
**DKEK** — a 256-bit key the device builds by XORing the shares imported into
it. No key leaves the device any other way. Whoever holds the shares can restore
the backups into another HSM initialized with the same shares; nobody without
them can read a backup.

No key can be generated while a share is still owed, so import the shares right
after initializing. With `rsk`, the share is drawn on the host and shown as
SLIP-39 words, any two of three of which rebuild it:

```sh
rsk hsm dkek create --threshold 2 --shares 3
```

```text
=== WRITE THESE DOWN — one DKEK share, as SLIP-39 shares ===
…
(any 2 of 3 rebuild the DKEK share; its check value is 09158bca71aab327)

Type IMPORT once the shares are written down: share imported ✓ — 1 of 1 in, DKEK KCV 09158bca71aab327
```

OpenSC's own way is a password-protected share file, which works the same:

```sh
sc-hsm-tool --create-dkek-share dkek-share-1.pbe     # asks for a password
sc-hsm-tool --import-dkek-share dkek-share-1.pbe
```

(`--pwd-shares-threshold 2 --pwd-shares-total 3` on the create splits the
*password* into shares instead.) Keep the share away from the device; a share
stored next to the backups it opens protects nothing.

For several custodians, initialize with `--dkek-shares 2` (or more) and let each
import their own: nobody alone then holds the DKEK. Either way, finish by
comparing the key check value the device reports with the one the share was
shown with — **while a share is owed, any program on the server can import one**,
and the check value is how you know the DKEK is yours:

```sh
rsk hsm status          # DKEK : 1 of 1 share(s) imported, KCV 09158bca71aab327
```

## Make keys

```sh
pkcs11-tool --module $P11 --login --keypairgen --key-type rsa:2048 --id 01 --label luks
pkcs11-tool --module $P11 --login --keypairgen --key-type EC:prime256v1 --id 02 --label ssh-host
pkcs11-tool --module $P11 --login --keypairgen --key-type EC:secp384r1 --id 03 --label tls-ca
pkcs11-tool --module $P11 --login --keypairgen --key-type EC:prime256v1 --id 04 --label ssh-ca
```

| Kind | Sizes and curves |
|---|---|
| RSA | 2048, 3072, 4096 (exponent 65537) |
| EC | P-256 (`prime256v1`), P-384 (`secp384r1`), P-521 (`secp521r1`), `secp256k1` |

Refused: RSA below 2048, P-192 and P-224, the brainpool curves, and Ed25519 —
OpenSC's driver for this card speaks RSA and ECDSA only. RSA generation runs the
same dual-core prime search as the security key's PIV and OpenPGP applets: a few
seconds at 2048, around a minute at 4096 with a wide spread
([limitations](../limitations.md)). The host is kept waiting, not timed out.
Those numbers are the security key's; the HSM image has not been timed on a board
yet.

Each key also gets a **key reference** on the device — the first free one, so 1,
2, 3 … on a fresh device. PKCS#11 tools name a key by its `--id` or `--label`;
`sc-hsm-tool` and `rsk hsm attest` take the reference, which
`pkcs15-tool --list-keys` shows:

```text
Private RSA Key [luks]
	…
	Key ref        : 1 (0x01)
	ID             : 01
```

## Check where a key was made

The HSM answers a key generation with a request the new key signs and the
device's own attestation key countersigns. OpenSC keeps that request on the
token, so it can be checked against the device:

```sh
rsk hsm attest --key 1
```

```text
device           : RSK3901318900001
device root      : secp256k1, SHA-256 3d792423492198c20a6fbb4aecfecc9da8d1a54c841f841d7118b45194185a63
chain            : device certificate ← root ← the rescue applet's device key ✓
key 1            : RSA-2048, generated on this device ✓

Pin this root: pass --expect-root next time, so a swapped device cannot pass.
```

The chain ends at the device root, the same device key the rescue applet
reports; record its fingerprint the first time and pass it from then on:

```sh
rsk hsm attest --key 1 --expect-root <sha256>
```

A different device fails that check, and so does a key it did not make. What it
does not prove is that the device is genuine RS-Key hardware — there is no
manufacturer CA behind the root, so the trust is the first use. **Check a key
before you store a certificate for it**: OpenSC writes the certificate into the
file that held the request, and from then on `attest --key` says the proof is
gone.

## LUKS

`systemd-cryptenroll` adds a LUKS2 keyslot whose key only the HSM can recover. On
systemd 255 that takes an **RSA key with an X.509 certificate** on the token;
from systemd 256 an EC key works too, and a public key alone is enough.

**1. A certificate for the key.** Any certificate carrying the key will do; it is
only how systemd finds the public key. With OpenSSL and `pkcs11-provider`:

```sh
export PKCS11_PROVIDER_MODULE=$P11
openssl req -provider pkcs11 -provider default -new -x509 -days 7300 \
  -key "pkcs11:token=homelab%20%28UserPIN%29;object=luks;type=private?pin-source=file:/root/hsm-pin" \
  -subj "/CN=homelab LUKS" -outform DER -out luks.der
pkcs11-tool --module $P11 --login --write-object luks.der --type cert --id 01 --label luks
```

`/root/hsm-pin` holds the PIN (mode `0600`) for this one command; delete it
afterwards. GnuTLS does the same with `certtool --generate-self-signed
--load-privkey "pkcs11:…;object=luks;type=private"` and `p11tool --login --write
--load-certificate`.

**2. Enroll.** List the tokens to get the URI, then name the key in it:

```sh
systemd-cryptenroll --pkcs11-token-uri=list
systemd-cryptenroll /dev/disk/by-uuid/<uuid> \
  --pkcs11-token-uri='pkcs11:model=PKCS%2315%20emulated;manufacturer=RS-Key;token=homelab%20%28UserPIN%29;object=luks'
```

It asks for an existing passphrase of the volume, then the PIN. The URI above
leaves out the device's serial on purpose: a replacement HSM restored from your
backups (below) then opens the volume without enrolling again. `object=luks`
matters once the token holds more than one key — systemd 256 and later refuse a
URI that matches several.

**Keep the passphrase keyslot.** The HSM is one board; the passphrase is the way
in when it is lost and before a replacement is restored.

**3. Try it.** No device-mapper needed:

```sh
cryptsetup open --test-passphrase --token-only /dev/disk/by-uuid/<uuid>
```

**4. At boot.** In `/etc/crypttab`:

```text
data  UUID=<uuid>  none  pkcs11-uri=auto
```

`auto` tells `systemd-cryptsetup` to take the token from the LUKS header, and it
asks for the PIN like any passphrase. Two things have to be true when it runs:
`pcscd` answers, and — if [the lock](#the-lock) is armed — the HSM has been
unlocked. Volumes opened early in boot, the root volume above all, need `pcscd`,
OpenSC and its p11-kit module in the initramfs (dracut has `pcsc` and `pkcs11`
modules for it); that is distribution-specific and not covered by the tests here.

A data volume nobody types at is simpler to open once the system is up: mark it
`noauto` in `/etc/crypttab` so boot leaves it alone, and run

```sh
rsk hsm lock unlock --secret-file /etc/rsk/hsm-unlock.key    # only if the lock is armed
cryptsetup open --token-only /dev/disk/by-uuid/<uuid> data < /etc/rsk/hsm-pin
```

from a oneshot unit. A sketch: its two commands were run here, the open as
`--test-passphrase`; the unit was not.

```ini
# /etc/systemd/system/hsm-data.service
[Unit]
Description=Unlock the HSM and open the data volume
Wants=pcscd.socket
After=pcscd.socket

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/rsk hsm lock unlock --secret-file /etc/rsk/hsm-unlock.key
ExecStart=/bin/sh -c 'exec cryptsetup open --token-only /dev/disk/by-uuid/<uuid> data < /etc/rsk/hsm-pin'
ExecStop=/usr/sbin/cryptsetup close data

[Install]
WantedBy=multi-user.target
```

Both files then sit on the server, which is a choice with a price —
[where the secret lives](#where-the-secret-lives) weighs it.

Two newer systemd behaviours are worth knowing. systemd 261 enrolls RSA keys with
RSA-OAEP (SHA-256) instead of PKCS#1 v1.5; OpenSC removes the OAEP padding itself
over the HSM's raw RSA, which `pkcs11-tool` decrypts correctly, but systemd 261
itself has not been run against it here. EC enrollment (systemd 256 and later)
uses ECDH, which the HSM does, but is likewise untested here.

## SSH

`ssh-keygen -D` lists the token's public keys in OpenSSH form, the key's label as
the comment:

```sh
ssh-keygen -D $P11
```

**A certificate authority.** Keep the CA's public key in a file and let
`ssh-keygen` sign with the private half on the HSM:

```sh
ssh-keygen -D $P11 | grep ' ssh-ca$' > ssh-ca.pub
ssh-keygen -s ssh-ca.pub -D $P11 -I alice -n alice -V +52w id_ed25519.pub
```

It asks for the PIN and writes `id_ed25519-cert.pub`; servers trust the CA with
`TrustedUserCAKeys /etc/ssh/ssh-ca.pub`.

**A host key.** `sshd` cannot open a PKCS#11 module, but it can have an
`ssh-agent` sign for it. Load the token into an agent root owns, and point
`sshd` at the agent and at the public key:

```sh
ssh-agent -a /run/ssh-hsm.sock
SSH_AUTH_SOCK=/run/ssh-hsm.sock ssh-add -s $P11       # asks for the PIN
ssh-keygen -D $P11 | grep ' ssh-host$' > /etc/ssh/ssh_host_hsm_key.pub
```

```text
# /etc/ssh/sshd_config.d/hsm.conf
HostKeyAgent /run/ssh-hsm.sock
HostKey /etc/ssh/ssh_host_hsm_key.pub
```

`sshd` logs `Unable to load host key` for that file — it tries it as a private
key first — and then signs through the agent. The agent has to hold a logged-in
session from boot, so the PIN is typed at each boot or kept in a root-only file
for an `SSH_ASKPASS` helper. The second keeps the private key off the disk, but
whoever takes the disk *and* the HSM has both halves.

## A TLS CA

With OpenSSL and `pkcs11-provider`, the CA's key never leaves the HSM:

```sh
export PKCS11_PROVIDER_MODULE=$P11
CA_KEY='pkcs11:token=homelab%20%28UserPIN%29;object=tls-ca;type=private?pin-source=file:/root/hsm-pin'
openssl req -provider pkcs11 -provider default -new -x509 -days 3650 -key "$CA_KEY" \
  -subj "/CN=homelab CA" -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" -out ca.pem
```

Issue a server certificate from a request (`nas.csr`) and an extensions file:

```text
# server.cnf
[req]
distinguished_name = dn
x509_extensions = server

[dn]

[server]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:nas.home.arpa
```

```sh
openssl req -config server.cnf -provider pkcs11 -provider default -x509 -in nas.csr \
  -CA ca.pem -CAkey "$CA_KEY" -days 397 -out nas.pem
openssl verify -CAfile ca.pem nas.pem
```

Use `openssl req -x509 -CA`, not `openssl x509 -req -CAkey`: with OpenSSL 3.0 and
pkcs11-provider 0.3 the second fails with `operation not supported for this
keytype`.

## Back up and restore a key

```sh
sc-hsm-tool --wrap-key luks.wrapped --key-reference 1       # asks for the PIN
```

The file holds the key encrypted under the DKEK, its PKCS#15 description and its
certificate. Restoring it takes an HSM initialized with the same DKEK shares:

```sh
sc-hsm-tool --initialize --dkek-shares 1 --label homelab
rsk hsm dkek import                  # or: sc-hsm-tool --import-dkek-share dkek-share-1.pbe
sc-hsm-tool --unwrap-key luks.wrapped --key-reference 1     # --force replaces a key there
```

The HSM checks the MAC before it decrypts anything and rebuilds and checks the
key whole before storing it. The round trip has been run end to end on the
emulator: a LUKS volume enrolled with one HSM opened with a second one restored
this way. A key generated with an algorithm list that leaves out wrapping
(`0x92`) can never be exported, not even this way.

## PINs

```sh
pkcs11-tool --module $P11 --change-pin                           # the user PIN
pkcs11-tool --module $P11 --login --login-type so --init-pin     # a new user PIN, on the SO-PIN's say-so
pkcs11-tool --module $P11 --login --login-type so --change-pin   # the SO-PIN
```

Each asks for what it needs; the second is also how a blocked user PIN comes
back. A blocked SO-PIN cannot be unblocked, and every SO operation needs it —
initializing again, unblocking the user PIN, arming and disarming the lock. The
keys stay usable with the user PIN; the device can no longer be managed. Fifteen
tries make that hard to reach by accident.

## The lock

Armed, the lock keeps the key store shut at every power-up until a 32-byte unlock
secret you hold is presented. What opens the store is then sealed under the
device root *and* that secret, so a thief with the board alone has nothing to try
PINs against — not even one who reads its flash and fuses out in a lab — and a
locked HSM does not spend a PIN try at all: it refuses the attempt. It is the
HSM's counterpart of the security key's [soft-lock](soft-lock.md).

```sh
rsk hsm lock arm                               # SO-PIN, type ARM-HSM, touch
rsk hsm lock arm --scheme slip39 --threshold 2 --shares 3
```

`arm` draws the secret, shows it **once** — 24 BIP-39 words by default, SLIP-39
shares or hex on request — then arms with the SO-PIN and a touch. The HSM stays
open until it loses power. `--secret-out FILE` also writes it to a new `0600`
file, which is what a boot-time unlock reads.

```sh
rsk hsm lock unlock                            # asks for the words
rsk hsm lock unlock --secret-file /etc/rsk/hsm-unlock.key
rsk hsm lock disarm                            # SO-PIN and a touch, on an unlocked HSM
```

`unlock` needs no PIN and no touch: knowing the secret is the authorization. It
crosses the wire in a box sealed to a fresh key agreement with the device, never
in the clear. While locked, `rsk hsm status` says `LOCKED`, OpenSC still lists
the token and reads its public objects, and every login fails — a LUKS unlock
through it stops at `Failed to log into security token`.

### Where the secret lives

That is the whole decision, and the PIN raises the same question whenever nobody
types it:

- **Typed at each boot** — the strongest, and it needs a person.
- **On another machine**, fetched at boot (`--secret-file /dev/stdin` reads it
  from a pipe) — the HSM and the server together are then not enough without
  that machine.
- **In a root-only file on the server** — protects against the HSM taken on its
  own, not against the server taken whole. What it still buys is that the keys
  cannot be copied: someone who images the disk gets the files but not the keys,
  and has to come back for the board.

**A lost secret is unrecoverable by design.** The keys are then reachable only
from their backups: `sc-hsm-tool --initialize` with the SO-PIN erases the device
and disarms the lock, and the backups restore into it.

The lock records which *factor* holds the secret. This build ships one, the host
key above. A second — a FIDO2 token's `hmac-secret`, read on the Waveshare
RP2350-USB-A's USB-A port with no host involved — is reserved, and arming with
it is refused until it exists.

## Try it without a board

The emulator runs the HSM image's card on the host, and with vsmartcard's `vpcd`
it sits in a PC/SC reader that `pcscd` — and OpenSC above it — treat like any
other:

```sh
sudo apt install pcscd vsmartcard-vpcd opensc     # then restart pcscd
nix develop -c cargo run --release --manifest-path tools/emu/Cargo.toml \
  --target "$HOST" -- --hsm --vpcd --store ./hsm.store
```

Every command on this page then works against it; a replug is
`python3 -c 'import emu; emu.power_cycle()'` from `tests/` with
`RSK_EMU_CCID=127.0.0.1:7800`. `scripts/hsm-interop.sh` does all of it in one
go: it builds the emulator, inserts the card and runs `tests/86_hsm.py` and
`tests/interop/hsm.py` — OpenSC, GnuTLS, OpenSSL and LUKS, each result checked
with a different tool than the one that made it ([testing.md](../testing.md)).
