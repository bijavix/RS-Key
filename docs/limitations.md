# Limitations — what RS-Key does not do, and why

Each gap below comes with its reasoning. "Not yet" and "never" are marked. The
project as a whole is experimental and unaudited. The [threat model](threat-model.md)
covers the security boundary. This page covers feature and hardware gaps.

## Cryptography

- **brainpoolP512r1 (OpenPGP)**: not offered. brainpoolP256r1 and P384r1 are
  supported (advertised in DO `0xFA`, generate / keytocard / sign / decrypt), but
  no Rust arithmetic for the 512-bit brainpool curve exists yet, so the applet
  neither advertises nor generates it. *Status: until a crate exists.*
- **X448 / Ed448 (OpenPGP)**: not offered, same reason. RustCrypto coverage
  of Curve448 is thin and unaudited. Cv25519/Ed25519 plus the NIST curves and
  secp256k1 cover practical use. *Status: until a serious crate exists.*
- **PSO:DECIPHER is a padding oracle by response code.** The card answers
  malformed padding with a distinct status word and well-formed padding with
  plaintext. That is inherent to the command — it must either hand back a session
  key or report failure — and no implementation choice removes it. Assume a host
  that can drive DECIPHER at will with PW1 verified can mount
  Bleichenbacher-class attacks on ciphertexts of its choosing. The on-card
  unpadding is constant-time so the *reason* for a refusal does not leak on top
  of the refusal itself, but the message copy that follows a success is
  length-proportional, as in every conforming implementation.
  *Status: inherent to the OpenPGP card command.*
- **The RSA private paths are our own code, and it is unaudited.** The `rsa`
  crate is gone from the tree (0.4.12), and with it RUSTSEC-2023-0071 — the
  Marvin timing side channel, which never had a fixed release. What replaced it
  is `rsk-rsa`: its own key type, `RsaKey`, and a software private operation for
  the two paths the asm CRT core cannot serve (PIV certificate signing, and a
  legacy `P‖Q` key whose prime width is not a multiple of 32). Both are
  base-blinded and Bellcore-fault-checked like the asm path, and every signature
  and decryption is checked byte-for-byte against OpenSSL vectors in the host
  tests. It is still ours, still single-maintainer, and still unaudited — the
  advisory is closed, the class of bug it names is not. The one residual that
  audit leaves open is the modexp's secret-indexed window lookup on `dP`/`dQ`,
  reachable over USB on PIV and OpenPGP signing and decryption; it is recorded
  LOW because reading the window sequence back needs a time-resolved look inside
  a single operation, which a host timing whole operations does not have, and the
  hardening that would remove it is deferred with a stated price
  (`PLAT-CRYPTO-002` and `PLAT-BUILD-005` in
  [platform assumptions](platform-assumptions.md)). *Status: accepted;
  see the [constant-time audit](ct-audit.md) for what has been looked at.*
- **RSA-3072/4096 on-card generation is slow.** The prime search dominates the
  cost: *rejecting* hundreds of composite candidates, each one asm-modexp-bound.
  Both cores run the search with the modexp hot path in SRAM
  ([architecture](architecture.md)). Typical timings, measured on the
  reference board (single-core → dual-core):

  | key | before | after |
  |---|---|---|
  | RSA-2048 | ~8.9 s | ~4–6 s |
  | RSA-3072 | ~35 s | ~22 s |
  | RSA-4096 | ~65 s | ~50 s |

  The total is set by how many candidates a given draw happens to need, which is
  random. The per-keygen spread is wide (17 s to 124 s seen at 4096) because
  that count varies, not because the silicon does. Per candidate the throughput
  is ~6.9 ms across both cores.

  **These are reference-board numbers and do not carry to every board.** A
  Waveshare RP2350-Zero measures RSA-2048 at a median of ~9.7 s where the
  reference board does 4–6 s. Budget for the board you ship, not for this table.

  Both halves of the hot path — the asm modexp, and the small-prime sieve loop
  with its prime table — are held in SRAM rather than run from XIP flash. That
  is not a micro-optimization: while the sieve was still in flash it and the
  surrounding code evicted each other from the small XIP cache, and *which* of
  them won depended on where the linker happened to put things, so an unrelated
  1.7 KB of image growth moved RSA-2048 keygen by 1.36× (9.7 s → 12.7 s, three
  and four batches of 12, no overlap between them). Keep new hot loops out of
  XIP if you want a timing that survives the next commit.

  The lever is *fewer candidates reaching the modexp*: a deeper small-prime
  sieve. (The Baillie–PSW that confirms a survivor, asm strong Miller–Rabin
  plus a software Lucas test, runs only a handful of times per keygen, so it
  doesn't move the total.) Depth is set by the measured cost ratio: one
  strong-MR modexp is ~35 ms (1024-bit) / ~239 ms (2048-bit) against ~11 µs /
  ~23 µs for one trial division, so it pays to sieve by every prime up to
  ~3.1k / ~10.5k, far past the old flat 256-prime (≤1619) sieve. Depth now
  scales with key size (448 primes at RSA-2048 ... 1280 at RSA-4096), and the
  sieve runs *incrementally*: a candidate stream `n, n+2, n+4, …` from a random
  odd start, each residue `n mod pᵢ` stepped by one add instead of re-derived by
  a Horner pass (OpenSSL/GMP do the same). The primality decision is untouched,
  so key strength is unchanged. Same-device A/B (per-candidate cost, which
  divides out the prime-search-luck variance): depth-scaling took **RSA-2048
  7.84 → 6.48 ms/candidate and RSA-4096 36.0 → 26.2 ms** versus the old flat
  256-prime sieve, and the incremental step took those a further **6.48 → 5.28
  ms (−18.5%) and 26.2 → 20.9 ms (−20.4%)**. The device streams keepalives
  throughout, so tools wait it out. Import is fast. *Status: inherent to the
  hardware class; the parallel-scan share is at the two-core limit, the sieve
  at the measured modexp:division ratio and now incremental.*
- **ML-KEM is scaffolding**: compiled, tested, unused. No CTAP PIN/UV
  protocol number for PQC key agreement exists yet to implement.
  *Status: waiting on standards.*
- **PQC interop is limited by client support**: ML-DSA-44 (COSE −48),
  ML-DSA-65 (−49) and ML-DSA-87 (−50) credentials work and verify on-device.
  Their signatures verify under OpenSSL and Yubico's python-fido2, but no browser
  or mainstream WebAuthn library *negotiates* these COSE ids against security keys
  yet. Released Firefox versions abort getInfo if the algorithm is *advertised*
  (hence the `advertise-pqc` build flag, default off; capability stays on
  regardless). These are the ML-DSA schemes, not a FIPS-validated module.
  *Status: waiting on clients.*

## Backup & migration

- **The seed backup covers the deterministic identity only.** Non-resident
  credentials (`ssh ed25519-sk`, most 2FA registrations) derive from the
  master seed and survive a restore onto a new board. **Not covered:**
  resident passkeys (stored records, not derivable), OpenPGP private keys,
  PIV private keys, OATH secrets, OTP slots, all sealed to the source
  chip. A board swap means re-enrolling those. *Status: by design; a full
  at-rest export would gut the at-rest story.*
- **A finalized backup window stays closed** until a factory reset
  regenerates the seed. Lost words cannot be re-exported. Pick a generous
  SLIP-39 share count. *Status: by design (anti-exfiltration gate).*

## Hardware / physical

- **No secure element.** The RP2350's OTP fuses, glitch detectors and secure
  boot are real, and RS-Key adds anti-imaging OTP chaffing on top. But decap,
  microprobing, FIB imaging, advanced fault injection and power/EM side channels
  remain out of scope. The public RP2350 hacking challenge broke the **A2**
  stepping. The **A4** stepping fixes the boot-ROM and OTP power-glitch attacks
  in silicon, but **not** the antifuse-array readout (mitigated only by how
  secrets are stored: the chaffing RS-Key applies). Our development boards are
  A2. The firmware is A4-compatible and A4 is recommended. *Status: never. These
  are silicon properties, not firmware ones; closing them fully is what a
  dedicated secure element is for.*
- **The TRNG is not characterised, and there is no vendor number to check it
  against.** The RP2350's ring-oscillator source runs behind three continuous
  health checks and RS-Key leaves all of them armed, so a source that *dies*
  stalls or halts the device rather than handing out predictable keys. What nobody has
  measured is what the raw source is *worth*. Raspberry Pi's datasheet asserts
  compliance and publishes a generation rate, states that its software does not
  configure the ROSC settings Arm's characterisation procedure provides, and
  gives no min-entropy figure; the part carries no NIST ESV or ENT listing.
  Qualifying it across temperature, supply and process would need a thermal
  chamber, a programmable supply and parts from several lots — and even with all
  of that, a result with nothing published to hold it against. A
  degraded-but-still-passing source is the one TRNG failure this device cannot
  notice. *Status: accepted. The desk-conditions measurement that IS reachable is
  `PLAT-TRNG-002`, and this corner gap is `PLAT-TRNG-003`, both in
  [platform assumptions](platform-assumptions.md).*
- **The at-rest seals are not authenticated against a flash writer.** They keep a
  flash *dump* from yielding key material, which is what the OTP burn buys. They
  do not stop someone who can *write* flash over BOOTSEL from planting a record:
  the pre-OTP key base derives from the public chip serial, and those arms stay
  readable after the burn so an already-provisioned device survives the upgrade.
  The boot migration then re-seals the planted record under the fused root.
  *Status: needs a fuse-rooted latch that closes the migration window once the
  device is provisioned; the analysis is audit run-27 #8, the decision is the
  maintainer's because it makes `lock-page58` load-bearing for boot correctness.*
- **A PIN-derived record stays on the weaker root until its own reference is
  presented after the burn.** Every record sealed under the key base alone is
  moved to the fused root by a boot pass, but re-keying a PIN-derived one needs
  the secret, so it happens at that reference's next VERIFY. Ordinary use presents
  PW1; PW3 gates the admin surface only, and an OpenPGP resetting code may never
  be presented at all. Until one is, a flash dump plus the public chip serial
  opens the DEK copy behind it — every OpenPGP private key and the AES key with
  them — and a PW3 still on its published default needs no search at all. PIV's
  PUK has the same shape, with no DEK behind it. The card cannot retire what it
  cannot recognise: a verifier is an opaque hash, so a record written before the
  burn and one written after are indistinguishable. *Status: registered as
  `PLAT-THREAT-002`. After the burn, verify PW3 once and set the resetting code
  again — presenting a reference is what moves it. Closing it for good needs the
  DEK copies under an outer device-rooted seal a boot pass can move, which is a
  persistent-format decision and the maintainer's.*
- **A flash read that fails still reads as an absent record in most of the
  tree.** The store's `read` and `size` return the same "nothing there" for a key
  that was never written and for one the medium could not serve, and an absent
  record is how the firmware spells *not provisioned* and *no gate configured*.
  Every place where that reading would overwrite configured material or open a
  gate now uses a probe that keeps the two apart and refuses the command instead
  — 50 guards in 25 functions across PIV, OpenPGP, FIDO and OATH. The rest still
  collapse them on purpose: their absent arm reports a status field, repeats an
  idempotent repair, or already fails closed. What is not settled is who can produce such a
  fault on this hardware. A chip or bus fault does; whether a NOR power cut can is
  a board measurement nobody has taken. *Status: the dangerous arm is closed; the
  reachability question is open and belongs with `PLAT-FLASH-001`.*
- **PIV data objects are access-gated, not sealed.** SP 800-73-4 pt1 Table 3
  gives four of them a read condition of PIN — Cardholder Fingerprints
  (`5FC103`), Facial Image (`5FC108`), Printed Information (`5FC109`) and Iris
  Images (`5FC121`) — and RS-Key enforces exactly those four at the APDU layer.
  It does not back them at rest: the seal rule covers key material, so a flash
  dump of a provisioned device yields whatever a host put in them. Their names
  are the standard's, not a capability of this firmware — there is no sensor, no
  enrolment and no matching here, and the 1900-byte object ceiling is far under a
  real FIPS 201 biometric template, so what they hold is whatever the owner chose
  to store. *Status: won't fix. The read condition is an access rule, not a
  confidentiality promise, and the device cannot produce the content a seal here
  would be protecting.*
- **XIP TOCTOU residual**: secure boot verifies the image in external QSPI
  flash, then executes from it. Nothing binds the bytes that were hashed to the
  bytes later fetched, so hardware interposing on the QSPI bus can serve the
  genuine image to the verifier and a tampered one to the CPU. The clean fix
  (copy the image into SRAM, verify, run verified-in-place) does not fit: the
  ~1.7 MB image plus working RAM far exceeds the 520 KB SRAM. There is also no
  runtime flash authentication in hardware. Part selection is the real lever: an
  in-package-flash device (**RP2354**) stacks the flash die on the QSPI bus
  inside the package, so there is no discrete flash chip to clip an emulator
  onto and a reliable interposer needs decap-class access. RS-Key is developed
  and tested on external-flash RP2350 boards, so RP2354 is a recommendation here,
  not a configuration the project has validated. *Status: never on an
  external-flash board; decap-class effort on RP2354.*
- **No TrustZone-M secure/non-secure split.** Considered and rejected: the
  embassy ecosystem has no TrustZone support, so it would mean hand-rolling
  SAU/IDAU configuration, NSC veneers and dual images (the project's
  single biggest item) to defend mainly against parser memory corruption,
  which safe Rust plus fuzzing already address. Physical attacks are
  orthogonal to TrustZone. *Status: revisit only with ecosystem support.*
- **Anti-rollback is opt-in and coarse**: `picotool seal --rollback`
  plus the `ROLLBACK_REQUIRED` fuse ([anti-rollback.md](anti-rollback.md)). The
  OTP thermometer has 48 steps for the board's life, so the rollback floor is
  raised for security-relevant releases only. Until the fuse is set, any
  previously-signed image still boots. *Status: shipped (optional).*
- **No image encryption**: pointless for open-source code (no secrets in
  the image; secrets live sealed in flash), and the RP2350 has no
  transparent XIP decryption anyway. *Status: never.*
- **The trusted-display build runs the RP2350 above its rated clock.** That
  flavor sets `clk_sys` to 160 MHz where the part is specified to 150, because
  the panel's PIO transport spends two instructions per serial bit and takes the
  wire rate straight from `clk_sys / 2` — 80 MHz, and a 15.36 ms full frame
  against 16.38 at the stock 150. The panel link is out of spec on its own side
  too: 80 MHz is past the 62.5 MHz this project had previously recorded as the
  ST7789's write ceiling, and the transport is write-only, so a frame the panel
  garbles at that rate is not detectable in software. What that buys is 1 ms per
  full repaint. What it costs is that XIP timing, TRNG sampling and every
  constant-time measurement in this repo were taken at 150 MHz and do not cover
  this flavor, which no other build shares. The standard key without a screen is
  unaffected — it never sets a clock. *Status: accepted deliberately for the
  display flavor; the ratio is held by a const assert in `firmware/src/main.rs`
  so a board file cannot move one half of it alone.*

## Protocol / compatibility

- **The default USB identity is RS-Key's own** (`0x1209:0x0001` on the
  pid.codes FOSS VID, manufacturer `RS-Key`, product `RS-Key Security Key`,
  reported firmware 5.8.0), *not* a YubiKey masquerade. We no longer ship
  Yubico's identifiers by default. A YubiKey identity (`0x1050:0x0407`,
  reader name `Yubico YubiKey …`) exists only as the opt-in `VIDPID=Yubikey5`
  build flavor ([build.md](build.md)), built for local interop testing and
  never distributed. Distributing hardware with Yubico's identifiers is not
  OK. The trade-off: `ykman`, Yubico Authenticator and the stock Yubico udev
  rules gate on the `Yubico YubiKey` reader name / VID `0x1050`, so on the
  default RS-Key build they do not see the device. Use them against the
  `VIDPID=Yubikey5` flavor, or add a udev rule matching VID `0x1209`.
  FIDO2/WebAuthn, `ssh -sk`, `gpg`/OpenPGP, OpenSC/PKCS#11 and the project's
  own `rsk`/`rsk-tui` tools are identity-independent and work on the default
  build.
- **The attestation certificate is per-device, so it identifies the key.** Every
  `makeCredential` carries packed basic attestation whose `x5c` leaf is this
  board's own certificate ([guides/attestation.md](guides/attestation.md)), and
  it is the same certificate for every relying party. A batch certificate shared
  across devices would avoid that, but it would have to ship inside open-source
  firmware, where anyone could extract it. Browsers hide the leaf unless a site
  asks for `attestation: "direct"`; native CTAP clients such as `ssh-keygen` see
  it. A factory reset regenerates the seed and with it the certificate.
- **The PIV attestation identity cannot be replaced by a host.** A YubiKey lets
  one load its own chain — `IMPORT` into slot `f9` for the key,
  `PUT DATA 5FFF01` for the certificate — and that is a documented enterprise
  feature there. RS-Key refuses both (`6A86` and `6A80`). The `f9` key is
  generated by the device at first boot and never leaves it, so accepting those
  two commands would let anyone holding the management key swap the device's
  attestation identity irreversibly, over a single APDU, for a key they control.
  The cost of the other choice is on the record: one probe pass in this project
  destroyed a real YubiKey's factory attestation chain with a single
  `PUT DATA 5FFF01`, and no reset brings it back. `ATTEST` and `GET METADATA` at
  `f9` work normally, and a factory reset regenerates the identity.
  *Status: never — deliberate.*
- **`SET RETRIES` will not set a zero budget.** `00 FA 00 00` on a YubiKey
  answers `9000` and leaves the card at `0/0` tries, permanently blocked, with
  only a factory reset — which destroys every key — to recover. RS-Key answers
  `6A80` and changes nothing. The project matches a YubiKey everywhere except
  where matching would lose user data, and this is that exception.
  *Status: never — deliberate.*
- **OpenPGP secure messaging** is not implemented (rarely used by clients;
  PINs gate everything in practice).
- **One physical button on the base build.** Touch = the BOOTSEL button, and
  there is no fingerprint reader, so UV is the PIN and "number matching" style
  UV is impossible. The trusted-display flavor
  ([guides/display.md](guides/display.md)) adds a screen for on-device PIN entry
  and per-signature relying-party approval, but still no biometric UV.

## Operational

- **The flash log heals lazily**: deleting/superseding a record (e.g.
  enabling the soft-lock) leaves the old record in the log until compaction
  naturally overwrites it, so most at-rest guarantees harden over time rather
  than instantly. *(On a provisioned device the superseded copy is sealed to
  the fused root — unless it is PIN-derived, which the burn cannot re-root.)*
  What is **not** left to lazy healing is every record the boot passes re-seal
  off the chip-serial root — the seed, the attestation key and the persistent
  `pcmr` grant: the first boot after provisioning scrubs their superseded copies
  eagerly with a one-shot full-GC-lap compaction.
- **The board is the security boundary**: anyone with the device and your
  PIN is you. Same as every security key.

## HSM image

The [HSM image](guides/hsm.md) is a separate build with gaps of its own, listed
here. The board's gaps above — no secure element, slow RSA generation — hold for
it unchanged, and its security boundary is in the
[threat model](threat-model.md#the-hsm-image).

- **Not certified, and not a substitute for an HSM that is.** No FIPS 140 or
  Common Criteria claim exists or is sought. Use it for keys whose loss you can
  recover from — a homelab's LUKS, SSH and internal CA keys — not for keys a
  lab-funded attacker would be after. *Status: inherent to the hardware class.*
- **No Ed25519.** OpenSC's driver for the SmartCard-HSM command set knows RSA and
  ECDSA only, so an EdDSA key would be invisible to every PKCS#11 application;
  the image does not make one. *Status: until that driver reaches EdDSA.*
- **Brainpool, P-192 and P-224 are refused.** The image keeps P-256, P-384, P-521
  and secp256k1. The brainpool arithmetic exists (the OpenPGP applet uses it) but
  is not in the HSM's curve table; the two short NIST curves are below the
  strength of every other key here. RSA below 2048 bits is refused for the same
  reason. *Status: brainpool not yet; the rest by design.*
- **No AES through PKCS#11.** The HSM makes, uses (CBC, CMAC) and backs up AES
  keys, but OpenSC exposes no secret-key objects for this card, and `rsk hsm`
  has no AES commands either: they are reachable by raw APDU, which is how
  `tests/86_hsm.py` drives them. *Status: not yet — a host tool could.*
- **The SmartCard-HSM's other features are absent.** Key domains beyond the
  default, public-key authentication (m-of-n operator keys), secure messaging,
  and transport, session and biometric PINs are refused with a status word
  rather than half-done, and so is an INITIALIZE that asks for them. *Status:
  not planned for a single server's key store.*
- **No SHA-1 on the device.** SIGN can hash on the device with SHA-224 to
  SHA-512, never SHA-1. OpenSC hashes on the host and sends the digest anyway,
  so this binds only a client that drives the card directly. *Status: by
  design.*
- **No touch policy from host tools.** INITIALIZE option `0x0100` makes every
  private-key operation wait for a touch, but `sc-hsm-tool` cannot set it and
  `rsk hsm` does not yet; only a raw INITIALIZE does. A server that unlocks
  unattended would not want it on anyway. *Status: not yet.*
- **The lock's second factor is not here yet.** The lock reserves a factor for
  a FIDO2 token's `hmac-secret`, read on the Waveshare RP2350-USB-A's PIO USB-A
  port with no host involved; this build refuses to arm with it and ships the
  host-delivered secret only ([roadmap](roadmap.md)). *Status: not yet.*
- **LUKS depends on the systemd version.** systemd 255 enrolls an RSA key with a
  certificate on the token and nothing else; EC keys and a bare public key need
  systemd 256, and systemd 261 enrolls RSA with OAEP. OpenSC unpads OAEP over
  the card's raw RSA, and that has been checked through `pkcs11-tool`, but no
  systemd past 255 has been run against the image. *Status: upstream.*
- **Not yet run on a board.** Every interop result so far is the emulator in a
  virtual PC/SC reader ([testing.md](testing.md)): the USB transport, the
  timings of RSA generation and restore, and the board-specific parts of the
  Waveshare RP2350-USB-A preset (its LED, its button) are unverified on
  hardware. *Status: not yet.*
- **A blocked SO-PIN cannot be unblocked.** The keys stay usable with the user
  PIN, but the device can no longer be re-initialized, unblock the user PIN or
  arm and disarm its lock. Nothing above the SO-PIN could unblock it without
  becoming the way around it. *Status: by design.*
