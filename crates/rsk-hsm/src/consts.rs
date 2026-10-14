// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The wire vocabulary — instructions, references, tags, file identifiers and the
//! bounds on each — named once. The SmartCard-HSM numbers are the ones OpenSC's
//! built-in `sc-hsm` driver sends (`card-sc-hsm.c`, `pkcs15-sc-hsm.c`); the lock
//! instruction is RS-Key's own and sits outside that command set.

/// The application identifier the `sc-hsm` driver selects to recognise a card.
pub const HSM_AID: &[u8] = &[
    0xE8, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x81, 0xC3, 0x1F, 0x02, 0x01,
];

// Class bytes: interindustry commands arrive as `00`, the proprietary ones as `80`.
pub const CLA_ISO: u8 = 0x00;
pub const CLA_PROPRIETARY: u8 = 0x80;

pub const INS_VERIFY: u8 = 0x20;
pub const INS_CHANGE_REFERENCE: u8 = 0x24;
pub const INS_RESET_RETRY: u8 = 0x2C;
pub const INS_INITIALIZE: u8 = 0x50;
pub const INS_KEY_DOMAIN: u8 = 0x52;
pub const INS_ENUMERATE: u8 = 0x58;
pub const INS_GENERATE_KEYPAIR: u8 = 0x46;
pub const INS_DECIPHER: u8 = 0x62;
pub const INS_SIGN: u8 = 0x68;
pub const INS_GET_CHALLENGE: u8 = 0x84;
pub const INS_SELECT: u8 = 0xA4;
pub const INS_READ_BINARY: u8 = 0xB0;
pub const INS_READ_BINARY_ODD: u8 = 0xB1;
pub const INS_UPDATE_BINARY_ODD: u8 = 0xD7;
pub const INS_DELETE_FILE: u8 = 0xE4;
/// RS-Key's lock instruction (status, channel, unlock, arm, disarm by P1).
pub const INS_LOCK: u8 = 0xE8;

// SELECT P1: by file identifier (MF/DF/EF, child EF), by DF name, by path.
pub const SEL_FID: u8 = 0x00;
pub const SEL_CHILD_EF: u8 = 0x02;
pub const SEL_DF_NAME: u8 = 0x04;
pub const SEL_PATH_FROM_MF: u8 = 0x08;
pub const SEL_PATH_FROM_CURRENT: u8 = 0x09;
/// SELECT P2 asking for no response data.
pub const SEL_NO_DATA: u8 = 0x0C;
/// The master file. OpenSC simulates it for this driver; a host that sends it
/// anyway gets the application back.
pub const FID_MF: u16 = 0x3F00;

// PIN references.
pub const PIN_USER: u8 = 0x81;
pub const PIN_SO: u8 = 0x88;
/// The two biometric references; OpenSC probes them to decide whether the card
/// has a PIN pad, and "no such reference" is the answer that says it has none.
pub const PIN_BIO_1: u8 = 0x85;
pub const PIN_BIO_2: u8 = 0x86;

/// User PIN bounds, the ones `sc-hsm-tool` and the PKCS#15 profile enforce.
pub const USER_PIN_MIN: usize = 6;
pub const USER_PIN_MAX: usize = 16;
/// The SO-PIN (initialization code) is 8 bytes — 16 hexadecimal digits on the host.
pub const SO_PIN_LEN: usize = 8;
/// User PIN retry counter: the INITIALIZE range, and the default OpenSC uses.
pub const USER_RETRIES_MAX: u8 = 10;
pub const USER_RETRIES_DEFAULT: u8 = 3;
/// The SO-PIN's fixed retry counter.
pub const SO_RETRIES: u8 = 15;

// INITIALIZE DEVICE data objects.
pub const TAG_INIT_OPTIONS: u16 = 0x80;
pub const TAG_INIT_USER_PIN: u16 = 0x81;
pub const TAG_INIT_SO_PIN: u16 = 0x82;
pub const TAG_INIT_RETRIES: u16 = 0x91;
pub const TAG_INIT_DKEK_SHARES: u16 = 0x92;

/// Option bits in the INITIALIZE `80` object, reported back in the FCP's `85`.
/// RESET RETRY COUNTER is permitted at all.
pub const OPT_RRC: u16 = 0x0001;
/// RESET RETRY COUNTER may only unblock, never set a new PIN.
pub const OPT_RRC_UNBLOCK_ONLY: u16 = 0x0020;
/// RS-Key's own: every private-key operation asks for a touch.
pub const OPT_TOUCH_KEY_USE: u16 = 0x0100;
/// Every option this build implements; INITIALIZE refuses the rest rather than
/// recording a promise (transport PIN, session PIN, public-key auth) it cannot keep.
pub const OPT_SUPPORTED: u16 = OPT_RRC | OPT_RRC_UNBLOCK_ONLY | OPT_TOUCH_KEY_USE;

/// READ / UPDATE BINARY offset data object (odd instruction).
pub const TAG_OFFSET: u16 = 0x54;
/// UPDATE BINARY discretionary data object.
pub const TAG_DATA: u16 = 0x53;

// FCP template and the objects in it.
pub const TAG_FCP: u8 = 0x62;
pub const TAG_FCP_SIZE: u8 = 0x80;
pub const TAG_FCP_DESCRIPTOR: u8 = 0x82;
pub const TAG_FCP_FID: u8 = 0x83;
pub const TAG_FCP_PROPRIETARY: u8 = 0x85;
/// File descriptor bytes: a DF, and a transparent working EF.
pub const FD_DF: u8 = 0x38;
pub const FD_EF_TRANSPARENT: u8 = 0x01;
/// The byte the driver reads as "applet type" ahead of the version; any value
/// past the two JCOP ones names the device plain "SmartCard-HSM".
pub const FCP_TYPE_GENERIC: u8 = 0xFF;

// SmartCard-HSM file identifier prefixes (high byte), one per object class.
pub const PREFIX_PRKD: u8 = 0xC4;
pub const PREFIX_CD: u8 = 0xC8;
pub const PREFIX_DCOD: u8 = 0xC9;
pub const PREFIX_CA_CERT: u8 = 0xCA;
pub const PREFIX_KEY: u8 = 0xCC;
pub const PREFIX_PROT_DATA: u8 = 0xCD;
pub const PREFIX_EE_CERT: u8 = 0xCE;
pub const PREFIX_DATA: u8 = 0xCF;

// The fixed elementary files.
/// The device certificate chain the driver reads its serial number from.
pub const FID_DEVAUT: u16 = 0x2F02;
/// EF.TokenInfo (PKCS#15).
pub const FID_TOKENINFO: u16 = 0x2F03;
/// Where UNWRAP KEY expects the wrapped blob.
pub const FID_STAGING: u16 = 0x2F10;

/// The key reference of the device authentication key: listed, never usable.
pub const KEY_ID_DEVICE: u8 = 0x00;

/// Most objects the store may hold: ENUMERATE lists every one, two bytes each,
/// in one response under the CCID frame's body cap.
pub const MAX_OBJECTS: usize = 1000;

// SIGN and DECIPHER algorithms (P2). The SHA-1 variants of the protocol (`31`,
// `41`, `71`) are absent on purpose: this firmware hashes no new signature with
// SHA-1, and a host that insists can still hash it itself and send `20` or `70`.
/// RSA over a block the host padded.
pub const ALGO_RSA_RAW: u8 = 0x20;
/// RSA decryption, answered unpadded: the host strips the padding.
pub const ALGO_RSA_DECRYPT: u8 = 0x21;
/// PKCS#1 v1.5 over a DigestInfo the host built.
pub const ALGO_RSA_PKCS1: u8 = 0x30;
/// PKCS#1 v1.5 over a digest the device takes of the data.
pub const ALGO_RSA_PKCS1_SHA256: u8 = 0x33;
pub const ALGO_RSA_PKCS1_SHA384: u8 = 0x34;
pub const ALGO_RSA_PKCS1_SHA512: u8 = 0x35;
/// PSS over a digest the host took; its length names the hash.
pub const ALGO_RSA_PSS: u8 = 0x40;
/// PSS over a digest the device takes of the data.
pub const ALGO_RSA_PSS_SHA256: u8 = 0x43;
pub const ALGO_RSA_PSS_SHA384: u8 = 0x44;
pub const ALGO_RSA_PSS_SHA512: u8 = 0x45;
/// ECDSA over a digest the host took.
pub const ALGO_EC_RAW: u8 = 0x70;
/// ECDSA over a digest the device takes of the data.
pub const ALGO_EC_SHA224: u8 = 0x72;
pub const ALGO_EC_SHA256: u8 = 0x73;
pub const ALGO_EC_SHA384: u8 = 0x74;
pub const ALGO_EC_SHA512: u8 = 0x75;
/// ECDH, answered as the whole shared point.
pub const ALGO_EC_DH: u8 = 0x80;

// Card-verifiable certificates (BSI TR-03110): the authenticated request GENERATE
// KEY PAIR answers, and the device certificate in `2F02`.
pub const TAG_CV_AUTH_REQUEST: u16 = 0x67;
pub const TAG_CV_CERT: u16 = 0x7F21;
pub const TAG_CV_BODY: u16 = 0x7F4E;
pub const TAG_CV_PROFILE: u16 = 0x5F29;
pub const TAG_CV_CAR: u16 = 0x42;
pub const TAG_CV_PUBKEY: u16 = 0x7F49;
pub const TAG_CV_CHR: u16 = 0x5F20;
pub const TAG_CV_SIGNATURE: u16 = 0x5F37;
/// The only certificate profile there is.
pub const CV_PROFILE: u8 = 0x00;
/// A certification authority or holder reference: at most 16 characters.
pub const CV_REF_MAX: usize = 16;
// The public key's data objects, in the order a body carries them. RSA reuses
// the first two for the modulus and the public exponent.
pub const TAG_PK_OID: u16 = 0x06;
pub const TAG_PK_PRIME: u16 = 0x81;
pub const TAG_PK_A: u16 = 0x82;
pub const TAG_PK_B: u16 = 0x83;
pub const TAG_PK_BASE: u16 = 0x84;
pub const TAG_PK_ORDER: u16 = 0x85;
pub const TAG_PK_POINT: u16 = 0x86;
pub const TAG_PK_COFACTOR: u16 = 0x87;
/// A request template's RSA modulus size, in bits.
pub const TAG_PK_MODULUS_BITS: u16 = 0x02;
// GENERATE KEY PAIR's own objects, after the body's.
pub const TAG_KEY_USE_COUNTER: u16 = 0x90;
pub const TAG_KEY_ALGORITHMS: u16 = 0x91;
pub const TAG_KEY_DOMAIN: u16 = 0x92;
/// The key domain every key lives in; this build has no other.
pub const KEY_DOMAIN_DEFAULT: u8 = 0x00;

/// GET CHALLENGE ceiling, the one the driver itself clamps to.
pub const MAX_CHALLENGE: usize = 1024;

// LOCK (`80 E8`) P1 values.
pub const LOCK_STATUS: u8 = 0x00;
pub const LOCK_CHANNEL: u8 = 0x01;
pub const LOCK_UNLOCK: u8 = 0x02;
pub const LOCK_ARM: u8 = 0x03;
pub const LOCK_DISARM: u8 = 0x04;
/// Where the unlock secret comes from: LOCK ARM's P2, LOCK STATUS's third byte,
/// and the device record's. None — the lock is disarmed.
pub const LOCK_FACTOR_NONE: u8 = 0x00;
/// A key the host boxes over the lock channel.
pub const LOCK_FACTOR_HOST_KEY: u8 = 0x01;
/// A FIDO2 token's `hmac-secret` on the board's USB-A port. Reserved: this build
/// refuses to arm with it.
pub const LOCK_FACTOR_FIDO2_HMAC_SECRET: u8 = 0x02;
/// The unlock secret, whichever source delivers it.
pub const UNLOCK_SECRET_LEN: usize = 32;
/// LOCK STATUS's state byte.
pub const LOCK_STATE_DISARMED: u8 = 0x00;
pub const LOCK_STATE_LOCKED: u8 = 0x01;
pub const LOCK_STATE_UNLOCKED: u8 = 0x02;
/// The device record could not be read this power cycle.
pub const LOCK_STATE_UNKNOWN: u8 = 0xFF;
/// LOCK STATUS's flag byte.
pub const LOCK_FLAG_INITIALIZED: u8 = 0x01;
/// The device root is the OTP-fused one, not the chip-serial fallback.
pub const LOCK_FLAG_OTP_ROOT: u8 = 0x02;
pub const LOCK_FLAG_USER_VERIFIED: u8 = 0x04;
/// The medium refused to re-arm the at-rest lap this power cycle.
pub const LOCK_FLAG_RESCRUB_REFUSED: u8 = 0x08;
