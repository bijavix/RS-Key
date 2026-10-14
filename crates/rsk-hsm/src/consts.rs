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
