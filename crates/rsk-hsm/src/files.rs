// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The file system the driver sees: SELECT, READ / UPDATE BINARY, DELETE FILE and
//! ENUMERATE OBJECTS over the object classes `store` maps, plus EF.TokenInfo,
//! which is synthesized rather than stored.
//!
//! Access, per class: key objects are never read and only ever written by the
//! commands that create keys; PIN-protected data is sealed under HMK and needs the
//! user PIN both ways; everything else reads freely and writes with the user PIN.

use rsk_fs::{Fs, KeyFid, Sealed, Storage};
use rsk_sdk::tlv::{Tlv, find_tag, len_tag};
use rsk_sdk::{Apdu, ResBuf, Sw};

use crate::HsmApplet;
use crate::auth::{into_sw, load_init};
use crate::consts::*;
use crate::seal::{self, SEAL_OVERHEAD, Wiped};
use crate::store::{self, Class, File, MAX_PLAIN, read_plain, read_sealed};

/// The token label's ceiling: a PKCS#11 label is 32 characters.
const LABEL_MAX: usize = 32;
/// What EF.TokenInfo names when no label has been written.
const DEFAULT_LABEL: &[u8] = b"RS-Key HSM";
const MANUFACTURER: &[u8] = b"RS-Key";
/// PKCS#15 TokenInfo tags: the SEQUENCE, version, manufacturerID (UTF8String),
/// label (`[0]`) and tokenflags (BIT STRING).
const TI_SEQUENCE: u8 = 0x30;
const TI_VERSION: [u8; 3] = [0x02, 0x01, 0x00];
const TI_MANUFACTURER: u8 = 0x0C;
const TI_LABEL: u8 = 0x80;
/// tokenflags with only `prnGeneration` set: the device has its own RNG.
const TI_FLAGS: [u8; 4] = [0x03, 0x02, 0x05, 0x20];
/// The largest synthesized TokenInfo.
const TOKENINFO_MAX: usize =
    2 + TI_VERSION.len() + 2 + MANUFACTURER.len() + 2 + LABEL_MAX + TI_FLAGS.len();

/// Largest plaintext a sealed data object can hold.
const MAX_SEALED_PLAIN: usize = MAX_PLAIN - SEAL_OVERHEAD;

/// The FCP SELECT of the application answers with. Its proprietary `85` object is
/// what the driver recognises the card by: the options, the applet-type byte and
/// the version. A store that cannot be read reports no options rather than
/// failing the SELECT — the options gate nothing on the host.
pub(crate) fn application_fcp<S: Storage>(fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
    let options = load_init(fs).ok().flatten().map_or(0, |i| i.options);
    let [hi, lo] = options.to_be_bytes();
    let (major, minor, _) = rsk_sdk::FIRMWARE_VERSION;
    let body = [
        TAG_FCP_DESCRIPTOR,
        1,
        FD_DF,
        TAG_FCP_PROPRIETARY,
        5,
        hi,
        lo,
        FCP_TYPE_GENERIC,
        major,
        minor,
    ];
    if res.push(TAG_FCP) && res.push(body.len() as u8) && res.extend(&body) {
        Sw::OK
    } else {
        Sw::WRONG_LENGTH
    }
}

/// The FCP of an elementary file.
fn ef_fcp(fid: u16, size: usize, res: &mut ResBuf) -> Sw {
    let [fh, fl] = fid.to_be_bytes();
    let [sh, sl] = (size as u16).to_be_bytes();
    let body = [
        TAG_FCP_SIZE,
        2,
        sh,
        sl,
        TAG_FCP_DESCRIPTOR,
        1,
        FD_EF_TRANSPARENT,
        TAG_FCP_FID,
        2,
        fh,
        fl,
    ];
    if res.push(TAG_FCP) && res.push(body.len() as u8) && res.extend(&body) {
        Sw::OK
    } else {
        Sw::WRONG_LENGTH
    }
}

/// Write the TokenInfo for `label` into `out`; returns its length.
fn token_info(label: &[u8], out: &mut [u8; TOKENINFO_MAX]) -> usize {
    let body_len = TI_VERSION.len() + 2 + MANUFACTURER.len() + 2 + label.len() + TI_FLAGS.len();
    let mut n = 0;
    let mut put = |b: &[u8]| {
        out[n..n + b.len()].copy_from_slice(b);
        n += b.len();
    };
    put(&[TI_SEQUENCE, body_len as u8]);
    put(&TI_VERSION);
    put(&[TI_MANUFACTURER, MANUFACTURER.len() as u8]);
    put(MANUFACTURER);
    put(&[TI_LABEL, label.len() as u8]);
    put(label);
    put(&TI_FLAGS);
    n
}

/// The label a host-written TokenInfo carries: `Ok(None)` when it names none.
/// Only the label is kept; the rest of EF.TokenInfo is the device's to state.
fn label_of(token_info: &[u8]) -> Result<Option<&[u8]>, Sw> {
    let body = single(token_info, TI_SEQUENCE as u16)?;
    walk(body, |_, _| Ok(()))?;
    match find_tag(body, TI_LABEL as u16) {
        Some(l) if l.len() <= LABEL_MAX => Ok(Some(l)),
        Some(_) => Err(Sw::WRONG_DATA),
        None => Ok(None),
    }
}

/// Walk `data` as BER-TLV, failing unless the objects cover it exactly. The
/// shared iterator stops quietly at the first malformed object; a command must
/// not quietly drop what follows it.
pub(crate) fn walk<'d>(
    data: &'d [u8],
    mut f: impl FnMut(u16, &'d [u8]) -> Result<(), Sw>,
) -> Result<(), Sw> {
    let mut used = 0usize;
    for (tag, v) in Tlv::new(data) {
        used += len_tag(tag, v.len() as u16);
        f(tag, v)?;
    }
    if used == data.len() {
        Ok(())
    } else {
        Err(Sw::WRONG_DATA)
    }
}

/// The value of `data` when it is exactly one object with `tag`.
fn single(data: &[u8], tag: u16) -> Result<&[u8], Sw> {
    let mut found = None;
    walk(data, |t, v| {
        if t != tag || found.is_some() {
            return Err(Sw::WRONG_DATA);
        }
        found = Some(v);
        Ok(())
    })?;
    found.ok_or(Sw::WRONG_DATA)
}

/// The offset an offset data object (`54`) carries: one or two bytes.
fn offset_of(v: &[u8]) -> Result<usize, Sw> {
    match *v {
        [b] => Ok(b as usize),
        [hi, lo] => Ok(u16::from_be_bytes([hi, lo]) as usize),
        _ => Err(Sw::WRONG_DATA),
    }
}

/// ENUMERATE OBJECTS: the file identifier of every live object, two bytes each.
pub(crate) fn enumerate<S: Storage>(fs: &mut Fs<S>, apdu: &Apdu, res: &mut ResBuf) -> Sw {
    if apdu.p1 != 0 || apdu.p2 != 0 {
        return Sw::INCORRECT_P1P2;
    }
    if apdu.nc != 0 {
        return Sw::WRONG_LENGTH;
    }
    let Some(live) = store::live_objects(fs) else {
        return Sw::MEMORY_FAILURE;
    };
    for (class, ids) in Class::ALL.into_iter().zip(live.iter()) {
        for id in 0..=255u8 {
            if ids[id as usize / 8] & (1 << (id % 8)) != 0 && !res.extend(&[class.prefix(), id]) {
                return Sw::FILE_FULL;
            }
        }
    }
    Sw::OK
}

/// Whether one more object may be created: ENUMERATE must always be able to list
/// them all in one response.
pub(crate) fn room_for_object<S: Storage>(fs: &mut Fs<S>) -> Result<(), Sw> {
    let live = store::live_objects(fs).ok_or(Sw::MEMORY_FAILURE)?;
    let count: u32 = live.iter().flatten().map(|b| b.count_ones()).sum();
    if (count as usize) < MAX_OBJECTS {
        Ok(())
    } else {
        Err(Sw::FILE_FULL)
    }
}

impl HsmApplet<'_> {
    /// The current EF, or the one a command names in P1/P2 (`0000` meaning "the
    /// current one").
    fn target(&self, p1: u8, p2: u8) -> Result<u16, Sw> {
        match u16::from_be_bytes([p1, p2]) {
            0 => self.sess.ef.ok_or(Sw::COMMAND_NOT_ALLOWED),
            fid => Ok(fid),
        }
    }

    /// How many bytes `file` holds as the host sees it, or `None` when absent.
    fn file_size<S: Storage>(&self, fs: &mut Fs<S>, file: File) -> Result<Option<usize>, Sw> {
        match file {
            File::TokenInfo => {
                let mut out = [0u8; TOKENINFO_MAX];
                Ok(Some(self.token_info(fs, &mut out)?))
            }
            File::Object(Class::Key, _) => Ok(store::size(fs, file.store())?.map(|_| 0)),
            File::Object(Class::ProtData, _) => {
                Ok(store::size(fs, file.store())?.map(|n| n.saturating_sub(SEAL_OVERHEAD)))
            }
            _ => store::size(fs, file.store()),
        }
    }

    /// EF.TokenInfo around the stored label, or the default one.
    fn token_info<S: Storage>(
        &self,
        fs: &mut Fs<S>,
        out: &mut [u8; TOKENINFO_MAX],
    ) -> Result<usize, Sw> {
        let mut label = [0u8; LABEL_MAX];
        Ok(match read_plain(fs, store::REC_LABEL, &mut label)? {
            Some(n) => token_info(&label[..n], out),
            None => token_info(DEFAULT_LABEL, out),
        })
    }

    /// SELECT of an elementary file, or of the application by name or as `3F00`.
    pub(crate) fn select_file<S: Storage>(
        &mut self,
        fs: &mut Fs<S>,
        apdu: &Apdu,
        res: &mut ResBuf,
    ) -> Sw {
        let no_data = match apdu.p2 {
            SEL_NO_DATA => true,
            0x00 | 0x04 => false,
            _ => return Sw::INCORRECT_P1P2,
        };
        match apdu.p1 {
            SEL_DF_NAME => {
                if apdu.data.is_empty() || !HSM_AID.starts_with(apdu.data) {
                    return Sw::FILE_NOT_FOUND;
                }
                self.sess = crate::Session::default();
                self.channel = None;
                return if no_data {
                    Sw::OK
                } else {
                    application_fcp(fs, res)
                };
            }
            SEL_FID | SEL_CHILD_EF | SEL_PATH_FROM_MF | SEL_PATH_FROM_CURRENT => {}
            _ => return Sw::INCORRECT_P1P2,
        }
        let [hi, lo] = *apdu.data else {
            return Sw::WRONG_LENGTH;
        };
        let fid = u16::from_be_bytes([hi, lo]);
        if fid == FID_MF {
            self.sess.ef = None;
            return if no_data {
                Sw::OK
            } else {
                application_fcp(fs, res)
            };
        }
        let Some(file) = File::from_fid(fid) else {
            return Sw::FILE_NOT_FOUND;
        };
        let size = match self.file_size(fs, file) {
            Ok(Some(n)) => n,
            Ok(None) => return Sw::FILE_NOT_FOUND,
            Err(sw) => return sw,
        };
        self.sess.ef = Some(fid);
        if no_data {
            Sw::OK
        } else {
            ef_fcp(fid, size, res)
        }
    }

    /// READ BINARY, plain (`B0`, offset in P1/P2, current EF) or odd (`B1`, the
    /// file in P1/P2 and the offset in a `54` object).
    pub(crate) fn read_binary<S: Storage>(
        &mut self,
        fs: &mut Fs<S>,
        apdu: &Apdu,
        res: &mut ResBuf,
    ) -> Sw {
        let r = if apdu.ins == INS_READ_BINARY {
            if apdu.p1 & 0x80 != 0 {
                return Sw::INCORRECT_P1P2;
            }
            if apdu.nc != 0 {
                return Sw::WRONG_LENGTH;
            }
            self.sess
                .ef
                .ok_or(Sw::COMMAND_NOT_ALLOWED)
                .map(|fid| (fid, u16::from_be_bytes([apdu.p1, apdu.p2]) as usize))
        } else {
            self.target(apdu.p1, apdu.p2)
                .and_then(|fid| Ok((fid, offset_of(single(apdu.data, TAG_OFFSET)?)?)))
        };
        let (fid, offset) = match r {
            Ok(t) => t,
            Err(sw) => return sw,
        };
        into_sw(self.read_file(fs, fid, offset, apdu.ne, res))
    }

    fn read_file<S: Storage>(
        &mut self,
        fs: &mut Fs<S>,
        fid: u16,
        offset: usize,
        ne: usize,
        res: &mut ResBuf,
    ) -> Result<(), Sw> {
        let file = File::from_fid(fid).ok_or(Sw::FILE_NOT_FOUND)?;
        let mut buf = Wiped::<MAX_PLAIN>::zeroed();
        let len = match file {
            File::Object(Class::Key, _) => return Err(Sw::SECURITY_STATUS_NOT_SATISFIED),
            File::TokenInfo => {
                let mut ti = [0u8; TOKENINFO_MAX];
                let n = self.token_info(fs, &mut ti)?;
                buf[..n].copy_from_slice(&ti[..n]);
                n
            }
            File::Object(Class::ProtData, _) => {
                let hmk = self
                    .sess
                    .hmk
                    .as_ref()
                    .ok_or(Sw::SECURITY_STATUS_NOT_SATISFIED)?;
                let mut sealed = [0u8; MAX_PLAIN];
                let fid = KeyFid::new(file.store());
                let n = read_sealed(fs, fid, &mut sealed)?.ok_or(Sw::FILE_NOT_FOUND)?;
                let k = seal::object_key(hmk, fid.get());
                seal::open(&k, fid.get(), &[], &sealed[..n], &mut buf[..])
                    .map_err(|_| Sw::MEMORY_FAILURE)?
            }
            _ => read_plain(fs, file.store(), &mut buf[..])?.ok_or(Sw::FILE_NOT_FOUND)?,
        };
        self.sess.ef = Some(fid);
        if offset > len {
            return Err(Sw::WRONG_P1P2);
        }
        let want = if ne == 0 {
            rsk_sdk::apdu::NE_SHORT_MAX
        } else {
            ne
        };
        let n = want.min(len - offset).min(res.capacity() - res.len());
        res.extend(&buf[offset..offset + n]);
        if offset + n == len && n < want {
            return Err(Sw::WARNING_EOF);
        }
        Ok(())
    }

    /// UPDATE BINARY (`D7`): `54` offset, `53` data. Bytes past the written range
    /// are dropped — the driver writes a file front to back, so a rewrite never
    /// keeps a stale tail.
    pub(crate) fn update_binary<S: Storage>(&mut self, fs: &mut Fs<S>, apdu: &Apdu) -> Sw {
        let fid = match self.target(apdu.p1, apdu.p2) {
            Ok(fid) => fid,
            Err(sw) => return sw,
        };
        let mut offset = None;
        let mut data = None;
        let parsed = walk(apdu.data, |tag, v| {
            let slot = match tag {
                TAG_OFFSET if offset.is_none() => {
                    offset = Some(offset_of(v)?);
                    return Ok(());
                }
                TAG_DATA => &mut data,
                _ => return Err(Sw::WRONG_DATA),
            };
            if slot.is_some() {
                return Err(Sw::WRONG_DATA);
            }
            *slot = Some(v);
            Ok(())
        });
        if let Err(sw) = parsed {
            return sw;
        }
        let Some(data) = data else {
            return Sw::WRONG_DATA;
        };
        into_sw(self.write_file(fs, fid, offset.unwrap_or(0), data))
    }

    fn write_file<S: Storage>(
        &mut self,
        fs: &mut Fs<S>,
        fid: u16,
        offset: usize,
        data: &[u8],
    ) -> Result<(), Sw> {
        let file = File::from_fid(fid).ok_or(Sw::FILE_NOT_FOUND)?;
        match file {
            File::Object(Class::Key, _) | File::DevAut => {
                return Err(Sw::SECURITY_STATUS_NOT_SATISFIED);
            }
            File::TokenInfo if self.sess.label_grant => {}
            _ if self.sess.hmk.is_none() => return Err(Sw::SECURITY_STATUS_NOT_SATISFIED),
            _ => {}
        }
        if let File::TokenInfo = file {
            if offset != 0 {
                return Err(Sw::WRONG_P1P2);
            }
            let r = match label_of(data)? {
                Some(label) => fs.put(store::REC_LABEL, label),
                None => fs.delete(store::REC_LABEL),
            };
            return r.map_err(|_| Sw::MEMORY_FAILURE);
        }
        let exists = store::size(fs, file.store())?.is_some();
        if !exists && matches!(file, File::Object(..)) {
            room_for_object(fs)?;
        }
        let mut buf = Wiped::<MAX_PLAIN>::zeroed();
        if let File::Object(Class::ProtData, _) = file {
            let hmk = self
                .sess
                .hmk
                .clone()
                .ok_or(Sw::SECURITY_STATUS_NOT_SATISFIED)?;
            let key_fid = KeyFid::new(file.store());
            let k = seal::object_key(&hmk, key_fid.get());
            let mut sealed = Wiped::<MAX_PLAIN>::zeroed();
            let old = match read_sealed(fs, key_fid, &mut sealed[..])? {
                Some(n) => seal::open(&k, key_fid.get(), &[], &sealed[..n], &mut buf[..])
                    .map_err(|_| Sw::MEMORY_FAILURE)?,
                None => 0,
            };
            let len = splice(&mut buf[..MAX_SEALED_PLAIN], old, offset, data)?;
            let mut rng = self.rng.borrow_mut();
            let n = seal::seal(
                &k,
                key_fid.get(),
                &[],
                &buf[..len],
                &mut *rng,
                &mut sealed[..],
            );
            fs.put_key(key_fid, Sealed::wrap(&sealed[..n]))
                .map_err(|_| Sw::MEMORY_FAILURE)?;
        } else {
            let old = read_plain(fs, file.store(), &mut buf[..])?.unwrap_or(0);
            let len = splice(&mut buf[..], old, offset, data)?;
            fs.put(file.store(), &buf[..len])
                .map_err(|_| Sw::MEMORY_FAILURE)?;
        }
        self.sess.ef = Some(fid);
        Ok(())
    }

    /// DELETE FILE: the identifier in the data field.
    pub(crate) fn delete_file<S: Storage>(&mut self, fs: &mut Fs<S>, apdu: &Apdu) -> Sw {
        if !matches!(apdu.p1, 0x00 | 0x02) || apdu.p2 != 0 {
            return Sw::INCORRECT_P1P2;
        }
        let [hi, lo] = *apdu.data else {
            return Sw::WRONG_LENGTH;
        };
        into_sw(self.erase_file(fs, u16::from_be_bytes([hi, lo])))
    }

    fn erase_file<S: Storage>(&mut self, fs: &mut Fs<S>, fid: u16) -> Result<(), Sw> {
        let file = File::from_fid(fid).ok_or(Sw::FILE_NOT_FOUND)?;
        if self.sess.hmk.is_none() {
            return Err(Sw::SECURITY_STATUS_NOT_SATISFIED);
        }
        if matches!(file, File::DevAut | File::Object(Class::Key, KEY_ID_DEVICE)) {
            return Err(Sw::SECURITY_STATUS_NOT_SATISFIED);
        }
        if store::size(fs, file.store())?.is_none() {
            // EF.TokenInfo always exists; deleting it only drops a label never written.
            return if file == File::TokenInfo {
                Ok(())
            } else {
                Err(Sw::FILE_NOT_FOUND)
            };
        }
        // A deleted secret's sealed copy stays in the flash log until the at-rest
        // lap reclaims its page; best-effort, like every wipe in the tree.
        if matches!(file, File::Object(class, _) if class.sealed()) {
            let _ = rsk_fs::request_rescrub(fs);
        }
        fs.delete(file.store()).map_err(|_| Sw::MEMORY_FAILURE)?;
        if self.sess.ef == Some(fid) {
            self.sess.ef = None;
        }
        Ok(())
    }
}

/// Write `data` at `offset` over the first `old` bytes of `buf`, dropping what
/// followed; returns the new length.
fn splice(buf: &mut [u8], old: usize, offset: usize, data: &[u8]) -> Result<usize, Sw> {
    if offset > old {
        return Err(Sw::WRONG_P1P2);
    }
    let end = offset.checked_add(data.len()).ok_or(Sw::FILE_FULL)?;
    if end > buf.len() {
        return Err(Sw::FILE_FULL);
    }
    buf[offset..end].copy_from_slice(data);
    Ok(end)
}

#[cfg(test)]
#[path = "files_tests.rs"]
mod tests;
