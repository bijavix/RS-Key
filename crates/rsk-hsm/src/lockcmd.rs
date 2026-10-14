// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The LOCK instruction (`80 E8`): the commands that drive the lock state machine
//! in `lock`, and the flash writes behind them.
//!
//! | P1 | Data | Does |
//! |----|------|------|
//! | `00` | — | status: `ver ‖ state ‖ factor ‖ flags` |
//! | `01` | host point | opens a channel; answers the device point |
//! | `02` | box(L) | unlocks: DK is held until power-off |
//! | `03` | box(L ‖ SO-PIN), P2 = factor | arms, with a touch |
//! | `04` | SO-PIN | disarms an unlocked device, with a touch |

use rsk_crypto::Device;
use rsk_fs::{Fs, Storage};
use rsk_sdk::{Apdu, Confirm, ResBuf, Sw};

use crate::auth::{check_so, into_sw, load_init, require_init};
use crate::channel::{BOX_OVERHEAD, Channel};
use crate::consts::*;
use crate::lock::{Event, Refusal};
use crate::records::Factor;
use crate::seal::{KEY_LEN, Key, Wiped};
use crate::{HsmApplet, UnlockError, dk};

/// The status record's format.
const STATUS_VERSION: u8 = 1;

/// The status word a refused lock event answers.
fn refusal_sw(r: Refusal) -> Sw {
    match r {
        Refusal::Unknown => Sw::MEMORY_FAILURE,
        Refusal::Armed | Refusal::NotArmed | Refusal::Closed => Sw::CONDITIONS_NOT_SATISFIED,
    }
}

impl HsmApplet<'_> {
    pub(crate) fn lock_command<S: Storage>(
        &mut self,
        dev: &Device,
        fs: &mut Fs<S>,
        apdu: &Apdu,
        res: &mut ResBuf,
    ) -> Sw {
        if apdu.p1 != LOCK_ARM && apdu.p2 != 0 {
            return Sw::INCORRECT_P1P2;
        }
        into_sw(match apdu.p1 {
            LOCK_STATUS if apdu.nc == 0 => self.lock_status(dev, fs, res),
            LOCK_CHANNEL => self.lock_channel(apdu.data, res),
            LOCK_UNLOCK => self.lock_unlock(fs, apdu.data),
            LOCK_ARM => self.lock_arm(dev, fs, apdu.p2, apdu.data),
            LOCK_DISARM => self.lock_disarm(dev, fs, apdu.data),
            LOCK_STATUS => Err(Sw::WRONG_LENGTH),
            _ => Err(Sw::INCORRECT_P1P2),
        })
    }

    /// The four status bytes. A record that cannot be read reports itself as such
    /// rather than failing the status: this is how a host finds out.
    fn lock_status<S: Storage>(
        &mut self,
        dev: &Device,
        fs: &mut Fs<S>,
        res: &mut ResBuf,
    ) -> Result<(), Sw> {
        let _ = self.probe(fs);
        let factor = dk::factor(fs).ok().flatten().unwrap_or(Factor::None);
        let mut flags = 0u8;
        if matches!(load_init(fs), Ok(Some(_))) {
            flags |= LOCK_FLAG_INITIALIZED;
        }
        if dev.otp_key.is_some() {
            flags |= LOCK_FLAG_OTP_ROOT;
        }
        if self.sess.hmk.is_some() {
            flags |= LOCK_FLAG_USER_VERIFIED;
        }
        if fs.rescrub_refused() {
            flags |= LOCK_FLAG_RESCRUB_REFUSED;
        }
        if res.extend(&[STATUS_VERSION, self.lock.wire(), factor.id(), flags]) {
            Ok(())
        } else {
            Err(Sw::WRONG_LENGTH)
        }
    }

    /// A fresh agreement replaces any unused one: a second process can only spoil
    /// the first one's box, never read it.
    fn lock_channel(&mut self, host_pub: &[u8], res: &mut ResBuf) -> Result<(), Sw> {
        self.channel = None;
        let ch = Channel::agree(host_pub, &mut *self.rng.borrow_mut()).ok_or(Sw::WRONG_DATA)?;
        if !res.extend(ch.dev_pub()) {
            return Err(Sw::WRONG_LENGTH);
        }
        self.channel = Some(ch);
        Ok(())
    }

    /// Open the pending channel's box into `out`; the channel is gone either way.
    fn open_box(&mut self, blob: &[u8], out: &mut [u8]) -> Result<(), Sw> {
        let ch = self.channel.take().ok_or(Sw::CONDITIONS_NOT_SATISFIED)?;
        if blob.len() != BOX_OVERHEAD + out.len() {
            return Err(Sw::WRONG_LENGTH);
        }
        if ch.open(blob, out) {
            Ok(())
        } else {
            Err(Sw::WRONG_DATA)
        }
    }

    fn lock_unlock<S: Storage>(&mut self, fs: &mut Fs<S>, blob: &[u8]) -> Result<(), Sw> {
        let mut secret = Key::zeroed();
        self.open_box(blob, &mut secret[..])?;
        self.unlock(fs, &secret).map_err(|e| match e {
            UnlockError::NotArmed => Sw::CONDITIONS_NOT_SATISFIED,
            UnlockError::Refused => Sw::SECURITY_STATUS_NOT_SATISFIED,
            UnlockError::Memory => Sw::MEMORY_FAILURE,
        })
    }

    /// Arm: DK is re-sealed under the device root and the new secret in one write,
    /// and this session stays unlocked. The disarmed copy that write supersedes
    /// would open DK without the secret, so the at-rest lap must be re-armed
    /// before it, and the write waits on that.
    fn lock_arm<S: Storage>(
        &mut self,
        dev: &Device,
        fs: &mut Fs<S>,
        factor: u8,
        blob: &[u8],
    ) -> Result<(), Sw> {
        if Factor::from_id(factor) != Some(Factor::HostKey) {
            return Err(Sw::INCORRECT_P1P2);
        }
        let mut init = require_init(fs)?;
        self.probe(fs)?;
        self.lock.admits(Event::Arm).map_err(refusal_sw)?;
        let mut plain = Wiped::<{ KEY_LEN + SO_PIN_LEN }>::zeroed();
        self.open_box(blob, &mut plain[..])?;
        let (secret, so_pin) = plain.split_at(KEY_LEN);
        check_so(fs, dev, &mut init, so_pin)?;
        self.require_touch(Confirm::titled("Arm the HSM lock?"))?;
        let dk = self.dk(dev, fs)?;
        let mut l = Key::zeroed();
        l.copy_from_slice(secret);
        rsk_fs::request_rescrub(fs).map_err(|_| Sw::MEMORY_FAILURE)?;
        dk::write(
            fs,
            dev,
            &mut *self.rng.borrow_mut(),
            &dk,
            Factor::HostKey,
            Some(&l),
        )?;
        self.lock.armed(dk);
        Ok(())
    }

    /// Disarm an unlocked device: DK goes back under the device root alone.
    fn lock_disarm<S: Storage>(
        &mut self,
        dev: &Device,
        fs: &mut Fs<S>,
        so_pin: &[u8],
    ) -> Result<(), Sw> {
        let mut init = require_init(fs)?;
        if so_pin.len() != SO_PIN_LEN {
            return Err(Sw::WRONG_LENGTH);
        }
        self.probe(fs)?;
        self.lock.admits(Event::Disarm).map_err(refusal_sw)?;
        check_so(fs, dev, &mut init, so_pin)?;
        self.require_touch(Confirm::titled("Disarm the HSM lock?"))?;
        let dk = self
            .lock
            .held()
            .ok_or(Sw::CONDITIONS_NOT_SATISFIED)?
            .clone();
        dk::write(
            fs,
            dev,
            &mut *self.rng.borrow_mut(),
            &dk,
            Factor::None,
            None,
        )?;
        self.lock.disarmed();
        Ok(())
    }
}
