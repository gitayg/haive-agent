// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

//! One self-update at a time per process.
//!
//! A relay agent runs two updaters: the `auto_update_relay` / `auto_update_loop`
//! poll and a hub-pushed `POST /update`. Run together they raced on one temp file
//! and installed a 0-byte binary (LMmOS-AHGQCQ0G6CR, 2026-09-01). The unique temp
//! path and the empty-bytes guard in `selfheal` close that particular hole; this
//! closes the class: download, verify and install never overlap.
//!
//! `try_begin` never waits. `/update` runs on the HTTP thread and the hub is
//! waiting on its answer, so a second caller is refused at once (the loop skips
//! its cycle) rather than blocking for the length of someone else's download.

use std::sync::{Mutex, MutexGuard, TryLockError};

static SLOT: Mutex<()> = Mutex::new(());

/// Proof that this thread owns the update slot. Dropping it frees the slot;
/// `apply_update` keeps it held once it has relaunched, because the process is
/// about to exit and nothing may install over the binary in the meantime.
pub(crate) struct UpdateSlot(#[allow(dead_code)] MutexGuard<'static, ()>);

/// The slot, or `None` if another update is already in progress.
pub(crate) fn try_begin() -> Option<UpdateSlot> {
    match SLOT.try_lock() {
        Ok(g) => Some(UpdateSlot(g)),
        // A panic mid-update poisons the mutex but the slot is free again.
        Err(TryLockError::Poisoned(p)) => Some(UpdateSlot(p.into_inner())),
        Err(TryLockError::WouldBlock) => None,
    }
}

impl UpdateSlot {
    /// Never release the slot: this process is exiting into the new binary.
    pub(crate) fn hold_until_exit(self) {
        std::mem::forget(self);
    }
}

/// Tests that take the real slot run one at a time, or they would see each other.
#[cfg(test)]
pub(crate) static TEST_SERIAL: Mutex<()> = Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};

    /// Two updaters arriving together: exactly one gets the slot. Both attempts
    /// happen while the winner still holds it (the second barrier), so a lock that
    /// let both through would show two winners.
    #[test]
    fn two_concurrent_updates_only_one_proceeds() {
        let _serial = TEST_SERIAL.lock().unwrap_or_else(|p| p.into_inner());
        let barrier = Arc::new(Barrier::new(2));
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let b = barrier.clone();
                std::thread::spawn(move || {
                    b.wait();
                    let slot = try_begin();
                    let got = slot.is_some();
                    b.wait();
                    drop(slot);
                    got
                })
            })
            .collect();
        let winners = handles.into_iter().map(|h| h.join().unwrap()).filter(|&g| g).count();
        assert_eq!(winners, 1, "exactly one of two concurrent updates may proceed");
        // And a finished (or failed) update frees the slot for the next one.
        assert!(try_begin().is_some(), "the slot must be free once the holder drops it");
    }
}
