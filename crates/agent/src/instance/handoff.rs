// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

//! The one-agent lock across a self-restart. A self-update or app relaunch execs in
//! place, so the new image has our pid and the exec closes the lock file. But on
//! macOS a pre-exec image running mDNS threads keeps its files, the lock among them,
//! for ~10 s while the kernel tears it down: the new image found its own pid holding
//! the lock and ran without it for the rest of its life. So the exec lets go of the
//! lock first, and a new image that still finds its own pid waits for it.

use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::Path;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

use super::{try_claim, Claim};

static HELD: AtomicI32 = AtomicI32::new(-1);

const WAIT: Duration = Duration::from_secs(30);

pub(super) fn remember(f: &File) {
    HELD.store(f.as_raw_fd(), Ordering::Relaxed);
}

pub(super) fn let_go() {
    let fd = HELD.load(Ordering::Relaxed);
    if fd >= 0 {
        unsafe { libc::flock(fd, libc::LOCK_UN) };
    }
}

fn take_back() {
    let fd = HELD.load(Ordering::Relaxed);
    if fd >= 0 && unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        eprintln!("agent: another process took the one-agent lock during the failed restart; running without it");
    }
}

/// `cmd.exec()` with the one-agent lock released first, so the new image takes it at
/// once; taken back when the exec fails and this image keeps running.
pub(crate) fn exec(mut cmd: std::process::Command) -> std::io::Error {
    use std::os::unix::process::CommandExt;
    let_go();
    let e = cmd.exec();
    take_back();
    e
}

/// The lock is held under our own pid: this image is a self-restart and the holder
/// is its pre-exec image, still being torn down. Wait for it to let go.
pub(super) fn reclaim(path: &Path) -> Option<File> {
    let t0 = Instant::now();
    while t0.elapsed() < WAIT {
        std::thread::sleep(Duration::from_millis(100));
        if let Claim::Held(f) = try_claim(path) {
            eprintln!("agent: took the one-agent lock back from this agent's pre-restart image after {} ms", t0.elapsed().as_millis());
            return Some(f);
        }
    }
    eprintln!("agent: this agent's pre-restart image still holds the one-agent lock after {} s; running without it", WAIT.as_secs());
    None
}
