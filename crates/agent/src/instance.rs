// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

//! One long-running agent per user (agent 3.14.2).
//!
//! The install command used to save the agent as `./it-ai-<pid>` wherever the
//! terminal was, so running it twice left two agents of one machine competing for
//! its relay id, and an old one kept starting from a stale launchd job. The agent now
//! holds `~/.it-ai/agent.lock` (an advisory lock, holder's pid inside) while it runs:
//! - started by hand (an install command, `--background`, `--ttl`), it replaces the
//!   holder: SIGTERM, then SIGKILL after 5 s;
//! - started by launchd or systemd while another holds the lock, it exits at once,
//!   before any capture, so a restart loop costs nothing and asks for nothing.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub(crate) fn lock_path() -> PathBuf {
    PathBuf::from(crate::persistence::home()).join(".it-ai").join("agent.lock")
}

/// Who holds the lock, as far as one try can tell.
pub(crate) enum Claim {
    /// This process holds it now; keep the file open for as long as the agent runs.
    Held(File),
    /// Another process holds it; its pid when it wrote one.
    Taken(Option<u32>),
    /// The lock file could not be opened or locked (logged, not fatal).
    Unavailable(String),
}

fn open(path: &Path) -> std::io::Result<File> {
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    OpenOptions::new().read(true).write(true).create(true).truncate(false).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(path)
}

fn record_pid(mut f: &File) {
    let _ = f.set_len(0);
    let _ = f.rewind();
    let _ = write!(f, "{}", std::process::id());
    let _ = f.flush();
}

fn holder(path: &Path) -> Option<u32> {
    let mut s = String::new();
    File::open(path).ok()?.read_to_string(&mut s).ok()?;
    s.trim().parse().ok()
}

/// One attempt at the lock at `path`.
pub(crate) fn try_claim(path: &Path) -> Claim {
    let f = match open(path) {
        Ok(f) => f,
        Err(e) => return Claim::Unavailable(format!("cannot open {}: {e}", path.display())),
    };
    match f.try_lock() {
        Ok(()) => {
            record_pid(&f);
            Claim::Held(f)
        }
        Err(std::fs::TryLockError::WouldBlock) => Claim::Taken(holder(path)),
        Err(std::fs::TryLockError::Error(e)) => Claim::Unavailable(format!("cannot lock {}: {e}", path.display())),
    }
}

/// launchd starts its jobs with XPC_SERVICE_NAME = their label; systemd sets INVOCATION_ID.
fn started_by_service_manager() -> bool {
    std::env::var("XPC_SERVICE_NAME").as_deref() == Ok("com.itai.agent") || std::env::var_os("INVOCATION_ID").is_some()
}

/// Become this user's only agent, or exit (see the module doc). The returned file
/// must stay open while the agent runs; None means it runs without the lock.
pub(crate) fn claim() -> Option<File> {
    let path = lock_path();
    let pid = match try_claim(&path) {
        Claim::Held(f) => return Some(f),
        Claim::Unavailable(e) => {
            eprintln!("agent: {e}; running without the one-agent lock");
            return None;
        }
        Claim::Taken(pid) => pid,
    };
    if started_by_service_manager() {
        println!("agent: another IT-AI agent (pid {}) runs for this user; this start exits", pid.map(|p| p.to_string()).unwrap_or("?".into()));
        std::process::exit(0);
    }
    let Some(pid) = pid.filter(|p| *p != std::process::id()) else {
        eprintln!("agent: the one-agent lock is held by an unknown process; running without it");
        return None;
    };
    println!("agent: replacing the IT-AI agent already running for this user (pid {pid})");
    unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
    for i in 0..60 {
        std::thread::sleep(Duration::from_millis(100));
        if i == 50 {
            unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
        }
        if let Claim::Held(f) = try_claim(&path) {
            return Some(f);
        }
    }
    eprintln!("agent: pid {pid} did not let go of the one-agent lock; running without it");
    None
}

#[cfg(test)]
mod tests;
