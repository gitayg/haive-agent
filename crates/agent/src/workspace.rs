// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

//! Throwaway job workspaces (agent 3.16.0): `/jobs/start {"workspace": true}` runs the
//! job in a fresh `~/.it-ai/workspaces/<job id>/` (owner-only on unix; on Windows it
//! inherits the data dir's ACL) and the tree is removed when the job's process exits.
//! A tree that cannot be removed in a few tries (Windows: a still-running grandchild
//! holds a file or its working directory open) is left for the startup sweep, which
//! removes anything in `workspaces/` older than 24 h.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

pub const SWEEP_AGE: Duration = Duration::from_secs(24 * 3600);
const REMOVE_TRIES: u32 = 10;
const REMOVE_PAUSE: Duration = Duration::from_millis(200);

pub fn root() -> PathBuf {
    PathBuf::from(crate::persistence::home()).join(".it-ai").join("workspaces")
}

/// `<root>/<id>`, created new: an existing directory of that name is an error, never reused.
pub fn create(root: &Path, id: &str) -> std::io::Result<PathBuf> {
    let mut b = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.recursive(true).create(root)?;
    let dir = root.join(id);
    b.recursive(false).create(&dir)?;
    Ok(dir)
}

/// Remove `dir` and everything under it, never through a link. True when it is gone.
pub fn remove(dir: &Path) -> bool {
    for i in 0..REMOVE_TRIES {
        match std::fs::remove_dir_all(dir) {
            Ok(()) => return true,
            Err(e) if e.kind() == ErrorKind::NotFound => return true,
            Err(_) => {
                // Read-only entries (git objects on Windows, a Go module cache on unix)
                // refuse deletion until they are writable again.
                if i == 0 {
                    make_writable(dir);
                }
                if i + 1 < REMOVE_TRIES {
                    std::thread::sleep(REMOVE_PAUSE);
                }
            }
        }
    }
    false
}

fn make_writable(p: &Path) {
    let Ok(md) = p.symlink_metadata() else { return };
    if md.file_type().is_symlink() {
        return;
    }
    let mut perm = md.permissions();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        perm.set_mode(perm.mode() | if md.is_dir() { 0o700 } else { 0o600 });
    }
    #[cfg(not(unix))]
    perm.set_readonly(false);
    let _ = std::fs::set_permissions(p, perm);
    if md.is_dir() {
        if let Ok(rd) = std::fs::read_dir(p) {
            for e in rd.flatten() {
                make_writable(&e.path());
            }
        }
    }
}

/// Remove every entry of `root` last modified more than `older_than` ago. Returns how many went.
pub fn sweep(root: &Path, older_than: Duration) -> usize {
    let Ok(rd) = std::fs::read_dir(root) else { return 0 };
    let now = SystemTime::now();
    let mut n = 0;
    for e in rd.flatten() {
        let p = e.path();
        let Ok(md) = p.symlink_metadata() else { continue };
        let old = md.modified().ok().and_then(|m| now.duration_since(m).ok()).is_some_and(|a| a > older_than);
        if !old {
            continue;
        }
        let gone = if md.is_dir() { remove(&p) } else { std::fs::remove_file(&p).is_ok() };
        if gone {
            n += 1;
        }
    }
    n
}

/// The startup sweep, off the main thread: a big leftover tree must not delay the agent.
pub fn sweep_at_startup() {
    std::thread::spawn(|| {
        let n = sweep(&root(), SWEEP_AGE);
        if n > 0 {
            eprintln!("removed {n} job workspace(s) older than 24 h");
        }
    });
}

#[cfg(test)]
mod tests;
