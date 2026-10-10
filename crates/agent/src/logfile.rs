// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

//! `~/.it-ai/agent.log`: where a `--background` or launchd-started agent's
//! stdout/stderr land, so "it just vanished" is always answerable.
//!
//! Two kinds of writer can hold it open: the `--background` relaunch (our own
//! `O_APPEND` handle) and launchd (`StandardOutPath`/`StandardErrorPath`, which it
//! also opens `O_APPEND` — measured with `F_GETFL` on a scratch job). Appenders
//! interleave whole writes and never clobber each other, so the only thing that
//! has to be careful is trimming: see `cap`.

use std::fs::OpenOptions;
use std::path::{Path, PathBuf};

/// Past this the log is emptied at the next start, so an agent that restart-loops
/// for months can't fill the disk.
const MAX_LEN: u64 = 1_000_000;

pub(crate) fn path_in(home: &Path) -> PathBuf {
    home.join(".it-ai").join("agent.log")
}

/// Create the log's directory (0700) and the file (0600) before anything opens it.
/// launchd creates a missing `StandardOutPath` itself, but as 0644 inside a 0744
/// directory (measured); a file that already exists keeps its mode when launchd
/// opens it, so the installer makes both first. Also trims an oversized log.
pub(crate) fn prepare(path: &Path) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    let mut o = OpenOptions::new();
    o.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)?;
    // `.mode()` only applies when open(2) creates the file.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    cap(path);
    Ok(())
}

/// Send a child's stdout and stderr to the log, appending (prepared as above:
/// owner-only, capped), or to null when it cannot be opened. Used by the
/// `--background` relaunch and by the Windows restart after a self-update.
pub(crate) fn redirect(c: &mut std::process::Command, path: &Path) {
    let open = || OpenOptions::new().append(true).open(path).ok();
    match prepare(path).ok().and_then(|_| Some((open()?, open()?))) {
        Some((out, err)) => {
            c.stdout(out).stderr(err);
        }
        None => {
            c.stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
        }
    }
}

/// Empty the log IN PLACE once it passes `MAX_LEN`. Truncate, never unlink: a
/// launchd-started agent writes through an fd launchd opened, so removing the path
/// would send that agent's output to an orphaned inode until its next restart, and
/// launchd would then recreate the file 0644. Every writer is `O_APPEND`, so after
/// a truncate each one simply continues at the new end of file.
pub(crate) fn cap(path: &Path) {
    if std::fs::metadata(path).map(|m| m.len() > MAX_LEN).unwrap_or(false) {
        if let Ok(f) = OpenOptions::new().write(true).open(path) {
            let _ = f.set_len(0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("it-ai-logfile-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[cfg(unix)]
    fn mode(p: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    /// The installer makes the dir 0700 and the file 0600, and tightens a log an
    /// older `--background` run left world-readable.
    #[cfg(unix)]
    #[test]
    fn prepare_creates_owner_only_dir_and_file() {
        use std::os::unix::fs::PermissionsExt;
        let home = scratch("perm");
        let log = path_in(&home);
        prepare(&log).unwrap();
        assert!(log.exists());
        assert_eq!(mode(log.parent().unwrap()), 0o700, "log dir");
        assert_eq!(mode(&log), 0o600, "log file");

        std::fs::set_permissions(&log, std::fs::Permissions::from_mode(0o644)).unwrap();
        prepare(&log).unwrap();
        assert_eq!(mode(&log), 0o600, "an existing 0644 log must be tightened");
        let _ = std::fs::remove_dir_all(&home);
    }

    /// Trimming must keep the SAME file: a writer that already holds it open (the
    /// launchd case) has to keep logging into the file at the path, from offset 0,
    /// not into an unlinked inode.
    #[cfg(unix)]
    #[test]
    fn cap_truncates_in_place_so_an_open_writer_keeps_logging() {
        use std::io::Write;
        use std::os::unix::fs::MetadataExt;
        let home = scratch("cap");
        let log = path_in(&home);
        prepare(&log).unwrap();
        // Stand-in for launchd's handle: opened before the trim, O_APPEND.
        let mut held = OpenOptions::new().append(true).open(&log).unwrap();
        held.write_all(&vec![b'x'; MAX_LEN as usize + 1]).unwrap();
        let ino = std::fs::metadata(&log).unwrap().ino();

        cap(&log);

        assert_eq!(std::fs::metadata(&log).unwrap().ino(), ino, "cap must not replace the file");
        held.write_all(b"after\n").unwrap();
        assert_eq!(std::fs::read(&log).unwrap(), b"after\n", "the open writer must continue at the new end");
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn cap_leaves_a_small_log_alone() {
        let home = scratch("small");
        let log = path_in(&home);
        prepare(&log).unwrap();
        std::fs::write(&log, b"keep me\n").unwrap();
        cap(&log);
        assert_eq!(std::fs::read(&log).unwrap(), b"keep me\n");
        let _ = std::fs::remove_dir_all(&home);
    }
}
