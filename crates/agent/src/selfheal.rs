// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

//! The post-condition of a self-update: the launch path must end up holding the
//! new binary.
//!
//! `self_replace` renames the running exe ASIDE and then writes the new one in
//! its place. If that second step fails partway (AV grabs the file, a lock, a
//! full disk) the path is left EMPTY while the process keeps running from the
//! now-unlinked inode. The device stays up until the next reboot/logon — then
//! the launcher (scheduled task, service, autostart entry) hits
//! ERROR_FILE_NOT_FOUND (0x80070002) and the agent never comes back. That is
//! what happened on DESKTOP-JOL2MB8.
//!
//! This lives apart from `apply_update` so it can be exercised on temp files:
//! the branch that matters only runs when `self_replace` has already failed,
//! which cannot be provoked on demand against the real running binary.

use std::path::Path;

/// Make sure `exe` holds `bytes`, rewriting it if it doesn't. `replaced` is
/// whether `self_replace` reported success, and only affects what is logged.
///
/// Returns `false` if the path could not be made right. The caller must then NOT
/// exit: staying alive on the old version is the whole point, because a process
/// that exits with an empty launch path is a device that goes dark on the next
/// restart.
///
/// "Holds `bytes`" is judged by length, as `apply_update` always has. It is not
/// a content comparison; the case it guards against is a missing or truncated
/// file, which a length check catches.
pub(crate) fn ensure_installed(exe: &Path, bytes: &[u8], replaced: bool) -> bool {
    let ok_now = std::fs::metadata(exe).map(|m| m.len() as usize == bytes.len()).unwrap_or(false);
    if ok_now {
        return true;
    }
    // The path is now free (the old exe was moved aside, or was already gone),
    // so write the new binary straight to it. If the old exe is still sitting
    // there, this write fails — ETXTBSY on Linux, a sharing violation on Windows —
    // and we report failure rather than pretend.
    if !replaced {
        eprintln!("update: self_replace failed; restoring binary directly at {}", exe.display());
    }
    if std::fs::write(exe, bytes).is_err() {
        eprintln!("update: could not restore binary at {} — staying on current version", exe.display());
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(exe, std::fs::Permissions::from_mode(0o755));
    }
    true
}

#[cfg(test)]
mod tests {
    use super::ensure_installed;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const NEW: &[u8] = b"new-agent-binary-v3.5.1";

    /// A fresh empty directory per test, so parallel tests never share a path.
    fn scratch(name: &str) -> PathBuf {
        static N: AtomicUsize = AtomicUsize::new(0);
        let d = std::env::temp_dir().join(format!(
            "it-ai-selfheal-{}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst),
            name
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// The field failure: self_replace moved the old exe aside and never wrote
    /// the new one, so the launch path is empty.
    #[test]
    fn restores_a_missing_binary() {
        let d = scratch("missing");
        let exe = d.join("it-ai.exe");
        assert!(!exe.exists());

        assert!(ensure_installed(&exe, NEW, false));
        assert_eq!(std::fs::read(&exe).unwrap(), NEW);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&exe).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o755, "a restored binary the launcher cannot execute is still dead");
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A truncated or half-written file at the launch path.
    #[test]
    fn rewrites_a_wrong_sized_binary() {
        let d = scratch("truncated");
        let exe = d.join("it-ai.exe");
        std::fs::write(&exe, b"half").unwrap();

        assert!(ensure_installed(&exe, NEW, true));
        assert_eq!(std::fs::read(&exe).unwrap(), NEW);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The normal case must not touch the file. It is made read-only, so any
    /// write attempt would fail and turn `true` into `false`.
    #[test]
    fn leaves_a_correct_binary_alone() {
        let d = scratch("correct");
        let exe = d.join("it-ai.exe");
        std::fs::write(&exe, NEW).unwrap();
        let mut p = std::fs::metadata(&exe).unwrap().permissions();
        p.set_readonly(true);
        std::fs::set_permissions(&exe, p).unwrap();

        assert!(ensure_installed(&exe, NEW, true));
        assert_eq!(std::fs::read(&exe).unwrap(), NEW);

        let mut p = std::fs::metadata(&exe).unwrap().permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        p.set_readonly(false);
        let _ = std::fs::set_permissions(&exe, p);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// When the rescue itself cannot write, it must report failure so the caller
    /// stays alive rather than exiting into an empty launch path.
    #[test]
    fn reports_failure_when_it_cannot_restore() {
        let d = scratch("unwritable");
        let exe = d.join("no-such-dir").join("it-ai.exe");

        assert!(!ensure_installed(&exe, NEW, false));
        assert!(!exe.exists());
        let _ = std::fs::remove_dir_all(&d);
    }
}
