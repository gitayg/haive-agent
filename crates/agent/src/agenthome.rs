// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

//! The agent's home, whose `.it-ai` holds its relay credential, cert and key,
//! lock, log, jobs, workspaces, schedules and update staging. Always absolute.
//!
//! HOME (else USERPROFILE) when set. Without one the home used to be the empty
//! string, so `.it-ai` was relative to the working directory: `/` for a systemd
//! or launchd service, and since 3.14.2 the agent chdirs to `/` before it loads
//! its credential, so such a device keeps everything in `/.it-ai`. That directory
//! (a real directory, ours) stays the home unless it has no relay credential and
//! the OS's home has one; nothing is ever moved, so an agent mid-update, an older
//! agent after a downgrade and the one-agent lock all keep finding the same files.
//! Otherwise the OS's home for this user (passwd entry of the effective uid; the
//! token's profile directory on Windows), and only failing that a fixed
//! directory. Worked out once per process.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub(crate) fn get() -> &'static Path {
    static HOME: OnceLock<PathBuf> = OnceLock::new();
    HOME.get_or_init(|| {
        let env = ["HOME", "USERPROFILE"].into_iter().find_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty()));
        pick(env.as_deref(), legacy_root().as_deref(), &owned, &os_home)
    })
}

pub(crate) fn pick(env: Option<&str>, legacy: Option<&Path>, owned: &dyn Fn(&Path) -> bool, os_home: &dyn Fn() -> Option<PathBuf>) -> PathBuf {
    if let Some(h) = env {
        let p = PathBuf::from(h);
        if p.is_absolute() {
            return p;
        }
        if let Ok(abs) = std::path::absolute(&p) {
            return abs;
        }
    }
    let os = os_home().filter(|h| h.is_absolute());
    let has_cred = |h: &Path| crate::relaycred::path_in(h).exists();
    if let Some(l) = legacy.filter(|l| l.is_absolute() && owned(l)) {
        if has_cred(l) || !os.as_deref().is_some_and(has_cred) {
            return l.to_path_buf();
        }
    }
    os.unwrap_or_else(fallback)
}

/// Where an agent without a home kept `.it-ai`: `/` on unix (its working
/// directory once it chdirs there), the working directory on Windows (it never does).
fn legacy_root() -> Option<PathBuf> {
    #[cfg(unix)]
    {
        Some(PathBuf::from("/"))
    }
    #[cfg(not(unix))]
    {
        std::env::current_dir().ok()
    }
}

fn owned(dir: &Path) -> bool {
    #[cfg(unix)]
    {
        owned_dir(dir, unsafe { libc::geteuid() })
    }
    #[cfg(not(unix))]
    {
        dir.join(".it-ai").is_dir()
    }
}

/// `<dir>/.it-ai` is a directory, not a link, of `euid`: one this agent made.
#[cfg(unix)]
pub(crate) fn owned_dir(dir: &Path, euid: u32) -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::symlink_metadata(dir.join(".it-ai")).is_ok_and(|m| m.is_dir() && m.uid() == euid)
}

#[cfg(unix)]
fn os_home() -> Option<PathBuf> {
    passwd_home(unsafe { libc::geteuid() })
}

#[cfg(unix)]
pub(crate) fn passwd_home(uid: libc::uid_t) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStrExt;
    let mut size = 4096;
    loop {
        let mut buf = vec![0 as libc::c_char; size];
        let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
        let mut out: *mut libc::passwd = std::ptr::null_mut();
        let rc = unsafe { libc::getpwuid_r(uid, &mut pw, buf.as_mut_ptr(), buf.len(), &mut out) };
        if rc == libc::ERANGE && size < 1 << 20 {
            size *= 2;
            continue;
        }
        if rc != 0 || out.is_null() || pw.pw_dir.is_null() {
            return None;
        }
        let dir = unsafe { std::ffi::CStr::from_ptr(pw.pw_dir) }.to_bytes();
        return (!dir.is_empty()).then(|| PathBuf::from(std::ffi::OsStr::from_bytes(dir)));
    }
}

/// The profile directory of this process's token: what Windows itself sets
/// USERPROFILE to, so a service started without its environment lands where it
/// would with one (SYSTEM: `...\System32\config\systemprofile`).
#[cfg(windows)]
fn os_home() -> Option<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::TOKEN_QUERY;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows_sys::Win32::UI::Shell::GetUserProfileDirectoryW;
    unsafe {
        let mut tok: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok) == 0 {
            return None;
        }
        let mut buf = vec![0u16; 32768];
        let mut n = buf.len() as u32;
        let ok = GetUserProfileDirectoryW(tok, buf.as_mut_ptr(), &mut n);
        CloseHandle(tok);
        let len = buf.iter().position(|&c| c == 0).unwrap_or(0);
        (ok != 0 && len > 0).then(|| PathBuf::from(std::ffi::OsString::from_wide(&buf[..len])))
    }
}

/// `/`: the `/.it-ai` every earlier agent without a home used, writable by root only.
#[cfg(unix)]
fn fallback() -> PathBuf {
    PathBuf::from("/")
}

/// SYSTEM's profile: only SYSTEM and administrators may write it, so no user can
/// plant a credential for the agent there.
#[cfg(windows)]
fn fallback() -> PathBuf {
    PathBuf::from(std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into())).join(r"System32\config\systemprofile")
}

#[cfg(test)]
mod tests;
