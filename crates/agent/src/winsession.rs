// Windows Session 0 isolation: a service runs as SYSTEM in session 0, walled off
// from the interactive desktop — so it can't screen-capture. We keep the service
// running normally (always connected, self-updating, exec/reports/presence all
// work) and delegate ONLY screen capture to the active user's session, on demand.
//
// Two things this got wrong before, both found the hard way on a real box:
//   * schtasks /RU <user> — fails with "No mapping between account names and
//     security IDs" on Azure AD / Microsoft-account machines (no local account to
//     resolve). We now address the session by ID via WTS, so no username is ever
//     involved.
//   * launching the installed exe directly — it can live somewhere the logged-in
//     user cannot read (e.g. C:\Users\<other>\airm.exe, ACL'd to that profile), so
//     CreateProcessAsUser fails with access-denied. We stage a copy in %PUBLIC%
//     (where INTERACTIVE has Modify) and launch that instead. The screenshot is
//     written there too, since a service's %TEMP% isn't writable by the user.
//
// Every failure returns a specific reason — an opaque bool made this near
// impossible to diagnose remotely.
#![cfg(windows)]

use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::sync::OnceLock;

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::{
    DuplicateTokenEx, SecurityImpersonation, TokenPrimary, TOKEN_ALL_ACCESS,
};
use windows_sys::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
use windows_sys::Win32::System::RemoteDesktop::{WTSGetActiveConsoleSessionId, WTSQueryUserToken};
use windows_sys::Win32::System::Threading::{
    CreateProcessAsUserW, GetExitCodeProcess, WaitForSingleObject, CREATE_NO_WINDOW,
    CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION, STARTUPINFOW,
};

/// True when we're running as SYSTEM in session 0 — a service with no access to
/// the interactive desktop. Cached (it can't change over a run).
pub fn is_session0() -> bool {
    static CACHE: OnceLock<bool> = OnceLock::new();
    *CACHE.get_or_init(|| {
        use std::os::windows::process::CommandExt;
        std::process::Command::new("whoami")
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().eq_ignore_ascii_case("nt authority\\system"))
            .unwrap_or(false)
    })
}

fn wide(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

/// Whether the workstation is locked (or sitting at the sign-in screen). LogonUI
/// owns the secure desktop in both cases, and a locked desktop has no user
/// content to capture — so this is why a capture in a live session can still fail.
/// Also surfaced in presence: "logged in" is not the same as "at the machine".
pub fn workstation_locked() -> bool {
    use std::os::windows::process::CommandExt;
    std::process::Command::new("tasklist")
        .args(["/FI", "IMAGENAME eq LogonUI.exe", "/NH"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.to_lowercase().contains("logonui.exe"))
        .unwrap_or(false)
}

fn public_dir() -> String {
    std::env::var("PUBLIC").unwrap_or_else(|_| "C:\\Users\\Public".into())
}

/// Stage a copy of ourselves somewhere the logged-in user can actually execute.
/// The installed exe may sit in another profile (ACL'd to that user), so we can't
/// launch it as them. Refreshed when our binary changes (e.g. after auto-update).
fn ensure_helper(exe: &Path, dir: &str) -> Result<String, String> {
    let helper = format!("{dir}\\haive_helper.exe");
    let stale = match (std::fs::metadata(&helper), std::fs::metadata(exe)) {
        (Ok(h), Ok(e)) => h.len() != e.len(),
        _ => true,
    };
    if stale {
        // A copy can fail if a previous helper is still running; fall back to the
        // existing one if it's there.
        if let Err(e) = std::fs::copy(exe, &helper) {
            if !Path::new(&helper).exists() {
                return Err(format!("staging helper to {helper} failed: {e}"));
            }
        }
    }
    Ok(helper)
}

/// Grab one screen frame from the active user's session and return the JPEG, or a
/// reason it couldn't. The caller stays online regardless — only this screenshot
/// fails.
pub fn capture_once() -> Result<Vec<u8>, String> {
    // A locked desktop has nothing to capture — say so plainly instead of
    // spawning a helper that can only fail.
    if workstation_locked() {
        return Err("workstation is locked — unlock the screen to capture".into());
    }
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let dir = public_dir();
    let helper = ensure_helper(&exe, &dir)?;
    let shot = format!("{dir}\\haive_shot.jpg");
    let _ = std::fs::remove_file(&shot);

    let cmdline = format!("\"{helper}\" --capture-once \"{shot}\"");
    unsafe { run_in_active_session(&cmdline) }.map_err(|e| {
        // It can lock between the check and the grab.
        if workstation_locked() {
            "workstation is locked — unlock the screen to capture".to_string()
        } else {
            e
        }
    })?;

    let bytes = std::fs::read(&shot).map_err(|e| format!("helper produced no frame ({e})"))?;
    let _ = std::fs::remove_file(&shot);
    if bytes.is_empty() {
        return Err("helper produced an empty frame".into());
    }
    Ok(bytes)
}

/// Run `cmdline` inside the active console session, waiting (bounded) for it to
/// exit. Addresses the session by ID — no username, so Azure AD / MSA is fine.
unsafe fn run_in_active_session(cmdline: &str) -> Result<(), String> {
    let session = WTSGetActiveConsoleSessionId();
    if session == u32::MAX {
        return Err("no active console session".into());
    }
    let mut token: HANDLE = std::ptr::null_mut();
    if WTSQueryUserToken(session, &mut token) == 0 || token.is_null() || token == INVALID_HANDLE_VALUE {
        return Err(format!("no interactive user in session {session} (nobody logged in?) [err {}]", GetLastError()));
    }

    let mut primary: HANDLE = std::ptr::null_mut();
    let dup = DuplicateTokenEx(token, TOKEN_ALL_ACCESS, std::ptr::null(), SecurityImpersonation, TokenPrimary, &mut primary);
    CloseHandle(token);
    if dup == 0 || primary.is_null() {
        return Err(format!("DuplicateTokenEx failed [err {}]", GetLastError()));
    }

    let mut env: *mut std::ffi::c_void = std::ptr::null_mut();
    let have_env = CreateEnvironmentBlock(&mut env, primary, 0) != 0;

    let mut si: STARTUPINFOW = std::mem::zeroed();
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut desktop = wide("winsta0\\default");
    si.lpDesktop = desktop.as_mut_ptr();
    let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
    let mut cl = wide(cmdline);

    let started = CreateProcessAsUserW(
        primary,
        std::ptr::null(),
        cl.as_mut_ptr(),
        std::ptr::null(),
        std::ptr::null(),
        0,
        CREATE_NO_WINDOW | if have_env { CREATE_UNICODE_ENVIRONMENT } else { 0 },
        if have_env { env } else { std::ptr::null_mut() },
        std::ptr::null(),
        &si,
        &mut pi,
    );
    let spawn_err = GetLastError();

    let mut result = Ok(());
    if started != 0 {
        WaitForSingleObject(pi.hProcess, 15_000);
        let mut code: u32 = 1;
        GetExitCodeProcess(pi.hProcess, &mut code);
        if code != 0 {
            result = Err(format!("helper exited {code} (capture failed in session {session})"));
        }
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    } else {
        // 5 = ACCESS_DENIED, typically the exe being unreadable by that user.
        result = Err(format!("CreateProcessAsUser failed [err {spawn_err}]"));
    }
    if have_env {
        DestroyEnvironmentBlock(env);
    }
    CloseHandle(primary);
    result
}
