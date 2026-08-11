// IT-AI — LAN remote control & screen sharing with an AI/MCP interface.
// Copyright (C) 2026 The IT-AI Authors.
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Native OPERATING-SYSTEM update check + install via the Windows Update Agent
// (WUA) COM API — NOT PowerShell, NOT winget. winget manages *applications*;
// the WUA (`Microsoft.Update.Session`, wuapi.dll) is the only interface that
// enumerates and installs actual OS patches (cumulative updates, servicing
// stack, .NET, driver, and definition updates), which is what this module does.
//
// Declared with `#[cfg(windows)] mod winupdate;` in main.rs; the inner
// `#![cfg(windows)]` compiles the whole file to nothing on non-Windows targets,
// exactly like winprobe.rs. The wiring in http.rs (the `it-ai:os-updates/*`
// sentinels) is what the mac/linux builds exercise — those builds never call
// into this file.
//
// House rules mirrored from winprobe.rs:
//   * Every fallible call is `?`/`.ok()`/`match` — this module NEVER panics or
//     unwraps. On any COM/WUA failure a probe returns a short, human-readable
//     "unavailable (…)" / "access denied …" string instead.
//   * COM is initialised and torn down per call on the *calling* thread (the
//     transient tiny_http /exec worker), balanced by a drop guard, so it never
//     clashes with the tao/wry/tray STA init that runs on a different thread.
//
// WUA is CLASSIC COM (wuapi type library), not WinRT. We therefore CoInitializeEx
// the worker thread, CoCreateInstance the `UpdateSession` coclass, and drive the
// `windows` crate's `Win32::System::UpdateAgent` interfaces
// (IUpdateSession / IUpdateSearcher / ISearchResult / IUpdateCollection /
// IUpdate / IUpdateDownloader / IUpdateInstaller / IInstallationResult).
//
// RUNTIME-VALIDATION RISK — must be confirmed on a real Windows box:
//   1. ELEVATION. Download() and especially Install() require the process to run
//      elevated (Administrator / SYSTEM). A non-elevated caller gets
//      E_ACCESSDENIED (0x80070005) — we DETECT that HRESULT and report
//      "access denied — needs Administrator", never a silent failure.
//   2. `windows`-crate WUA coverage. The interfaces used here live behind the
//      `Win32_System_UpdateAgent` feature (verified present in windows 0.56–0.62;
//      this code was written against the 0.59 bindings already in the tree via
//      `wmi`). If a future bump drops or renames that module, the fallback is to
//      declare the vtables by hand with `windows_core`'s `#[interface]` macro —
//      flagged here as the single biggest integration risk.
#![cfg(windows)]

use windows::core::BSTR;
use windows::Win32::Foundation::{DECIMAL, VARIANT_BOOL};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
};
use windows::Win32::System::UpdateAgent::{
    IUpdate, IUpdateCollection, IUpdateInstaller, IUpdateSession, OperationResultCode,
    UpdateCollection, UpdateSession,
};

/// The exact search criteria the WUA online searcher understands: not-installed,
/// genuine *software* OS updates (excludes the separate "Driver" type), and not
/// hidden by an admin. This is the canonical "what OS patches am I missing?"
/// query and mirrors what `check_updates`/`softwareupdate -l` surface on the
/// other platforms so the hub can render all three uniformly.
const SEARCH_CRITERIA: &str = "IsInstalled=0 AND Type='Software' AND IsHidden=0";

/// Identifies us to the Windows Update service in its logs (best-effort cosmetic).
const CLIENT_ID: &str = "IT-AI Agent";

/// E_ACCESSDENIED — the HRESULT a non-elevated caller hits on Download/Install
/// (and sometimes on the online Search). Surfaced as a clear "needs Administrator"
/// message rather than a raw hex code.
const E_ACCESSDENIED: i32 = 0x8007_0005u32 as i32;

/// RPC_E_CHANGED_MODE — CoInitializeEx was already called on this thread with a
/// different apartment model (e.g. the GUI thread went STA). Not fatal: COM is
/// usable, we simply must NOT balance it with a CoUninitialize we don't own.
const RPC_E_CHANGED_MODE: i32 = 0x8001_0106u32 as i32;

/// Balances a successful CoInitializeEx with CoUninitialize on drop — but ONLY
/// when this guard actually performed the initialisation. When COM was already
/// live on the thread (RPC_E_CHANGED_MODE) `owned` is false and drop is a no-op,
/// so we never tear down an apartment another subsystem owns.
struct ComGuard {
    owned: bool,
}

impl ComGuard {
    /// Initialise COM (MTA) for this worker thread. Returns a guard on success,
    /// or a short "unavailable" string if COM could not be brought up at all.
    fn enter() -> Result<ComGuard, String> {
        // SAFETY: CoInitializeEx on the current thread; the returned HRESULT is
        // inspected rather than assumed. S_OK / S_FALSE (already-init, same mode)
        // are success; RPC_E_CHANGED_MODE means "already up in another mode" —
        // usable but not ours to uninitialise; anything else is a hard failure.
        let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        if hr.is_ok() {
            Ok(ComGuard { owned: true })
        } else if hr.0 == RPC_E_CHANGED_MODE {
            Ok(ComGuard { owned: false })
        } else {
            Err(format!(
                "unavailable (CoInitializeEx failed, HRESULT 0x{:08X})",
                hr.0 as u32
            ))
        }
    }
}

impl Drop for ComGuard {
    fn drop(&mut self) {
        if self.owned {
            // SAFETY: balances exactly one successful CoInitializeEx made by this
            // same guard on this same thread.
            unsafe { CoUninitialize() };
        }
    }
}

/// Turn a `windows_core::Error` into a short, user-facing reason, calling out the
/// elevation case explicitly (the most common real-world failure for OS-update
/// download/install) so the hub can tell the admin to relaunch elevated.
fn reason(ctx: &str, e: &windows::core::Error) -> String {
    let code = e.code().0;
    if code == E_ACCESSDENIED {
        format!("{ctx}: access denied — needs Administrator (run the agent elevated)")
    } else {
        format!("{ctx}: unavailable (HRESULT 0x{:08X})", code as u32)
    }
}

/// A WUA `VARIANT_BOOL` is true when non-zero (VARIANT_TRUE is -1). No panic path.
fn vbool(v: VARIANT_BOOL) -> bool {
    v.0 != 0
}

/// Best-effort byte count from an update's `MaxDownloadSize` (a COM `DECIMAL`).
/// Download sizes are non-negative integers (scale 0), so we fold the 96-bit
/// mantissa (Hi32 : Lo64) into a u128 and ignore scale/sign. Never panics; on any
/// oddity the reader simply yields a possibly-imprecise value we then format.
fn decimal_bytes(d: &DECIMAL) -> u128 {
    // SAFETY: reading the union's 64-bit view is always valid for an initialised
    // DECIMAL; the two representations alias the same 8 bytes.
    let lo64 = unsafe { d.Anonymous2.Lo64 } as u128;
    ((d.Hi32 as u128) << 64) | lo64
}

/// Human-friendly size, e.g. `842.0 MB`. Keeps the check output compact.
fn human_size(bytes: u128) -> String {
    const KB: u128 = 1024;
    const MB: u128 = KB * 1024;
    const GB: u128 = MB * 1024;
    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}

/// Map WUA's `OperationResultCode` to a short label for the install summary.
fn result_label(code: OperationResultCode) -> &'static str {
    match code.0 {
        0 => "not started",
        1 => "in progress",
        2 => "succeeded",
        3 => "succeeded with errors",
        4 => "failed",
        5 => "aborted",
        _ => "unknown",
    }
}

/// Create a `Microsoft.Update.Session` (the `UpdateSession` coclass) and stamp our
/// client id. COM must already be initialised on this thread (hold a `ComGuard`).
fn new_session() -> Result<IUpdateSession, String> {
    // SAFETY: CoCreateInstance against the WUA UpdateSession CLSID, in-proc; the
    // Result is checked, never unwrapped.
    let session: IUpdateSession =
        unsafe { CoCreateInstance(&UpdateSession, None, CLSCTX_INPROC_SERVER) }
            .map_err(|e| reason("create UpdateSession", &e))?;
    // Cosmetic only; a failure here must not abort the operation.
    let _ = unsafe { session.SetClientApplicationID(&BSTR::from(CLIENT_ID)) };
    Ok(session)
}

// ── check ──────────────────────────────────────────────────────────────────────

/// List the OS updates the machine is missing, via the WUA online searcher.
///
/// Flow: `UpdateSession` → `CreateUpdateSearcher()` → `Search("IsInstalled=0 AND
/// Type='Software' AND IsHidden=0")` → enumerate the returned `IUpdateCollection`,
/// formatting each update's Title, security flag, and download size.
///
/// The `Search` call contacts Windows Update (or WSUS, if the box is managed) and
/// can take several seconds — the caller's /exec path already bounds the request,
/// so this returns whatever the search yields. Returns:
///   * a formatted list when updates are found,
///   * "No OS updates available." when the machine is up to date,
///   * a precise "unavailable (…)" / "access denied …" line on any COM failure.
/// Never panics.
pub fn check_updates() -> String {
    let _com = match ComGuard::enter() {
        Ok(g) => g,
        Err(msg) => return format!("OS updates: {msg}"),
    };
    match check_updates_inner() {
        Ok(s) => s,
        Err(msg) => format!("OS updates: {msg}"),
    }
}

/// Inner check that can use `?`; all errors are already reason-formatted strings.
fn check_updates_inner() -> Result<String, String> {
    let session = new_session()?;

    // SAFETY: each WUA call below returns a checked Result; nothing is unwrapped.
    let searcher = unsafe { session.CreateUpdateSearcher() }
        .map_err(|e| reason("create searcher", &e))?;

    let search_result = unsafe { searcher.Search(&BSTR::from(SEARCH_CRITERIA)) }
        .map_err(|e| reason("search", &e))?;

    let updates: IUpdateCollection =
        unsafe { search_result.Updates() }.map_err(|e| reason("read results", &e))?;

    let count = unsafe { updates.Count() }.map_err(|e| reason("count updates", &e))?;
    if count <= 0 {
        return Ok("No OS updates available.".to_string());
    }

    let mut lines: Vec<String> =
        vec![format!("{count} OS update(s) available (via Windows Update Agent):")];
    let mut security = 0i32;
    for i in 0..count {
        let update: IUpdate = match unsafe { updates.get_Item(i) } {
            Ok(u) => u,
            // Skip a single unreadable row rather than aborting the whole list.
            Err(_) => continue,
        };
        let title = unsafe { update.Title() }
            .map(|b| b.to_string())
            .unwrap_or_else(|_| "(untitled update)".to_string());

        // MsrcSeverity is non-empty only for security updates (e.g. "Critical").
        let severity = unsafe { update.MsrcSeverity() }
            .map(|b| b.to_string())
            .unwrap_or_default();
        let is_security = !severity.trim().is_empty();
        if is_security {
            security += 1;
        }

        let size = unsafe { update.MaxDownloadSize() }
            .map(|d| human_size(decimal_bytes(&d)))
            .unwrap_or_else(|_| "size unknown".to_string());

        let sec_tag = if is_security {
            format!(" [security: {}]", severity.trim())
        } else {
            String::new()
        };
        lines.push(format!("  - {title} ({size}){sec_tag}"));
    }
    lines.push(format!(
        "Summary: {count} update(s), {security} security update(s)."
    ));
    Ok(lines.join("\n"))
}

// ── install ─────────────────────────────────────────────────────────────────────

/// Download and install every OS update the searcher finds, via the WUA.
///
/// Flow: search (same criteria as [`check_updates`]) → build an `UpdateCollection`
/// of the results (accepting each EULA where required) → `IUpdateDownloader`
/// (`Download`) → `IUpdateInstaller` (`Install`) → report the overall result code,
/// per-update reboot requirement, and whether a reboot is pending
/// (`IInstallationResult::RebootRequired`).
///
/// REQUIRES ELEVATION: Download and Install fail with E_ACCESSDENIED for a
/// non-elevated process — that case is reported as "access denied — needs
/// Administrator", not swallowed. Returns a human-readable summary. Never panics.
pub fn install_updates() -> String {
    let _com = match ComGuard::enter() {
        Ok(g) => g,
        Err(msg) => return format!("OS update install: {msg}"),
    };
    match install_updates_inner() {
        Ok(s) => s,
        Err(msg) => format!("OS update install: {msg}"),
    }
}

/// Inner install that can use `?`; all errors are already reason-formatted.
fn install_updates_inner() -> Result<String, String> {
    let session = new_session()?;

    let searcher = unsafe { session.CreateUpdateSearcher() }
        .map_err(|e| reason("create searcher", &e))?;
    let search_result = unsafe { searcher.Search(&BSTR::from(SEARCH_CRITERIA)) }
        .map_err(|e| reason("search", &e))?;
    let found: IUpdateCollection =
        unsafe { search_result.Updates() }.map_err(|e| reason("read results", &e))?;
    let count = unsafe { found.Count() }.map_err(|e| reason("count updates", &e))?;
    if count <= 0 {
        return Ok("No OS updates to install.".to_string());
    }

    // Build a fresh UpdateCollection holding the updates we intend to act on,
    // accepting each per-update EULA (unattended installs stall otherwise).
    let to_install: IUpdateCollection =
        unsafe { CoCreateInstance(&UpdateCollection, None, CLSCTX_INPROC_SERVER) }
            .map_err(|e| reason("create update collection", &e))?;

    let mut titles: Vec<String> = Vec::new();
    for i in 0..count {
        let update: IUpdate = match unsafe { found.get_Item(i) } {
            Ok(u) => u,
            Err(_) => continue,
        };
        // Accept the EULA if one is attached and not yet accepted; a failure here
        // is non-fatal — the update simply may be skipped by the installer.
        if let Ok(accepted) = unsafe { update.EulaAccepted() } {
            if !vbool(accepted) {
                let _ = unsafe { update.AcceptEula() };
            }
        }
        titles.push(
            unsafe { update.Title() }
                .map(|b| b.to_string())
                .unwrap_or_else(|_| "(untitled update)".to_string()),
        );
        // SAFETY: Add borrows the update into the collection; Result is checked.
        let _ = unsafe { to_install.Add(&update) }.map_err(|e| reason("queue update", &e))?;
    }

    let queued = unsafe { to_install.Count() }.unwrap_or(0);
    if queued <= 0 {
        return Ok("No installable OS updates after filtering.".to_string());
    }

    // ── Download ────────────────────────────────────────────────────────────
    let downloader =
        unsafe { session.CreateUpdateDownloader() }.map_err(|e| reason("create downloader", &e))?;
    unsafe { downloader.SetUpdates(&to_install) }.map_err(|e| reason("set download list", &e))?;
    let download_result =
        unsafe { downloader.Download() }.map_err(|e| reason("download", &e))?;
    let dl_code = unsafe { download_result.ResultCode() }.unwrap_or(OperationResultCode(-1));

    // ── Install ─────────────────────────────────────────────────────────────
    let installer: IUpdateInstaller =
        unsafe { session.CreateUpdateInstaller() }.map_err(|e| reason("create installer", &e))?;
    unsafe { installer.SetUpdates(&to_install) }.map_err(|e| reason("set install list", &e))?;
    let install_result =
        unsafe { installer.Install() }.map_err(|e| reason("install", &e))?;

    let overall = unsafe { install_result.ResultCode() }.unwrap_or(OperationResultCode(-1));
    let reboot = unsafe { install_result.RebootRequired() }
        .map(vbool)
        .unwrap_or(false);

    // Per-update outcome, in the same order they were queued.
    let mut lines: Vec<String> = vec![format!(
        "OS update install: {queued} queued — download {}, install {}.",
        result_label(dl_code),
        result_label(overall),
    )];
    for (i, title) in titles.iter().enumerate() {
        let idx = i as i32;
        let (label, per_reboot) = match unsafe { install_result.GetUpdateResult(idx) } {
            Ok(r) => {
                let code = unsafe { r.ResultCode() }.unwrap_or(OperationResultCode(-1));
                let rb = unsafe { r.RebootRequired() }.map(vbool).unwrap_or(false);
                (result_label(code).to_string(), rb)
            }
            Err(_) => ("no result".to_string(), false),
        };
        let rb_tag = if per_reboot { " (reboot required)" } else { "" };
        lines.push(format!("  - {title}: {label}{rb_tag}"));
    }
    lines.push(if reboot {
        "Reboot required to finish installation.".to_string()
    } else {
        "No reboot required.".to_string()
    });
    Ok(lines.join("\n"))
}
