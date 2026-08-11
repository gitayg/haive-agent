// IT-AI — LAN remote control & screen sharing with an AI/MCP interface.
// Copyright (C) 2026 The IT-AI Authors.
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// On-demand `winget` bootstrap for the Windows endpoint agent, done with the
// NATIVE Windows AppX deployment API (WinRT `PackageManager`) — NO PowerShell,
// no `Add-AppxPackage`, no child processes beyond the `winget --version`
// presence probe. Declared with `#[cfg(windows)] mod winbootstrap;` in main.rs;
// the inner `#![cfg(windows)]` makes the whole file compile to nothing on the
// mac/linux targets, exactly like winprobe.rs.
//
// WHY THIS EXISTS
// `winget` (the "App Installer" package, family
// `Microsoft.DesktopAppInstaller_8wekyb3d8bbwe`) ships with client Windows but
// is frequently missing or unregistered on: freshly-imaged machines, Windows
// Server, LTSC/IoT SKUs, and profiles where the per-user registration never
// ran. When the hub asks the agent to run a `winget ...` command we first try
// to make winget available, cheaply and WITHOUT elevation.
//
// PER-USER, NO ELEVATION — the design constraint
// Every deployment call here is a PER-USER operation:
//   * `RegisterPackageByFamilyNameAsync` registers an already-staged
//     (provisioned-but-unregistered) package into the CURRENT user's profile.
//   * `AddPackageAsync` installs a downloaded `.msixbundle` for the CURRENT
//     user only.
// Neither needs administrator rights or the `runFullTrust`/provisioning path
// that `Add-AppxProvisionedPackage` (all-users) would. The IT-AI agent runs in
// the interactive user's session (see the Session-0 delegation note in
// Cargo.toml / winprobe.rs), so a per-user install is both sufficient to make
// `winget` runnable for that session and the only thing we can do without a
// UAC prompt. That is the deliberate trade-off: we make winget work for the
// logged-in user, not machine-wide.
//
// ERROR TOLERANCE
// Matches winprobe.rs: no `unwrap`/`expect` on any external (WinRT / network /
// filesystem / process) call, no panics. Every fallible step maps its error to
// a short string; `ensure_winget` always returns a PRECISE `Err` describing the
// most likely cause (Server/LTSC without the AppX runtime, a missing
// VCLibs/UI.Xaml dependency, or the raw HRESULT + error text) rather than a
// silent/empty failure.
#![cfg(windows)]

use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};

/// CREATE_NO_WINDOW — keep the `winget --version` probe from flashing a console
/// window on an interactive desktop. (Same constant the /exec capture path uses
/// in http.rs.)
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// The App Installer package family name. Stable, published by Microsoft; this
/// single identity covers winget, the `winget` app-execution alias, and the
/// MSIX manifest we register/add.
const APP_INSTALLER_FAMILY: &str = "Microsoft.DesktopAppInstaller_8wekyb3d8bbwe";

/// Microsoft's stable short link that 302-redirects to the latest App Installer
/// `.msixbundle`. `ureq` follows redirects by default, so a plain GET lands on
/// the bundle.
const GETWINGET_URL: &str = "https://aka.ms/getwinget";

/// True if `winget` is runnable right now.
///
/// We shell out to `winget --version` (with CREATE_NO_WINDOW and all stdio sent
/// to NUL) and treat a zero exit as "present". This is the ground truth the
/// caller actually cares about — whether the *alias* resolves on this process's
/// PATH — which a WinRT "is the package registered?" query can't fully confirm
/// (the app-execution alias lives under `%LOCALAPPDATA%\Microsoft\WindowsApps`
/// and may lag registration within a single process's environment block).
/// Never panics: any spawn/IO error collapses to `false`.
pub fn have_winget() -> bool {
    Command::new("winget")
        .arg("--version")
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Ensure `winget` is available for the current user, bootstrapping it on demand.
///
/// Ordered from cheapest/least-invasive to most:
///   1. Already present → nothing to do.
///   2. Re-REGISTER an already-provisioned-but-unregistered App Installer into
///      this user's profile via `RegisterPackageByFamilyNameAsync`. This is the
///      common case on freshly-imaged machines: the payload is staged
///      machine-wide but the per-user registration never ran. No download, no
///      elevation.
///   3. If still absent, DOWNLOAD the App Installer bundle from `aka.ms/getwinget`
///      into `%TEMP%` and install it for this user via `AddPackageAsync`.
///   4. Otherwise fail with a PRECISE reason.
///
/// Returns `Ok(<what happened>)` on success, `Err(<precise reason>)` otherwise.
/// Never panics.
pub fn ensure_winget() -> Result<String, String> {
    // 1 — fast path.
    if have_winget() {
        return Ok("winget already present".to_string());
    }

    // If the AppX runtime itself is unreachable there's no point attempting
    // either deployment call — this is the Server-Core / LTSC / IoT signature.
    // Probing it up front lets us give a precise diagnosis instead of two
    // confusing WinRT errors.
    let appx_runtime = appx_runtime_available();

    // 2 — try to re-register a staged-but-unregistered App Installer.
    let mut register_err: Option<String> = None;
    if appx_runtime {
        match register_app_installer() {
            Ok(deployed_ok) => {
                if have_winget() || deployed_ok {
                    return Ok("re-registered App Installer for this user".to_string());
                }
            }
            Err(e) => register_err = Some(e),
        }
    }

    // 3 — download the bundle and install it for this user.
    let mut install_err: Option<String> = None;
    if appx_runtime {
        match install_app_installer() {
            Ok(deployed_ok) => {
                if have_winget() || deployed_ok {
                    return Ok("installed App Installer".to_string());
                }
                // Deployment reported success-ish but winget still doesn't run:
                // usually the app-execution alias is not yet on THIS process's
                // PATH. Surface it rather than pretending we failed hard.
                install_err.get_or_insert_with(|| {
                    "App Installer deployed but `winget` is not yet on PATH for this \
                     process — a new session / PATH refresh is required"
                        .to_string()
                });
            }
            Err(e) => install_err = Some(e),
        }
    }

    // 4 — precise failure.
    Err(compose_failure(appx_runtime, register_err, install_err))
}

/// Best-effort probe: can we construct a `PackageManager` at all?
///
/// On Windows Server without the "App Installer"/AppX runtime, on Server Core,
/// and on some stripped LTSC/IoT images, the WinRT deployment activation fails
/// here. A `false` return is our strongest signal for the "no AppX runtime"
/// diagnosis in `compose_failure`.
fn appx_runtime_available() -> bool {
    windows::Management::Deployment::PackageManager::new().is_ok()
}

/// Register the App Installer for the current user by package family name.
///
/// `RegisterPackageByFamilyNameAsync(family, dependencyFamilyNames, options)`:
///   * `family` — the App Installer family name.
///   * dependency family names — `None`; the staged main package already
///     carries its framework dependencies, so we don't enumerate them.
///   * options — `DeploymentOptions::default()` (no force-shutdown, no dev
///     mode); registration is non-destructive.
///
/// The call returns an `IAsyncOperationWithProgress<DeploymentResult,
/// DeploymentProgress>`; `.get()` blocks the calling thread until it completes
/// and yields the `DeploymentResult`, whose `ExtendedErrorCode` is the real
/// success/failure verdict (a completed async op can still carry a failing
/// HRESULT). Returns `Ok(true)` when the deployment HRESULT is success.
fn register_app_installer() -> Result<bool, String> {
    use windows::core::HSTRING;
    use windows::Foundation::Collections::IIterable;
    use windows::Management::Deployment::{DeploymentOptions, PackageManager, PackageVolume};

    let pm = PackageManager::new().map_err(|e| format!("PackageManager init failed: {e}"))?;
    let family = HSTRING::from(APP_INSTALLER_FAMILY);

    // windows 0.59 exposes this as RegisterPackageByFamilyNameAndOptionalPackagesAsync
    // (5 args): no dependency families, default options, no app-data volume, no
    // optional packages. Optional WinRT params are passed as typed `None`.
    let op = pm
        .RegisterPackageByFamilyNameAndOptionalPackagesAsync(
            &family,
            None::<&IIterable<HSTRING>>,
            DeploymentOptions::default(),
            None::<&PackageVolume>,
            None::<&IIterable<HSTRING>>,
        )
        .map_err(|e| format!("RegisterPackageByFamilyName… call failed: {e}"))?;
    let result = op
        .get()
        .map_err(|e| format!("awaiting registration failed: {e}"))?;

    deployment_verdict(&result, "registration")
}

/// Download the App Installer bundle and install it for the current user.
///
/// `AddPackageAsync(packageUri, dependencyUris, options)`:
///   * `packageUri` — a `file://` `Windows.Foundation.Uri` pointing at the
///     downloaded `.msixbundle` in `%TEMP%`.
///   * dependency URIs — `None`. Most machines already carry the framework
///     dependencies (`Microsoft.VCLibs.140.00.UWPDesktop`,
///     `Microsoft.UI.Xaml.*`); if one is genuinely missing the call fails with
///     a dependency HRESULT, which `deployment_verdict` translates into a clear
///     "missing VCLibs/UI.Xaml dependency" message instead of silently
///     succeeding. (Bundling those framework packages is a deliberate follow-up,
///     not attempted here.)
///   * options — `DeploymentOptions::default()`.
///
/// Same async-then-`.get()` pattern as registration. Returns `Ok(true)` on a
/// success HRESULT.
fn install_app_installer() -> Result<bool, String> {
    use windows::core::HSTRING;
    use windows::Foundation::Collections::IIterable;
    use windows::Foundation::Uri;
    use windows::Management::Deployment::{DeploymentOptions, PackageManager};

    let path = download_bundle()?;

    let pm = PackageManager::new().map_err(|e| format!("PackageManager init failed: {e}"))?;

    // Build a file:// URI from the absolute temp path. Backslashes → forward
    // slashes and a `file:///` prefix give WinRT an unambiguous absolute
    // file URI (e.g. C:\Users\… → file:///C:/Users/…).
    let uri_str = format!("file:///{}", path.to_string_lossy().replace('\\', "/"));
    let uri = Uri::CreateUri(&HSTRING::from(uri_str))
        .map_err(|e| format!("building file:// URI failed: {e}"))?;

    let op = pm
        .AddPackageAsync(&uri, None::<&IIterable<Uri>>, DeploymentOptions::default())
        .map_err(|e| format!("AddPackageAsync call failed: {e}"))?;
    let result = op
        .get()
        .map_err(|e| format!("awaiting AddPackageAsync failed: {e}"))?;

    deployment_verdict(&result, "AddPackageAsync")
}

/// Download `aka.ms/getwinget` (the App Installer `.msixbundle`) into `%TEMP%`.
///
/// Uses the already-present `ureq` dependency; it follows the aka.ms redirect
/// to the real bundle URL. Streams the body straight to disk so we never buffer
/// the whole ~200 MB bundle in memory. Returns the written path.
fn download_bundle() -> Result<PathBuf, String> {
    let resp = ureq::get(GETWINGET_URL)
        .call()
        .map_err(|e| format!("downloading App Installer failed: {e}"))?;

    let dest = std::env::temp_dir().join("DesktopAppInstaller.msixbundle");
    let mut reader = resp.into_reader();
    let mut file = std::fs::File::create(&dest)
        .map_err(|e| format!("creating temp bundle file failed: {e}"))?;
    std::io::copy(&mut reader, &mut file)
        .map_err(|e| format!("writing App Installer bundle failed: {e}"))?;

    Ok(dest)
}

/// Interpret a `DeploymentResult`: `Ok(true)` on a success HRESULT, else an
/// `Err` carrying the HRESULT and the provider's `ErrorText`, with a targeted
/// hint when the failure looks like a missing framework dependency.
///
/// A completed async deployment op does NOT imply success — the verdict lives
/// in `ExtendedErrorCode`. `ErrorText` supplies the human-readable reason (e.g.
/// which dependency is unsatisfied).
fn deployment_verdict(
    result: &windows::Management::Deployment::DeploymentResult,
    phase: &str,
) -> Result<bool, String> {
    use windows::core::HRESULT;

    let hr = result.ExtendedErrorCode().unwrap_or(HRESULT(0));
    if hr.is_ok() {
        return Ok(true);
    }

    let error_text = result
        .ErrorText()
        .map(|t| t.to_string_lossy())
        .unwrap_or_default();
    let code = hr.0 as u32;

    // ERROR_INSTALL_PREREQUISITE_FAILED / open-package failures, or an error
    // text that names a framework dependency, mean a VCLibs/UI.Xaml package is
    // missing — the one case where passing `None` dependencies isn't enough.
    let looks_like_missing_dep = matches!(code, 0x8007_3CF3 | 0x8007_3D19 | 0x8007_3CF9)
        || {
            let t = error_text.to_ascii_lowercase();
            t.contains("dependency") || t.contains("vclibs") || t.contains("ui.xaml")
        };

    if looks_like_missing_dep {
        Err(format!(
            "{phase} failed: missing VCLibs/UI.Xaml dependency \
             (HRESULT 0x{code:08X}{}) — the App Installer's framework packages \
             must be installed for this user first",
            fmt_text(&error_text),
        ))
    } else {
        Err(format!(
            "{phase} failed: HRESULT 0x{code:08X}{}",
            fmt_text(&error_text),
        ))
    }
}

/// `", <text>"` when non-empty, else `""` — keeps the error strings tidy.
fn fmt_text(text: &str) -> String {
    let t = text.trim();
    if t.is_empty() {
        String::new()
    } else {
        format!(", {t}")
    }
}

/// Build the final, precise failure string for `ensure_winget`, folding in the
/// most likely root cause.
fn compose_failure(
    appx_runtime: bool,
    register_err: Option<String>,
    install_err: Option<String>,
) -> String {
    if !appx_runtime {
        return "winget unavailable: this machine has no AppX/App-Installer runtime \
                (Windows Server / Server Core / LTSC / IoT) — install App Installer \
                manually, e.g. via the offline .msixbundle + framework dependencies"
            .to_string();
    }

    match (register_err, install_err) {
        (Some(r), Some(i)) => {
            format!("winget bootstrap failed. re-register: {r}. install: {i}")
        }
        (_, Some(i)) => format!("winget bootstrap failed during install: {i}"),
        (Some(r), None) => format!("winget bootstrap failed during re-registration: {r}"),
        (None, None) => {
            "winget unavailable: bootstrap completed without error but `winget` is \
             still not runnable — the app-execution alias may not be on PATH for \
             this session"
                .to_string()
        }
    }
}
