// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

//! The agent installed as IT-AI.app (the macOS DMG).
//!
//! Inside a Developer ID-signed app the binary must never be replaced on its own.
//! The release's bare `it-ai-macos` is the unsigned CI build: written over
//! `IT-AI.app/Contents/MacOS/it-ai` it passes the ed25519 check, breaks the app's
//! signature, and macOS forgets the Screen Recording / Accessibility grants that
//! are the reason the app exists. And the hash check the update loops use can
//! never match there (the signed binary is not the published one), so they would
//! do exactly that on their first pass.
//!
//! So while running from an app bundle:
//! - the background update loops do nothing; the hub's version-based push
//!   (`POST /update`, sent when the agent's version differs from AGENT_VERSION)
//!   is the update path;
//! - `/update` installs `IT-AI-macos.zip`, published next to the bare binary,
//!   instead of the binary. It is accepted only if `codesign` says it is this app
//!   (bundle id) signed with a Developer ID certificate of this team, and only if
//!   it is newer than the running version. The whole bundle is swapped, and put
//!   back if anything after the swap fails.
//!
//! Apple's signature, pinned to the team, plays the part the pinned ed25519 key
//! plays for the bare binary; the zip is signed and notarized on Codemagic, which
//! does not hold the ed25519 key.

// Only the macOS `install` uses most of this; elsewhere it is reached by the tests.
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use std::path::{Path, PathBuf};

pub(crate) const BUNDLE_ID: &str = "com.itai.agent";
pub(crate) const TEAM_ID: &str = "DA4PX65QXV";
pub(crate) const APP_NAME: &str = "IT-AI.app";
pub(crate) const ZIP_ASSET: &str = "IT-AI-macos.zip";

/// The code requirement an update must meet: anchored at Apple, a Developer ID
/// Application certificate (the Developer ID intermediate and leaf markers, so a
/// same-team Apple Development build does not pass), this team, this bundle id.
pub(crate) fn requirement() -> String {
    format!(
        "anchor apple generic and identifier \"{BUNDLE_ID}\" \
         and certificate 1[field.1.2.840.113635.100.6.2.6] exists \
         and certificate leaf[field.1.2.840.113635.100.6.1.13] exists \
         and certificate leaf[subject.OU] = \"{TEAM_ID}\""
    )
}

/// `<X>.app` when `exe` is `<X>.app/Contents/MacOS/<name>`, else None.
pub(crate) fn bundle_of(exe: &Path) -> Option<PathBuf> {
    let macos = exe.parent()?;
    let contents = macos.parent()?;
    let app = contents.parent()?;
    (macos.file_name()? == "MacOS"
        && contents.file_name()? == "Contents"
        && app.extension().map(|e| e.eq_ignore_ascii_case("app")).unwrap_or(false))
    .then(|| app.to_path_buf())
}

/// The app bundle this agent runs from, on macOS only.
pub(crate) fn running_bundle() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        std::env::current_exe().ok().as_deref().and_then(bundle_of)
    }
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

/// The app zip published beside the binary the hub pointed at:
/// `https://hub/bin/it-ai-macos` → `https://hub/bin/IT-AI-macos.zip`.
pub(crate) fn zip_url(binary_url: &str) -> Option<String> {
    let path = binary_url.split(['?', '#']).next()?;
    let (dir, file) = path.rsplit_once('/')?;
    (!file.is_empty() && dir.contains("://")).then(|| format!("{dir}/{ZIP_ASSET}"))
}

fn parse_version(v: &str) -> Option<Vec<u64>> {
    let v = v.trim().trim_start_matches(['v', 'V']);
    let parts: Option<Vec<u64>> = v.split('.').map(|p| p.parse().ok()).collect();
    parts.filter(|p| !p.is_empty())
}

/// True when `candidate` is a strictly newer dotted version than `running`.
/// Anything unparsable is not newer.
pub(crate) fn is_newer(candidate: &str, running: &str) -> bool {
    match (parse_version(candidate), parse_version(running)) {
        (Some(mut a), Some(mut b)) => {
            let n = a.len().max(b.len());
            a.resize(n, 0);
            b.resize(n, 0);
            a > b
        }
        _ => false,
    }
}

/// `CFBundleShortVersionString` from an XML Info.plist.
pub(crate) fn plist_version(xml: &str) -> Option<String> {
    let after = &xml[xml.find("<key>CFBundleShortVersionString</key>")? + "<key>CFBundleShortVersionString</key>".len()..];
    let start = after.find("<string>")? + "<string>".len();
    if !after[..after.find("<string>")?].trim().is_empty() {
        return None; // the next element is not this key's value
    }
    let end = after[start..].find("</string>")?;
    Some(after[start..start + end].trim().to_string())
}

/// Put `new_app` where `app` is, keeping the old bundle at `old` until the caller
/// is done with it. On failure the original is back at `app`.
pub(crate) fn swap(app: &Path, new_app: &Path, old: &Path) -> Result<(), String> {
    std::fs::rename(app, old).map_err(|e| format!("cannot move the current app aside: {e}"))?;
    if let Err(e) = std::fs::rename(new_app, app) {
        let back = std::fs::rename(old, app);
        return Err(match back {
            Ok(()) => format!("cannot move the new app in: {e}"),
            Err(b) => format!("cannot move the new app in: {e}; and putting the old one back failed: {b}"),
        });
    }
    Ok(())
}

/// Undo a `swap` (the new app goes back to `new_app`, the old one to `app`).
pub(crate) fn unswap(app: &Path, new_app: &Path, old: &Path) -> Result<(), String> {
    std::fs::rename(app, new_app).map_err(|e| e.to_string())?;
    std::fs::rename(old, app).map_err(|e| e.to_string())
}

/// What an `/update` did while running as the app.
pub(crate) enum Outcome {
    /// Installed this version; the replacement has launched and the caller exits.
    Installed(String),
    /// The published app is not newer; nothing was changed.
    Current(String),
}

/// Leftovers from an update are named after these prefixes, beside the app.
const STAGE_PREFIX: &str = ".IT-AI-update-";
const OLD_PREFIX: &str = ".IT-AI.app.old-";

/// Remove a previous update's staging folder and the bundle it replaced. Run at
/// startup: the old bundle cannot be deleted by the process that swapped it out,
/// because that process execs into the new one.
pub(crate) fn cleanup_leftovers() {
    let Some(app) = running_bundle() else { return };
    let Some(parent) = app.parent() else { return };
    let Ok(entries) = std::fs::read_dir(parent) else { return };
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if name.starts_with(STAGE_PREFIX) || name.starts_with(OLD_PREFIX) {
            let _ = std::fs::remove_dir_all(e.path());
        }
    }
}

/// The executable inside IT-AI.app (`CFBundleExecutable`).
pub(crate) const APP_EXE: &str = "it-ai";
/// Where a bare-binary agent moves the app to (`migrate`).
pub(crate) const APPLICATIONS: &str = "/Applications";

/// A bare-binary agent moves into the app only if the app is not older than what it
/// runs: the same version (the release it is already on) or newer.
pub(crate) fn may_migrate_to(app_version: &str, running: &str) -> bool {
    parse_version(app_version).is_some() && !is_newer(running, app_version)
}

fn stage_tag() -> String {
    format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)
    )
}

/// Download the app zip into `stage`, unpack it and check it: it must hold
/// IT-AI.app with its executable, signed to `requirement()`. Nothing from the
/// download is read before the signature passes. Returns the app and its version.
#[cfg(target_os = "macos")]
fn fetch_verified(zip_url: &str, stage: &Path) -> Result<(PathBuf, String), String> {
    use std::process::Command;
    let bytes = crate::http::download_bytes(zip_url).filter(|b| !b.is_empty()).ok_or("download of the app failed")?;
    let zip = stage.join("update.zip");
    std::fs::write(&zip, &bytes).map_err(|e| format!("cannot write the download: {e}"))?;
    let unpacked = stage.join("app");
    let ok = Command::new("/usr/bin/ditto").arg("-x").arg("-k").arg(&zip).arg(&unpacked).status().map(|s| s.success()).unwrap_or(false);
    if !ok {
        return Err("cannot unpack the app zip".to_string());
    }
    let new_app = unpacked.join(APP_NAME);
    if !new_app.join("Contents/MacOS").join(APP_EXE).is_file() {
        return Err(format!("the zip holds no {APP_NAME} with {APP_EXE}"));
    }
    let verified = Command::new("/usr/bin/codesign")
        .args(["--verify", "--deep", "--strict"])
        .arg(format!("-R={}", requirement()))
        .arg(&new_app)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !verified {
        return Err(format!("the app is not {BUNDLE_ID} signed with team {TEAM_ID}'s Developer ID; refused"));
    }
    let plist = std::fs::read_to_string(new_app.join("Contents/Info.plist")).map_err(|e| format!("cannot read the app's Info.plist: {e}"))?;
    let version = plist_version(&plist).ok_or("the app's Info.plist has no version")?;
    Ok((new_app, version))
}

/// Restart as `exe` with this process's args and token handling (as `apply_update`):
/// exec in place, else spawn. Ok only when a spawned replacement is running and the
/// caller must exit; a successful exec never returns.
#[cfg(target_os = "macos")]
fn relaunch(exe: &Path) -> Result<(), String> {
    use std::os::unix::process::CommandExt;
    let args: Vec<String> = std::env::args().skip(1).collect();
    let e = crate::relaycred::restart_command(exe, args.clone()).exec();
    eprintln!("update: exec of {} failed ({e}); spawning it instead", exe.display());
    crate::relaycred::restart_command(exe, args).spawn().map(|_| ()).map_err(|e| e.to_string())
}

/// Install the signed app from `zip_url` over the running bundle and restart.
/// `slot` is the one-update-at-a-time lock, as for `http::apply_update`.
#[cfg(target_os = "macos")]
pub(crate) fn install(zip_url: &str, slot: crate::updatelock::UpdateSlot) -> Result<Outcome, String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let app = bundle_of(&exe).ok_or("not running from an app bundle")?;
    let parent = app.parent().ok_or("the app has no parent folder")?.to_path_buf();
    let tag = stage_tag();
    // Stage beside the app so the swap is a rename on one volume.
    let stage = parent.join(format!("{STAGE_PREFIX}{tag}"));
    std::fs::create_dir(&stage).map_err(|e| format!("cannot stage the update next to the app: {e}"))?;
    let result = (|| {
        let (new_app, version) = fetch_verified(zip_url, &stage)?;
        if !is_newer(&version, env!("CARGO_PKG_VERSION")) {
            return Ok(Outcome::Current(version));
        }
        let old = parent.join(format!("{OLD_PREFIX}{tag}"));
        swap(&app, &new_app, &old)?;
        match relaunch(&exe) {
            Ok(()) => Ok(Outcome::Installed(version)),
            Err(e) => {
                let back = unswap(&app, &new_app, &old);
                Err(format!("the new app did not start ({e}); {}", match back {
                    Ok(()) => "kept the current one".to_string(),
                    Err(b) => format!("and putting the current one back failed: {b}"),
                }))
            }
        }
    })();
    match &result {
        Ok(Outcome::Installed(_)) => slot.hold_until_exit(),
        _ => {
            let _ = std::fs::remove_dir_all(&stage);
        }
    }
    result
}

/// Move a bare-binary agent into IT-AI.app: install the signed app from beside
/// `binary_url` to /Applications, point the launchd entry that runs this binary at
/// the app, and restart as the app. Only an agent that a launchd entry runs moves (a
/// `--ttl` support session or a one-off run never installs anything), and only when
/// it can write /Applications. Every step is undone if a later one fails, and any
/// error leaves the caller to update the bare binary as before. Ok(Installed) means
/// the app is running and the caller must exit, holding its update slot.
#[cfg(target_os = "macos")]
pub(crate) fn migrate(binary_url: &str) -> Result<Outcome, String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    if bundle_of(&exe).is_some() {
        return Err("already running from an app".to_string());
    }
    let zip = zip_url(binary_url).ok_or("cannot derive the app zip from the update url")?;
    let parent = PathBuf::from(APPLICATIONS);
    let target = parent.join(APP_NAME);
    let new_exe = target.join("Contents/MacOS").join(APP_EXE);
    let tag = stage_tag();
    let stage = parent.join(format!("{STAGE_PREFIX}{tag}"));
    std::fs::create_dir(&stage).map_err(|e| format!("cannot write {APPLICATIONS} ({e}); staying a bare binary"))?;
    let result = (|| {
        let (new_app, version) = fetch_verified(&zip, &stage)?;
        if !may_migrate_to(&version, env!("CARGO_PKG_VERSION")) {
            return Ok(Outcome::Current(version));
        }
        // Move the app in first (beside any copy already there), then the entry.
        let old = parent.join(format!("{OLD_PREFIX}{tag}"));
        let had_app = target.exists();
        if had_app {
            swap(&target, &new_app, &old)?;
        } else {
            std::fs::rename(&new_app, &target).map_err(|e| format!("cannot move the app into {APPLICATIONS}: {e}"))?;
        }
        let undo_app = || {
            if had_app {
                let _ = unswap(&target, &new_app, &old);
            } else {
                let _ = std::fs::rename(&target, &new_app);
            }
        };
        let (entry, previous) = match crate::persistence::mac_repoint(&exe, &new_exe) {
            Ok(r) => r,
            Err(e) => {
                undo_app();
                return Err(e);
            }
        };
        eprintln!("update: moving into {} {version}; {} now runs it", target.display(), entry.display());
        match relaunch(&new_exe) {
            Ok(()) => Ok(Outcome::Installed(version)),
            Err(e) => {
                let _ = std::fs::write(&entry, previous);
                undo_app();
                Err(format!("the app did not start ({e}); stayed a bare binary"))
            }
        }
    })();
    if !matches!(result, Ok(Outcome::Installed(_))) {
        let _ = std::fs::remove_dir_all(&stage);
    }
    result
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn install(_zip_url: &str, _slot: crate::updatelock::UpdateSlot) -> Result<Outcome, String> {
    Err("app updates exist only on macOS".to_string())
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn migrate(_binary_url: &str) -> Result<Outcome, String> {
    Err("the app exists only on macOS".to_string())
}

#[cfg(test)]
mod tests;
