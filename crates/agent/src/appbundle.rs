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

/// Install the signed app from `zip_url` over the running bundle and restart.
/// `slot` is the one-update-at-a-time lock, as for `http::apply_update`.
#[cfg(target_os = "macos")]
pub(crate) fn install(zip_url: &str, slot: crate::updatelock::UpdateSlot) -> Result<Outcome, String> {
    use std::process::Command;
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let app = bundle_of(&exe).ok_or("not running from an app bundle")?;
    let exe_name = exe.file_name().ok_or("no executable name")?.to_owned();
    let parent = app.parent().ok_or("the app has no parent folder")?.to_path_buf();
    let tag = format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)
    );
    // Stage beside the app so the swap is a rename on one volume.
    let stage = parent.join(format!("{STAGE_PREFIX}{tag}"));
    std::fs::create_dir(&stage).map_err(|e| format!("cannot stage the update next to the app: {e}"))?;
    let result = (|| {
        let bytes = crate::http::download_bytes(zip_url).filter(|b| !b.is_empty()).ok_or("download of the app failed")?;
        let zip = stage.join("update.zip");
        std::fs::write(&zip, &bytes).map_err(|e| format!("cannot write the download: {e}"))?;
        let unpacked = stage.join("app");
        let ok = Command::new("/usr/bin/ditto").arg("-x").arg("-k").arg(&zip).arg(&unpacked).status().map(|s| s.success()).unwrap_or(false);
        if !ok {
            return Err("cannot unpack the app zip".to_string());
        }
        let new_app = unpacked.join(APP_NAME);
        if !new_app.join("Contents/MacOS").join(&exe_name).is_file() {
            return Err(format!("the zip holds no {APP_NAME} with {}", exe_name.to_string_lossy()));
        }
        // Signature first: nothing from the download is read before it passes.
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
        let running = env!("CARGO_PKG_VERSION");
        if !is_newer(&version, running) {
            return Ok(Outcome::Current(version));
        }
        let old = parent.join(format!("{OLD_PREFIX}{tag}"));
        swap(&app, &new_app, &old)?;
        // Same args and token handling as a binary update (`apply_update`).
        let args: Vec<String> = std::env::args().skip(1).collect();
        {
            use std::os::unix::process::CommandExt;
            let e = crate::relaycred::restart_command(&exe, args.clone()).exec();
            eprintln!("update: exec of the new app failed ({e}); spawning it instead");
        }
        match crate::relaycred::restart_command(&exe, args).spawn() {
            Ok(_) => Ok(Outcome::Installed(version)),
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

#[cfg(not(target_os = "macos"))]
pub(crate) fn install(_zip_url: &str, _slot: crate::updatelock::UpdateSlot) -> Result<Outcome, String> {
    Err("app updates exist only on macOS".to_string())
}

#[cfg(test)]
mod tests;
