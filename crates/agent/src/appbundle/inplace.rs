// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

//! The app update for a user who owns IT-AI.app but cannot write the folder it is in.
//!
//! A standard (non-admin) user can own /Applications/IT-AI.app and still not create
//! anything in /Applications (root:admin 775), so the rename-based swap cannot even
//! stage. Then the update stages in the agent's own folder (~/.it-ai) and replaces
//! the bundle's contents where it stands:
//! - every file is written beside its target and renamed over it, so nothing is ever
//!   written into the running executable's inode (the process keeps the old one);
//! - whatever the old bundle has and the new one does not is removed;
//! - the installed bundle must meet the same code requirement as the download, and on
//!   any failure the backup taken first is put back the same way.

use std::collections::HashSet;
use std::io;
use std::path::{Path, PathBuf};

/// Leftovers of an in-place update in the agent's folder are named after this prefix.
pub(super) const STAGE_PREFIX: &str = "app-update-";

/// The agent's own folder, where the in-place update stages.
pub(super) fn data_dir() -> PathBuf {
    PathBuf::from(crate::persistence::home()).join(".it-ai")
}

/// What creating the staging folder beside the app did.
pub(super) enum Beside {
    Staged,
    /// This user may not create anything beside the app: install in place.
    Denied(io::Error),
}

pub(super) fn stage_beside(stage: &Path) -> Result<Beside, String> {
    match std::fs::create_dir(stage) {
        Ok(()) => Ok(Beside::Staged),
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => Ok(Beside::Denied(e)),
        Err(e) => Err(format!("cannot stage the update next to the app: {e}")),
    }
}

/// A new folder only this user can open, for one attempt.
pub(super) fn make_stage(dir: &Path, tag: &str) -> Result<PathBuf, String> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let stage = dir.join(format!("{STAGE_PREFIX}{tag}"));
    std::fs::DirBuilder::new().mode(0o700).create(&stage).map_err(|e| format!("cannot stage the update in {}: {e}", dir.display()))?;
    Ok(stage)
}

/// Remove the stages earlier in-place updates left in `dir` (the last one holds the
/// backup until the new app has started).
pub(super) fn cleanup(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for e in entries.flatten() {
        if e.file_name().to_string_lossy().starts_with(STAGE_PREFIX) {
            let _ = std::fs::remove_dir_all(e.path());
        }
    }
}

/// Copy the current bundle to `to` before anything in it changes.
pub(super) fn backup(app: &Path, to: &Path) -> Result<(), String> {
    let ok = std::process::Command::new("/usr/bin/ditto").arg(app).arg(to).status().map(|s| s.success()).unwrap_or(false);
    ok.then_some(()).ok_or_else(|| "cannot back up the current app".to_string())
}

/// Make the tree at `dst` the same as the one at `src`: each file and symlink is
/// created beside its target and renamed over it, directories are updated in place,
/// and entries `src` does not have are removed.
pub(super) fn replace_contents(dst: &Path, src: &Path) -> io::Result<()> {
    let mut names = HashSet::new();
    for e in std::fs::read_dir(src)? {
        let e = e?;
        let name = e.file_name();
        let (from, to) = (e.path(), dst.join(&name));
        let existing = std::fs::symlink_metadata(&to).ok();
        if e.file_type()?.is_dir() {
            match existing {
                Some(m) if m.is_dir() => {}
                Some(_) => {
                    std::fs::remove_file(&to)?;
                    std::fs::create_dir(&to)?;
                }
                None => std::fs::create_dir(&to)?,
            }
            replace_contents(&to, &from)?;
            std::fs::set_permissions(&to, std::fs::symlink_metadata(&from)?.permissions())?;
        } else {
            let mut tmp_name = name.clone();
            tmp_name.push(format!(".itai-new-{}", std::process::id()));
            let tmp = dst.join(tmp_name);
            let _ = std::fs::remove_file(&tmp);
            if e.file_type()?.is_symlink() {
                std::os::unix::fs::symlink(std::fs::read_link(&from)?, &tmp)?;
            } else {
                std::fs::copy(&from, &tmp)?;
            }
            if existing.is_some_and(|m| m.is_dir()) {
                std::fs::remove_dir_all(&to)?;
            }
            if let Err(err) = std::fs::rename(&tmp, &to) {
                let _ = std::fs::remove_file(&tmp);
                return Err(err);
            }
        }
        names.insert(name);
    }
    let stale: Vec<_> = std::fs::read_dir(dst)?.collect::<io::Result<Vec<_>>>()?.into_iter().filter(|e| !names.contains(&e.file_name())).collect();
    for e in stale {
        if e.file_type()?.is_dir() {
            std::fs::remove_dir_all(e.path())?;
        } else {
            std::fs::remove_file(e.path())?;
        }
    }
    Ok(())
}

/// Put the contents of `backup` back into `app`.
pub(super) fn restore(app: &Path, backup: &Path) -> Result<(), String> {
    replace_contents(app, backup).map_err(|e| e.to_string())
}

/// Replace `app`'s contents with `new_app`'s and check the result with `verify`. On
/// failure `app` is restored from `backup` and the error says what failed.
pub(super) fn put_in_place(app: &Path, new_app: &Path, backup: &Path, verify: impl Fn(&Path) -> Result<(), String>) -> Result<(), String> {
    let failed = match replace_contents(app, new_app) {
        Err(e) => format!("cannot put the new app in place ({e})"),
        Ok(()) => match verify(app) {
            Ok(()) => return Ok(()),
            Err(e) => format!("the installed app failed verification ({e})"),
        },
    };
    Err(format!("{failed}; {}", match restore(app, backup) {
        Ok(()) => "kept the current one".to_string(),
        Err(b) => format!("and putting the current one back failed: {b}"),
    }))
}
