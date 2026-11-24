// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

//! Shell-free file reads (agent 3.17.0): `/list`, `/stat`, `/hash`.
//!
//! An AI session used to list a folder, check that a path exists or hash a file
//! through `/exec`, which needs a human approval for every command and does not
//! even work for PowerShell cmdlets on Windows (`/exec` runs `cmd /S /C`). These
//! read the filesystem directly, through the same `resolve_path` confinement as
//! `/download`, and are in `privileged_path` exactly like it.

use std::io::Read;
use std::path::Path;
use std::time::UNIX_EPOCH;

use sha2::{Digest, Sha256};

use super::{json_resp, percent_decode, resolve_path, Config, Resp};

/// Most entries one `/list` answers; past it the reply says `"truncated": true`.
pub(super) const LIST_CAP: usize = 2000;
/// `/hash` reads the file this much at a time, never all of it at once.
const CHUNK: usize = 64 * 1024;

fn path_arg(url: &str) -> String {
    let query = url.split('?').nth(1).unwrap_or("");
    let mut path = String::new();
    for kv in query.split('&') {
        if let Some(v) = kv.strip_prefix("path=") {
            path = percent_decode(v);
        }
    }
    path
}

fn mtime(md: &std::fs::Metadata) -> u64 {
    md.modified().ok().and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_secs()).unwrap_or(0)
}

fn bad_request() -> Resp {
    json_resp(&serde_json::json!({"ok": false, "error": "path is required"}), 400)
}

fn forbidden() -> Resp {
    json_resp(&serde_json::json!({"ok": false, "error": "forbidden"}), 403)
}

pub(super) fn list_ep(url: &str, cfg: &Config) -> Resp {
    let mut path = path_arg(url);
    if path.is_empty() {
        path = if !cfg.share.is_empty() {
            cfg.share.clone()
        } else {
            std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")).unwrap_or_else(|_| "/".to_string())
        };
    }
    let Some(full) = resolve_path(cfg, &path) else { return forbidden() };
    let (entries, truncated) = list_dir(&full, LIST_CAP);
    let parent = full.parent().map(|p| p.to_string_lossy().to_string());
    json_resp(
        &serde_json::json!({"ok": true, "path": full.to_string_lossy(), "parent": parent, "entries": entries, "truncated": truncated}),
        200,
    )
}

/// The entries of `dir`, directories first then by case-insensitive name, at most
/// `cap` of them; the bool says whether any were left out. An unreadable `dir`
/// lists as empty, as `/list` always has.
pub(super) fn list_dir(dir: &Path, cap: usize) -> (Vec<serde_json::Value>, bool) {
    let mut entries: Vec<serde_json::Value> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let md = e.metadata().ok();
            let isdir = md.as_ref().map(|m| m.is_dir()).unwrap_or(false);
            let size = md.as_ref().map(|m| m.len()).unwrap_or(0);
            let modified = md.as_ref().map(mtime).unwrap_or(0);
            let link = e.file_type().map(|t| t.is_symlink()).unwrap_or(false);
            entries.push(serde_json::json!({"name": e.file_name().to_string_lossy(), "dir": isdir, "size": size, "mtime": modified, "link": link}));
        }
    }
    entries.sort_by(|a, b| {
        let (ad, bd) = (a["dir"].as_bool().unwrap_or(false), b["dir"].as_bool().unwrap_or(false));
        bd.cmp(&ad).then_with(|| {
            a["name"].as_str().unwrap_or("").to_lowercase().cmp(&b["name"].as_str().unwrap_or("").to_lowercase())
        })
    });
    let truncated = entries.len() > cap;
    entries.truncate(cap);
    (entries, truncated)
}

pub(super) fn stat_ep(url: &str, cfg: &Config) -> Resp {
    let path = path_arg(url);
    if path.is_empty() {
        return bad_request();
    }
    let Some(full) = resolve_path(cfg, &path) else { return forbidden() };
    json_resp(&stat(&full), 200)
}

/// `kind` is the path itself (a symlink is "symlink"); size, mtime and readonly
/// are its target's when the link resolves, the link's own otherwise.
pub(super) fn stat(full: &Path) -> serde_json::Value {
    let shown = full.to_string_lossy();
    let Ok(own) = std::fs::symlink_metadata(full) else {
        return serde_json::json!({"ok": true, "path": shown, "exists": false});
    };
    let t = own.file_type();
    let kind = if t.is_symlink() {
        "symlink"
    } else if t.is_dir() {
        "dir"
    } else if t.is_file() {
        "file"
    } else {
        "other"
    };
    let md = std::fs::metadata(full).unwrap_or(own);
    serde_json::json!({
        "ok": true, "path": shown, "exists": true, "kind": kind,
        "size": md.len(), "mtime": mtime(&md), "readonly": md.permissions().readonly(),
    })
}

pub(super) fn hash_ep(url: &str, cfg: &Config) -> Resp {
    let path = path_arg(url);
    if path.is_empty() {
        return bad_request();
    }
    let Some(full) = resolve_path(cfg, &path) else { return forbidden() };
    match sha256_file(&full) {
        Ok(Some((size, sha))) => json_resp(&serde_json::json!({"ok": true, "path": full.to_string_lossy(), "size": size, "sha256": sha}), 200),
        Ok(None) => json_resp(&serde_json::json!({"ok": false, "error": "not a file"}), 404),
        Err(e) => json_resp(&serde_json::json!({"ok": false, "error": format!("read failed: {e}")}), 500),
    }
}

/// (bytes read, lowercase hex sha256) of a regular file, read `CHUNK` at a time;
/// None when `full` is not a regular file (following a symlink, as `/download` does).
pub(super) fn sha256_file(full: &Path) -> std::io::Result<Option<(u64, String)>> {
    if !full.is_file() {
        return Ok(None);
    }
    let mut f = std::fs::File::open(full)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; CHUNK];
    let mut size = 0u64;
    loop {
        let n = match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        h.update(&buf[..n]);
        size += n as u64;
    }
    Ok(Some((size, format!("{:x}", h.finalize()))))
}

#[cfg(test)]
mod tests;
