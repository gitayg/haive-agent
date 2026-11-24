// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

// Shell-free file reads (hub 3.31.0, agent 3.17.0): a folder listing, one path's
// details and a file's sha256, from the hub's `/m/list`, `/m/stat` and `/m/hash`.
// The agent answers them itself, so nothing goes through a shell, and they sit in
// the `download` tier: no approval by default, on every OS alike.
use it_ai_direct::op::urlencode;
use it_ai_direct::reply::{Reply, Settled};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock};
use rmcp::{tool, tool_router, ErrorData};
use serde::Deserialize;
use serde_json::Value;

use crate::approval::{settled_result, text};
use crate::{err, Srv};

#[derive(Deserialize, schemars::JsonSchema)]
pub struct ListDirArgs {
    device: String,
    /// folder on the device (default: the agent's share folder, else the user's home)
    #[serde(default)]
    path: Option<String>,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct FileArgs {
    device: String,
    /// full path on the device, e.g. C:\Program Files\GitHub CLI\gh.exe or /etc/hosts
    path: String,
}

#[cfg(test)]
impl ListDirArgs {
    pub fn for_test(path: Option<&str>) -> Self {
        ListDirArgs { device: "pc1".into(), path: path.map(Into::into) }
    }
}

#[cfg(test)]
impl FileArgs {
    pub fn for_test(path: &str) -> Self {
        FileArgs { device: "pc1".into(), path: path.into() }
    }
}

/// The `/m/list|stat|hash` query after `mtok`/`owner`.
pub fn fs_query(target: &str, path: Option<&str>) -> String {
    match path.filter(|p| !p.is_empty()) {
        Some(p) => format!("target={}&path={}", urlencode(target), urlencode(p)),
        None => format!("target={}", urlencode(target)),
    }
}

/// Unix seconds as `YYYY-MM-DD HH:MM UTC`.
pub fn utc(secs: i64) -> String {
    let (days, rem) = (secs.div_euclid(86400), secs.rem_euclid(86400));
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02} UTC", rem / 3600, rem % 3600 / 60)
}

fn when(v: &Value) -> String {
    match v.as_i64() {
        Some(s) if s > 0 => utc(s),
        _ => "-".to_string(),
    }
}

fn failed(v: &Value) -> Option<String> {
    (v["ok"].as_bool() != Some(true)).then(|| format!("[error] {}", v["error"].as_str().unwrap_or("failed")))
}

/// A `/m/list` answer: the folder, then one `d|f|l size mtime name` line per entry.
pub fn fmt_list(v: &Value) -> String {
    if let Some(e) = failed(v) {
        return e;
    }
    let entries = v["entries"].as_array().map(Vec::as_slice).unwrap_or_default();
    let mut out = vec![format!("{} ({} entries)", v["path"].as_str().unwrap_or(""), entries.len())];
    for e in entries {
        let kind = if e["link"].as_bool() == Some(true) {
            'l'
        } else if e["dir"].as_bool() == Some(true) {
            'd'
        } else {
            'f'
        };
        out.push(format!("{kind} {:>12} {:<20} {}", e["size"].as_u64().unwrap_or(0), when(&e["mtime"]), e["name"].as_str().unwrap_or("")));
    }
    if v["truncated"].as_bool() == Some(true) {
        out.push(format!("(truncated: the folder has more entries than one listing returns; {} shown)", entries.len()));
    }
    out.join("\n")
}

/// A `/m/stat` answer as `key: value` lines.
pub fn fmt_info(v: &Value) -> String {
    if let Some(e) = failed(v) {
        return e;
    }
    let path = format!("path: {}", v["path"].as_str().unwrap_or(""));
    if v["exists"].as_bool() != Some(true) {
        return format!("{path}\nexists: no");
    }
    let yes = |k: &str| if v[k].as_bool() == Some(true) { "yes" } else { "no" };
    format!(
        "{path}\nexists: yes\nkind: {}\nsize: {} bytes\nmodified: {}\nreadonly: {}",
        v["kind"].as_str().unwrap_or("other"),
        v["size"].as_u64().unwrap_or(0),
        when(&v["mtime"]),
        yes("readonly")
    )
}

/// A `/m/hash` answer: `<sha256>  <path> (<size> bytes)`.
pub fn fmt_hash(v: &Value) -> String {
    if let Some(e) = failed(v) {
        return e;
    }
    format!("{}  {} ({} bytes)", v["sha256"].as_str().unwrap_or(""), v["path"].as_str().unwrap_or(""), v["size"].as_u64().unwrap_or(0))
}

impl Srv {
    async fn fs_read(&self, route: &str, tool: &str, device: &str, path: Option<&str>, fmt: &(dyn Fn(&Value) -> String + Sync)) -> Result<CallToolResult, ErrorData> {
        let target = self.resolve(device).await.map_err(err)?;
        let resp = self.client().get(self.m(route, &fs_query(&target, path))).send().await.map_err(|e| err(e.without_url()))?;
        let status = resp.status().as_u16();
        self.seen.status(status);
        let body = resp.bytes().await.map_err(|e| err(e.without_url()))?;
        Ok(match Reply::parse(status, &body) {
            Reply::Done(Value::String(s)) if status == 404 => text(format!("[error] the hub has no /m/{route} ({}); {tool} needs hub 3.31.0", s.trim())),
            Reply::Done(Value::String(s)) => text(format!("[error] HTTP {status}: {}", s.trim())),
            r => match self.ctl.settle(r, self.wait).await {
                Settled::Refused { error, blocked: false } => CallToolResult::error(vec![ContentBlock::text(format!("[error] {error}"))]),
                s => settled_result(s, fmt),
            },
        })
    }
}

#[tool_router(router = fsread_router, vis = "pub(crate)")]
impl Srv {
    #[tool(description = "List a folder on the device: one line per entry with d (folder), f (file) or l (symlink), the size in bytes, the modified time in UTC, and the name. Reads the device's filesystem without a shell and without an approval; prefer it over run_command (dir, ls, Get-ChildItem) for listing folders. Works the same on Windows, macOS and Linux. path defaults to the agent's share folder, else the user's home. Needs hub 3.31.0; modified times need agent 3.17.0.")]
    async fn list_dir(&self, Parameters(a): Parameters<ListDirArgs>) -> Result<CallToolResult, ErrorData> {
        self.fs_read("list", "list_dir", &a.device, a.path.as_deref(), &fmt_list).await
    }

    #[tool(description = "Details of one path on the device: whether it exists, file/dir/symlink, size, modified time (UTC) and read-only flag. Reads the device's filesystem without a shell and without an approval; prefer it over run_command (test-path, stat, dir) for checking that a path exists and for sizes and dates. Works the same on Windows, macOS and Linux. Needs hub 3.31.0 and agent 3.17.0.")]
    async fn file_info(&self, Parameters(a): Parameters<FileArgs>) -> Result<CallToolResult, ErrorData> {
        self.fs_read("stat", "file_info", &a.device, Some(&a.path), &fmt_info).await
    }

    #[tool(description = "The sha256 of a file on the device, computed by the agent: `<sha256>  <path> (<size> bytes)`. Reads the device's filesystem without a shell and without an approval; prefer it over run_command (get-filehash, sha256sum, shasum) for hashes. Works the same on Windows, macOS and Linux. Needs hub 3.31.0 and agent 3.17.0.")]
    async fn file_hash(&self, Parameters(a): Parameters<FileArgs>) -> Result<CallToolResult, ErrorData> {
        self.fs_read("hash", "file_hash", &a.device, Some(&a.path), &fmt_hash).await
    }
}

#[cfg(test)]
mod tests;
