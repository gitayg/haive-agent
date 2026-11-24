// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

// fetch_url (hub 3.30.0): the device downloads a published https file itself and
// keeps it only if its sha256 matches. Nothing passes through this Mac or the
// relay tunnel, so it is the way to put a release asset or a CI artifact on a
// device. `/m/fetch-url` starts the download; `/m/file-status` reports it, the
// same status push_file polls.
use it_ai_direct::op::urlencode;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::CallToolResult;
use rmcp::{tool, tool_router, ErrorData};
use serde::Deserialize;
use serde_json::Value;

use crate::approval::{text, with_note};
use crate::{err, Srv};

/// The agent gives up on a download after 15 minutes; wait a little longer.
const FETCH_DEADLINE: std::time::Duration = std::time::Duration::from_secs(16 * 60);

#[derive(Deserialize, schemars::JsonSchema)]
pub struct FetchArgs {
    device: String,
    /// public https URL of the file, with no query string or fragment (e.g. a GitHub release asset)
    url: String,
    /// the file's expected sha256, 64 hex characters; the device keeps the file only if it matches
    sha256: String,
    /// destination directory on the device (default: the agent's share folder, else the user's home)
    #[serde(default)]
    dir: Option<String>,
    /// file name to save as (default: the last segment of the URL)
    #[serde(default)]
    name: Option<String>,
}

#[cfg(test)]
impl FetchArgs {
    pub fn for_test(url: &str, sha256: &str, dir: Option<&str>, name: Option<&str>) -> Self {
        FetchArgs { device: "pc1".into(), url: url.into(), sha256: sha256.into(), dir: dir.map(Into::into), name: name.map(Into::into) }
    }
}

/// The `/m/fetch-url` query after `mtok`/`owner`.
pub fn fetch_query(target: &str, a: &FetchArgs) -> String {
    let mut q = format!("target={}&url={}&sha256={}", urlencode(target), urlencode(&a.url), urlencode(a.sha256.trim()));
    for (k, v) in [("dir", &a.dir), ("name", &a.name)] {
        if let Some(v) = v.as_deref().filter(|v| !v.is_empty()) {
            q.push_str(&format!("&{k}={}", urlencode(v)));
        }
    }
    q
}

/// A finished `/file-status`, the way fetch_url reports it.
pub fn fmt_done(st: &Value) -> String {
    if st["success"].as_bool().unwrap_or(false) {
        format!("fetched {} bytes to {} (sha256 verified)", st["bytes"].as_u64().unwrap_or(0), st["path"].as_str().unwrap_or("device"))
    } else {
        format!("[error] fetch failed: {}", st["error"].as_str().unwrap_or("unknown"))
    }
}

#[tool_router(router = fetch_router, vis = "pub(crate)")]
impl Srv {
    #[tool(description = "Have the device download a file from a public https URL itself and save it only if its sha256 matches. Preferred over upload_file and push_file for anything that is already published (release assets, CI artifacts): the bytes go straight from the source to the device, not through this machine or the hub. Public https URLs only — no query string, no credentials, no IP addresses or local names. Waits for the download to finish and returns the saved path, or the error. Needs hub 3.30.0.")]
    async fn fetch_url(&self, Parameters(a): Parameters<FetchArgs>) -> Result<CallToolResult, ErrorData> {
        let target = self.resolve(&a.device).await.map_err(err)?;
        let r = self.hub(self.client().post(self.m("fetch-url", &fetch_query(&target, &a)))).await?;
        let (v, note) = match self.settled(r).await {
            Ok(x) => x,
            Err(done) => return Ok(done),
        };
        if !v["ok"].as_bool().unwrap_or(false) {
            let e = match &v {
                Value::String(s) => format!("the hub did not start the download ({}); fetch_url needs hub 3.30.0", s.trim()),
                _ => v["error"].as_str().unwrap_or("fetch failed").to_string(),
            };
            return Ok(text(with_note(note, format!("[error] {e}"))));
        }
        let job = v["job"].as_str().unwrap_or("").to_string();
        let dest = v["dest"].as_str().unwrap_or("the device").to_string();
        let status_q = format!("target={}&job={}", urlencode(&target), urlencode(&job));
        let deadline = tokio::time::Instant::now() + FETCH_DEADLINE;
        while tokio::time::Instant::now() < deadline {
            tokio::time::sleep(self.wait.every).await;
            let resp = match self.client().get(self.m("file-status", &status_q)).timeout(std::time::Duration::from_secs(30)).send().await {
                Ok(r) => r,
                Err(_) => continue,
            };
            self.seen.status(resp.status().as_u16());
            let st: Value = resp.json().await.unwrap_or_default();
            if st["done"].as_bool().unwrap_or(false) {
                return Ok(text(with_note(note, fmt_done(&st))));
            }
            // The agent forgot the job: it restarted, and the download died with it.
            if st["error"] == "unknown job" {
                return Ok(text(with_note(note, format!("[error] the device no longer knows download job {job} (the agent restarted?); nothing was saved to {dest}"))));
            }
        }
        Ok(text(with_note(note, format!("[error] the download to {dest} had not finished after 16 minutes (job {job})"))))
    }
}

#[cfg(test)]
mod tests;
