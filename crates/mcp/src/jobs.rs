// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

// Background-job tools (docs/JOBS-API.md, "CLI and MCP"): job_start, job_logs,
// job_stop, job_list. Jobs are relay-only in this version, so these call the
// hub's `/m/job/*` routes directly rather than `Controller::call_device`.
use it_ai_direct::op::urlencode;
use it_ai_direct::reply::Reply;
use it_ai_direct::Controller;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock};
use rmcp::{tool, tool_router, ErrorData};
use serde::Deserialize;

use crate::approval::with_note;
use crate::{DeviceArg, Srv};

const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

#[derive(Deserialize, schemars::JsonSchema)]
pub struct JobStartArgs {
    device: String,
    /// shell command to run in the background on the device
    command: String,
    /// working directory on the device (optional)
    #[serde(default)]
    cwd: Option<String>,
    /// true = only ask the hub what this would do (tier, approval, devices); nothing runs
    #[serde(default)]
    dry_run: bool,
}
#[derive(Deserialize, schemars::JsonSchema)]
pub struct JobLogsArgs {
    device: String,
    /// job id returned by job_start
    id: String,
    /// byte offset to read from — pass back the `offset` the previous job_logs returned (default 0)
    #[serde(default)]
    offset: Option<u64>,
}
#[derive(Deserialize, schemars::JsonSchema)]
pub struct JobIdArgs {
    device: String,
    /// job id returned by job_start
    id: String,
    /// true = only ask the hub what this would do (tier, approval, devices); nothing runs
    #[serde(default)]
    dry_run: bool,
}

#[cfg(test)]
impl JobStartArgs {
    pub fn for_test(device: &str, command: &str, dry_run: bool) -> Self {
        JobStartArgs { device: device.into(), command: command.into(), cwd: None, dry_run }
    }
}

pub fn start_url(ctl: &Controller, target: &str) -> String {
    ctl.hub_url("job/start", &format!("target={}", urlencode(target)))
}

pub fn logs_url(ctl: &Controller, target: &str, id: &str, offset: u64) -> String {
    ctl.hub_url(
        "job/logs",
        &format!("target={}&id={}&offset={offset}", urlencode(target), urlencode(id)),
    )
}

pub fn stop_url(ctl: &Controller, target: &str, id: &str) -> String {
    ctl.hub_url("job/stop", &format!("target={}&id={}", urlencode(target), urlencode(id)))
}

pub fn list_url(ctl: &Controller, target: &str) -> String {
    ctl.hub_url("job/list", &format!("target={}", urlencode(target)))
}

pub fn start_body(command: &str, cwd: Option<&str>) -> serde_json::Value {
    let mut body = serde_json::json!({ "cmd": command });
    if let Some(dir) = cwd.filter(|d| !d.is_empty()) {
        body["cwd"] = serde_json::json!(dir);
    }
    body
}

/// Mask any `mtok=` query value in an error message. `Controller::resolve`
/// returns reqwest errors verbatim, and their Display includes the hub URL.
pub fn redact_token(msg: &str) -> String {
    let mut out = String::with_capacity(msg.len());
    let mut rest = msg;
    while let Some(i) = rest.find("mtok=") {
        out.push_str(&rest[..i + 5]);
        rest = &rest[i + 5..];
        let end = rest.find(|c: char| c == '&' || c == ')' || c.is_whitespace()).unwrap_or(rest.len());
        if end > 0 {
            out.push_str("***");
        }
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

fn jerr(e: impl ToString) -> ErrorData {
    ErrorData::internal_error(redact_token(&e.to_string()), None)
}

/// Send a hub request and classify its answer. reqwest errors are stripped of
/// their URL, which carries the `mtok` token.
async fn send(srv: &Srv, rb: reqwest::RequestBuilder) -> Result<Reply, ErrorData> {
    srv.ctl.hub_send(rb.timeout(REQUEST_TIMEOUT)).await.map_err(jerr)
}

fn text(s: String) -> CallToolResult {
    CallToolResult::success(vec![ContentBlock::text(s)])
}

/// A hub or agent refusal (`{"ok":false}`), reported the way run_command does.
fn refused(v: &serde_json::Value) -> Option<CallToolResult> {
    if v["ok"].as_bool().unwrap_or(false) {
        return None;
    }
    Some(text(format!("[error] {}", v["error"].as_str().unwrap_or("failed"))))
}

pub fn fmt_logs(v: &serde_json::Value) -> Vec<ContentBlock> {
    let meta = serde_json::json!({
        "offset": v["offset"],
        "running": v["running"],
        "exit_code": v["exit_code"],
        "eof": v["eof"],
        "size": v["size"],
    });
    let data = v["data"].as_str().unwrap_or("");
    vec![
        ContentBlock::text(meta.to_string()),
        ContentBlock::text(if data.is_empty() { "(no new output)".to_string() } else { data.to_string() }),
    ]
}

fn exit_label(v: &serde_json::Value) -> String {
    v.as_i64().map(|c| c.to_string()).unwrap_or_else(|| "unknown".to_string())
}

pub fn fmt_list(v: &serde_json::Value) -> String {
    let jobs = v["jobs"].as_array().cloned().unwrap_or_default();
    if jobs.is_empty() {
        return "no jobs".to_string();
    }
    jobs.iter()
        .map(|j| {
            let state = if j["running"].as_bool().unwrap_or(false) {
                "running".to_string()
            } else {
                format!("exit {}", exit_label(&j["exit_code"]))
            };
            format!(
                "{} [{state}] pid {} started {} — {}",
                j["id"].as_str().unwrap_or(""),
                j["pid"].as_u64().unwrap_or(0),
                j["started"].as_u64().unwrap_or(0),
                j["cmd"].as_str().unwrap_or("")
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[tool_router(router = job_router, vis = "pub(crate)")]
impl Srv {
    #[tool(description = "Start a long-running command on the named device in the background (dev servers, builds, anything past run_command's ~65s limit). Returns the job id; read its output with job_logs and end it with job_stop. Like run_command, a command that is not on the hub's read-only allowlist needs a human's approval in the IT-AI dashboard (the tool waits up to 60 s, then returns an approval id for approval_status).")]
    pub(crate) async fn job_start(&self, Parameters(a): Parameters<JobStartArgs>) -> Result<CallToolResult, ErrorData> {
        let target = self.resolve(&a.device).await.map_err(jerr)?;
        let body = start_body(&a.command, a.cwd.as_deref());
        let mut url = start_url(&self.ctl, &target);
        if a.dry_run {
            url.push_str("&dry_run=1");
        }
        let (v, note) = match self.settled(send(self, self.client().post(url).json(&body)).await?).await {
            Ok(x) => x,
            Err(r) => return Ok(r),
        };
        if let Some(r) = refused(&v) {
            return Ok(r);
        }
        Ok(text(with_note(
            note,
            format!(
                "started job {} (pid {}, log {})",
                v["id"].as_str().unwrap_or(""),
                v["pid"].as_u64().unwrap_or(0),
                v["log"].as_str().unwrap_or("")
            ),
        )))
    }

    #[tool(description = "Read a background job's output from a byte offset. Returns a JSON line with the next `offset`, `running`, `exit_code` and `eof`, then the output text. Call again with the returned offset to read what was written since; stop when eof is true.")]
    async fn job_logs(&self, Parameters(a): Parameters<JobLogsArgs>) -> Result<CallToolResult, ErrorData> {
        let target = self.resolve(&a.device).await.map_err(jerr)?;
        let (v, _) = match self.settled(send(self, self.client().get(logs_url(&self.ctl, &target, &a.id, a.offset.unwrap_or(0)))).await?).await {
            Ok(x) => x,
            Err(r) => return Ok(r),
        };
        if let Some(r) = refused(&v) {
            return Ok(r);
        }
        Ok(CallToolResult::success(fmt_logs(&v)))
    }

    #[tool(description = "Stop a background job (and its child processes) on the named device.")]
    async fn job_stop(&self, Parameters(a): Parameters<JobIdArgs>) -> Result<CallToolResult, ErrorData> {
        let target = self.resolve(&a.device).await.map_err(jerr)?;
        let mut url = stop_url(&self.ctl, &target, &a.id);
        if a.dry_run {
            url.push_str("&dry_run=1");
        }
        let (v, note) = match self.settled(send(self, self.client().post(url)).await?).await {
            Ok(x) => x,
            Err(r) => return Ok(r),
        };
        if let Some(r) = refused(&v) {
            return Ok(r);
        }
        let verb = if v["stopped"].as_bool().unwrap_or(false) { "stopped" } else { "was not running" };
        Ok(text(with_note(note, format!("{} {verb} (exit {})", a.id, exit_label(&v["exit_code"])))))
    }

    #[tool(description = "List the background jobs on the named device: id, running or exit code, pid, start time (unix secs) and command.")]
    async fn job_list(&self, Parameters(a): Parameters<DeviceArg>) -> Result<CallToolResult, ErrorData> {
        let target = self.resolve(&a.device).await.map_err(jerr)?;
        let (v, _) = match self.settled(send(self, self.client().get(list_url(&self.ctl, &target))).await?).await {
            Ok(x) => x,
            Err(r) => return Ok(r),
        };
        if let Some(r) = refused(&v) {
            return Ok(r);
        }
        Ok(text(fmt_list(&v)))
    }
}

#[cfg(test)]
mod tests;
