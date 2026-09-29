// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

// `itai job …` — background jobs on a device (docs/JOBS-API.md, "CLI and MCP").
//
// Jobs are relay-only in this version, so these calls go straight to the hub's
// `/m/job/*` routes rather than through `Controller::call_device`.
use std::future::Future;
use std::io::Write;
use std::time::Duration;

use clap::Subcommand;
use it_ai_direct::op::urlencode;
use it_ai_direct::Controller;

const FOLLOW_INTERVAL: Duration = Duration::from_secs(2);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Subcommand, Debug)]
pub enum JobCmd {
    /// start a long-running command on a device; prints the job id
    Start {
        device: String,
        /// working directory on the device
        #[arg(long)]
        cwd: Option<String>,
        /// the command, after `--`
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// print a job's output
    Logs {
        device: String,
        id: String,
        /// byte offset to read from
        #[arg(long, default_value_t = 0)]
        offset: u64,
        /// keep polling until the job exits, then print its exit code
        #[arg(long)]
        follow: bool,
    },
    /// stop a job and its child processes
    Stop { device: String, id: String },
    /// list the jobs on a device
    List { device: String },
}

impl JobCmd {
    pub fn device(&self) -> &str {
        match self {
            JobCmd::Start { device, .. }
            | JobCmd::Logs { device, .. }
            | JobCmd::Stop { device, .. }
            | JobCmd::List { device } => device,
        }
    }
}

type R = Result<(), Box<dyn std::error::Error>>;

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

pub fn start_body(command: &[String], cwd: Option<&str>) -> serde_json::Value {
    let mut body = serde_json::json!({ "cmd": command.join(" ") });
    if let Some(dir) = cwd {
        body["cwd"] = serde_json::json!(dir);
    }
    body
}

/// Send a hub request and return its JSON, turning `{"ok":false}` into an error.
/// reqwest errors are stripped of their URL: it carries the `mtok` token.
async fn send(rb: reqwest::RequestBuilder) -> Result<serde_json::Value, String> {
    let r = rb.timeout(REQUEST_TIMEOUT).send().await.map_err(|e| e.without_url().to_string())?;
    let status = r.status();
    let text = r.text().await.map_err(|e| e.without_url().to_string())?;
    let v: serde_json::Value = serde_json::from_str(&text).map_err(|_| {
        let snippet: String = text.chars().take(200).collect();
        format!("hub returned HTTP {status}: {snippet}")
    })?;
    if !v["ok"].as_bool().unwrap_or(false) {
        return Err(v["error"].as_str().unwrap_or("failed").to_string());
    }
    Ok(v)
}

/// Print one log chunk and return the offset to read from next. A response with
/// no numeric `offset` is refused rather than re-polled at the same offset forever.
fn next_offset(v: &serde_json::Value) -> Result<u64, String> {
    v["offset"].as_u64().ok_or_else(|| "malformed job/logs response: no offset".to_string())
}

/// Poll `fetch` from `offset` until the job reports `eof`, writing each chunk's
/// `data` to `out`. Returns the job's exit code (None when the agent has none).
/// Waits `pause` between polls unless the last read stopped short of `size`.
pub async fn follow<F, Fut, P, PFut>(
    mut offset: u64,
    mut fetch: F,
    mut pause: P,
    out: &mut impl Write,
) -> Result<Option<i64>, String>
where
    F: FnMut(u64) -> Fut,
    Fut: Future<Output = Result<serde_json::Value, String>>,
    P: FnMut() -> PFut,
    PFut: Future<Output = ()>,
{
    loop {
        let v = fetch(offset).await?;
        out.write_all(v["data"].as_str().unwrap_or("").as_bytes()).map_err(|e| e.to_string())?;
        out.flush().map_err(|e| e.to_string())?;
        offset = next_offset(&v)?;
        if v["eof"].as_bool().unwrap_or(false) {
            return Ok(v["exit_code"].as_i64());
        }
        if offset >= v["size"].as_u64().unwrap_or(0) {
            pause().await;
        }
    }
}

fn exit_label(code: Option<i64>) -> String {
    code.map(|c| c.to_string()).unwrap_or_else(|| "unknown".to_string())
}

pub async fn run(ctl: &Controller, target: &str, cmd: &JobCmd) -> R {
    let client = ctl.client();
    match cmd {
        JobCmd::Start { cwd, command, .. } => {
            let v = send(client.post(start_url(ctl, target)).json(&start_body(command, cwd.as_deref()))).await?;
            println!("{}", v["id"].as_str().unwrap_or(""));
        }
        JobCmd::Logs { id, offset, follow: false, .. } => {
            let v = send(client.get(logs_url(ctl, target, id, *offset))).await?;
            print!("{}", v["data"].as_str().unwrap_or(""));
            let state = if v["running"].as_bool().unwrap_or(false) {
                "running".to_string()
            } else {
                format!("exited {}", exit_label(v["exit_code"].as_i64()))
            };
            eprintln!("[next offset {} · {state}]", next_offset(&v)?);
        }
        JobCmd::Logs { id, offset, follow: true, .. } => {
            let fetch = |off: u64| send(client.get(logs_url(ctl, target, id, off)));
            let pause = || tokio::time::sleep(FOLLOW_INTERVAL);
            let code = follow(*offset, fetch, pause, &mut std::io::stdout()).await?;
            eprintln!("exit code: {}", exit_label(code));
        }
        JobCmd::Stop { id, .. } => {
            let v = send(client.post(stop_url(ctl, target, id))).await?;
            if v["stopped"].as_bool().unwrap_or(false) {
                println!("stopped {id} (exit {})", exit_label(v["exit_code"].as_i64()));
            } else {
                println!("{id} was not running (exit {})", exit_label(v["exit_code"].as_i64()));
            }
        }
        JobCmd::List { .. } => {
            let v = send(client.get(list_url(ctl, target))).await?;
            for j in v["jobs"].as_array().into_iter().flatten() {
                let state = if j["running"].as_bool().unwrap_or(false) {
                    "running".to_string()
                } else {
                    format!("exit {}", exit_label(j["exit_code"].as_i64()))
                };
                println!(
                    "{:22} {:10} pid {:<8} {}",
                    j["id"].as_str().unwrap_or(""),
                    state,
                    j["pid"].as_u64().unwrap_or(0),
                    j["cmd"].as_str().unwrap_or("")
                );
            }
        }
    }
    Ok(())
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

#[cfg(test)]
mod tests;
