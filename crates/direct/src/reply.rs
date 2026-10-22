// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

//! The hub's graduated-autonomy answers (hub 3.18.0), read the same way by `itai`
//! and `it-ai-mcp`.
//!
//! Every `/m` action is classified into a tier before it reaches a device:
//! `read` and `change` run, `blocked` is refused with 403, and `privileged` does
//! not run at all — the hub files an approval request and answers 202
//! `{pending_approval, approval_id, poll}`. A human approves or denies it in the
//! dashboard; `GET /m/approval?id=` reports `pending | running | executed |
//! denied | expired` and, once executed, the result of the one replayed call.
//! `dry_run=1` on any action returns the classification and does nothing.

use std::time::Duration;

use serde_json::Value;

/// The header the hub reads to attribute a call made with the shared (legacy)
/// token to a CLI or an AI agent. A scoped token carries its own kind.
pub const CLIENT_HEADER: &str = "X-IT-AI-Client";

/// Default headers for a binary's hub client: `X-IT-AI-Client: <kind>`.
pub fn client_headers(kind: &'static str) -> reqwest::header::HeaderMap {
    let mut h = reqwest::header::HeaderMap::new();
    h.insert(CLIENT_HEADER, reqwest::header::HeaderValue::from_static(kind));
    h
}

/// How long to wait for a human, and how often to ask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Wait {
    pub max: Duration,
    pub every: Duration,
}

impl Wait {
    pub const fn secs(max: u64) -> Self {
        Wait { max: Duration::from_secs(max), every: Duration::from_secs(2) }
    }
}

impl Default for Wait {
    fn default() -> Self {
        Wait::secs(60)
    }
}

/// A privileged request the hub stored instead of running.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    pub id: String,
    pub action: String,
    pub device: String,
    pub reason: String,
    pub expires: u64,
}

impl Pending {
    fn from_json(v: &Value) -> Option<Pending> {
        let s = |k: &str| v[k].as_str().unwrap_or("").to_string();
        let id = v["approval_id"].as_str().or_else(|| v["id"].as_str())?.to_string();
        Some(Pending { id, action: s("action"), device: s("device"), reason: s("reason"), expires: v["expires"].as_u64().unwrap_or(0) })
    }
}

/// One hub answer, classified.
#[derive(Debug, Clone, PartialEq)]
pub enum Reply {
    /// It ran (or the handler answered on its own terms, `ok:false` included).
    /// A body that is not JSON is carried as a JSON string.
    Done(Value),
    /// 202: a human must approve it first.
    Pending(Pending),
    /// 403: refused. `blocked` = the hub's policy put it in the blocked tier.
    Refused { error: String, blocked: bool },
    /// `dry_run=1`: the plan, nothing ran.
    DryRun(Value),
}

impl Reply {
    pub fn parse(status: u16, body: &[u8]) -> Reply {
        let v: Option<Value> = serde_json::from_slice(body).ok();
        if let Some(v) = &v {
            if v["pending_approval"].as_bool() == Some(true) {
                if let Some(p) = Pending::from_json(v) {
                    return Reply::Pending(p);
                }
            }
            if v["dry_run"].as_bool() == Some(true) {
                return Reply::DryRun(v.clone());
            }
        }
        if status == 403 {
            let text = String::from_utf8_lossy(body).trim().to_string();
            let error = v.as_ref().and_then(|v| v["error"].as_str().map(String::from)).unwrap_or(text);
            let blocked = v.as_ref().map(|v| v["tier"] == "blocked").unwrap_or(false);
            return Reply::Refused { error: if error.is_empty() { "refused".into() } else { error }, blocked };
        }
        Reply::Done(v.unwrap_or_else(|| Value::String(String::from_utf8_lossy(body).into_owned())))
    }
}

/// Read a whole response as a `Reply`. The error carries no URL (it holds `mtok`).
pub async fn read(resp: reqwest::Response) -> Result<Reply, String> {
    let status = resp.status().as_u16();
    let body = resp.bytes().await.map_err(|e| e.without_url().to_string())?;
    Ok(Reply::parse(status, &body))
}

/// For the calls whose success is raw bytes (frame, camera, download): the bytes
/// on a plain success, else the classified answer (202 pending, 403, an error).
pub async fn bytes_or_reply(resp: reqwest::Response) -> Result<Result<Vec<u8>, Reply>, String> {
    let status = resp.status();
    let body = resp.bytes().await.map_err(|e| e.without_url().to_string())?;
    if status.is_success() && status.as_u16() != 202 {
        return Ok(Ok(body.to_vec()));
    }
    Ok(Err(Reply::parse(status.as_u16(), &body)))
}

/// Where a request ended up after any wait for a human.
#[derive(Debug, Clone, PartialEq)]
pub enum Settled {
    Done(Value),
    /// Approved and run; `result` is the replayed call's response body.
    Approved { id: String, approver: String, status: u16, result: Value },
    /// Still waiting for a human when the wait ran out.
    Pending(Pending),
    Denied { id: String, approver: String },
    Expired { id: String },
    Refused { error: String, blocked: bool },
    DryRun(Value),
}

impl Settled {
    /// A decided `/m/approval` view; `None` while it is still pending or running.
    pub fn from_view(v: &Value) -> Option<Settled> {
        let id = v["id"].as_str().unwrap_or("").to_string();
        let approver = v["approver"].as_str().unwrap_or("").to_string();
        match v["status"].as_str() {
            Some("executed") => Some(Settled::Approved {
                id,
                approver,
                status: v["result_status"].as_u64().unwrap_or(0) as u16,
                result: v["result"].clone(),
            }),
            Some("denied") => Some(Settled::Denied { id, approver }),
            Some("expired") => Some(Settled::Expired { id }),
            _ => None,
        }
    }

    /// The still-pending request an `/m/approval` view describes.
    pub fn pending_of_view(v: &Value) -> Pending {
        Pending::from_json(v).unwrap_or_else(|| Pending {
            id: String::new(),
            action: String::new(),
            device: String::new(),
            reason: String::new(),
            expires: 0,
        })
    }
}

pub fn pending_text(p: &Pending, check: &str) -> String {
    let on = if p.device.is_empty() || p.device == "—" { String::new() } else { format!(" on {}", p.device) };
    let why = if p.reason.is_empty() { String::new() } else { format!(" ({})", p.reason) };
    format!(
        "Waiting for approval in the IT-AI dashboard (approval id {}): '{}'{on} needs a human's approval{why}. It has not run. {check}",
        p.id, p.action
    )
}

pub fn approved_line(id: &str, approver: &str) -> String {
    let by = if approver.is_empty() { String::new() } else { format!(" by {approver}") };
    format!("Approved{by} in the IT-AI dashboard (approval id {id}); it ran:")
}

pub fn denied_text(id: &str, approver: &str) -> String {
    let by = if approver.is_empty() { String::new() } else { format!(" by {approver}") };
    format!("Denied{by} in the IT-AI dashboard (approval id {id}). The action did not run. Do not retry it or reach the same result another way; tell the user.")
}

pub fn expired_text(id: &str) -> String {
    format!("Approval {id} expired before anyone approved it. The action did not run. Asking again files a new approval request.")
}

pub fn refused_text(error: &str, blocked: bool) -> String {
    if blocked {
        format!("Blocked by the hub's policy: {error}. It did not run, and retrying will not change that. Report it; do not reword, split or reroute the action.")
    } else {
        format!("Refused by the hub (HTTP 403): {error}. It did not run.")
    }
}

/// A `dry_run=1` answer, for people.
pub fn dry_run_text(v: &Value) -> String {
    let s = |k: &str| v[k].as_str().unwrap_or("").to_string();
    let approval = if v["needs_approval"].as_bool() == Some(true) { ", needs a human's approval" } else { "" };
    let mut out = format!("Dry run, nothing ran: '{}' is tier {}{approval}; the hub would {}.", s("action"), s("tier"), s("would"));
    if !s("reason").is_empty() {
        out.push_str(&format!("\nReason: {}", s("reason")));
    }
    let devices: Vec<&str> = v["devices"].as_array().map(|a| a.iter().filter_map(|x| x.as_str()).collect()).unwrap_or_default();
    out.push_str(&format!("\nDevices: {}", if devices.is_empty() { "(none)".to_string() } else { devices.join(", ") }));
    if !s("detail").is_empty() {
        out.push_str(&format!("\nDetail: {}", s("detail")));
    }
    if let Some(f) = v.get("fleet").filter(|f| f.is_object()) {
        out.push_str(&format!(
            "\nFleet: at most {} devices; the first {} run as a canary and a failure stops the rest.",
            f["max_devices"].as_u64().unwrap_or(0),
            f["canary"].as_u64().unwrap_or(0)
        ));
    }
    if let Some(r) = v["refusal"].as_str() {
        out.push_str(&format!("\nRefusal: {r}"));
    }
    out
}

/// A fleet answer (`/m/fleet`, `/m/script-fleet`): one section per device, with a
/// canary stop and the devices it skipped said up front, and a refusal (the
/// blast-radius cap) as an error rather than "no devices".
pub fn fmt_fleet(v: &Value) -> String {
    let results = v["results"].as_array();
    let mut head = String::new();
    if v["stopped"].as_bool() == Some(true) {
        let skipped: Vec<&str> = v["skipped"].as_array().map(|a| a.iter().filter_map(|x| x.as_str()).collect()).unwrap_or_default();
        head = format!(
            "STOPPED: {}. Not run on {} device(s){}{}.",
            v["error"].as_str().unwrap_or("a canary device failed"),
            skipped.len(),
            if skipped.is_empty() { "" } else { ": " },
            skipped.join(", ")
        );
    } else if results.map(|a| a.is_empty()).unwrap_or(true) {
        if let Some(e) = v["error"].as_str() {
            return format!("[error] {e}");
        }
        if results.is_none() {
            let raw: String = v.to_string().chars().take(300).collect();
            return format!("[error] the hub's reply had no per-device results: {raw}");
        }
    }
    let body = results
        .filter(|a| !a.is_empty())
        .map(|arr| {
            arr.iter()
                .map(|r| {
                    let failed = if r["ok"].as_bool() == Some(false) { " (failed)" } else { "" };
                    format!("### {}{failed}\n{}", r["device"].as_str().unwrap_or("?"), r["output"].as_str().unwrap_or(""))
                })
                .collect::<Vec<_>>()
                .join("\n\n")
        })
        .unwrap_or_else(|| "no devices".to_string());
    if head.is_empty() {
        body
    } else {
        format!("{head}\n\n{body}")
    }
}

/// Any action's result, for when the caller does not know its shape (an approval
/// looked up later by id).
pub fn result_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "(no output)".to_string(),
        _ if v.get("results").is_some() => fmt_fleet(v),
        _ if v.get("stdout").is_some() || v.get("stderr").is_some() => {
            let s = format!("{}{}", v["stdout"].as_str().unwrap_or(""), v["stderr"].as_str().unwrap_or(""));
            match v["code"].as_i64() {
                Some(c) if s.is_empty() => format!("(exit {c})"),
                Some(c) if c != 0 => format!("{s}\n(exit {c})"),
                _ => s,
            }
        }
        _ if v["ok"].as_bool() == Some(false) => format!("[error] {}", v["error"].as_str().unwrap_or("failed")),
        _ => match v["output"].as_str() {
            Some(o) => o.to_string(),
            None => serde_json::to_string_pretty(v).unwrap_or_default(),
        },
    }
}
