// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

// list_approvals (hub 3.30.0): this owner's approval requests, from
// `GET /m/approvals[?status=pending|recent|all][&device=<name>]`, in the shape of
// the dashboard's list (`{ok, pending: […], recent: […]}`, newest first).
use it_ai_direct::op::urlencode;
use it_ai_direct::reply::Reply;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::CallToolResult;
use rmcp::{tool, tool_router, ErrorData};
use serde::Deserialize;
use serde_json::Value;

use crate::approval::text;
use crate::Srv;

const STATUSES: [&str; 3] = ["pending", "recent", "all"];

#[derive(Deserialize, schemars::JsonSchema)]
pub struct ListApprovalsArgs {
    /// "pending" (still waiting for a human), "recent" (decided ones), or "all" (default)
    #[serde(default)]
    status: Option<String>,
    /// only approvals for this device name
    #[serde(default)]
    device: Option<String>,
}

#[cfg(test)]
impl ListApprovalsArgs {
    pub fn for_test(status: Option<&str>, device: Option<&str>) -> Self {
        ListApprovalsArgs { status: status.map(Into::into), device: device.map(Into::into) }
    }
}

/// The query after `mtok`/`owner`, or the error for a status the hub does not know.
pub fn list_query(a: &ListApprovalsArgs) -> Result<String, String> {
    let mut q = Vec::new();
    if let Some(s) = a.status.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        if !STATUSES.contains(&s) {
            return Err(format!("[error] status must be one of {}, not '{s}'", STATUSES.join(", ")));
        }
        q.push(format!("status={s}"));
    }
    if let Some(d) = a.device.as_deref().filter(|d| !d.is_empty()) {
        q.push(format!("device={}", urlencode(d)));
    }
    Ok(q.join("&"))
}

fn line(a: &Value) -> String {
    let s = |k: &str| a[k].as_str().unwrap_or("");
    let mut l = format!("- {} [{}] '{}' on {}", s("id"), s("status"), s("action"), s("device"));
    if !s("detail").is_empty() {
        l.push_str(&format!(": {}", s("detail")));
    }
    if !s("token_name").is_empty() {
        l.push_str(&format!(" — requested by {}", s("token_name")));
    }
    if s("status") == "pending" {
        l.push_str(&format!(", expires {}", a["expires"].as_u64().unwrap_or(0)));
    } else if !s("approver").is_empty() {
        l.push_str(&format!(", decided by {}", s("approver")));
    }
    if let Some(c) = a["exit_code"].as_i64() {
        l.push_str(&format!(", exit {c}"));
    }
    if !s("error").is_empty() {
        l.push_str(&format!(", error: {}", s("error")));
    }
    l
}

/// A `/m/approvals` answer as text: each filled list, one approval per line.
pub fn fmt_list(v: &Value) -> String {
    if v["ok"].as_bool() != Some(true) {
        return format!("[error] {}", v["error"].as_str().unwrap_or("the hub did not return an approval list (list_approvals needs hub 3.30.0)"));
    }
    let mut out = Vec::new();
    for (k, title) in [("pending", "Waiting for a human"), ("recent", "Recently decided")] {
        if let Some(arr) = v[k].as_array() {
            out.push(format!("{title} ({}):", arr.len()));
            out.extend(arr.iter().map(line));
        }
    }
    if out.is_empty() {
        return "no approvals".to_string();
    }
    out.join("\n")
}

#[tool_router(router = approval_list_router, vis = "pub(crate)")]
impl Srv {
    #[tool(description = "List your approval requests on the hub: the ones still waiting for a human in the IT-AI dashboard, and the recently decided ones (approved, denied, expired) with who decided them. status: pending, recent or all (default). device: only that device. Use approval_status(id) for one request's result. Needs hub 3.30.0.")]
    async fn list_approvals(&self, Parameters(a): Parameters<ListApprovalsArgs>) -> Result<CallToolResult, ErrorData> {
        let q = match list_query(&a) {
            Ok(q) => q,
            Err(e) => return Ok(text(e)),
        };
        match self.hub(self.client().get(self.m("approvals", &q))).await? {
            Reply::Done(Value::String(s)) => Ok(text(format!("[error] the hub has no approval list ({}); list_approvals needs hub 3.30.0", s.trim()))),
            r => self.finish(r, &fmt_list).await,
        }
    }
}

#[cfg(test)]
mod tests;
