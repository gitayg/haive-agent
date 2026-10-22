// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

// How every tool reads the hub's answer (hub 3.18.0): a privileged action comes
// back 202 pending, so the tool polls `/m/approval` for up to `Srv::wait` and
// returns the result if a human approves in time — otherwise the approval id, to
// look up later with `approval_status`. Denied, expired and blocked are errors.
use it_ai_direct::reply::{self, Reply, Settled};
use it_ai_direct::Op;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock};
use rmcp::{tool, tool_router, ErrorData};
use serde::Deserialize;
use serde_json::Value;

use crate::{err, Srv};

#[derive(Deserialize, schemars::JsonSchema)]
pub struct ApprovalArgs {
    /// the approval id (apr_…) a privileged action returned
    id: String,
}

pub fn text(s: String) -> CallToolResult {
    CallToolResult::success(vec![ContentBlock::text(s)])
}

fn error(s: String) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(s)])
}

pub fn check_hint(id: &str) -> String {
    format!("Check later with approval_status(id: \"{id}\"). Do not resend the action: that files a second approval request.")
}

/// A settled answer as a tool result; `fmt` renders a result body.
pub fn settled_result(s: Settled, fmt: &(dyn Fn(&Value) -> String + Sync)) -> CallToolResult {
    let body = |v: &Value| if let Value::String(s) = v { s.clone() } else { fmt(v) };
    match s {
        Settled::Done(v) => text(body(&v)),
        Settled::Approved { id, approver, result, .. } => text(format!("{}\n{}", reply::approved_line(&id, &approver), body(&result))),
        Settled::DryRun(v) => text(reply::dry_run_text(&v)),
        Settled::Pending(p) => text(reply::pending_text(&p, &check_hint(&p.id))),
        Settled::Denied { id, approver } => error(reply::denied_text(&id, &approver)),
        Settled::Expired { id } => error(reply::expired_text(&id)),
        Settled::Refused { error: e, blocked } => error(reply::refused_text(&e, blocked)),
    }
}

impl Srv {
    /// Send a hub request and classify its answer.
    pub(crate) async fn hub(&self, rb: reqwest::RequestBuilder) -> Result<Reply, ErrorData> {
        self.ctl.hub_send(rb).await.map_err(err)
    }

    /// Run `op` on a device (LAN-direct or relay), or only ask the hub about it.
    pub(crate) async fn device_reply(&self, target: &str, op: Op, dry_run: bool) -> Result<Reply, ErrorData> {
        let resp = if dry_run { self.ctl.dry_run(target, op).await } else { self.ctl.call_device(target, op).await }.map_err(err)?;
        reply::read(resp).await.map_err(err)
    }

    /// Settle `r` (waiting for an approval if it needs one) and render it.
    pub(crate) async fn finish(&self, r: Reply, fmt: &(dyn Fn(&Value) -> String + Sync)) -> Result<CallToolResult, ErrorData> {
        Ok(settled_result(self.ctl.settle(r, self.wait).await, fmt))
    }

    /// Settle `r`: the body it ran with (plus an "approved by" line when a human
    /// approved it), or the tool result to return instead.
    pub(crate) async fn settled(&self, r: Reply) -> Result<(Value, Option<String>), CallToolResult> {
        match self.ctl.settle(r, self.wait).await {
            Settled::Done(v) => Ok((v, None)),
            Settled::Approved { id, approver, result, .. } => Ok((result, Some(reply::approved_line(&id, &approver)))),
            other => Err(settled_result(other, &reply::result_text)),
        }
    }
}

pub fn with_note(note: Option<String>, body: String) -> String {
    match note {
        Some(n) => format!("{n}\n{body}"),
        None => body,
    }
}

#[tool_router(router = approval_router, vis = "pub(crate)")]
impl Srv {
    #[tool(description = "Check an approval request by id. A privileged action (run_command with a non-allowlisted program, job_start, run_script, fleet_run, uninstall, power actions, update_agent, dissolve_agent, …) does not run until a human approves it in the IT-AI dashboard; the tool waits up to 60 s and otherwise returns an approval id. This returns its status — still waiting, denied, expired — or, once approved, the action's result.")]
    async fn approval_status(&self, Parameters(a): Parameters<ApprovalArgs>) -> Result<CallToolResult, ErrorData> {
        let v = match self.ctl.approval(&a.id).await {
            Ok(v) => v,
            Err(e) => return Ok(error(format!("[error] {}", crate::jobs::redact_token(&e)))),
        };
        Ok(match Settled::from_view(&v) {
            Some(s) => settled_result(s, &reply::result_text),
            None => {
                let p = Settled::pending_of_view(&v);
                let state = v["status"].as_str().unwrap_or("pending");
                text(format!(
                    "Approval {} is still {state}: '{}' on {} ({}). It has not run; a human must approve it in the IT-AI dashboard.",
                    p.id,
                    p.action,
                    p.device,
                    v["detail"].as_str().unwrap_or("")
                ))
            }
        })
    }
}

#[cfg(test)]
mod tests;
