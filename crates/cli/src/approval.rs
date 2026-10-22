// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

// How `itai` reads the hub's answer (hub 3.18.0). A privileged action comes back
// 202 pending: itai says so on stderr, polls `/m/approval` for up to `--wait`
// seconds (default 60), and carries on with the result if a human approves in
// time. Otherwise it prints the approval id and exits 75, so a script can tell
// "waiting for a human" from a failure; `itai approval <id>` checks it later.
// Denied, expired and blocked exit 1. `--dry-run` prints the hub's plan, exit 0.
use std::io::Write;

use it_ai_direct::reply::{self, Reply, Settled, Wait};
use it_ai_direct::Controller;

/// "Still waiting for a human" (EX_TEMPFAIL).
pub const EXIT_PENDING: i32 = 75;

/// What to do with a settled answer.
#[derive(Debug, PartialEq)]
pub enum Step {
    /// It ran: handle this body as the action's result.
    Run(serde_json::Value),
    /// Stop: print `text` (stdout when `code` is 0, stderr otherwise) and exit.
    Stop { text: String, code: i32 },
}

pub fn check_hint(id: &str) -> String {
    format!("Check later with: itai approval {id}")
}

/// `s` as a step. An approval is announced on `err` before its result is handed on.
pub fn step(s: Settled, err: &mut impl Write) -> Step {
    match s {
        Settled::Done(v) => Step::Run(v),
        Settled::Approved { id, approver, result, .. } => {
            let _ = writeln!(err, "{}", reply::approved_line(&id, &approver));
            Step::Run(result)
        }
        Settled::DryRun(v) => Step::Stop { text: reply::dry_run_text(&v), code: 0 },
        Settled::Pending(p) => Step::Stop { text: reply::pending_text(&p, &check_hint(&p.id)), code: EXIT_PENDING },
        Settled::Denied { id, approver } => Step::Stop { text: reply::denied_text(&id, &approver), code: 1 },
        Settled::Expired { id } => Step::Stop { text: reply::expired_text(&id), code: 1 },
        Settled::Refused { error, blocked } => Step::Stop { text: reply::refused_text(&error, blocked), code: 1 },
    }
}

/// Settle `r`, saying on `err` that it is waiting while it waits.
pub async fn resolve(ctl: &Controller, r: Reply, wait: Wait, err: &mut impl Write) -> Step {
    if let Reply::Pending(p) = &r {
        if !wait.max.is_zero() {
            let _ = writeln!(err, "Waiting for approval in the IT-AI dashboard (approval id {}), up to {}s…", p.id, wait.max.as_secs());
        }
    }
    step(ctl.settle(r, wait).await, err)
}

/// `itai approval <id>`: the approval's state, waiting up to `wait` for a decision.
pub async fn check(ctl: &Controller, id: &str, wait: Wait, err: &mut impl Write) -> Result<Step, String> {
    let v = ctl.approval(id).await?;
    let s = match Settled::from_view(&v) {
        Some(s) => s,
        None if wait.max.is_zero() => Settled::Pending(Settled::pending_of_view(&v)),
        None => {
            let _ = writeln!(err, "Waiting for approval in the IT-AI dashboard (approval id {id}), up to {}s…", wait.max.as_secs());
            ctl.wait_approval(Settled::pending_of_view(&v), wait).await
        }
    };
    Ok(match step(s, err) {
        Step::Run(v) => Step::Stop { text: reply::result_text(&v), code: 0 },
        stop => stop,
    })
}

/// Print a stop and exit with its code.
pub fn stop(text: &str, code: i32) -> ! {
    if code == 0 {
        println!("{text}");
    } else {
        eprintln!("{text}");
    }
    std::process::exit(code)
}

#[cfg(test)]
mod tests;
