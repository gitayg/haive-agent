// End-to-end: the built `itai` binary against a scripted hub (hub 3.18.0 answers).
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use it_ai_direct::testhub::{self, FakeHub, Req, Resp};
use serde_json::json;

/// A hub with one relay device, `pc1`, and no LAN-direct route; everything else
/// goes to `f`, and `None` is a 404.
fn hub(f: impl Fn(&Req) -> Option<Resp> + Send + Sync + 'static) -> FakeHub {
    FakeHub::start(move |r| match r.path.as_str() {
        "/m/agents" => testhub::json(200, json!({"agents": [{"name": "pc1", "ip": "r1", "port": 0, "scheme": "relay"}]})),
        _ => f(r).unwrap_or_else(|| testhub::text(404, "not found")),
    })
}

fn itai(h: &FakeHub, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_itai"))
        .args(args)
        .env("HAIVE_HUB", &h.url)
        .env("HIVE_MCP_TOKEN", "TOK")
        .env("HIVE_OWNER", "me@x.io")
        .env_remove("HAIVE_CAFILE")
        .env_remove("SCREEN_PW")
        .output()
        .expect("run itai")
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn pending(id: &str) -> Resp {
    testhub::json(
        202,
        json!({"ok": false, "pending_approval": true, "status": "pending", "approval_id": id, "action": "exec",
               "tier": "privileged", "reason": "needs approval: 'rm' is not on the safe-command list", "device": "pc1",
               "expires": 1790003600, "poll": format!("/m/approval?id={id}"), "error": "approval required"}),
    )
}

/// `/m/approval` answers pending `n` times, then `then`.
fn decided_after(n: usize, then: serde_json::Value) -> impl Fn(&Req) -> Resp + Send + Sync {
    let k = Arc::new(AtomicUsize::new(0));
    move |r| {
        if k.fetch_add(1, Ordering::SeqCst) < n {
            testhub::json(200, json!({"ok": true, "id": r.param("id"), "status": "pending", "action": "exec", "device": "pc1"}))
        } else {
            testhub::json(200, then.clone())
        }
    }
}

#[test]
fn pending_says_it_is_waiting_then_exits_75_with_the_id() {
    let poll = decided_after(usize::MAX, json!({}));
    let h = hub(move |r| match r.path.as_str() {
        "/m/exec" => Some(pending("apr_1")),
        "/m/approval" => Some(poll(r)),
        _ => None,
    });
    let o = itai(&h, &["--wait", "1", "exec", "pc1", "rm", "/tmp/x"]);
    let e = err(&o);
    assert_eq!(o.status.code(), Some(75), "{e}");
    assert!(e.starts_with("Waiting for approval in the IT-AI dashboard (approval id apr_1), up to 1s…\n"), "{e}");
    assert!(e.contains("Waiting for approval in the IT-AI dashboard (approval id apr_1): 'exec' on pc1 needs a human's approval"), "{e}");
    assert!(e.trim_end().ends_with("Check later with: itai approval apr_1"), "{e}");
    assert!(!h.hits("/m/approval").is_empty());
}

#[test]
fn approved_within_the_wait_runs_with_the_remote_exit_code() {
    let poll = decided_after(
        0,
        json!({"ok": true, "id": "apr_2", "status": "executed", "approver": "boss@x.io", "result_status": 200,
               "result": {"ok": true, "stdout": "removed\n", "stderr": "", "code": 3}}),
    );
    let h = hub(move |r| match r.path.as_str() {
        "/m/exec" => Some(pending("apr_2")),
        "/m/approval" => Some(poll(r)),
        _ => None,
    });
    let o = itai(&h, &["--wait", "5", "exec", "pc1", "rm", "/tmp/x"]);
    assert_eq!(out(&o), "removed\n");
    assert_eq!(o.status.code(), Some(3), "{}", err(&o));
    assert!(err(&o).contains("Approved by boss@x.io in the IT-AI dashboard (approval id apr_2); it ran:"), "{}", err(&o));
}

#[test]
fn denied_exits_1_and_says_so() {
    let poll = decided_after(0, json!({"ok": true, "id": "apr_3", "status": "denied", "approver": "boss@x.io"}));
    let h = hub(move |r| match r.path.as_str() {
        "/m/job/start" => Some(pending("apr_3")),
        "/m/approval" => Some(poll(r)),
        _ => None,
    });
    let o = itai(&h, &["--wait", "5", "job", "start", "pc1", "--", "make"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(err(&o).contains("Denied by boss@x.io in the IT-AI dashboard (approval id apr_3). The action did not run."), "{}", err(&o));
    assert_eq!(out(&o), "");
}

#[test]
fn approval_command_reports_expired_and_executed() {
    let k = Arc::new(AtomicUsize::new(0));
    let h = hub(move |r| match r.path.as_str() {
        "/m/approval" => Some(match k.fetch_add(1, Ordering::SeqCst) {
            0 => testhub::json(200, json!({"ok": true, "id": "apr_4", "status": "expired"})),
            1 => testhub::json(200, json!({"ok": true, "id": "apr_5", "status": "executed", "approver": "boss@x.io", "result_status": 200, "result": "updated (9 bytes); restarting"})),
            _ => testhub::json(200, json!({"ok": true, "id": "apr_6", "status": "pending", "action": "update", "device": "pc1"})),
        }),
        _ => None,
    });
    let o = itai(&h, &["approval", "apr_4"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(err(&o).starts_with("Approval apr_4 expired before anyone approved it."), "{}", err(&o));
    let o = itai(&h, &["approval", "apr_5"]);
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    assert_eq!(out(&o), "updated (9 bytes); restarting\n");
    // Without --wait, `approval` does not wait: still pending is exit 75 at once.
    let o = itai(&h, &["approval", "apr_6"]);
    assert_eq!(o.status.code(), Some(75));
    assert!(err(&o).starts_with("Waiting for approval in the IT-AI dashboard (approval id apr_6): 'update' on pc1"), "{}", err(&o));
    assert_eq!(h.hits("/m/approval")[0].param("id").as_deref(), Some("apr_4"));
}

#[test]
fn blocked_exits_1_without_waiting() {
    let h = hub(|r| match r.path.as_str() {
        "/m/exec" => Some(testhub::json(403, json!({"ok": false, "error": "command blocked by hub policy (matched 'mkfs')", "tier": "blocked", "action": "exec"}))),
        _ => None,
    });
    let o = itai(&h, &["exec", "pc1", "mkfs", "/dev/sda"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(err(&o).starts_with("Blocked by the hub's policy: command blocked by hub policy (matched 'mkfs')."), "{}", err(&o));
    assert!(h.hits("/m/approval").is_empty());
}

#[test]
fn dry_run_passes_the_flag_and_prints_the_plan() {
    let h = hub(|r| match r.path.as_str() {
        "/m/exec" | "/m/job/start" | "/m/upload" => Some(testhub::json(
            200,
            json!({"ok": true, "dry_run": true, "action": "exec", "tier": "privileged", "needs_approval": true,
                   "reason": "needs approval: 'reboot' is not on the safe-command list", "devices": ["pc1"], "detail": "reboot",
                   "would": "file an approval request; run once a human approves"}),
        )),
        _ => None,
    });
    let o = itai(&h, &["--dry-run", "exec", "pc1", "reboot"]);
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    assert!(out(&o).starts_with("Dry run, nothing ran: 'exec' is tier privileged, needs a human's approval"), "{}", out(&o));
    assert!(out(&o).contains("\nDevices: pc1\n"), "{}", out(&o));
    assert_eq!(itai(&h, &["job", "start", "pc1", "--dry-run", "--", "make"]).status.code(), Some(0));
    assert_eq!(itai(&h, &["--dry-run", "put", "pc1", "/definitely/not/here.bin"]).status.code(), Some(0));
    for p in ["/m/exec", "/m/job/start", "/m/upload"] {
        let hits = h.hits(p);
        assert_eq!(hits.len(), 1, "{p}");
        assert_eq!(hits[0].param("dry_run").as_deref(), Some("1"), "{p}");
    }
    assert!(h.hits("/m/direct").is_empty() && h.hits("/m/capability").is_empty());
}

#[test]
fn every_request_carries_the_client_header() {
    let h = hub(|r| match r.path.as_str() {
        "/m/exec" => Some(testhub::json(200, json!({"ok": true, "stdout": "hi\n", "stderr": "", "code": 0}))),
        _ => None,
    });
    let o = itai(&h, &["exec", "pc1", "echo", "hi"]);
    assert_eq!((o.status.code(), out(&o)), (Some(0), "hi\n".to_string()), "{}", err(&o));
    let reqs = h.requests();
    assert!(reqs.len() >= 3, "{reqs:?}");
    for r in reqs {
        assert_eq!(r.header("X-IT-AI-Client"), Some("cli"), "{} {}", r.method, r.path);
    }
}
