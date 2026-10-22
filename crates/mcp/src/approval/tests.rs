use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use it_ai_direct::testhub::{self, FakeHub, Req, Resp};
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::*;

const FAST: Wait = Wait { max: Duration::from_millis(300), every: Duration::from_millis(20) };

/// A hub with one relay device, `pc1`, and no LAN-direct route; every other
/// request goes to `f`, and `None` from it is a 404.
fn hub(f: impl Fn(&Req) -> Option<Resp> + Send + Sync + 'static) -> FakeHub {
    FakeHub::start(move |r| match r.path.as_str() {
        "/m/agents" => testhub::json(200, json!({"agents": [{"name": "pc1", "ip": "r1", "port": 0, "scheme": "relay"}]})),
        _ => f(r).unwrap_or_else(|| testhub::text(404, "not found")),
    })
}

fn srv(h: &FakeHub) -> Srv {
    Srv::with(Controller::new(h.url.clone(), "TOK".into(), "me@x.io".into(), reqwest::Client::new()), "me@x.io".into(), FAST)
}

fn pending(id: &str, action: &str) -> Resp {
    testhub::json(
        202,
        json!({"ok": false, "pending_approval": true, "status": "pending", "approval_id": id, "action": action,
               "tier": "privileged", "reason": "needs approval: 'rm' is not on the safe-command list", "device": "pc1",
               "expires": 1790003600, "poll": format!("/m/approval?id={id}"),
               "error": format!("approval required: poll GET /m/approval?id={id}")}),
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

fn out(r: &CallToolResult) -> String {
    r.content.iter().filter_map(|c| c.as_text().map(|t| t.text.clone())).collect::<Vec<_>>().join("\n")
}

fn run(cmd: &str, dry_run: bool) -> Parameters<RunArgs> {
    Parameters(RunArgs { device: "pc1".into(), command: cmd.into(), detach: false, dry_run })
}

#[tokio::test]
async fn pending_approval_says_it_is_waiting_and_gives_the_id() {
    let poll = decided_after(usize::MAX, json!({}));
    let h = hub(move |r| match r.path.as_str() {
        "/m/exec" => Some(pending("apr_1", "exec")),
        "/m/approval" => Some(poll(r)),
        _ => None,
    });
    let r = srv(&h).run_command(run("rm -rf /tmp/x", false)).await.unwrap();
    let t = out(&r);
    assert_eq!(r.is_error, Some(false), "{t}");
    assert!(t.starts_with("Waiting for approval in the IT-AI dashboard (approval id apr_1): 'exec' on pc1 needs a human's approval"), "{t}");
    assert!(t.contains("approval_status(id: \"apr_1\")"), "{t}");
    assert!(!h.hits("/m/approval").is_empty(), "the tool polled before giving up");
    // The privileged call went to the relay, never a capability mint for a dead route.
    assert_eq!(h.hits("/m/exec").len(), 1);
}

#[tokio::test]
async fn approved_within_the_wait_returns_the_result() {
    let poll = decided_after(
        2,
        json!({"ok": true, "id": "apr_2", "status": "executed", "approver": "boss@x.io", "result_status": 200,
               "result": {"ok": true, "stdout": "removed\n", "stderr": "", "code": 0}}),
    );
    let h = hub(move |r| match r.path.as_str() {
        "/m/exec" => Some(pending("apr_2", "exec")),
        "/m/approval" => Some(poll(r)),
        _ => None,
    });
    let r = srv(&h).run_command(run("rm -rf /tmp/x", false)).await.unwrap();
    assert_eq!(out(&r), "Approved by boss@x.io in the IT-AI dashboard (approval id apr_2); it ran:\nremoved\n");
    assert_eq!(r.is_error, Some(false));
}

#[tokio::test]
async fn denied_is_a_clear_error() {
    let poll = decided_after(1, json!({"ok": true, "id": "apr_3", "status": "denied", "approver": "boss@x.io"}));
    let h = hub(move |r| match r.path.as_str() {
        "/m/exec" => Some(pending("apr_3", "exec")),
        "/m/approval" => Some(poll(r)),
        _ => None,
    });
    let r = srv(&h).run_command(run("rm -rf /tmp/x", false)).await.unwrap();
    assert_eq!(r.is_error, Some(true));
    assert!(out(&r).starts_with("Denied by boss@x.io in the IT-AI dashboard (approval id apr_3). The action did not run."), "{}", out(&r));
}

#[tokio::test]
async fn expired_is_a_clear_error() {
    let poll = decided_after(0, json!({"ok": true, "id": "apr_4", "status": "expired"}));
    let h = hub(move |r| match r.path.as_str() {
        "/m/update" => Some(pending("apr_4", "update")),
        "/m/approval" => Some(poll(r)),
        _ => None,
    });
    let r = srv(&h).update_agent(Parameters(AgentArgs { device: "pc1".into(), dry_run: false })).await.unwrap();
    assert_eq!(r.is_error, Some(true));
    assert!(out(&r).starts_with("Approval apr_4 expired before anyone approved it."), "{}", out(&r));
}

#[tokio::test]
async fn blocked_is_refused_and_says_so() {
    let h = hub(|r| match r.path.as_str() {
        "/m/exec" => Some(testhub::json(403, json!({"ok": false, "error": "command blocked by hub policy (matched 'mkfs')", "tier": "blocked", "action": "exec"}))),
        _ => None,
    });
    let r = srv(&h).run_command(run("mkfs /dev/sda", false)).await.unwrap();
    assert_eq!(r.is_error, Some(true));
    assert!(out(&r).starts_with("Blocked by the hub's policy: command blocked by hub policy (matched 'mkfs')."), "{}", out(&r));
    assert!(h.hits("/m/approval").is_empty());
}

#[tokio::test]
async fn update_and_dissolve_print_text_not_json() {
    let poll = decided_after(0, json!({"ok": true, "id": "apr_5", "status": "executed", "approver": "boss@x.io", "result_status": 200, "result": "updated (123 bytes); restarting"}));
    let h = hub(move |r| match r.path.as_str() {
        "/m/update" => Some(pending("apr_5", "update")),
        "/m/dissolve" => Some(testhub::text(200, "dissolving — removing autostart and exiting")),
        "/m/approval" => Some(poll(r)),
        _ => None,
    });
    let s = srv(&h);
    let r = s.update_agent(Parameters(AgentArgs { device: "pc1".into(), dry_run: false })).await.unwrap();
    assert_eq!(out(&r), "Approved by boss@x.io in the IT-AI dashboard (approval id apr_5); it ran:\nupdated (123 bytes); restarting");
    let r = s.dissolve_agent(Parameters(AgentArgs { device: "pc1".into(), dry_run: false })).await.unwrap();
    assert_eq!(out(&r), "dissolving — removing autostart and exiting");
}

#[tokio::test]
async fn fleet_results_with_stopped_and_skipped_are_not_no_devices() {
    let h = hub(|r| match r.path.as_str() {
        "/m/fleet" => Some(testhub::json(
            200,
            json!({"ok": false, "count": 1, "stopped": true, "error": "canary a failed — the remaining devices were not touched",
                   "skipped": ["b", "c"], "results": [{"device": "a", "output": "boom", "ok": false}]}),
        )),
        "/m/script-fleet" => Some(testhub::json(200, json!({"ok": false, "error": "blast-radius cap: this fleet run would touch 12 devices, over the cap of 3", "devices": 12, "max_devices": 3}))),
        _ => None,
    });
    let s = srv(&h);
    let r = s
        .fleet_run(Parameters(FleetRunArgs { command: "uptime".into(), max: Some(5), canary: Some(2), dry_run: false }))
        .await
        .unwrap();
    let t = out(&r);
    assert!(!t.contains("no devices"), "{t}");
    assert!(t.starts_with("STOPPED: canary a failed"), "{t}");
    assert!(t.contains("Not run on 2 device(s): b, c."), "{t}");
    assert!(t.contains("### a (failed)\nboom"), "{t}");
    let q = &h.hits("/m/fleet")[0];
    assert_eq!((q.param("kind").as_deref(), q.param("cmd").as_deref()), (Some("exec"), Some("uptime")));
    assert_eq!((q.param("max").as_deref(), q.param("canary").as_deref()), (Some("5"), Some("2")));
    let r = s
        .run_script_fleet(Parameters(RunScriptFleetArgs { script: "x.ps1".into(), max: Some(3), canary: None, dry_run: false }))
        .await
        .unwrap();
    assert_eq!(out(&r), "[error] blast-radius cap: this fleet run would touch 12 devices, over the cap of 3");
    let q = &h.hits("/m/script-fleet")[0];
    assert_eq!((q.param("max").as_deref(), q.param("canary")), (Some("3"), None));
}

#[tokio::test]
async fn fleet_report_lists_every_device() {
    let h = hub(|r| match r.path.as_str() {
        "/m/fleet" => Some(testhub::json(200, json!({"ok": true, "count": 2, "results": [{"device": "a", "output": "x", "ok": true}, {"device": "b", "output": "y", "ok": true}]}))),
        _ => None,
    });
    let r = srv(&h).fleet_report(Parameters(FleetReportArgs { kind: "hardware".into() })).await.unwrap();
    assert_eq!(out(&r), "### a\nx\n\n### b\ny");
}

#[tokio::test]
async fn dry_run_passes_the_flag_and_runs_nothing() {
    let h = hub(|r| match r.path.as_str() {
        "/m/exec" | "/m/fleet" | "/m/update" | "/m/job/start" => Some(testhub::json(
            200,
            json!({"ok": true, "dry_run": true, "action": "exec", "tier": "privileged", "needs_approval": true,
                   "reason": "needs approval: 'reboot' is not on the safe-command list", "devices": ["pc1"], "detail": "reboot",
                   "would": "file an approval request; run once a human approves"}),
        )),
        _ => None,
    });
    let s = srv(&h);
    let r = s.run_command(run("reboot", true)).await.unwrap();
    assert!(out(&r).starts_with("Dry run, nothing ran: 'exec' is tier privileged, needs a human's approval; the hub would file an approval request"), "{}", out(&r));
    s.fleet_run(Parameters(FleetRunArgs { command: "reboot".into(), max: None, canary: None, dry_run: true })).await.unwrap();
    s.update_agent(Parameters(AgentArgs { device: "pc1".into(), dry_run: true })).await.unwrap();
    s.job_start(Parameters(crate::jobs::JobStartArgs::for_test("pc1", "make", true))).await.unwrap();
    for p in ["/m/exec", "/m/fleet", "/m/update", "/m/job/start"] {
        let hits = h.hits(p);
        assert_eq!(hits.len(), 1, "{p}");
        assert_eq!(hits[0].param("dry_run").as_deref(), Some("1"), "{p}");
    }
    // A dry run never asks for a LAN-direct route or a capability.
    assert!(h.hits("/m/direct").is_empty() && h.hits("/m/capability").is_empty());
    assert!(h.hits("/m/approval").is_empty());
}

#[tokio::test]
async fn the_client_header_is_sent() {
    let h = hub(|_| None);
    let s = Srv::with(Controller::new(h.url.clone(), "TOK".into(), String::new(), build_client()), String::new(), FAST);
    s.list_devices().await.unwrap();
    let r = &h.hits("/m/agents")[0];
    assert_eq!(r.header("X-IT-AI-Client"), Some("mcp"));
}

#[tokio::test]
async fn approval_status_reports_each_state() {
    let k = Arc::new(AtomicUsize::new(0));
    let h = hub(move |r| match r.path.as_str() {
        "/m/approval" => Some(match k.fetch_add(1, Ordering::SeqCst) {
            0 => testhub::json(200, json!({"ok": true, "id": "apr_9", "status": "pending", "action": "update", "device": "pc1", "detail": ""})),
            1 => testhub::json(200, json!({"ok": true, "id": "apr_9", "status": "executed", "approver": "boss@x.io", "result_status": 200, "result": {"ok": true, "stdout": "hi\n", "code": 0}})),
            _ => testhub::json(404, json!({"ok": false, "error": "no such approval (or not yours)"})),
        }),
        _ => None,
    });
    let s = srv(&h);
    let id = || Parameters(super::ApprovalArgs { id: "apr_9".into() });
    assert!(out(&s.approval_status(id()).await.unwrap()).starts_with("Approval apr_9 is still pending: 'update' on pc1"));
    assert_eq!(out(&s.approval_status(id()).await.unwrap()), "Approved by boss@x.io in the IT-AI dashboard (approval id apr_9); it ran:\nhi\n");
    let r = s.approval_status(id()).await.unwrap();
    assert_eq!((r.is_error, out(&r)), (Some(true), "[error] no such approval (or not yours)".to_string()));
}

/// tools/list over a real MCP session: every tool carries readOnlyHint and
/// destructiveHint from the hub's tier table.
#[tokio::test]
async fn tools_list_carries_the_tier_annotations() {
    let h = hub(|_| None);
    let (client, server) = tokio::io::duplex(1 << 20);
    let (sr, sw) = tokio::io::split(server);
    let s = srv(&h);
    tokio::spawn(async move {
        let running = s.serve((sr, sw)).await.expect("serve");
        let _ = running.waiting().await;
    });
    let (cr, mut cw) = tokio::io::split(client);
    let mut lines = BufReader::new(cr).lines();
    let send = |v: serde_json::Value| format!("{v}\n");
    cw.write_all(send(json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}})).as_bytes()).await.unwrap();
    let _init = lines.next_line().await.unwrap().unwrap();
    cw.write_all(send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"})).as_bytes()).await.unwrap();
    cw.write_all(send(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})).as_bytes()).await.unwrap();
    let list: serde_json::Value = loop {
        let l = tokio::time::timeout(Duration::from_secs(5), lines.next_line()).await.unwrap().unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_str(&l).unwrap();
        if v["id"] == 2 {
            break v;
        }
    };
    let tools = list["result"]["tools"].as_array().expect("tools");
    assert_eq!(tools.len(), policy::TOOLS.len(), "every tool is in the tier table and vice versa");
    let ann = |n: &str| {
        let t = tools.iter().find(|t| t["name"] == n).unwrap_or_else(|| panic!("{n} not listed"));
        (t["annotations"]["readOnlyHint"].clone(), t["annotations"]["destructiveHint"].clone())
    };
    for (name, _, tier) in policy::TOOLS {
        let want = match tier {
            policy::Tier::Read => (json!(true), json!(false)),
            policy::Tier::Change => (json!(false), json!(false)),
            policy::Tier::Privileged => (json!(false), json!(true)),
        };
        assert_eq!(ann(name), want, "{name}");
    }
    assert_eq!(ann("list_devices"), (json!(true), json!(false)));
    assert_eq!(ann("click"), (json!(false), json!(false)));
    assert_eq!(ann("dissolve_agent"), (json!(false), json!(true)));
    assert_eq!(ann("run_command"), (json!(false), json!(true)));
}
