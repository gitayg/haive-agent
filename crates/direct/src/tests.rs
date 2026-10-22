use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;

use super::reply::{Pending, Reply, Settled, Wait};
use super::testhub::{self, FakeHub};
use super::*;

const FAST: Wait = Wait { max: Duration::from_millis(400), every: Duration::from_millis(20) };

fn ctl(hub: &FakeHub) -> Controller {
    Controller::new(hub.url.clone(), "TOK".into(), "me@x.io".into(), reqwest::Client::new())
}

fn pending_body(id: &str) -> serde_json::Value {
    json!({
        "ok": false, "pending_approval": true, "status": "pending", "approval_id": id,
        "action": "exec", "tier": "privileged", "reason": "needs approval: 'rm' is not on the safe list",
        "device": "pc1", "expires": 1790003600, "poll": format!("/m/approval?id={id}"),
        "error": "approval required",
    })
}

#[test]
fn parse_classifies_the_hub_answers() {
    let p = Reply::parse(202, pending_body("apr_1").to_string().as_bytes());
    assert_eq!(
        p,
        Reply::Pending(Pending {
            id: "apr_1".into(),
            action: "exec".into(),
            device: "pc1".into(),
            reason: "needs approval: 'rm' is not on the safe list".into(),
            expires: 1790003600
        })
    );
    let b = json!({"ok": false, "error": "command blocked by hub policy (matched 'rm -rf')", "tier": "blocked", "action": "exec"});
    assert_eq!(
        Reply::parse(403, b.to_string().as_bytes()),
        Reply::Refused { error: "command blocked by hub policy (matched 'rm -rf')".into(), blocked: true }
    );
    assert_eq!(
        Reply::parse(403, b"this MCP token is read-only"),
        Reply::Refused { error: "this MCP token is read-only".into(), blocked: false }
    );
    let d = json!({"ok": true, "dry_run": true, "action": "exec", "tier": "change"});
    assert_eq!(Reply::parse(200, d.to_string().as_bytes()), Reply::DryRun(d));
    assert_eq!(Reply::parse(200, b"already running this build (5 bytes); nothing to do"), Reply::Done(json!("already running this build (5 bytes); nothing to do")));
    assert_eq!(Reply::parse(200, br#"{"ok":true,"stdout":"hi"}"#), Reply::Done(json!({"ok":true,"stdout":"hi"})));
}

/// A hub whose `/m/approval` answers `pending` for the first `pending_polls`
/// polls, then `then`.
fn approval_hub(pending_polls: usize, then: serde_json::Value) -> (FakeHub, Arc<AtomicUsize>) {
    let n = Arc::new(AtomicUsize::new(0));
    let c = n.clone();
    let hub = FakeHub::start(move |r| match r.path.as_str() {
        "/m/approval" => {
            let k = c.fetch_add(1, Ordering::SeqCst);
            if k < pending_polls {
                testhub::json(200, json!({"ok": true, "id": r.param("id"), "status": "pending", "action": "exec"}))
            } else {
                testhub::json(200, then.clone())
            }
        }
        _ => testhub::text(404, "no"),
    });
    (hub, n)
}

fn pending(id: &str) -> Reply {
    Reply::parse(202, pending_body(id).to_string().as_bytes())
}

#[tokio::test]
async fn approved_within_the_wait_returns_the_result() {
    let (hub, polls) = approval_hub(
        2,
        json!({"ok": true, "id": "apr_1", "status": "executed", "approver": "boss@x.io", "result_status": 200,
               "result": {"ok": true, "stdout": "done\n", "stderr": "", "code": 0}}),
    );
    let s = ctl(&hub).settle(pending("apr_1"), FAST).await;
    assert_eq!(
        s,
        Settled::Approved { id: "apr_1".into(), approver: "boss@x.io".into(), status: 200, result: json!({"ok": true, "stdout": "done\n", "stderr": "", "code": 0}) }
    );
    assert_eq!(polls.load(Ordering::SeqCst), 3);
    let q = &hub.hits("/m/approval")[0];
    assert_eq!(q.param("id").as_deref(), Some("apr_1"));
    assert_eq!(q.param("mtok").as_deref(), Some("TOK"));
}

#[tokio::test]
async fn denied_and_expired_are_decisions() {
    let (hub, _) = approval_hub(0, json!({"ok": true, "id": "apr_2", "status": "denied", "approver": "boss@x.io"}));
    assert_eq!(ctl(&hub).settle(pending("apr_2"), FAST).await, Settled::Denied { id: "apr_2".into(), approver: "boss@x.io".into() });
    let (hub, _) = approval_hub(1, json!({"ok": true, "id": "apr_3", "status": "expired"}));
    assert_eq!(ctl(&hub).settle(pending("apr_3"), FAST).await, Settled::Expired { id: "apr_3".into() });
}

#[tokio::test]
async fn still_pending_after_the_wait_keeps_the_id() {
    let (hub, polls) = approval_hub(usize::MAX, json!({}));
    let s = ctl(&hub).settle(pending("apr_4"), FAST).await;
    match s {
        Settled::Pending(p) => assert_eq!(p.id, "apr_4"),
        other => panic!("{other:?}"),
    }
    let n = polls.load(Ordering::SeqCst);
    assert!((5..=25).contains(&n), "polled {n} times in 400 ms at 20 ms");
    // A zero wait does not poll at all.
    let (hub, polls) = approval_hub(usize::MAX, json!({}));
    assert!(matches!(ctl(&hub).settle(pending("apr_5"), Wait { max: Duration::ZERO, every: Duration::from_millis(20) }).await, Settled::Pending(_)));
    assert_eq!(polls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn running_is_not_a_decision() {
    let n = Arc::new(AtomicUsize::new(0));
    let c = n.clone();
    let hub = FakeHub::start(move |_| {
        if c.fetch_add(1, Ordering::SeqCst) == 0 {
            testhub::json(200, json!({"ok": true, "id": "apr_6", "status": "running"}))
        } else {
            testhub::json(200, json!({"ok": true, "id": "apr_6", "status": "executed", "approver": "a", "result_status": 200, "result": "updated"}))
        }
    });
    assert!(matches!(ctl(&hub).settle(pending("apr_6"), FAST).await, Settled::Approved { .. }));
}

#[tokio::test]
async fn privileged_capability_falls_back_to_the_relay() {
    let hub = FakeHub::start(|r| match r.path.as_str() {
        "/m/capability" => testhub::json(200, json!({"ok": true, "cap": null, "route": "relay", "tier": "privileged", "reason": "needs approval"})),
        _ => testhub::text(404, "no"),
    });
    assert_eq!(ctl(&hub).mint_capability("relay://r1", "exec", "rm x").await, Ok(None));
}

#[tokio::test]
async fn blocked_capability_is_a_refusal_not_a_relay() {
    let hub = FakeHub::start(|_| testhub::json(403, json!({"ok": false, "error": "command blocked by hub policy (matched 'rm -rf')", "tier": "blocked", "action": "exec"})));
    let e = ctl(&hub).mint_capability("relay://r1", "exec", "rm -rf /").await.unwrap_err();
    assert!(e.starts_with("Blocked by the hub's policy: command blocked"), "{e}");
}

#[tokio::test]
async fn dry_run_goes_to_the_relay_with_the_flag() {
    let hub = FakeHub::start(|_| testhub::json(200, json!({"ok": true, "dry_run": true, "action": "exec", "tier": "privileged"})));
    let op = Op::post_json("exec", json!({"cmd": "reboot"})).target_in_body();
    let r = ctl(&hub).dry_run("relay://r1", op).await.unwrap();
    assert!(matches!(reply::read(r).await.unwrap(), Reply::DryRun(_)));
    let reqs = hub.requests();
    assert_eq!(reqs.len(), 1, "a dry run never probes or mints: {reqs:?}");
    assert_eq!(reqs[0].path, "/m/exec");
    assert_eq!(reqs[0].param("dry_run").as_deref(), Some("1"));
    assert_eq!(reqs[0].json(), json!({"cmd": "reboot", "target": "relay://r1"}));
}

#[test]
fn fleet_text_surfaces_stop_skip_and_refusal() {
    let stopped = json!({"ok": false, "count": 1, "stopped": true, "error": "canary a failed — the remaining devices were not touched",
        "skipped": ["b", "c"], "results": [{"device": "a", "output": "boom", "ok": false}]});
    let t = reply::fmt_fleet(&stopped);
    assert!(t.starts_with("STOPPED: canary a failed"), "{t}");
    assert!(t.contains("Not run on 2 device(s): b, c."), "{t}");
    assert!(t.contains("### a (failed)\nboom"), "{t}");
    assert!(!t.contains("no devices"), "{t}");
    let capped = json!({"ok": false, "error": "blast-radius cap: this fleet run would touch 12 devices, over the cap of 10", "devices": 12, "max_devices": 10});
    assert_eq!(reply::fmt_fleet(&capped), "[error] blast-radius cap: this fleet run would touch 12 devices, over the cap of 10");
    let ok = json!({"ok": true, "count": 2, "results": [{"device": "a", "output": "1", "ok": true}, {"device": "b", "output": "2", "ok": true}]});
    assert_eq!(reply::fmt_fleet(&ok), "### a\n1\n\n### b\n2");
    assert_eq!(reply::fmt_fleet(&json!({"ok": true, "count": 0, "results": []})), "no devices");
}
