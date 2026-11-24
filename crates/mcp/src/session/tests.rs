use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use it_ai_direct::testhub::{self, Req, Resp};
use serde_json::json;

use super::*;
use crate::testmcp::{hub, Live};

fn ran() -> Resp {
    testhub::json(200, json!({"ok": true, "stdout": "ran\n", "stderr": "", "code": 0}))
}

fn mint_ok(token: &str) -> Resp {
    testhub::json(200, json!({"ok": true, "token": token, "id": "mt_1", "name": "session: x", "scope": "full", "expires_at": 1790086400}))
}

fn mtoks(h: &it_ai_direct::testhub::FakeHub, path: &str) -> Vec<String> {
    h.hits(path).iter().map(|r| r.param("mtok").unwrap_or_default()).collect()
}

#[test]
fn a_mint_is_a_token_only_on_200_ok_with_a_token() {
    assert_eq!(read_mint(200, br#"{"ok":true,"token":"S1","expires_at":1}"#), Minted::Token("S1".into()));
    assert_eq!(read_mint(404, b"not found"), Minted::Refused("HTTP 404".into()));
    assert_eq!(
        read_mint(400, br#"{"ok":false,"error":"open hub: no token needed"}"#),
        Minted::Refused("HTTP 400: open hub: no token needed".into())
    );
    assert_eq!(read_mint(200, br#"{"ok":true,"count":1}"#), Minted::Refused("HTTP 200".into()));
    assert_eq!(read_mint(200, br#"{"ok":true,"token":""}"#), Minted::Refused("HTTP 200".into()));
    assert_eq!(read_mint(201, br#"{"ok":true,"token":"S1"}"#), Minted::Refused("HTTP 201".into()));
    // A hub error that quotes a URL never brings a token into the log line.
    let Minted::Refused(m) = read_mint(500, br#"{"ok":false,"error":"bad /m/x?mtok=SECRET&owner=a"}"#) else { panic!() };
    assert!(!m.contains("SECRET"), "{m}");
}

#[test]
fn the_label_names_the_client_the_host_and_the_pid() {
    assert_eq!(label(Some("claude-code"), "mac1", 42), "claude-code · mac1 · pid 42");
    assert_eq!(label(None, "mac1", 42), "it-ai-mcp · mac1 · pid 42");
    assert_eq!(label(Some("  "), "mac1", 42), "it-ai-mcp · mac1 · pid 42");
    assert!(!hostname().is_empty());
}

#[tokio::test]
async fn the_first_call_mints_once_and_every_later_request_uses_the_session_token() {
    let h = hub(|r| match r.path.as_str() {
        "/m/session-token" => Some(mint_ok("S1")),
        "/m/exec" => Some(ran()),
        _ => None,
    });
    let mut s = Live::start(&h, "TOK", "claude-code").await;
    assert_eq!(s.call("run_command", json!({"device": "pc1", "command": "uptime"})).await, "ran\n");
    assert_eq!(s.call("run_command", json!({"device": "pc1", "command": "uptime"})).await, "ran\n");
    let mint = h.hits("/m/session-token");
    assert_eq!(mint.len(), 1, "minted once for the whole session");
    assert_eq!(mint[0].method, "POST");
    assert_eq!(mint[0].param("mtok").as_deref(), Some("TOK"), "the parent is the configured token");
    assert_eq!(mint[0].param("owner").as_deref(), Some("me@x.io"));
    assert_eq!(mint[0].param("name"), Some(format!("claude-code · {} · pid {}", hostname(), std::process::id())));
    for r in h.requests().iter().filter(|r| r.path != "/m/session-token") {
        assert_eq!(r.param("mtok").as_deref(), Some("S1"), "{}", r.path);
    }
    assert_eq!(h.hits("/m/exec").len(), 2);
}

#[tokio::test]
async fn an_old_hub_without_the_route_keeps_the_configured_token_and_is_asked_once() {
    let h = hub(|r| match r.path.as_str() {
        "/m/exec" => Some(ran()),
        _ => None,
    });
    let mut s = Live::start(&h, "TOK", "claude-code").await;
    assert_eq!(s.call("run_command", json!({"device": "pc1", "command": "uptime"})).await, "ran\n");
    assert_eq!(s.call("run_command", json!({"device": "pc1", "command": "uptime"})).await, "ran\n");
    assert_eq!(h.hits("/m/session-token").len(), 1);
    assert_eq!(mtoks(&h, "/m/exec"), ["TOK", "TOK"]);
}

#[tokio::test]
async fn no_configured_token_means_nothing_to_exchange() {
    let h = hub(|r| match r.path.as_str() {
        "/m/exec" => Some(ran()),
        _ => None,
    });
    let mut s = Live::start(&h, "", "claude-code").await;
    assert_eq!(s.call("run_command", json!({"device": "pc1", "command": "uptime"})).await, "ran\n");
    assert!(h.hits("/m/session-token").is_empty());
}

/// `/m/session-token` mints S1, S2, …; any request carrying a token in `dead` is 401.
/// After `max_mints` tokens the hub mints no more (503).
fn revocable_upto(max_mints: usize, dead: Arc<std::sync::Mutex<Vec<String>>>, minted: Arc<AtomicUsize>, exec: impl Fn(&Req) -> Resp + Send + Sync + 'static) -> it_ai_direct::testhub::FakeHub {
    it_ai_direct::testhub::FakeHub::start(move |r| {
        let tok = r.param("mtok").unwrap_or_default();
        if dead.lock().unwrap().contains(&tok) {
            return testhub::text(401, "unauthorized");
        }
        match r.path.as_str() {
            "/m/session-token" if minted.load(Ordering::SeqCst) >= max_mints => testhub::json(503, json!({"ok": false, "error": "token store unavailable"})),
            "/m/session-token" => mint_ok(&format!("S{}", minted.fetch_add(1, Ordering::SeqCst) + 1)),
            "/m/agents" => testhub::json(200, json!({"agents": [{"name": "pc1", "ip": "r1", "port": 0, "scheme": "relay"}]})),
            "/m/exec" | "/m/input" => exec(r),
            _ => testhub::text(404, "not found"),
        }
    })
}

fn revocable(dead: Arc<std::sync::Mutex<Vec<String>>>, minted: Arc<AtomicUsize>, exec: impl Fn(&Req) -> Resp + Send + Sync + 'static) -> it_ai_direct::testhub::FakeHub {
    revocable_upto(usize::MAX, dead, minted, exec)
}

#[tokio::test]
async fn a_revoked_session_token_is_reminted_once_and_the_call_still_runs() {
    let dead = Arc::new(std::sync::Mutex::new(Vec::new()));
    let minted = Arc::new(AtomicUsize::new(0));
    let h = revocable(dead.clone(), minted.clone(), |_| ran());
    let mut s = Live::start(&h, "TOK", "claude-code").await;
    assert_eq!(s.call("run_command", json!({"device": "pc1", "command": "uptime"})).await, "ran\n");
    dead.lock().unwrap().push("S1".into());
    assert_eq!(s.call("run_command", json!({"device": "pc1", "command": "uptime"})).await, "ran\n");
    assert_eq!(minted.load(Ordering::SeqCst), 2, "one re-mint");
    assert_eq!(mtoks(&h, "/m/exec"), ["S1", "S2"], "the command ran once per call, the second time on the new token");
    assert_eq!(mtoks(&h, "/m/session-token"), ["TOK", "TOK"]);
}

#[tokio::test]
async fn a_session_token_that_never_worked_falls_back_to_the_configured_token() {
    let dead = Arc::new(std::sync::Mutex::new(vec!["S1".to_string()]));
    let minted = Arc::new(AtomicUsize::new(0));
    let h = revocable(dead, minted.clone(), |_| ran());
    let mut s = Live::start(&h, "TOK", "claude-code").await;
    assert_eq!(s.call("run_command", json!({"device": "pc1", "command": "uptime"})).await, "ran\n");
    assert_eq!(s.call("run_command", json!({"device": "pc1", "command": "uptime"})).await, "ran\n");
    assert_eq!(minted.load(Ordering::SeqCst), 1, "no re-mint for a token that was never accepted");
    assert_eq!(mtoks(&h, "/m/exec"), ["TOK", "TOK"]);
}

#[tokio::test]
async fn a_reminted_token_that_is_rejected_too_falls_back_to_the_configured_token() {
    let dead = Arc::new(std::sync::Mutex::new(Vec::new()));
    let minted = Arc::new(AtomicUsize::new(0));
    let h = revocable(dead.clone(), minted.clone(), |_| ran());
    let mut s = Live::start(&h, "TOK", "claude-code").await;
    assert_eq!(s.call("run_command", json!({"device": "pc1", "command": "uptime"})).await, "ran\n");
    // S1 revoked, and S2 is dead on arrival too.
    dead.lock().unwrap().extend(["S1".to_string(), "S2".to_string()]);
    assert_eq!(s.call("run_command", json!({"device": "pc1", "command": "uptime"})).await, "ran\n");
    assert_eq!(mtoks(&h, "/m/exec"), ["S1", "TOK"]);
    assert_eq!(minted.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_remint_the_hub_refuses_falls_back_to_the_configured_token() {
    let dead = Arc::new(std::sync::Mutex::new(Vec::new()));
    let minted = Arc::new(AtomicUsize::new(0));
    let h = revocable_upto(1, dead.clone(), minted.clone(), |_| ran());
    let mut s = Live::start(&h, "TOK", "claude-code").await;
    assert_eq!(s.call("run_command", json!({"device": "pc1", "command": "uptime"})).await, "ran\n");
    dead.lock().unwrap().push("S1".into());
    assert_eq!(s.call("run_command", json!({"device": "pc1", "command": "uptime"})).await, "ran\n");
    assert_eq!(s.call("run_command", json!({"device": "pc1", "command": "uptime"})).await, "ran\n");
    assert_eq!(mtoks(&h, "/m/exec"), ["S1", "TOK", "TOK"]);
    assert_eq!(h.hits("/m/session-token").len(), 2, "the first mint and the one refused re-mint, nothing after");
}

#[tokio::test]
async fn a_call_that_was_partly_sent_is_not_repeated_after_a_401() {
    let dead = Arc::new(std::sync::Mutex::new(Vec::new()));
    let minted = Arc::new(AtomicUsize::new(0));
    let n = Arc::new(AtomicUsize::new(0));
    let d = dead.clone();
    let h = revocable(dead.clone(), minted.clone(), move |r| {
        // press_key sends two events; the first event of the next call lands, then S1 is revoked.
        if r.path == "/m/input" && r.param("mtok").as_deref() == Some("S1") && n.fetch_add(1, Ordering::SeqCst) == 2 {
            d.lock().unwrap().push("S1".into());
        }
        ran()
    });
    let mut s = Live::start(&h, "TOK", "claude-code").await;
    s.call("press_key", json!({"device": "pc1", "key": "Enter"})).await;
    let before = h.hits("/m/input").len();
    s.call("type_text", json!({"device": "pc1", "text": "ab"})).await;
    assert_eq!(h.hits("/m/input").len() - before, 4, "four key events, none of them sent twice");
    assert_eq!(minted.load(Ordering::SeqCst), 2, "the next call gets a fresh token");
    s.call("press_key", json!({"device": "pc1", "key": "Enter"})).await;
    assert_eq!(mtoks(&h, "/m/input").last().map(String::as_str), Some("S2"));
}
