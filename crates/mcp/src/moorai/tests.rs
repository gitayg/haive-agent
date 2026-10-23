use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use base64::Engine;
use it_ai_direct::testhub::{self, FakeHub, Req, Resp};
use rmcp::handler::server::router::tool::ToolRoute;
use rmcp::model::{JsonObject, Tool};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream, Lines, ReadHalf, WriteHalf};

use crate::*;

const FAST: Wait = Wait { max: Duration::from_millis(300), every: Duration::from_millis(20) };
const RECEIPT: &str = "eyJ2IjoxfQ.c2ln";
const HEADERS: [&str; 3] = ["x-moorai-receipt", "x-moorai-tool", "x-moorai-args"];

fn obj(v: Value) -> Option<JsonObject> {
    v.as_object().cloned()
}

fn decode(s: &str) -> String {
    String::from_utf8(base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).expect("base64url, no padding")).unwrap()
}

#[test]
fn take_strips_the_key_and_builds_the_three_headers() {
    let mut a = obj(json!({"device": "pc1", "command": "echo hi", "_moorai": {"receipt": RECEIPT}}));
    let h = moorai::take("run_command", &mut a).expect("headers");
    assert_eq!(a, obj(json!({"device": "pc1", "command": "echo hi"})));
    assert_eq!(h.len(), 3);
    assert_eq!(h["x-moorai-receipt"], RECEIPT);
    assert_eq!(h["x-moorai-tool"], "run_command");
    assert_eq!(decode(h["x-moorai-args"].to_str().unwrap()), r#"{"command":"echo hi","device":"pc1"}"#);
    assert!(h["x-moorai-receipt"].is_sensitive() && h["x-moorai-args"].is_sensitive());
    assert!(!format!("{h:?}").contains(RECEIPT), "Debug never prints the receipt");
}

#[test]
fn take_strips_a_malformed_key_and_sends_nothing() {
    for bad in [json!("x"), json!(null), json!({}), json!({"receipt": 5}), json!({"receipt": ["a"]}), json!({"receipt": "a\nb"})] {
        let mut a = obj(json!({"device": "pc1", "_moorai": bad.clone()}));
        assert!(moorai::take("screenshot", &mut a).is_none(), "{bad}");
        assert_eq!(a, obj(json!({"device": "pc1"})), "{bad}");
    }
}

#[test]
fn take_sends_nothing_without_a_receipt_or_on_a_dry_run() {
    let mut a = obj(json!({"device": "pc1"}));
    assert!(moorai::take("screenshot", &mut a).is_none());
    assert!(moorai::take("list_devices", &mut None).is_none());
    let mut a = obj(json!({"device": "pc1", "command": "reboot", "dry_run": true, "_moorai": {"receipt": RECEIPT}}));
    assert!(moorai::take("run_command", &mut a).is_none());
    assert_eq!(a, obj(json!({"device": "pc1", "command": "reboot", "dry_run": true})));
    let mut a = obj(json!({"device": "pc1", "command": "reboot", "dry_run": false, "_moorai": {"receipt": RECEIPT}}));
    assert!(moorai::take("run_command", &mut a).is_some(), "dry_run false is a real call");
}

#[test]
fn take_sends_nothing_when_the_encoded_args_pass_16384_bytes() {
    // `{"command":""}` is 14 bytes; 12288 bytes of JSON encode to exactly 16384.
    let args = |k: usize| obj(json!({"command": "x".repeat(k), "_moorai": {"receipt": RECEIPT}}));
    let h = moorai::take("run_command", &mut args(12274)).expect("16384 is within the limit");
    assert_eq!(h["x-moorai-args"].len(), 16384);
    let mut a = args(12275);
    assert!(moorai::take("run_command", &mut a).is_none());
    assert!(!a.unwrap().contains_key("_moorai"));
}

/// A test-only tool that answers with the arguments it was handed.
fn echo_args<'a>(ctx: ToolCallContext<'a, Srv>) -> Pin<Box<dyn Future<Output = Result<CallToolResult, ErrorData>> + Send + 'a>> {
    let seen = Value::Object(ctx.arguments.clone().unwrap_or_default()).to_string();
    Box::pin(async move { Ok(approval::text(seen)) })
}

/// A hub with one relay device, `pc1`; `/m/exec` answers with `exec`.
fn hub(exec: impl Fn(&Req) -> Resp + Send + Sync + 'static) -> FakeHub {
    FakeHub::start(move |r| match r.path.as_str() {
        "/m/agents" => testhub::json(200, json!({"agents": [{"name": "pc1", "ip": "r1", "port": 0, "scheme": "relay"}]})),
        "/m/exec" | "/m/fleet" => exec(r),
        "/m/approval" => testhub::json(
            200,
            json!({"ok": true, "id": "apr_1", "status": "executed", "approver": "boss@x.io", "result_status": 200,
                   "result": {"ok": true, "stdout": "ran\n", "stderr": "", "code": 0}}),
        ),
        _ => testhub::text(404, "not found"),
    })
}

fn ran(_: &Req) -> Resp {
    testhub::json(200, json!({"ok": true, "stdout": "ran\n", "stderr": "", "code": 0}))
}

/// A live MCP session over an in-memory pipe, so calls go through `call_tool`.
struct Session {
    w: WriteHalf<DuplexStream>,
    lines: Lines<BufReader<ReadHalf<DuplexStream>>>,
    id: u64,
}

impl Session {
    async fn start(h: &FakeHub) -> Session {
        let mut s = Srv::with(h.url.clone(), "TOK".into(), "me@x.io".into(), FAST);
        s.tool_router.add_route(ToolRoute::new_dyn(Tool::new("echo_args", "test only", JsonObject::new()), echo_args));
        let (client, server) = tokio::io::duplex(1 << 20);
        let (sr, sw) = tokio::io::split(server);
        tokio::spawn(async move {
            let running = s.serve((sr, sw)).await.expect("serve");
            let _ = running.waiting().await;
        });
        let (cr, w) = tokio::io::split(client);
        let mut me = Session { w, lines: BufReader::new(cr).lines(), id: 0 };
        me.request("initialize", json!({"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}})).await;
        me.send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"})).await;
        me
    }

    async fn send(&mut self, v: Value) {
        self.w.write_all(format!("{v}\n").as_bytes()).await.unwrap();
    }

    async fn request(&mut self, method: &str, params: Value) -> Value {
        self.id += 1;
        let id = self.id;
        self.send(json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})).await;
        loop {
            let l = tokio::time::timeout(Duration::from_secs(10), self.lines.next_line()).await.unwrap().unwrap().unwrap();
            let v: Value = serde_json::from_str(&l).unwrap();
            if v["id"] == id {
                return v;
            }
        }
    }

    /// The text of a tool call's result.
    async fn call(&mut self, name: &str, args: Value) -> String {
        let v = self.request("tools/call", json!({"name": name, "arguments": args})).await;
        let content = v["result"]["content"].as_array().unwrap_or_else(|| panic!("no result: {v}"));
        content.iter().filter_map(|c| c["text"].as_str()).collect::<Vec<_>>().join("\n")
    }
}

fn assert_no_moorai(reqs: &[Req]) {
    assert!(!reqs.is_empty());
    for r in reqs {
        for k in HEADERS {
            assert_eq!(r.header(k), None, "{k} on {}", r.path);
        }
    }
}

#[tokio::test]
async fn the_tool_never_sees_the_moorai_key() {
    let h = hub(ran);
    let mut s = Session::start(&h).await;
    let seen = s.call("echo_args", json!({"device": "pc1", "_moorai": {"receipt": RECEIPT}, "n": 1})).await;
    assert_eq!(seen, r#"{"device":"pc1","n":1}"#);
    let seen = s.call("echo_args", json!({"device": "pc1", "_moorai": {"receipt": 7}})).await;
    assert_eq!(seen, r#"{"device":"pc1"}"#, "a malformed key is stripped too");
}

#[tokio::test]
async fn every_hub_request_of_the_call_carries_the_receipt_and_raw_args() {
    let h = hub(ran);
    let mut s = Session::start(&h).await;
    let out = s.call("run_command", json!({"device": "pc1", "command": "echo \"héllo\" 1.5", "_moorai": {"receipt": RECEIPT}})).await;
    assert_eq!(out, "ran\n");
    let reqs = h.requests();
    assert!(reqs.iter().any(|r| r.path == "/m/agents") && reqs.iter().any(|r| r.path == "/m/exec"));
    for r in &reqs {
        assert_eq!(r.header("x-moorai-receipt"), Some(RECEIPT), "{}", r.path);
        assert_eq!(r.header("x-moorai-tool"), Some("run_command"), "{}", r.path);
        // The input as received minus `_moorai`: no `detach`/`dry_run` defaults
        // from the typed args, values untouched.
        assert_eq!(decode(r.header("x-moorai-args").unwrap()), r#"{"command":"echo \"héllo\" 1.5","device":"pc1"}"#, "{}", r.path);
    }
    // The tool still ran with its own arguments, and the device never saw the receipt.
    let exec = &h.hits("/m/exec")[0];
    assert_eq!(exec.json(), json!({"cmd": "echo \"héllo\" 1.5", "detach": false, "target": "relay://r1"}));
}

#[tokio::test]
async fn approval_polls_and_fleet_calls_carry_the_headers_and_the_next_call_does_not() {
    let h = hub(|r| {
        if r.path == "/m/exec" {
            testhub::json(202, json!({"ok": false, "pending_approval": true, "status": "pending", "approval_id": "apr_1", "action": "exec",
                                      "tier": "privileged", "device": "pc1", "poll": "/m/approval?id=apr_1"}))
        } else {
            testhub::json(200, json!({"ok": true, "count": 1, "results": [{"device": "pc1", "output": "up", "ok": true}]}))
        }
    });
    let mut s = Session::start(&h).await;
    let out = s.call("run_command", json!({"device": "pc1", "command": "rm -rf /tmp/x", "_moorai": {"receipt": RECEIPT}})).await;
    assert!(out.starts_with("Approved by boss@x.io"), "{out}");
    assert!(!h.hits("/m/approval").is_empty());
    for r in h.requests() {
        assert_eq!(r.header("x-moorai-receipt"), Some(RECEIPT), "{}", r.path);
    }
    let before = h.requests().len();
    s.call("fleet_run", json!({"_moorai": {"receipt": RECEIPT}, "command": "uptime", "max": 3})).await;
    let fleet = &h.hits("/m/fleet")[0];
    assert_eq!(fleet.header("x-moorai-tool"), Some("fleet_run"));
    assert_eq!(decode(fleet.header("x-moorai-args").unwrap()), r#"{"command":"uptime","max":3}"#);
    let before_plain = h.requests().len();
    assert!(before_plain > before);
    s.call("run_command", json!({"device": "pc1", "command": "uptime"})).await;
    assert_no_moorai(&h.requests()[before_plain..]);
}

#[tokio::test]
async fn no_headers_without_a_receipt_on_a_dry_run_oversized_or_malformed() {
    let dry = |r: &Req| {
        if r.param("dry_run").as_deref() == Some("1") {
            testhub::json(200, json!({"ok": true, "dry_run": true, "action": "exec", "tier": "privileged", "needs_approval": true,
                                      "devices": ["pc1"], "detail": "reboot", "would": "file an approval request"}))
        } else {
            ran(r)
        }
    };
    let cases = [
        ("none", json!({"device": "pc1", "command": "uptime"})),
        ("dry run", json!({"device": "pc1", "command": "reboot", "dry_run": true, "_moorai": {"receipt": RECEIPT}})),
        ("oversized", json!({"device": "pc1", "command": "x".repeat(13000), "_moorai": {"receipt": RECEIPT}})),
        ("receipt not a string", json!({"device": "pc1", "command": "uptime", "_moorai": {"receipt": 5}})),
        ("not an object", json!({"device": "pc1", "command": "uptime", "_moorai": RECEIPT})),
    ];
    for (name, args) in cases {
        let h = hub(dry);
        let mut s = Session::start(&h).await;
        let out = s.call("run_command", args).await;
        assert_eq!(h.hits("/m/exec").len(), 1, "{name}: the call still went to the hub");
        assert!(out == "ran\n" || out.starts_with("Dry run, nothing ran"), "{name}: {out}");
        assert_no_moorai(&h.requests());
    }
}
