// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

// A live MCP session over an in-memory pipe, so tool calls go through `call_tool`
// (session tokens, MoorAI headers) the way a real client's do.
use std::time::Duration;

use it_ai_direct::testhub::{self, FakeHub, Req, Resp};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream, Lines, ReadHalf, WriteHalf};

use crate::*;

pub const FAST: Wait = Wait { max: Duration::from_millis(300), every: Duration::from_millis(20) };

/// A hub with one relay device, `pc1`, and no LAN-direct route; every other
/// request goes to `f`, and `None` from it is a 404.
pub fn hub(f: impl Fn(&Req) -> Option<Resp> + Send + Sync + 'static) -> FakeHub {
    FakeHub::start(move |r| match r.path.as_str() {
        "/m/agents" => testhub::json(200, json!({"agents": [{"name": "pc1", "ip": "r1", "port": 0, "scheme": "relay"}]})),
        _ => f(r).unwrap_or_else(|| testhub::text(404, "not found")),
    })
}

pub fn out(r: &CallToolResult) -> String {
    r.content.iter().filter_map(|c| c.as_text().map(|t| t.text.clone())).collect::<Vec<_>>().join("\n")
}

pub struct Live {
    w: WriteHalf<DuplexStream>,
    lines: Lines<BufReader<ReadHalf<DuplexStream>>>,
    id: u64,
}

impl Live {
    /// Serve `Srv::with(hub, token, "me@x.io")` to a client that calls itself `client`.
    pub async fn start(h: &FakeHub, token: &str, client: &str) -> Live {
        let s = Srv::with(h.url.clone(), token.into(), "me@x.io".into(), FAST);
        let (c, server) = tokio::io::duplex(1 << 20);
        let (sr, sw) = tokio::io::split(server);
        tokio::spawn(async move {
            let running = s.serve((sr, sw)).await.expect("serve");
            let _ = running.waiting().await;
        });
        let (cr, w) = tokio::io::split(c);
        let mut me = Live { w, lines: BufReader::new(cr).lines(), id: 0 };
        me.request("initialize", json!({"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": client, "version": "0"}})).await;
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
    pub async fn call(&mut self, name: &str, args: Value) -> String {
        let v = self.request("tools/call", json!({"name": name, "arguments": args})).await;
        let content = v["result"]["content"].as_array().unwrap_or_else(|| panic!("no result: {v}"));
        content.iter().filter_map(|c| c["text"].as_str()).collect::<Vec<_>>().join("\n")
    }
}
