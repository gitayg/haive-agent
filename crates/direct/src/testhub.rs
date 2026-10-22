// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

//! A scripted stand-in for the hub, for tests (feature `test-hub`). It listens on
//! 127.0.0.1, answers each request with whatever the handler returns, closes the
//! connection, and records every request it saw.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug)]
pub struct Req {
    pub method: String,
    /// The path without the query: `/m/exec`.
    pub path: String,
    pub query: String,
    /// Header names lower-cased.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Req {
    pub fn header(&self, name: &str) -> Option<&str> {
        let n = name.to_ascii_lowercase();
        self.headers.iter().find(|(k, _)| *k == n).map(|(_, v)| v.as_str())
    }

    /// A query parameter, percent-decoded.
    pub fn param(&self, key: &str) -> Option<String> {
        self.query.split('&').find_map(|kv| {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            (decode(k) == key).then(|| decode(v))
        })
    }

    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap_or_default()
    }
}

fn decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => {
                let hex = std::str::from_utf8(&b[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok());
                match hex {
                    Some(x) => {
                        out.push(x);
                        i += 3;
                        continue;
                    }
                    None => out.push(b'%'),
                }
            }
            b'+' => out.push(b' '),
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub struct Resp {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
}

pub fn json(status: u16, v: serde_json::Value) -> Resp {
    Resp { status, content_type: "application/json", body: v.to_string().into_bytes() }
}

pub fn text(status: u16, s: &str) -> Resp {
    Resp { status, content_type: "text/plain", body: s.as_bytes().to_vec() }
}

pub fn bytes(status: u16, content_type: &'static str, b: &[u8]) -> Resp {
    Resp { status, content_type, body: b.to_vec() }
}

pub struct FakeHub {
    pub url: String,
    log: Arc<Mutex<Vec<Req>>>,
}

impl FakeHub {
    pub fn start(handler: impl Fn(&Req) -> Resp + Send + Sync + 'static) -> FakeHub {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake hub");
        let url = format!("http://{}", listener.local_addr().unwrap());
        let log = Arc::new(Mutex::new(Vec::new()));
        let handler = Arc::new(handler);
        let l = log.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let (handler, log) = (handler.clone(), l.clone());
                std::thread::spawn(move || {
                    let mut stream = stream;
                    let Some(req) = read_request(&mut stream) else { return };
                    log.lock().unwrap().push(req.clone());
                    let r = handler(&req);
                    let head = format!(
                        "HTTP/1.1 {} X\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        r.status,
                        r.content_type,
                        r.body.len()
                    );
                    let _ = stream.write_all(head.as_bytes());
                    let _ = stream.write_all(&r.body);
                });
            }
        });
        FakeHub { url, log }
    }

    pub fn requests(&self) -> Vec<Req> {
        self.log.lock().unwrap().clone()
    }

    /// The requests to one path (`/m/approval`).
    pub fn hits(&self, path: &str) -> Vec<Req> {
        self.requests().into_iter().filter(|r| r.path == path).collect()
    }
}

fn read_request(stream: &mut std::net::TcpStream) -> Option<Req> {
    let mut r = BufReader::new(stream.try_clone().ok()?);
    let mut line = String::new();
    r.read_line(&mut line).ok()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();
    let (path, query) = target.split_once('?').map(|(p, q)| (p.to_string(), q.to_string())).unwrap_or((target, String::new()));
    let mut headers = Vec::new();
    loop {
        let mut h = String::new();
        if r.read_line(&mut h).ok()? == 0 {
            break;
        }
        let h = h.trim_end();
        if h.is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
    }
    let len = headers.iter().find(|(k, _)| k == "content-length").and_then(|(_, v)| v.parse::<usize>().ok()).unwrap_or(0);
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).ok()?;
    Some(Req { method, path, query, headers, body })
}
