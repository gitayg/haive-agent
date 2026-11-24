// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::relaycred::{RelayCred, Resolved};

/// What the fake hub's `/relay/body` answers.
#[derive(Clone)]
enum Serve {
    Bytes(Vec<u8>),
    Status(u16),
    /// Declares `Content-Length: declared`, sends `sent`, then closes.
    Short { declared: usize, sent: Vec<u8> },
    /// Sends the first half, then holds the rest until the loopback has read
    /// some of it (or 5 s pass). `streamed` says which happened.
    Gated { data: Vec<u8>, loop_read: Arc<AtomicUsize>, streamed: Arc<AtomicUsize> },
}

type Log = Arc<Mutex<Vec<(String, String, Vec<u8>)>>>;

/// Raw TCP, so it can lie about a Content-Length and hang up mid-body. Records
/// `(path, query, body)` of every request.
fn hub(serve: Serve) -> (String, Log) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let log: Log = Arc::default();
    let seen = Arc::clone(&log);
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            let (serve, seen) = (serve.clone(), Arc::clone(&seen));
            std::thread::spawn(move || conn(s, serve, seen));
        }
    });
    (format!("http://127.0.0.1:{port}"), log)
}

fn conn(s: TcpStream, serve: Serve, log: Log) {
    let mut w = s.try_clone().unwrap();
    let mut r = BufReader::new(s);
    loop {
        let mut line = String::new();
        if r.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        let target = line.split_whitespace().nth(1).unwrap_or("").to_string();
        let (path, query) = target.split_once('?').map(|(p, q)| (p.to_string(), q.to_string())).unwrap_or((target, String::new()));
        let (mut len, mut chunked) = (0usize, false);
        loop {
            let mut h = String::new();
            r.read_line(&mut h).unwrap();
            let h = h.trim_end();
            if h.is_empty() {
                break;
            }
            let (k, v) = h.split_once(':').unwrap();
            match k.to_ascii_lowercase().as_str() {
                "content-length" => len = v.trim().parse().unwrap(),
                "transfer-encoding" => chunked = v.to_ascii_lowercase().contains("chunked"),
                _ => {}
            }
        }
        let body = if chunked { dechunk(&mut r) } else { read_n(&mut r, len) };
        log.lock().unwrap().push((path.clone(), query, body));
        if path == "/relay/body" {
            match &serve {
                Serve::Bytes(b) => {
                    let _ = write!(w, "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n", b.len());
                    let _ = w.write_all(b);
                }
                Serve::Status(st) => {
                    let _ = write!(w, "HTTP/1.1 {st} Nope\r\nContent-Length: 0\r\n\r\n");
                }
                Serve::Short { declared, sent } => {
                    let _ = write!(w, "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {declared}\r\n\r\n");
                    let _ = w.write_all(sent);
                    let _ = w.flush();
                    let _ = w.shutdown(std::net::Shutdown::Both);
                    return;
                }
                Serve::Gated { data, loop_read, streamed } => {
                    let _ = write!(w, "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n", data.len());
                    let (head, tail) = data.split_at(data.len() / 2);
                    let _ = w.write_all(head);
                    let _ = w.flush();
                    for _ in 0..500 {
                        if loop_read.load(Ordering::SeqCst) > 0 {
                            streamed.store(1, Ordering::SeqCst);
                            break;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    let _ = w.write_all(tail);
                }
            }
        } else {
            let _ = write!(w, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        }
    }
}

fn read_n(r: &mut impl Read, n: usize) -> Vec<u8> {
    let mut b = vec![0; n];
    r.read_exact(&mut b).unwrap();
    b
}

fn dechunk(r: &mut BufReader<TcpStream>) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut size = String::new();
        r.read_line(&mut size).unwrap();
        let n = usize::from_str_radix(size.trim().split(';').next().unwrap(), 16).unwrap();
        out.extend(read_n(r, n));
        read_n(r, 2);
        if n == 0 {
            return out;
        }
    }
}

/// What the loopback self-call received: method, path, Content-Length,
/// Content-Type, Transfer-Encoding, and the body as tiny_http handed it over.
type Got = Arc<Mutex<Vec<(String, String, Option<usize>, Option<String>, Option<String>, Vec<u8>)>>>;

/// tiny_http, like the agent's real loopback server.
fn loopback() -> (u16, Got) {
    loopback_counting(Arc::default())
}

/// `read` counts body bytes as the handler reads them, before the body is whole.
fn loopback_counting(read: Arc<AtomicUsize>) -> (u16, Got) {
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let port = server.server_addr().to_ip().unwrap().port();
    let got: Got = Arc::default();
    let log = Arc::clone(&got);
    std::thread::spawn(move || {
        for mut rq in server.incoming_requests() {
            let h = |n: &'static str| rq.headers().iter().find(|h| h.field.equiv(n)).map(|h| h.value.as_str().to_string());
            let (ct, te) = (h("Content-Type"), h("Transfer-Encoding"));
            let (m, p, cl) = (rq.method().to_string(), rq.url().split('?').next().unwrap_or("").to_string(), rq.body_length());
            let mut body = Vec::new();
            let mut chunk = [0u8; 16384];
            while let Ok(n) = rq.as_reader().read(&mut chunk) {
                if n == 0 {
                    break;
                }
                read.fetch_add(n, Ordering::SeqCst);
                body.extend_from_slice(&chunk[..n]);
            }
            log.lock().unwrap().push((m, p, cl, ct, te, body));
            let _ = rq.respond(tiny_http::Response::from_string("looped"));
        }
    });
    (port, got)
}

fn cred(hub: &str, tag: &str) -> (RelayCred, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("it-ai-relay-body-{tag}-{}", std::process::id()));
    let r = Resolved { token: "hdev_x".into(), is_device: true, supplied_enroll: None };
    (RelayCred::new(hub, "hc-1", dir.join("relay.cred"), r), dir)
}

fn replies(log: &Log) -> Vec<(String, Vec<u8>)> {
    log.lock().unwrap().iter().filter(|(p, _, _)| p == "/relay/reply").map(|(_, q, b)| (q.clone(), b.clone())).collect()
}

fn wait<T>(f: impl Fn() -> Option<T>) -> T {
    for _ in 0..200 {
        if let Some(v) = f() {
            return v;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    panic!("timed out waiting");
}

fn poll(req: u64, extra: &str) -> String {
    format!(r#"{{"id":{req},"m":"POST","p":"/upload","ct":"multipart/form-data; boundary=XyZ"{extra}}}"#)
}

#[test]
fn a_staged_body_is_streamed_byte_exact_into_the_loopback_call() {
    let data: Vec<u8> = (0..3_000_000u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
    let (base, log) = hub(Serve::Bytes(data.clone()));
    let (lp, got) = loopback();
    let (c, dir) = cred(&base, "ok");
    crate::relay::serve_req(&c, &poll(41, &format!(r#","b":"","bf":1,"bl":{}"#, data.len())), lp);

    let fetched: Vec<_> = log.lock().unwrap().iter().filter(|(p, _, _)| p == "/relay/body").map(|(_, q, _)| q.clone()).collect();
    assert_eq!(fetched.len(), 1);
    assert!(fetched[0].split('&').any(|kv| kv == "req=41") && fetched[0].split('&').any(|kv| kv == "tok=hdev_x"), "{}", fetched[0]);

    let got = got.lock().unwrap();
    assert_eq!(got.len(), 1);
    let (m, p, cl, ct, te, body) = &got[0];
    assert_eq!((m.as_str(), p.as_str()), ("POST", "/upload"));
    assert_eq!(*cl, Some(data.len()), "explicit Content-Length, not chunked");
    assert_eq!(*te, None);
    assert_eq!(ct.as_deref(), Some("multipart/form-data; boundary=XyZ"));
    assert!(body == &data, "body differs: {} bytes vs {}", body.len(), data.len());

    let r = wait(|| replies(&log).into_iter().next());
    assert!(r.0.split('&').any(|kv| kv == "st=200"), "{}", r.0);
    assert_eq!(r.1, b"looped");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_staged_body_reaches_the_loopback_before_the_hub_has_sent_all_of_it() {
    let data: Vec<u8> = (0..4_000_000u32).map(|i| (i % 251) as u8).collect();
    let (loop_read, streamed) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let (lp, got) = loopback_counting(Arc::clone(&loop_read));
    let (base, log) = hub(Serve::Gated { data: data.clone(), loop_read, streamed: Arc::clone(&streamed) });
    let (c, dir) = cred(&base, "gated");
    crate::relay::serve_req(&c, &poll(5, &format!(r#","b":"","bf":1,"bl":{}"#, data.len())), lp);
    assert_eq!(streamed.load(Ordering::SeqCst), 1, "the loopback saw nothing until the whole body was fetched: it was buffered");
    assert!(got.lock().unwrap()[0].5 == data);
    let r = wait(|| replies(&log).into_iter().next());
    assert!(r.0.split('&').any(|kv| kv == "st=200"), "{}", r.0);
    let _ = std::fs::remove_dir_all(&dir);
}

fn failed(serve: Serve, bl: usize, tag: &str) -> (String, usize) {
    let (base, log) = hub(serve);
    let (lp, got) = loopback();
    let (c, dir) = cred(&base, tag);
    crate::relay::serve_req(&c, &poll(9, &format!(r#","b":"","bf":1,"bl":{bl}"#)), lp);
    let r = wait(|| replies(&log).into_iter().next());
    assert!(r.0.split('&').any(|kv| kv == "st=502"), "{}", r.0);
    let _ = std::fs::remove_dir_all(&dir);
    // Give a cut-off self-call time to land, so the count below is not a race.
    std::thread::sleep(std::time::Duration::from_millis(100));
    let complete = got.lock().unwrap().iter().filter(|g| g.2.is_some_and(|n| n == g.5.len())).count();
    (String::from_utf8(r.1).unwrap(), complete)
}

#[test]
fn a_missing_staged_body_replies_502_with_the_reason() {
    let (msg, complete) = failed(Serve::Status(404), 10, "404");
    assert_eq!(msg, "relay body fetch failed: hub answered 404");
    assert_eq!(complete, 0);
}

#[test]
fn a_staged_body_cut_short_replies_502_and_never_completes_the_self_call() {
    let (msg, complete) = failed(Serve::Short { declared: 200_000, sent: vec![7; 70_000] }, 200_000, "short");
    assert_eq!(msg, "relay body fetch failed: short body: got 70000 of 200000 bytes");
    assert_eq!(complete, 0, "the loopback must never see a whole body");
}

#[test]
fn a_staged_body_of_the_wrong_length_replies_502() {
    let (msg, complete) = failed(Serve::Bytes(vec![1; 5]), 10, "len");
    assert_eq!(msg, "relay body fetch failed: length mismatch: hub sent 5 bytes, expected 10");
    assert_eq!(complete, 0);
}

#[test]
fn a_request_without_bf_still_sends_the_inline_body() {
    let (base, log) = hub(Serve::Status(500));
    let (lp, got) = loopback();
    let (c, dir) = cred(&base, "inline");
    crate::relay::serve_req(&c, &poll(3, r#","b":"aGVsbG8=""#), lp);
    assert!(log.lock().unwrap().iter().all(|(p, _, _)| p != "/relay/body"), "no body fetch without bf");
    let got = got.lock().unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!((got[0].2, got[0].3.as_deref(), got[0].5.as_slice()), (Some(5), Some("multipart/form-data; boundary=XyZ"), &b"hello"[..]));
    let r = wait(|| replies(&log).into_iter().next());
    assert!(r.0.split('&').any(|kv| kv == "st=200"), "{}", r.0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_failed_self_call_never_sends_the_loopback_token_to_the_hub() {
    let (base, log) = hub(Serve::Status(500));
    let lp = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let (c, dir) = cred(&base, "leak");
    crate::relay::serve_req(&c, &poll(4, r#","b":"aGVsbG8=""#), lp);
    let r = wait(|| replies(&log).into_iter().next());
    let msg = String::from_utf8(r.1).unwrap();
    assert!(r.0.split('&').any(|kv| kv == "st=502"), "{}", r.0);
    assert!(msg.starts_with("relay self-call failed: "), "{msg}");
    assert!(!msg.contains("dtok") && !msg.contains(c.direct_token()) && !msg.contains("127.0.0.1"), "{msg}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bf_zero_or_false_is_not_staged() {
    for (v, want) in [(r#"{"bf":1}"#, true), (r#"{"bf":true}"#, true), (r#"{"bf":0}"#, false), (r#"{"bf":false}"#, false), (r#"{}"#, false)] {
        assert_eq!(super::staged(&serde_json::from_str(v).unwrap()), want, "{v}");
    }
}
