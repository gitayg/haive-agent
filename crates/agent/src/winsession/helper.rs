// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

// The SYSTEM screen helper (`--screen-helper <SPEC>`), running as LocalSystem
// inside the console session. Unlike a user-token process it can open the
// Winlogon desktop, so it captures and injects input on the UAC prompt, the lock
// screen and the Ctrl+Alt+Del screen. Microsoft
// (https://learn.microsoft.com/en-us/windows/win32/api/dxgi1_2/nf-dxgi1_2-idxgioutput1-duplicateoutput):
// "only an application that runs at LOCAL_SYSTEM can access the secure desktop."
//
// It serves 127.0.0.1:<port> only, and answers nothing without a valid request
// HMAC (securedesk/auth.rs). It exits when the service that launched it is gone
// or after `idle` seconds without a request. It creates no windows or hooks, so
// every thread can follow the input desktop (SetThreadDesktop's restriction).

use std::io::Read;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tiny_http::{Header, Request, Response, Server};
use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
use windows_sys::Win32::System::Threading::{OpenProcess, WaitForSingleObject, PROCESS_SYNCHRONIZE};

use crate::capture::Grabber;
use crate::input::Ev;
use crate::securedesk::auth::{self, NonceCache, KEY_LEN};
use crate::securedesk::follow_input_desktop;
use crate::securedesk::spec::{HelperSpec, EXIT_BAD_SPEC, EXIT_BIND, EXIT_IDLE, EXIT_PARENT_GONE, KEY_ENV};

/// Concurrent requests: /screen long-polls up to ~1 s per viewer, and input must
/// not queue behind them.
const WORKERS: usize = 8;
const MAX_REQUEST_BODY: u64 = 64 * 1024;

struct Ctx {
    key: [u8; KEY_LEN],
    spec: HelperSpec,
    grabber: Grabber,
    input: Mutex<Sender<Ev>>,
    nonces: Mutex<NonceCache>,
    start: Instant,
    last_used: AtomicU64,
}

pub fn run(spec: &str) -> ! {
    let Ok(spec) = HelperSpec::parse(spec) else { std::process::exit(EXIT_BAD_SPEC as i32) };
    let Some(key) = std::env::var(KEY_ENV).ok().and_then(|k| auth::parse_key(&k)) else {
        std::process::exit(EXIT_BAD_SPEC as i32)
    };
    std::env::remove_var(KEY_ENV);

    let parent = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, spec.ppid) };
    if parent.is_null() {
        std::process::exit(EXIT_PARENT_GONE as i32);
    }
    let Ok(server) = Server::http(("127.0.0.1", spec.port)) else { std::process::exit(EXIT_BIND as i32) };
    let server = Arc::new(server);

    let grabber = Grabber { index: spec.monitor };
    // Geometry for normalized input coordinates; follow first so it measures the
    // desktop that is actually showing.
    follow_input_desktop();
    let geo = grabber.geometry();
    let (tx, rx) = std::sync::mpsc::channel::<Ev>();
    std::thread::spawn(move || crate::input::run(rx, geo));

    let ctx = Arc::new(Ctx {
        key,
        spec,
        grabber,
        input: Mutex::new(tx),
        nonces: Mutex::new(NonceCache::new(4096)),
        start: Instant::now(),
        last_used: AtomicU64::new(0),
    });
    for _ in 0..WORKERS {
        let (server, ctx) = (server.clone(), ctx.clone());
        std::thread::spawn(move || loop {
            match server.recv_timeout(Duration::from_secs(1)) {
                Ok(Some(rq)) => handle(rq, &ctx),
                Ok(None) => {}
                Err(_) => break,
            }
        });
    }

    // Watchdog: bounded waits only.
    loop {
        if unsafe { WaitForSingleObject(parent, 1_000) } == WAIT_OBJECT_0 {
            std::process::exit(EXIT_PARENT_GONE as i32);
        }
        let idle = ctx.start.elapsed().as_secs().saturating_sub(ctx.last_used.load(Ordering::Relaxed));
        if idle >= ctx.spec.idle_secs {
            std::process::exit(EXIT_IDLE as i32);
        }
    }
}

fn header<'a>(rq: &'a Request, name: &'static str) -> &'a str {
    rq.headers().iter().find(|h| h.field.equiv(name)).map(|h| h.value.as_str()).unwrap_or("")
}

fn hdr(k: &str, v: &str) -> Header {
    Header::from_bytes(k.as_bytes(), v.as_bytes()).expect("static header")
}

fn handle(mut rq: Request, ctx: &Ctx) {
    let method = rq.method().as_str().to_string();
    let url = rq.url().to_string();
    let nonce = header(&rq, "X-Itai-N").to_string();
    let tag = header(&rq, "X-Itai-A").to_string();
    let mut body = Vec::new();
    if rq.as_reader().take(MAX_REQUEST_BODY).read_to_end(&mut body).is_err() {
        let _ = rq.respond(Response::empty(400));
        return;
    }
    let authed = auth::verify_request(&ctx.key, &method, &url, &nonce, &body, &tag)
        && ctx.nonces.lock().unwrap_or_else(|e| e.into_inner()).claim(&nonce);
    if !authed {
        // No proof header: an unauthenticated caller learns nothing.
        let _ = rq.respond(Response::empty(401));
        return;
    }
    ctx.last_used.store(ctx.start.elapsed().as_secs(), Ordering::Relaxed);

    let (path, query) = url.split_once('?').unwrap_or((url.as_str(), ""));
    let (status, ctype, data): (u16, &str, Vec<u8>) = match (method.as_str(), path) {
        ("GET", "/hello") => (204, "text/plain", Vec::new()),
        ("GET", "/frame") => {
            follow_input_desktop();
            match ctx.grabber.grab(ctx.spec.quality, ctx.spec.max_width) {
                Ok(jpeg) => (200, "image/jpeg", jpeg),
                Err(reason) => (500, "text/plain; charset=utf-8", reason.into_bytes()),
            }
        }
        ("GET", "/screen") => {
            follow_input_desktop();
            let r = crate::screen::handle(&ctx.grabber, ctx.spec.quality, ctx.spec.max_width, query);
            (r.status, r.ctype, r.body)
        }
        ("POST", "/input") => match std::str::from_utf8(&body).ok().and_then(crate::input::parse_body) {
            Some(ev) => {
                let _ = ctx.input.lock().unwrap_or_else(|e| e.into_inner()).send(ev);
                (204, "text/plain", Vec::new())
            }
            None => (400, "text/plain", Vec::new()),
        },
        _ => (404, "text/plain", Vec::new()),
    };
    let resp = Response::from_data(data)
        .with_status_code(status)
        .with_header(hdr("Content-Type", ctype))
        .with_header(hdr("X-Itai-P", &auth::response_tag(&ctx.key, &nonce, status)));
    let _ = rq.respond(resp);
}
