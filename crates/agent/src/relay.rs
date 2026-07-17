// Reverse tunnel client. Instead of holding a socket, the agent talks to the
// hub over ordinary HTTP long-poll — so it traverses NAT and rides a single
// HTTPS endpoint (PaaS bypass path):
//   POST /relay/hello   — register + heartbeat (fresh sysinfo/metrics)
//   GET  /relay/poll    — long-poll for the next request the hub wants run
//   POST /relay/reply   — stream the response back (chunked upload)
// Each request is satisfied by calling our own loopback server, so every
// existing endpoint works over the tunnel with no special-casing.
use std::io::Read;
use std::time::Duration;

use base64::Engine;

fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// Accept `http://host:port`, `host:port`, or a bare host (→ http://host).
fn normalize(hub: &str) -> String {
    let h = hub.trim_end_matches('/');
    if h.starts_with("http://") || h.starts_with("https://") {
        h.to_string()
    } else {
        format!("http://{h}")
    }
}

fn hello_payload(relay_id: &str, name: &str, sysinfo: &serde_json::Value) -> Vec<u8> {
    let mut d = sysinfo.clone();
    if let Some(o) = d.as_object_mut() {
        o.insert("relay_id".into(), serde_json::json!(relay_id));
        o.insert("name".into(), serde_json::json!(name));
        if let Some(m) = crate::live_metrics().as_object() {
            for (k, v) in m {
                o.insert(k.clone(), v.clone());
            }
        }
    }
    d.to_string().into_bytes()
}

/// `&tok=…` (or empty) to authenticate against a token-protected relay.
fn tok_q(token: &str) -> String {
    if token.is_empty() {
        String::new()
    } else {
        format!("&tok={}", urlencode(token))
    }
}

fn post_hello(base: &str, relay_id: &str, name: &str, sysinfo: &serde_json::Value, token: &str) -> bool {
    ureq::post(&format!("{base}/relay/hello?id={}{}", urlencode(relay_id), tok_q(token)))
        .timeout(Duration::from_secs(10))
        .send_bytes(&hello_payload(relay_id, name, sysinfo))
        .is_ok()
}

pub fn relay_loop(hub: String, relay_id: String, name: String, sysinfo: serde_json::Value, token: String) {
    let base = normalize(&hub);

    // Register (retry until the hub is reachable) before polling.
    while !post_hello(&base, &relay_id, &name, &sysinfo, &token) {
        std::thread::sleep(Duration::from_secs(3));
    }
    println!("relay: connected to {base} as {relay_id}");

    // Heartbeat: re-send HELLO (fresh CPU/RAM) so the hub keeps us live. 10s keeps
    // us well inside the hub's staleness window (tolerates a few missed beats) and
    // acts as an app-level keepalive so NAT/proxy idle timeouts don't drop us.
    {
        let (b, rid, nm, si, tk) = (base.clone(), relay_id.clone(), name.clone(), sysinfo.clone(), token.clone());
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(10));
            let _ = post_hello(&b, &rid, &nm, &si, &tk);
        });
    }

    let poll_url = format!("{base}/relay/poll?id={}{}", urlencode(&relay_id), tok_q(&token));
    loop {
        match ureq::get(&poll_url).timeout(Duration::from_secs(35)).call() {
            Ok(resp) => {
                if resp.status() == 204 {
                    continue;
                }
                let mut body = String::new();
                if resp.into_reader().read_to_string(&mut body).is_ok() && !body.is_empty() {
                    let (b, rid, tk) = (base.clone(), relay_id.clone(), token.clone());
                    std::thread::spawn(move || handle_req(&b, &rid, &tk, &body));
                }
            }
            Err(_) => {
                // A failed poll means the tunnel dropped (hub redeploy, NAT/proxy
                // reset). Re-register at a steady fast cadence until the hub
                // answers — recreating our tunnel within ~½s of it coming back,
                // not on the next 10s heartbeat — so the hub's wait-for-reconnect
                // lands the command instead of reporting us unreachable. Jitter
                // keeps a fleet from reconnecting in lockstep.
                while !post_hello(&base, &relay_id, &name, &sysinfo, &token) {
                    let jitter = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| (d.subsec_nanos() as u64) % 250)
                        .unwrap_or(0);
                    std::thread::sleep(Duration::from_millis(500 + jitter));
                }
            }
        }
    }
}

fn handle_req(base: &str, relay_id: &str, token: &str, body: &str) {
    let v: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
    let req_id = v.get("id").and_then(|x| x.as_u64()).unwrap_or(0);
    let method = v.get("m").and_then(|x| x.as_str()).unwrap_or("GET").to_uppercase();
    let path = v.get("p").and_then(|x| x.as_str()).unwrap_or("/").to_string();
    let ct = v.get("ct").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let reqbody = v
        .get("b")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok());

    let reply = |status: u16, ctype: &str| format!("{base}/relay/reply?id={}&req={}&st={}&ct={}{}", urlencode(relay_id), req_id, status, urlencode(ctype), tok_q(token));

    let lp = crate::http::loopback_port();
    if lp == 0 {
        let _ = ureq::post(&reply(503, "text/plain")).send_string("agent loopback not ready");
        return;
    }

    let url = format!("http://127.0.0.1:{lp}{path}");
    let r = ureq::request(&method, &url);
    let sent = match &reqbody {
        Some(b) if ct.is_empty() => r.send_bytes(b),
        Some(b) => r.set("Content-Type", &ct).send_bytes(b),
        None => r.call(),
    };
    let resp = match sent {
        Ok(r) => r,
        Err(ureq::Error::Status(_, r)) => r,
        Err(e) => {
            let _ = ureq::post(&reply(502, "text/plain")).send_string(&format!("relay self-call failed: {e}"));
            return;
        }
    };
    let status = resp.status();
    let ctype = resp.header("Content-Type").unwrap_or("application/octet-stream").to_string();
    // Stream the response body straight up as the reply's (chunked) upload; if
    // the hub stops reading (browser gone), this write fails and we stop.
    let _ = ureq::post(&reply(status, &ctype)).send(resp.into_reader());
}
