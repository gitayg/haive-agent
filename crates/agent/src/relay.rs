// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

// Reverse tunnel client. Instead of holding a socket, the agent talks to the
// hub over ordinary HTTP long-poll — so it traverses NAT and rides a single
// HTTPS endpoint (PaaS bypass path):
//   POST /relay/hello   — register + heartbeat (fresh sysinfo/metrics)
//   GET  /relay/poll    — long-poll for the next request the hub wants run
//   POST /relay/reply   — stream the response back (chunked upload)
// Each request is satisfied by calling our own loopback server, so every
// existing endpoint works over the tunnel with no special-casing.
use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;

use crate::relay_redirect::{self, Body, Rule};
use crate::relaycred::{auth_query, urlencode, RelayCred};

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

/// How long to wait between hellos while the hub rejects our device secret and
/// there is no enrollment token to fall back to. Never exit; just stop hammering.
const REJECTED_RETRY: Duration = Duration::from_secs(60);

pub(crate) fn hello_url(base: &str, relay_id: &str, token: &str) -> String {
    format!("{base}/relay/hello?{}&ds=1", auth_query(relay_id, token))
}

pub(crate) fn poll_url(base: &str, relay_id: &str, token: &str) -> String {
    format!("{base}/relay/poll?{}", auth_query(relay_id, token))
}

pub(crate) fn reply_url(base: &str, relay_id: &str, token: &str, req_id: u64, status: u16, ctype: &str) -> String {
    format!("{base}/relay/reply?{}&req={req_id}&st={status}&ct={}", auth_query(relay_id, token), urlencode(ctype))
}

/// The self-call into our own loopback server, presenting the direct token the
/// loopback gate holds (frozen at startup, so a credential switch can't break it).
pub(crate) fn loopback_url(lp: u16, path: &str, cred: &RelayCred) -> String {
    let sep = if path.contains('?') { '&' } else { '?' };
    format!("http://127.0.0.1:{lp}{path}{sep}dtok={}", urlencode(cred.direct_token()))
}

/// One hello. Always asks for a device secret (`ds=1`); a 200 carrying one
/// switches every caller to it. Serialized on `hello_lock` so two hellos can't
/// both mint and leave us on the secret the hub already replaced. A redirect not
/// followed is a failure (`relay_redirect`), never "connected".
fn post_hello(name: &str, sysinfo: &serde_json::Value, cred: &RelayCred) -> bool {
    hello(name, sysinfo, cred, relay_redirect::same_family)
}

fn hello(name: &str, sysinfo: &serde_json::Value, cred: &RelayCred, follow: Rule) -> bool {
    let _g = cred.hello_lock.lock().unwrap_or_else(|e| e.into_inner());
    let (token, was_device) = (cred.token(), cred.is_device());
    let rid = cred.relay_id();
    let payload = hello_payload(rid, name, sysinfo);
    let sent = relay_redirect::send(cred, "POST", &hello_url(&cred.base(), rid, &token), Body::Bytes(None, &payload), Some(Duration::from_secs(10)), follow);
    match sent {
        Ok(resp) => {
            let status = resp.status();
            let body = if status == 200 { resp.into_string().unwrap_or_default() } else { String::new() };
            if let Some(secret) = crate::relaycred::parse_issued(status, &body) {
                if let Err(e) = cred.issued(&secret) {
                    eprintln!("relay: could not save the device credential ({e}) — using it for this run only");
                }
                println!("relay: device credential issued");
            }
            true
        }
        Err(ureq::Error::Status(401, _)) if was_device => {
            eprintln!("relay: device credential rejected — re-enroll this device");
            if cred.rejected() {
                eprintln!("relay: falling back to the enrollment token supplied on this start to re-enroll");
            } else {
                std::thread::sleep(REJECTED_RETRY);
            }
            false
        }
        Err(_) => false,
    }
}

pub fn relay_loop(name: String, sysinfo: serde_json::Value, cred: Arc<RelayCred>) {
    let relay_id = cred.relay_id().to_string();

    // Register (retry until the hub is reachable) before polling.
    while !post_hello(&name, &sysinfo, &cred) {
        std::thread::sleep(Duration::from_secs(3));
    }
    println!("relay: connected to {} as {relay_id}", cred.base());

    // Heartbeat: re-send HELLO (fresh CPU/RAM) so the hub keeps us live. 10s keeps
    // us well inside the hub's staleness window (tolerates a few missed beats) and
    // acts as an app-level keepalive so NAT/proxy idle timeouts don't drop us.
    {
        let (nm, si, c) = (name.clone(), sysinfo.clone(), Arc::clone(&cred));
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(10));
            let _ = post_hello(&nm, &si, &c);
        });
    }

    loop {
        // Rebuilt every time: the credential or the base may have switched since the last poll.
        match relay_redirect::get(&cred, &poll_url(&cred.base(), &relay_id, &cred.token()), Some(Duration::from_secs(35))) {
            Ok(resp) => {
                if resp.status() == 204 {
                    continue;
                }
                let mut body = String::new();
                if resp.into_reader().read_to_string(&mut body).is_ok() && !body.is_empty() {
                    let c = Arc::clone(&cred);
                    std::thread::spawn(move || handle_req(&c, &body));
                }
            }
            Err(_) => {
                // A failed poll means the tunnel dropped (hub redeploy, NAT/proxy
                // reset). Re-register at a steady fast cadence until the hub
                // answers — recreating our tunnel within ~½s of it coming back,
                // not on the next 10s heartbeat — so the hub's wait-for-reconnect
                // lands the command instead of reporting us unreachable. Jitter
                // keeps a fleet from reconnecting in lockstep.
                while !post_hello(&name, &sysinfo, &cred) {
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

fn handle_req(cred: &RelayCred, body: &str) {
    let relay_id = cred.relay_id();
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

    let reply = |status: u16, ctype: &str| reply_url(&cred.base(), relay_id, &cred.token(), req_id, status, ctype);
    let short = |status: u16, msg: &str| {
        let _ = relay_redirect::post(cred, &reply(status, "text/plain"), Body::Bytes(None, msg.as_bytes()), None);
    };

    let lp = crate::http::loopback_port();
    if lp == 0 {
        short(503, "agent loopback not ready");
        return;
    }

    // Present the agent's own direct token: loopback no longer authorizes the
    // privileged endpoints by itself (see http::privileged_path). It is derived
    // from the relay credentials we already hold, so no new secret is needed —
    // and frozen at startup, so it still matches the loopback gate after the
    // credential switches to a device secret.
    let url = loopback_url(lp, &path, cred);
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
            short(502, &format!("relay self-call failed: {e}"));
            return;
        }
    };
    let status = resp.status();
    let ctype = resp.header("Content-Type").unwrap_or("application/octet-stream").to_string();
    // Stream the response body straight up as the reply's (chunked) upload; if
    // the hub stops reading (browser gone), this write fails and we stop. A
    // streamed body can't be re-sent, so a redirect here fails (and is logged);
    // the next hello follows it and moves the base for the replies after it.
    let _ = relay_redirect::post(cred, &reply(status, &ctype), Body::Stream(None, Box::new(resp.into_reader())), None);
}

#[cfg(test)]
mod tests {
    #[test]
    fn every_relay_url_carries_the_relay_id() {
        let (b, rid, tok) = ("https://hub.example", "hc-0badf00d", "hdev_x");
        let urls = [
            super::hello_url(b, rid, tok),
            super::poll_url(b, rid, tok),
            super::reply_url(b, rid, tok, 7, 200, "text/plain"),
            crate::config::config_url(b, rid, tok),
            crate::config::cap_key_url(b, rid, tok),
            crate::config::cert_url(b, rid, tok),
            crate::analysis::analysis_url(b, rid, tok),
            crate::http::ai_url(b, "ai-chat", rid, tok),
        ];
        for u in &urls {
            let q = u.split_once('?').map(|x| x.1).unwrap_or("");
            assert!(q.split('&').any(|kv| kv == "id=hc-0badf00d"), "no id= in {u}");
            assert!(q.split('&').any(|kv| kv == "tok=hdev_x"), "no tok= in {u}");
        }
        assert!(urls[0].ends_with("&ds=1"), "hello must ask for a device secret: {}", urls[0]);
    }

    #[test]
    fn loopback_dtok_survives_the_credential_switch() {
        use crate::relaycred::{RelayCred, Resolved};
        let dir = std::env::temp_dir().join(format!("it-ai-relay-dtok-{}", std::process::id()));
        let r = Resolved { token: "htok_e".into(), is_device: false, supplied_enroll: None };
        let cred = RelayCred::new("https://hub.example", "hc-1", dir.join("relay.cred"), r);
        let before = super::loopback_url(9, "/exec", &cred);
        assert!(before.ends_with(&format!("dtok={}", crate::agent_direct_token("htok_e", "hc-1"))));
        cred.issued("hdev_x").unwrap();
        assert_eq!(super::loopback_url(9, "/exec", &cred), before);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn cred(hub: &str, tag: &str) -> (crate::relaycred::RelayCred, std::path::PathBuf) {
        use crate::relaycred::{RelayCred, Resolved};
        let dir = std::env::temp_dir().join(format!("it-ai-relay-{tag}-{}", std::process::id()));
        let r = Resolved { token: "htok_e".into(), is_device: false, supplied_enroll: Some("htok_e".into()) };
        (RelayCred::new(hub, "hc-1", dir.join("relay.cred"), r), dir)
    }

    #[test]
    fn a_hello_answered_with_a_redirect_is_not_connected() {
        use crate::relay_redirect::testhub;
        for (st, to) in [(308, "https://evil.example{path}?{query}"), (307, "http://127.0.0.1:{port}/moved{path}?{query}"), (301, "https://evil.example{path}")] {
            let (hub, seen) = testhub::start(st, to, r#"{"device_secret":"hdev_new"}"#);
            let (c, dir) = cred(&hub, &format!("no{st}"));
            assert!(!super::post_hello("n", &serde_json::json!({}), &c), "{st} to {to} must not count as connected");
            assert_eq!(seen.lock().unwrap().len(), 1);
            assert_eq!((c.token(), c.base()), ("htok_e".to_string(), hub));
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn a_hello_follows_the_hub_within_its_family_and_keeps_the_saved_hub() {
        use crate::relay_redirect::testhub;
        use crate::relaycred::{load, resolve};
        let (hub, seen) = testhub::start(308, "http://127.0.0.1:{port}/moved{path}?{query}", r#"{"device_secret":"hdev_new"}"#);
        let (c, dir) = cred(&hub, "follow");
        assert!(super::hello("n", &serde_json::json!({}), &c, testhub::same_host));
        {
            let seen = seen.lock().unwrap();
            assert_eq!(seen.len(), 2);
            assert_eq!(seen[1].0, "/moved/relay/hello");
            assert_eq!(seen[0].2, seen[1].2, "the hello body is re-sent unchanged");
            assert!(String::from_utf8_lossy(&seen[1].2).contains("\"relay_id\":\"hc-1\""));
        }
        assert_eq!(c.base(), format!("{hub}/moved"));
        assert_eq!((c.token(), c.is_device()), ("hdev_new".to_string(), true));
        // The next start still finds the secret under the --relay it was given.
        let r = resolve(&hub, None, None, load(c.file()).as_ref()).unwrap();
        assert_eq!((r.token.as_str(), r.is_device), ("hdev_new", true));
        // Later calls go straight to the new base.
        assert!(super::post_hello("n", &serde_json::json!({}), &c));
        assert_eq!(seen.lock().unwrap().last().unwrap().0, "/moved/relay/hello");
        assert!(super::reply_url(&c.base(), "hc-1", &c.token(), 1, 200, "x").starts_with(&format!("{hub}/moved/relay/reply?")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_reply_answered_with_a_redirect_fails() {
        use crate::relay_redirect::{post, testhub, Body};
        let (hub, seen) = testhub::start(308, "https://evil.example{path}?{query}", "");
        let (c, dir) = cred(&hub, "reply");
        let url = super::reply_url(&c.base(), "hc-1", &c.token(), 7, 200, "text/plain");
        assert!(matches!(post(&c, &url, Body::Stream(None, Box::new(&b"out"[..])), None), Err(ureq::Error::Status(308, _))));
        assert!(matches!(post(&c, &url, Body::Bytes(None, b"short"), None), Err(ureq::Error::Status(308, _))));
        assert_eq!(seen.lock().unwrap().len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
