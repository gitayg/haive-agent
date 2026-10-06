// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

// Server-driven agent config: keep the enrollment command minimal and pull the
// rest (e.g. whether to show the tray icon) from the hub, refreshed periodically.
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::relaycred::{auth_query, RelayCred};

static TRAY: AtomicBool = AtomicBool::new(true);

/// Whether the hub wants a tray/menu-bar icon shown while the agent runs.
#[allow(dead_code)]
pub fn tray_enabled() -> bool {
    TRAY.load(Ordering::Relaxed)
}

pub(crate) fn config_url(hub: &str, relay_id: &str, token: &str) -> String {
    format!("{}/relay/config?{}", hub.trim_end_matches('/'), auth_query(relay_id, token))
}

pub(crate) fn cap_key_url(hub: &str, relay_id: &str, token: &str) -> String {
    format!("{}/relay/cap-key?{}", hub.trim_end_matches('/'), auth_query(relay_id, token))
}

pub(crate) fn cert_url(hub: &str, relay_id: &str, token: &str) -> String {
    format!("{}/relay/cert?{}", hub.trim_end_matches('/'), auth_query(relay_id, token))
}

/// Poll `{hub}/relay/config` every 60s and apply the returned config. The token
/// is read from the shared credential on every poll, so a switch is picked up.
pub fn start_poll(hub: String, cred: Arc<RelayCred>) {
    std::thread::spawn(move || loop {
        let url = config_url(&hub, cred.relay_id(), &cred.token());
        if let Ok(r) = ureq::get(&url).call() {
            if let Ok(v) = r.into_json::<serde_json::Value>() {
                if let Some(tray) = v.get("tray").and_then(|x| x.as_bool()) {
                    TRAY.store(tray, Ordering::Relaxed);
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(60));
    });
}

/// A startup fetch made with the shared credential. These run before the first
/// hello, so a device secret the hub has revoked would otherwise cost the cap key
/// and the hub cert for the whole run. On a 401 to a device secret, fall back to
/// the enrollment token supplied on this start exactly as a hello does
/// (`RelayCred::rejected`), and retry once; the first hello then re-enrolls.
/// Holds `hello_lock` so no hello can issue a secret between the try and the fallback.
/// `call` maps its error to `unauthorized(e)`: whether the hub answered 401.
fn call_with_fallback(cred: &RelayCred, call: impl Fn(&str) -> Result<ureq::Response, bool>) -> Option<ureq::Response> {
    let _g = cred.hello_lock.lock().unwrap_or_else(|e| e.into_inner());
    let (token, was_device) = (cred.token(), cred.is_device());
    match call(&token) {
        Ok(r) => Some(r),
        Err(true) if was_device => {
            eprintln!("relay: device credential rejected — re-enroll this device");
            if !cred.rejected() {
                return None;
            }
            eprintln!("relay: falling back to the enrollment token supplied on this start to re-enroll");
            call(&cred.token()).ok()
        }
        Err(_) => None,
    }
}

fn unauthorized(e: ureq::Error) -> bool {
    matches!(e, ureq::Error::Status(401, _))
}

/// Fetch the hub's ed25519 capability public key (64 lowercase hex characters),
/// which is what the agent verifies LAN-direct capability tokens against.
///
/// Taken over `/relay/*` — the channel `relay_ok` already authenticates with the
/// enrollment token — because the agent holds no MCP token and so cannot reach
/// the `/m/cap-key` copy the controllers use. Both serve the same key.
///
/// Beyond the rejected-secret fallback there is no retry: None means the direct
/// path stays closed (see `http::CAP_PUBKEY`), and the agent runs on the relay.
pub fn fetch_cap_key(hub: &str, cred: &RelayCred) -> Option<String> {
    let get = |tok: &str| ureq::get(&cap_key_url(hub, cred.relay_id(), tok)).timeout(std::time::Duration::from_secs(10)).call().map_err(unauthorized);
    let body = call_with_fallback(cred, get)?.into_string().ok()?;
    let key = body.trim().to_string();
    (key.len() == 64).then_some(key)
}

/// Ask the hub to sign a leaf cert for this agent (SANs = our LAN IPs + a stable
/// name), so a same-LAN controller can validate a direct connection against the
/// hub CA. Returns (cert_pem, key_pem) bytes, or None to fall back to self-signed.
pub fn fetch_hub_cert(hub: &str, cred: &RelayCred, sans: Vec<String>) -> Option<(Vec<u8>, Vec<u8>)> {
    let body = serde_json::json!({ "relay_id": cred.relay_id(), "sans": sans });
    let post = |tok: &str| ureq::post(&cert_url(hub, cred.relay_id(), tok)).timeout(std::time::Duration::from_secs(10)).send_json(body.clone()).map_err(unauthorized);
    let r = call_with_fallback(cred, post)?;
    let v: serde_json::Value = r.into_json().ok()?;
    let cert = v.get("cert")?.as_str()?.as_bytes().to_vec();
    let key = v.get("key")?.as_str()?.as_bytes().to_vec();
    Some((cert, key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relaycred::Resolved;

    const KEY: &str = "abababababababababababababababababababababababababababababababab";

    /// A hub that has revoked `hdev_revoked` (401, as `relay_ok` answers) and
    /// still accepts the enrollment token `htok_e`. Returns its base URL.
    fn fake_hub() -> String {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = server.server_addr().to_ip().unwrap().port();
        std::thread::spawn(move || {
            for mut rq in server.incoming_requests() {
                let mut body = String::new();
                let _ = std::io::Read::read_to_string(rq.as_reader(), &mut body);
                let url = rq.url().to_string();
                let ok = url.split_once('?').is_some_and(|(_, q)| q.split('&').any(|kv| kv == "tok=htok_e"));
                let resp = match (ok, url.split('?').next().unwrap_or("")) {
                    (false, _) => tiny_http::Response::from_string("device credential rejected").with_status_code(401),
                    (true, "/relay/cap-key") => tiny_http::Response::from_string(KEY),
                    (true, "/relay/cert") => tiny_http::Response::from_string(r#"{"cert":"C","key":"K"}"#),
                    _ => tiny_http::Response::from_string("").with_status_code(404),
                };
                let _ = rq.respond(resp);
            }
        });
        format!("http://127.0.0.1:{port}")
    }

    fn cred(hub: &str, tag: &str, supplied: Option<&str>) -> RelayCred {
        let file = std::env::temp_dir().join(format!("it-ai-config-{tag}-{}", std::process::id())).join("relay.cred");
        let r = Resolved { token: "hdev_revoked".into(), is_device: true, supplied_enroll: supplied.map(String::from) };
        RelayCred::new(hub, "hc-1", file, r)
    }

    #[test]
    fn startup_fetches_recover_from_a_rejected_device_secret() {
        let hub = fake_hub();
        // Revoked secret + an enrollment token supplied on this start: both
        // fetches fall back to it, and the credential the first hello will use
        // (with ds=1) is the enrollment token, so it re-enrolls.
        let c = cred(&hub, "cap", Some("htok_e"));
        assert_eq!(fetch_cap_key(&hub, &c).as_deref(), Some(KEY));
        assert_eq!((c.token(), c.is_device()), ("htok_e".to_string(), false));
        let c = cred(&hub, "cert", Some("htok_e"));
        assert_eq!(fetch_hub_cert(&hub, &c, vec![]), Some((b"C".to_vec(), b"K".to_vec())));
        // Nothing to fall back to: no key, and the secret is kept.
        let c = cred(&hub, "none", None);
        assert_eq!(fetch_cap_key(&hub, &c), None);
        assert_eq!((c.token(), c.is_device()), ("hdev_revoked".to_string(), true));
    }
}
