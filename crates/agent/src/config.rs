// Server-driven agent config: keep the enrollment command minimal and pull the
// rest (e.g. whether to show the tray icon) from the hub, refreshed periodically.
use std::sync::atomic::{AtomicBool, Ordering};

static TRAY: AtomicBool = AtomicBool::new(true);

/// Whether the hub wants a tray/menu-bar icon shown while the agent runs.
#[allow(dead_code)]
pub fn tray_enabled() -> bool {
    TRAY.load(Ordering::Relaxed)
}

/// Poll `{hub}/relay/config` every 60s and apply the returned config.
pub fn start_poll(hub: String, token: Option<String>) {
    std::thread::spawn(move || loop {
        let mut url = format!("{}/relay/config", hub.trim_end_matches('/'));
        if let Some(t) = token.as_deref() {
            url.push_str(&format!("?tok={t}"));
        }
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

/// Ask the hub to sign a leaf cert for this agent (SANs = our LAN IPs + a stable
/// name), so a same-LAN controller can validate a direct connection against the
/// hub CA. Returns (cert_pem, key_pem) bytes, or None to fall back to self-signed.
pub fn fetch_hub_cert(hub: &str, relay_id: &str, token: &str, sans: Vec<String>) -> Option<(Vec<u8>, Vec<u8>)> {
    let base = hub.trim_end_matches('/');
    let mut url = format!("{base}/relay/cert");
    if !token.is_empty() {
        url.push_str(&format!("?tok={token}"));
    }
    let body = serde_json::json!({ "relay_id": relay_id, "sans": sans });
    let r = ureq::post(&url).timeout(std::time::Duration::from_secs(10)).send_json(body).ok()?;
    let v: serde_json::Value = r.into_json().ok()?;
    let cert = v.get("cert")?.as_str()?.as_bytes().to_vec();
    let key = v.get("key")?.as_str()?.as_bytes().to_vec();
    Some((cert, key))
}
