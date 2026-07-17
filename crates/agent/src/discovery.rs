// Resolve the Mac hub by its Bonjour id and (re)register this agent every 15s.
use std::net::UdpSocket;
use std::time::{Duration, Instant};

use mdns_sd::{ServiceDaemon, ServiceEvent};

const HUB_SERVICE: &str = "_rmtscrn._tcp.local.";

pub fn local_ip() -> String {
    UdpSocket::bind("0.0.0.0:0")
        .ok()
        .and_then(|s| {
            s.connect("8.8.8.8:80").ok()?;
            Some(s.local_addr().ok()?.ip().to_string())
        })
        .unwrap_or_else(|| "127.0.0.1".to_string())
}

// `primary` is the hub target: a direct IP / host:port, OR a Bonjour Mac ID.
// `fallback_id` is an optional Mac ID used for mDNS when `primary` is an IP that
// can't be reached — so the agent supports IP, ID, or both (IP first, ID fallback).
pub fn register_loop(primary: String, fallback_id: Option<String>, name: String, port: u16, scheme: &'static str, info: serde_json::Value) {
    let mut enrolled = false;
    loop {
        // Merge freshly-sampled CPU load + free RAM into the static sysinfo each cycle.
        let mut payload = info.clone();
        if let (Some(obj), Some(metrics)) = (payload.as_object_mut(), crate::live_metrics().as_object()) {
            for (k, v) in metrics {
                obj.insert(k.clone(), v.clone());
            }
        }
        let mut ok = false;
        if let Some((ip, hport)) = direct_addr(&primary) {
            ok = post_register(&ip, hport, &name, port, scheme, &payload);
        }
        if !ok {
            let id = if direct_addr(&primary).is_some() {
                fallback_id.as_deref()
            } else {
                Some(primary.as_str())
            };
            if let Some(id) = id {
                if let Some((ip, hport)) = mdns_resolve(id) {
                    ok = post_register(&ip, hport, &name, port, scheme, &payload);
                }
            }
        }
        if ok && !enrolled {
            enrolled = true;
            println!("ready");
        }
        std::thread::sleep(Duration::from_secs(15));
    }
}

fn post_register(hub_ip: &str, hub_port: u16, name: &str, port: u16, scheme: &'static str, info: &serde_json::Value) -> bool {
    let url = format!("http://{hub_ip}:{hub_port}/register");
    let mut body = serde_json::json!({
        "name": name, "ip": local_ip(), "port": port, "scheme": scheme
    });
    if let (Some(obj), Some(extra)) = (body.as_object_mut(), info.as_object()) {
        for (k, v) in extra {
            obj.insert(k.clone(), v.clone());
        }
    }
    ureq::post(&url).send_json(body).is_ok()
}

fn direct_addr(target: &str) -> Option<(String, u16)> {
    if let Some((host, port)) = target.rsplit_once(':') {
        if let Ok(p) = port.parse::<u16>() {
            return Some((host.to_string(), p));
        }
    }
    if target.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
        return Some((target.to_string(), 8770));
    }
    None
}

fn mdns_resolve(mac_id: &str) -> Option<(String, u16)> {
    let mdns = ServiceDaemon::new().ok()?;
    let rx = mdns.browse(HUB_SERVICE).ok()?;
    let prefix = format!("{mac_id}.");
    let deadline = Instant::now() + Duration::from_secs(4);
    let mut found = None;
    while Instant::now() < deadline {
        if let Ok(ServiceEvent::ServiceResolved(info)) = rx.recv_timeout(Duration::from_secs(1)) {
            if info.get_fullname().starts_with(&prefix) {
                if let Some(ip) = info.get_addresses().iter().next() {
                    found = Some((ip.to_string(), info.get_port()));
                    break;
                }
            }
        }
    }
    let _ = mdns.shutdown();
    found
}

fn resolve_hub(primary: &str, fallback_id: &Option<String>) -> Option<(String, u16)> {
    if let Some(addr) = direct_addr(primary) {
        return Some(addr);
    }
    let id = fallback_id.as_deref().or(Some(primary));
    id.and_then(mdns_resolve)
}

/// Every 2 minutes, fetch the agent binary the hub is hosting for this platform;
/// if it differs from the running executable, self-update and restart.
pub fn auto_update_loop(primary: String, fallback_id: Option<String>, asset: String) {
    let self_bytes = match std::env::current_exe().ok().and_then(|p| std::fs::read(p).ok()) {
        Some(b) => b,
        None => return,
    };
    loop {
        std::thread::sleep(Duration::from_secs(120));
        if let Some((ip, port)) = resolve_hub(&primary, &fallback_id) {
            let url = format!("http://{ip}:{port}/bin/{asset}");
            if let Some(newb) = download_agent(&url) {
                if !newb.is_empty() && newb != self_bytes && crate::http::apply_update(&newb) {
                    std::thread::sleep(Duration::from_millis(500));
                    std::process::exit(0);
                }
            }
        }
    }
}

/// Same as `auto_update_loop`, but for relay agents (no LAN mac-id to resolve):
/// pull the binary straight from the relay URL's `/bin/`. `apply_update` self-
/// replaces AND re-execs, so this self-restarts without needing a supervisor.
pub fn auto_update_relay(base: String, asset: String) {
    let self_bytes = match std::env::current_exe().ok().and_then(|p| std::fs::read(p).ok()) {
        Some(b) => b,
        None => return,
    };
    let b = base.trim_end_matches('/').to_string();
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(120));
        let url = format!("{b}/bin/{asset}");
        if let Some(newb) = download_agent(&url) {
            if !newb.is_empty() && newb != self_bytes && crate::http::apply_update(&newb) {
                std::thread::sleep(Duration::from_millis(500));
                std::process::exit(0);
            }
        }
    });
}

fn download_agent(url: &str) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut r = ureq::get(url).call().ok()?.into_reader();
    let mut buf = Vec::new();
    r.read_to_end(&mut buf).ok()?;
    Some(buf)
}
