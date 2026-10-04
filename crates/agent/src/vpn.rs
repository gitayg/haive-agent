// SPDX-License-Identifier: MIT
//! VPN exit node: lets phones and PCs browse with this device's public IP.
//!
//! The device is assumed to sit behind CGNAT, so nothing can connect IN to it.
//! Instead it dials OUT to the hub's UDP relay and keeps that path open:
//!
//! ```text
//!  WireGuard app ──UDP──▶ hub relay (public) ──UDP, framed──▶ this shim ──▶ 127.0.0.1:51820 (wg)
//!                                                                                 │ NAT
//!                                                                                 ▼ internet
//! ```
//!
//! The relay only ever moves WireGuard ciphertext; it cannot read traffic. The
//! WireGuard interface listens on a port this module firewalls to loopback, so
//! the shim is its only door. For each client address the relay reports, the
//! shim opens a loopback socket, so WireGuard sees every peer at a distinct
//! `127.0.0.1:<port>` endpoint and roaming keeps working.
//!
//! Driven by the hub over the relay (`/vpn/apply`, `/vpn/disable`, `/vpn/status`
//! — all privileged). The last applied state is saved, so the exit comes back on
//! its own after a reboot, and pass expiry is enforced here too, so a pass ends
//! on time even if the hub is unreachable. Linux only; needs root (`--install`).

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const IFACE: &str = "itai-wg";
const ADDR: &str = "10.77.0.1/24";
const SUBNET: &str = "10.77.0.0/24";
/// WireGuard's listen port. Firewalled to loopback: only the shim reaches it.
const WG_PORT: u16 = 51820;
/// Leaves room for the relay's framing on the relay→device hop (≤22 bytes).
pub const MTU: u32 = 1380;
const TAG: &str = "it-ai-vpn";
/// Pass holders get the internet — not this device's LAN, not CGNAT space.
const BLOCKED_NETS: &[&str] = &["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10"];

// ---- wire format shared with the hub relay (crates/hub/src/vpnrelay.rs) -------
// WireGuard messages start with a type byte 1..=4 followed by three zero bytes,
// so a leading 0xF0 can never be mistaken for one.
pub const MAGIC: u8 = 0xF0;
pub const T_HELLO: u8 = 1; // device → relay: F0 01 | ts_ms u64 | idlen u8 | id | hmac[32]
pub const T_ACK: u8 = 2; //   relay → device: F0 02 | ts_ms u64 (echo)
pub const T_DATA: u8 = 3; //  both ways:      F0 03 | fam u8 (4|6) | ip | port u16 | payload

pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let (mut ipad, mut opad) = ([0x36u8; 64], [0x5cu8; 64]);
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let inner = Sha256::new().chain_update(ipad).chain_update(msg).finalize();
    Sha256::new().chain_update(opad).chain_update(inner).finalize().into()
}

pub fn encode_hello(ts_ms: u64, device: &str, secret: &[u8]) -> Vec<u8> {
    let id = &device.as_bytes()[..device.len().min(255)];
    let mut f = vec![MAGIC, T_HELLO];
    f.extend_from_slice(&ts_ms.to_be_bytes());
    f.push(id.len() as u8);
    f.extend_from_slice(id);
    let mac = hmac_sha256(secret, &f);
    f.extend_from_slice(&mac);
    f
}

pub fn encode_data(client: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(payload.len() + 22);
    f.extend_from_slice(&[MAGIC, T_DATA]);
    match client.ip() {
        IpAddr::V4(ip) => {
            f.push(4);
            f.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            f.push(6);
            f.extend_from_slice(&ip.octets());
        }
    }
    f.extend_from_slice(&client.port().to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// `(client, payload)` from a DATA frame, or None if it is not one.
pub fn decode_data(f: &[u8]) -> Option<(SocketAddr, &[u8])> {
    if f.len() < 3 || f[0] != MAGIC || f[1] != T_DATA {
        return None;
    }
    let (ip, rest): (IpAddr, &[u8]) = match f[2] {
        4 if f.len() >= 9 => (IpAddr::from(<[u8; 4]>::try_from(&f[3..7]).ok()?), &f[7..]),
        6 if f.len() >= 21 => (IpAddr::from(<[u8; 16]>::try_from(&f[3..19]).ok()?), &f[19..]),
        _ => return None,
    };
    let port = u16::from_be_bytes([rest[0], rest[1]]);
    Some((SocketAddr::new(ip, port), &rest[2..]))
}

// ---- desired state -------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Peer {
    #[serde(rename = "publicKey")]
    pub public_key: String,
    #[serde(rename = "presharedKey")]
    pub preshared_key: String,
    #[serde(rename = "allowedIps")]
    pub allowed_ips: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Desired {
    /// The hub's public relay, `host:port`.
    pub relay: String,
    /// Hex HMAC key for HELLO frames — per device, issued by the hub.
    pub secret: String,
    #[serde(default)]
    pub peers: Vec<Peer>,
}

/// A WireGuard key: 32 bytes, base64 (44 chars, '=' padded).
pub fn is_wg_key(k: &str) -> bool {
    use base64::Engine;
    k.len() == 44 && base64::engine::general_purpose::STANDARD.decode(k).map(|b| b.len() == 32).unwrap_or(false)
}

/// Peers may only claim a single address in the tunnel subnet — never a route.
/// Without this the hub (or anyone holding its token) could steer arbitrary
/// destinations into a peer.
pub fn is_peer_ip(s: &str) -> bool {
    s.strip_prefix("10.77.0.")
        .and_then(|r| r.strip_suffix("/32"))
        .and_then(|h| h.parse::<u8>().ok())
        .map(|h| (2..=254).contains(&h))
        .unwrap_or(false)
}

pub fn validate(d: &Desired) -> Result<(), String> {
    let (host, port) = d.relay.rsplit_once(':').ok_or("relay must be host:port")?;
    if host.is_empty() || port.parse::<u16>().is_err() {
        return Err("relay must be host:port".into());
    }
    if d.secret.len() < 32 || hex_decode(&d.secret).is_none() {
        return Err("secret must be at least 16 bytes of hex".into());
    }
    if d.peers.len() > 250 {
        return Err("too many peers".into());
    }
    for p in &d.peers {
        if !is_wg_key(&p.public_key) || !is_wg_key(&p.preshared_key) {
            return Err(format!("bad key for peer {}", p.allowed_ips));
        }
        if !is_peer_ip(&p.allowed_ips) {
            return Err(format!("allowedIps must be one 10.77.0.N/32 address, got {}", p.allowed_ips));
        }
    }
    Ok(())
}

pub fn live_peers(peers: &[Peer], now: u64) -> Vec<Peer> {
    peers.iter().filter(|p| p.expires_at > now).cloned().collect()
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}
fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

// ---- persistence -----------------------------------------------------------------

fn dir() -> std::path::PathBuf {
    std::path::PathBuf::from(crate::persistence::home()).join(".it-ai").join("vpn")
}

fn save_desired(d: &Desired) {
    let p = dir();
    let _ = std::fs::create_dir_all(&p);
    let f = p.join("desired.json");
    let tmp = p.join("desired.json.tmp");
    if std::fs::write(&tmp, serde_json::to_vec(d).unwrap_or_default()).is_ok() {
        restrict(&tmp);
        let _ = std::fs::rename(tmp, f);
    }
}

fn load_desired() -> Option<Desired> {
    std::fs::read(dir().join("desired.json")).ok().and_then(|b| serde_json::from_slice(&b).ok())
}

#[cfg(unix)]
fn restrict(p: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600));
}
#[cfg(not(unix))]
fn restrict(_: &std::path::Path) {}

struct State {
    desired: Option<Desired>,
    wan: String,
    last_error: Option<String>,
}

fn state() -> &'static Mutex<State> {
    static S: OnceLock<Mutex<State>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(State { desired: None, wan: String::new(), last_error: None }))
}

static DEVICE: OnceLock<String> = OnceLock::new();

/// Called once at startup with this agent's relay id, which names it in HELLO.
/// Re-applies the saved exit (if any) and starts the expiry ticker.
pub fn start(device: String) {
    if !cfg!(target_os = "linux") {
        return;
    }
    let _ = DEVICE.set(device);
    std::thread::spawn(|| {
        if let Some(d) = load_desired() {
            // The network may not be up yet at boot: keep trying until it takes.
            loop {
                match apply_desired(d.clone()) {
                    Ok(_) => break,
                    Err(e) => {
                        println!("[vpn] resume failed, retrying in 30s: {e}");
                        std::thread::sleep(Duration::from_secs(30));
                    }
                }
            }
        }
        ticker();
    });
}

/// Every 15s: drop expired peers, and re-point NAT if the uplink changed (Wi-Fi ↔ Ethernet).
fn ticker() {
    loop {
        std::thread::sleep(Duration::from_secs(15));
        let Some(d) = state().lock().unwrap_or_else(|e| e.into_inner()).desired.clone() else { continue };
        let live = live_peers(&d.peers, now_secs());
        if live.len() != d.peers.len() {
            let mut next = d.clone();
            next.peers = live;
            reconcile_peers(&next.peers);
            save_desired(&next);
            state().lock().unwrap_or_else(|e| e.into_inner()).desired = Some(next);
        }
        if let Some(wan) = wan_iface() {
            let old = state().lock().unwrap_or_else(|e| e.into_inner()).wan.clone();
            if wan != old {
                remove_rules(&old);
                if ensure_rules(&wan).is_ok() {
                    state().lock().unwrap_or_else(|e| e.into_inner()).wan = wan;
                }
            }
        }
    }
}

// ---- system plumbing ---------------------------------------------------------------

fn run(cmd: &str, args: &[&str]) -> Result<String, String> {
    let out = Command::new(cmd).args(args).output().map_err(|e| format!("{cmd}: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(format!("{cmd} {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim()))
    }
}

fn have(cmd: &str) -> bool {
    Command::new("sh").args(["-c", &format!("command -v {cmd}")]).output().map(|o| o.status.success()).unwrap_or(false)
}

fn is_root() -> bool {
    run("id", &["-u"]).map(|s| s.trim() == "0").unwrap_or(false)
}

fn ensure_prereqs() -> Result<(), String> {
    if !is_root() {
        return Err("the VPN exit needs root — install the agent as a service (--install)".into());
    }
    if !have("wg") || !have("iptables") {
        if have("apt-get") {
            println!("[vpn] installing wireguard-tools + iptables");
            run("apt-get", &["install", "-y", "-qq", "wireguard-tools", "iptables"])?;
        } else {
            return Err("install wireguard-tools and iptables".into());
        }
    }
    Ok(())
}

fn wan_iface() -> Option<String> {
    let out = run("ip", &["-4", "route", "show", "default"]).ok()?;
    let mut it = out.split_whitespace();
    while let Some(w) = it.next() {
        if w == "dev" {
            return it.next().map(String::from);
        }
    }
    None
}

fn server_key() -> Result<(String, String), String> {
    let p = dir().join("server.key");
    if !p.exists() {
        let _ = std::fs::create_dir_all(dir());
        let k = run("wg", &["genkey"])?;
        std::fs::write(&p, k.trim()).map_err(|e| e.to_string())?;
        restrict(&p);
    }
    let private = p.to_string_lossy().into_owned();
    let mut child = Command::new("wg")
        .arg("pubkey")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    use std::io::Write;
    let key = std::fs::read(&p).map_err(|e| e.to_string())?;
    child.stdin.take().unwrap().write_all(&key).map_err(|e| e.to_string())?;
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    Ok((private, String::from_utf8_lossy(&out.stdout).trim().to_string()))
}

fn iface_up() -> bool {
    run("ip", &["link", "show", IFACE]).is_ok()
}

fn ensure_iface() -> Result<(), String> {
    let (key_file, _) = server_key()?;
    if !iface_up() {
        // Some L4T (Jetson) kernels ship without the module; fall back to the
        // userspace implementation when it is installed.
        if run("ip", &["link", "add", "dev", IFACE, "type", "wireguard"]).is_err() {
            if have("wireguard-go") {
                run("wireguard-go", &[IFACE])?;
            } else {
                return Err("this kernel has no WireGuard module and wireguard-go is not installed".into());
            }
        }
        run("ip", &["address", "add", ADDR, "dev", IFACE])?;
    }
    run("wg", &["set", IFACE, "private-key", &key_file, "listen-port", &WG_PORT.to_string()])?;
    run("ip", &["link", "set", IFACE, "mtu", &MTU.to_string(), "up"])?;
    let _ = std::fs::write("/proc/sys/net/ipv4/ip_forward", "1");
    Ok(())
}

/// (table, chain, rule) — every rule carries the module's comment tag so it can
/// be found and removed exactly, without touching anyone else's rules.
fn rules(wan: &str) -> Vec<(&'static str, &'static str, Vec<String>)> {
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    let port = WG_PORT.to_string();
    // Inserted (-I) in this order, so the later entries end up on top: the drops
    // win over the accepts, and all of them sit above Docker's FORWARD chains.
    let mut r = vec![
        ("filter", "FORWARD", s(&["-i", IFACE, "-o", wan, "-j", "ACCEPT"])),
        ("filter", "FORWARD", s(&["-i", wan, "-o", IFACE, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"])),
        ("filter", "FORWARD", s(&["-i", IFACE, "-o", IFACE, "-j", "DROP"])),
    ];
    for net in BLOCKED_NETS {
        r.push(("filter", "FORWARD", s(&["-i", IFACE, "-d", net, "-j", "DROP"])));
    }
    r.extend([
        // Pass holders cannot reach services on this device itself.
        ("filter", "INPUT", s(&["-i", IFACE, "-j", "DROP"])),
        // WireGuard answers only the shim on loopback.
        ("filter", "INPUT", s(&["-p", "udp", "--dport", &port, "!", "-i", "lo", "-j", "DROP"])),
        ("nat", "POSTROUTING", s(&["-s", SUBNET, "-o", wan, "-j", "MASQUERADE"])),
        ("mangle", "FORWARD", s(&["-o", IFACE, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"])),
        ("mangle", "FORWARD", s(&["-i", IFACE, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"])),
    ]);
    for (_, _, rule) in r.iter_mut() {
        rule.extend(s(&["-m", "comment", "--comment", TAG]));
    }
    r
}

fn ipt(table: &str, op: &str, chain: &str, rule: &[String]) -> bool {
    let mut args = vec!["-w", "-t", table, op, chain];
    args.extend(rule.iter().map(String::as_str));
    run("iptables", &args).is_ok()
}

fn ensure_rules(wan: &str) -> Result<(), String> {
    for (t, c, r) in rules(wan) {
        if !ipt(t, "-C", c, &r) && !ipt(t, "-I", c, &r) {
            return Err(format!("iptables: could not add {t}/{c} {}", r.join(" ")));
        }
    }
    Ok(())
}

fn remove_rules(wan: &str) {
    if wan.is_empty() {
        return;
    }
    for (t, c, r) in rules(wan) {
        while ipt(t, "-D", c, &r) {}
    }
}

fn current_peers() -> Vec<String> {
    run("wg", &["show", IFACE, "peers"]).map(|s| s.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect()).unwrap_or_default()
}

fn reconcile_peers(peers: &[Peer]) {
    let want: Vec<&str> = peers.iter().map(|p| p.public_key.as_str()).collect();
    for pk in current_peers() {
        if !want.contains(&pk.as_str()) {
            let _ = run("wg", &["set", IFACE, "peer", &pk, "remove"]);
        }
    }
    for p in peers {
        // The PSK goes through a 0600 file, never argv (visible in ps).
        let f = dir().join(format!("psk-{}", std::process::id()));
        if std::fs::write(&f, &p.preshared_key).is_ok() {
            restrict(&f);
            if let Err(e) = run("wg", &["set", IFACE, "peer", &p.public_key, "preshared-key", &f.to_string_lossy(), "allowed-ips", &p.allowed_ips]) {
                println!("[vpn] {e}");
            }
            let _ = std::fs::remove_file(&f);
        }
    }
}

fn apply_desired(d: Desired) -> Result<Value, String> {
    validate(&d)?;
    ensure_prereqs()?;
    ensure_iface()?;
    let wan = wan_iface().ok_or("no default route — is the device online?")?;
    {
        let old = state().lock().unwrap_or_else(|e| e.into_inner()).wan.clone();
        if old != wan {
            remove_rules(&old);
        }
    }
    ensure_rules(&wan)?;
    let mut d = d;
    d.peers = live_peers(&d.peers, now_secs());
    reconcile_peers(&d.peers);
    shim_ensure(&d.relay, hex_decode(&d.secret).unwrap_or_default());
    save_desired(&d);
    {
        let mut s = state().lock().unwrap_or_else(|e| e.into_inner());
        s.desired = Some(d);
        s.wan = wan;
        s.last_error = None;
    }
    Ok(status())
}

// ---- the relay shim ----------------------------------------------------------------

struct Shim {
    relay: String,
    secret: Vec<u8>,
    stop: Arc<AtomicBool>,
    last_ack_ms: Arc<AtomicU64>,
    sessions: Arc<Mutex<HashMap<SocketAddr, Arc<Session>>>>,
}

struct Session {
    sock: UdpSocket,
    last_ms: AtomicU64,
    stop: AtomicBool,
}

fn shim() -> &'static Mutex<Option<Shim>> {
    static S: OnceLock<Mutex<Option<Shim>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(None))
}

fn shim_ensure(relay: &str, secret: Vec<u8>) {
    let mut g = shim().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(s) = g.as_ref() {
        if s.relay == relay && s.secret == secret {
            return;
        }
        s.stop.store(true, Ordering::SeqCst);
    }
    let s = Shim {
        relay: relay.to_string(),
        secret,
        stop: Arc::new(AtomicBool::new(false)),
        last_ack_ms: Arc::new(AtomicU64::new(0)),
        sessions: Arc::new(Mutex::new(HashMap::new())),
    };
    let (relay, secret, stop, ack, sessions) = (s.relay.clone(), s.secret.clone(), s.stop.clone(), s.last_ack_ms.clone(), s.sessions.clone());
    std::thread::spawn(move || shim_loop(relay, secret, stop, ack, sessions));
    *g = Some(s);
}

fn shim_stop() {
    if let Some(s) = shim().lock().unwrap_or_else(|e| e.into_inner()).take() {
        s.stop.store(true, Ordering::SeqCst);
    }
}

fn shim_loop(relay: String, secret: Vec<u8>, stop: Arc<AtomicBool>, ack: Arc<AtomicU64>, sessions: Arc<Mutex<HashMap<SocketAddr, Arc<Session>>>>) {
    let device = DEVICE.get().cloned().unwrap_or_default();
    let local_wg: SocketAddr = ([127, 0, 0, 1], WG_PORT).into();
    while !stop.load(Ordering::SeqCst) {
        // (Re)resolve every connection attempt: the hub's IP can change.
        let Some(addr) = relay.to_socket_addrs().ok().and_then(|mut a| a.next()) else {
            println!("[vpn] cannot resolve relay {relay}; retrying");
            std::thread::sleep(Duration::from_secs(10));
            continue;
        };
        let bind: SocketAddr = if addr.is_ipv4() { ([0, 0, 0, 0], 0).into() } else { "[::]:0".parse().unwrap() };
        let Ok(up) = UdpSocket::bind(bind) else {
            std::thread::sleep(Duration::from_secs(10));
            continue;
        };
        let _ = up.set_read_timeout(Some(Duration::from_secs(1)));
        let up = Arc::new(up);
        let mut last_hello = 0u64;
        let mut buf = vec![0u8; 65535];
        let started = now_ms();
        loop {
            if stop.load(Ordering::SeqCst) {
                break;
            }
            let now = now_ms();
            // HELLO every 10s keeps the CGNAT mapping open and tells the relay where we are.
            if now.saturating_sub(last_hello) >= 10_000 {
                let _ = up.send_to(&encode_hello(now, &device, &secret), addr);
                last_hello = now;
            }
            // No ACK for 60s: rebuild the socket (new NAT mapping, fresh DNS).
            let last = ack.load(Ordering::SeqCst).max(started);
            if now.saturating_sub(last) > 60_000 {
                println!("[vpn] relay silent for 60s; reconnecting");
                break;
            }
            match up.recv_from(&mut buf) {
                Ok((n, from)) if from == addr => {
                    let f = &buf[..n];
                    if n >= 10 && f[0] == MAGIC && f[1] == T_ACK {
                        ack.store(now, Ordering::SeqCst);
                    } else if let Some((client, payload)) = decode_data(f) {
                        let sess = session_for(&sessions, client, &up, addr);
                        if let Some(sess) = sess {
                            sess.last_ms.store(now, Ordering::SeqCst);
                            let _ = sess.sock.send_to(payload, local_wg);
                        }
                    }
                }
                _ => {}
            }
            // Idle sessions go after 3 minutes (a phone that left).
            let mut g = sessions.lock().unwrap_or_else(|e| e.into_inner());
            g.retain(|_, s| {
                // Saturating: a reader thread may stamp last_ms after `now` was taken.
                let keep = now.saturating_sub(s.last_ms.load(Ordering::SeqCst)) < 180_000;
                if !keep {
                    s.stop.store(true, Ordering::SeqCst);
                }
                keep
            });
        }
        for (_, s) in sessions.lock().unwrap_or_else(|e| e.into_inner()).drain() {
            s.stop.store(true, Ordering::SeqCst);
        }
    }
}

/// The loopback socket standing in for `client`, created on first sight, with a
/// reader thread that frames whatever WireGuard sends back and ships it to the relay.
fn session_for(sessions: &Arc<Mutex<HashMap<SocketAddr, Arc<Session>>>>, client: SocketAddr, up: &Arc<UdpSocket>, relay: SocketAddr) -> Option<Arc<Session>> {
    let mut g = sessions.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(s) = g.get(&client) {
        return Some(s.clone());
    }
    if g.len() >= 512 {
        return None;
    }
    let sock = UdpSocket::bind(("127.0.0.1", 0)).ok()?;
    let _ = sock.set_read_timeout(Some(Duration::from_secs(1)));
    let s = Arc::new(Session { sock, last_ms: AtomicU64::new(now_ms()), stop: AtomicBool::new(false) });
    g.insert(client, s.clone());
    let (r, up) = (s.clone(), up.clone());
    std::thread::spawn(move || {
        let mut buf = vec![0u8; 65535];
        while !r.stop.load(Ordering::SeqCst) {
            if let Ok((n, from)) = r.sock.recv_from(&mut buf) {
                if from.port() == WG_PORT && from.ip().is_loopback() {
                    r.last_ms.store(now_ms(), Ordering::SeqCst);
                    let _ = up.send_to(&encode_data(client, &buf[..n]), relay);
                }
            }
        }
    });
    Some(s)
}

// ---- endpoints ---------------------------------------------------------------------

pub fn status() -> Value {
    let supported = cfg!(target_os = "linux");
    let s = state().lock().unwrap_or_else(|e| e.into_inner());
    let enabled = s.desired.is_some();
    let (public_key, peers) = if supported && iface_up() {
        let pk = server_key().map(|(_, p)| p).unwrap_or_default();
        // wg dump, per peer: pubkey psk endpoint allowed-ips handshake rx tx keepalive
        let peers: Vec<Value> = run("wg", &["show", IFACE, "dump"])
            .unwrap_or_default()
            .lines()
            .skip(1)
            .filter_map(|l| {
                let f: Vec<&str> = l.split('\t').collect();
                (f.len() >= 7).then(|| json!({
                    "publicKey": f[0], "allowedIps": f[3],
                    "latestHandshake": f[4].parse::<u64>().unwrap_or(0),
                    "rx": f[5].parse::<u64>().unwrap_or(0), "tx": f[6].parse::<u64>().unwrap_or(0),
                }))
            })
            .collect();
        (pk, peers)
    } else {
        (String::new(), vec![])
    };
    let (relay_ok, sessions) = shim()
        .lock()
        .unwrap()
        .as_ref()
        .map(|sh| (now_ms().saturating_sub(sh.last_ack_ms.load(Ordering::SeqCst)) < 30_000, sh.sessions.lock().unwrap_or_else(|e| e.into_inner()).len()))
        .unwrap_or((false, 0));
    json!({
        "supported": supported,
        "root": supported && is_root(),
        "enabled": enabled,
        "up": supported && iface_up(),
        "publicKey": public_key,
        "mtu": MTU,
        "wan": s.wan,
        "relayConnected": relay_ok,
        "sessions": sessions,
        "peers": peers,
        "error": s.last_error,
    })
}

pub fn apply_ep(body: &str) -> (Value, u16) {
    if !cfg!(target_os = "linux") {
        return (json!({"ok": false, "error": "the VPN exit is Linux-only"}), 400);
    }
    let d: Desired = match serde_json::from_str(body) {
        Ok(d) => d,
        Err(e) => return (json!({"ok": false, "error": format!("bad body: {e}")}), 400),
    };
    match apply_desired(d) {
        Ok(st) => (json!({"ok": true, "status": st}), 200),
        Err(e) => {
            state().lock().unwrap_or_else(|e| e.into_inner()).last_error = Some(e.clone());
            (json!({"ok": false, "error": e}), 500)
        }
    }
}

pub fn disable_ep() -> (Value, u16) {
    shim_stop();
    let wan = {
        let mut s = state().lock().unwrap_or_else(|e| e.into_inner());
        s.desired = None;
        std::mem::take(&mut s.wan)
    };
    remove_rules(&wan);
    if iface_up() {
        let _ = run("ip", &["link", "del", IFACE]);
    }
    let _ = std::fs::remove_file(dir().join("desired.json"));
    (json!({"ok": true}), 200)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_matches_rfc4231_case_2() {
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        let hex: String = mac.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    }

    #[test]
    fn data_frames_round_trip_v4_and_v6() {
        for a in ["203.0.113.7:51000", "[2001:db8::1]:443"] {
            let addr: SocketAddr = a.parse().unwrap();
            let f = encode_data(addr, b"\x04\0\0\0cipher");
            let (got, payload) = decode_data(&f).unwrap();
            assert_eq!(got, addr);
            assert_eq!(payload, b"\x04\0\0\0cipher");
        }
        assert!(decode_data(&[MAGIC, T_DATA, 4, 1, 2]).is_none(), "truncated frame");
        assert!(decode_data(b"\x01\0\0\0handshake").is_none(), "raw WireGuard is not a frame");
    }

    #[test]
    fn hello_is_authenticated_over_everything_before_the_mac() {
        let f = encode_hello(1_700_000_000_000, "hc-abc", b"k");
        let (body, mac) = f.split_at(f.len() - 32);
        assert_eq!(mac, hmac_sha256(b"k", body));
        assert_eq!(&body[..2], &[MAGIC, T_HELLO]);
        assert_eq!(body[10] as usize, "hc-abc".len());
    }

    #[test]
    fn peers_may_only_hold_one_tunnel_address() {
        assert!(is_peer_ip("10.77.0.2/32"));
        assert!(!is_peer_ip("10.77.0.1/32"), "the device's own address");
        assert!(!is_peer_ip("10.77.0.0/24"));
        assert!(!is_peer_ip("0.0.0.0/0"), "a route would steer all traffic into the peer");
        assert!(!is_peer_ip("10.77.0.300/32"));
    }

    #[test]
    fn validation_and_expiry() {
        let key = "A2+2dpchy903HY/kmF70XH8jsgBgj1Vvf4+64neJqwI=".to_string();
        let p = |ip: &str, exp| Peer { public_key: key.clone(), preshared_key: key.clone(), allowed_ips: ip.into(), expires_at: exp };
        let mut d = Desired { relay: "crane.glick.run:31820".into(), secret: "ab".repeat(16), peers: vec![p("10.77.0.2/32", 10)] };
        assert!(validate(&d).is_ok());
        d.peers.push(p("0.0.0.0/0", 10));
        assert!(validate(&d).is_err());
        d.peers.pop();
        d.relay = "no-port".into();
        assert!(validate(&d).is_err());
        assert_eq!(live_peers(&[p("10.77.0.2/32", 10), p("10.77.0.3/32", 20)], 15).len(), 1);
    }
}
