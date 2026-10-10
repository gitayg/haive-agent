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
//!
//! WireGuard itself is the kernel module when the box has it and `wg` is installed,
//! and otherwise the agent's embedded boringtun device (`vpn/userspace.rs`), which
//! needs only /dev/net/tun. See `vpn/backend.rs` for the choice. A watchdog checks the
//! embedded device every 10s and after every apply, and rebuilds it if its worker thread died
//! or it stopped answering (`vpn/health.rs`).

mod backend;
mod health;
mod uapi;
#[cfg(target_os = "linux")]
mod userspace;

use backend::Backend;
use health::Userspace as _;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock};
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
    /// Bumped by every hub apply and disable. Work that started under an older
    /// generation (the boot resume, a ticker step) must not write its result back.
    generation: u64,
    /// The userspace backend's watchdog record.
    watch: health::Watch,
}

impl State {
    /// The hub changed its mind: anything already in flight is stale.
    fn supersede(&mut self) {
        self.generation += 1;
    }

    fn disable(&mut self) {
        self.supersede();
        self.desired = None;
        self.wan.clear();
        self.watch = health::Watch::default();
    }

    fn is_current(&self, generation: u64) -> bool {
        self.generation == generation
    }

    /// The ticker's read: the generation it saw, and the desired state without
    /// its expired peers. None when nothing expired.
    fn expiry_plan(&self, now: u64) -> Option<(u64, Desired)> {
        let d = self.desired.as_ref()?;
        let live = live_peers(&d.peers, now);
        (live.len() != d.peers.len()).then(|| (self.generation, Desired { peers: live, ..d.clone() }))
    }

    /// The ticker's write: refused if the hub applied or disabled since the read.
    fn commit_expiry(&mut self, generation: u64, next: Desired) -> bool {
        if !self.is_current(generation) {
            return false;
        }
        self.desired = Some(next);
        true
    }
}

fn state() -> &'static Mutex<State> {
    static S: OnceLock<Mutex<State>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(State { desired: None, wan: String::new(), last_error: None, generation: 0, watch: Default::default() }))
}

/// Serialises everything that changes the exit (hub apply and disable, the boot
/// resume, the ticker), so their system changes never interleave. Take it
/// before `state()`, never while holding `state()`.
fn op() -> MutexGuard<'static, ()> {
    static O: OnceLock<Mutex<()>> = OnceLock::new();
    O.get_or_init(|| Mutex::new(())).lock().unwrap_or_else(|e| e.into_inner())
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
        // Read the generation before the file: a hub apply that lands in between
        // then either wrote the file we load, or supersedes the resume.
        let generation = state().lock().unwrap_or_else(|e| e.into_inner()).generation;
        if let Some(d) = load_desired() {
            resume(d, generation);
        }
        ticker();
    });
}

/// The network may not be up yet at boot: keep trying until it takes, unless
/// the hub applies or disables in the meantime.
fn resume(d: Desired, generation: u64) {
    loop {
        {
            let _op = op();
            if !state().lock().unwrap_or_else(|e| e.into_inner()).is_current(generation) {
                println!("[vpn] resume superseded by the hub");
                return;
            }
            match apply_desired(d.clone()) {
                Ok(_) => return,
                Err(e) => println!("[vpn] resume failed, retrying in 30s: {e}"),
            }
        }
        std::thread::sleep(Duration::from_secs(30));
    }
}

/// Every 15s: drop expired peers, and re-point NAT if the uplink changed (Wi-Fi ↔ Ethernet).
fn ticker() {
    loop {
        std::thread::sleep(Duration::from_secs(15));
        let _op = op();
        let expired = {
            // Read, decide, write and persist under one lock: a disable cannot
            // land in between and be undone.
            let mut s = state().lock().unwrap_or_else(|e| e.into_inner());
            match s.expiry_plan(now_secs()) {
                Some((generation, next)) if s.commit_expiry(generation, next.clone()) => {
                    save_desired(&next);
                    Some(next)
                }
                _ => None,
            }
        };
        if let Some(next) = expired {
            if let Err(e) = reconcile_peers(&next.peers) {
                // The watchdog's next check decides whether the device needs rebuilding.
                println!("[vpn] dropping expired passes: {e}");
            }
        }
        let (enabled, old) = {
            let s = state().lock().unwrap_or_else(|e| e.into_inner());
            (s.desired.is_some(), s.wan.clone())
        };
        if !enabled {
            continue;
        }
        if let Some(wan) = wan_iface() {
            // Rebuilds every tagged rule for the new uplink, whatever the old one was.
            if wan != old && ensure_rules(&wan, forwarding_isolated()).is_ok() {
                state().lock().unwrap_or_else(|e| e.into_inner()).wan = wan;
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
    if have("iptables") {
        return Ok(());
    }
    let pm = backend::pick_pkg_manager(have).ok_or(backend::NO_PKG_MANAGER)?;
    let (install, refresh) = backend::iptables_install(pm).ok_or(backend::NO_PKG_MANAGER)?;
    println!("[vpn] installing iptables with {pm}");
    if run(pm, &install).is_err() {
        // A fresh image may never have downloaded its package index.
        let _ = run(pm, &refresh);
        run(pm, &install).map_err(|e| format!("the VPN exit needs iptables, and installing it failed: {e}"))?;
    }
    if !have("iptables") {
        return Err(format!("the VPN exit needs iptables; {pm} installed it, but there is still no iptables command"));
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

/// A WireGuard private key as `wg genkey` makes it: 32 random bytes, clamped.
fn clamp(mut k: [u8; 32]) -> [u8; 32] {
    k[0] &= 248;
    k[31] = (k[31] & 127) | 64;
    k
}

fn public_key_of(private: &[u8; 32]) -> [u8; 32] {
    x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*private)).to_bytes()
}

/// The exit's key: the file (base64, as `wg genkey` writes it — earlier agents' files are
/// kept), its 32 bytes, and the base64 public key. Made on first use, without `wg`.
fn server_key() -> Result<(std::path::PathBuf, [u8; 32], String), String> {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD;
    let p = dir().join("server.key");
    if !p.exists() {
        let _ = std::fs::create_dir_all(dir());
        let mut k = [0u8; 32];
        use std::io::Read;
        std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut k)).map_err(|e| format!("/dev/urandom: {e}"))?;
        std::fs::write(&p, b64.encode(clamp(k))).map_err(|e| format!("writing the server key: {e}"))?;
        restrict(&p);
    }
    let text = std::fs::read_to_string(&p).map_err(|e| format!("reading the server key: {e}"))?;
    let private: [u8; 32] = b64.decode(text.trim()).ok().and_then(|b| b.try_into().ok()).ok_or_else(|| format!("{} is not a WireGuard key", p.display()))?;
    let public = b64.encode(public_key_of(&private));
    Ok((p, private, public))
}

fn iface_up() -> bool {
    run("ip", &["link", "show", IFACE]).is_ok()
}

/// The WireGuard implementation behind `itai-wg`, while the agent has it up.
enum Live {
    Kernel,
    #[cfg(target_os = "linux")]
    Userspace(userspace::Device),
}

impl Live {
    fn backend(&self) -> Backend {
        match self {
            Live::Kernel => Backend::Kernel,
            #[cfg(target_os = "linux")]
            Live::Userspace(_) => Backend::Userspace,
        }
    }
}

/// Lock order: `op()`, then `state()`, then this.
fn wg() -> MutexGuard<'static, Option<Live>> {
    static W: OnceLock<Mutex<Option<Live>>> = OnceLock::new();
    W.get_or_init(|| Mutex::new(None)).lock().unwrap_or_else(|e| e.into_inner())
}

fn force_userspace() -> bool {
    std::env::var("HIVE_VPN_USERSPACE").map(|v| v.trim() == "1").unwrap_or(false)
}

/// Creates the interface for real, for `backend::bring_up`.
#[derive(Default)]
struct SysBringup {
    #[cfg(target_os = "linux")]
    dev: Option<userspace::Device>,
}

impl backend::Bringup for SysBringup {
    fn kernel(&mut self) -> Result<(), String> {
        run("ip", &["link", "add", "dev", IFACE, "type", "wireguard"]).map(|_| ())
    }
    #[cfg(target_os = "linux")]
    fn userspace(&mut self) -> Result<(), String> {
        self.dev = Some(userspace::Device::start(IFACE)?);
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    fn userspace(&mut self) -> Result<(), String> {
        Err("Linux only".into())
    }
}

/// Stops whatever runs `itai-wg` and removes the interface.
fn iface_down(live: &mut Option<Live>) {
    #[cfg(target_os = "linux")]
    if let Some(Live::Userspace(d)) = live.take() {
        if let Err(e) = d.stop() {
            println!("[vpn] {e}");
        }
    }
    *live = None;
    if iface_up() {
        let _ = run("ip", &["link", "del", IFACE]);
    }
}

fn ensure_iface() -> Result<Backend, String> {
    #[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
    let (key_file, private, public) = server_key()?;
    let mut live = wg();
    if live.is_some() && !iface_up() {
        println!("[vpn] {IFACE} disappeared; recreating it");
        iface_down(&mut live);
    }
    if live.is_none() && iface_up() {
        // Left by an earlier run: a kernel interface outlives the agent and is kept; anything
        // else (3.8's wireguard-go, a stray TUN) is replaced.
        let kernel = run("ip", &["-d", "link", "show", IFACE]).map(|o| backend::is_kernel_wireguard(&o)).unwrap_or(false);
        if kernel && have("wg") && !force_userspace() {
            *live = Some(Live::Kernel);
        } else {
            iface_down(&mut live);
        }
    }
    if live.is_none() {
        let mut b = SysBringup::default();
        let chosen = backend::bring_up(force_userspace(), have("wg"), &mut b)?;
        println!("[vpn] {IFACE} is up on the {} WireGuard backend", chosen.name());
        *live = Some(match chosen {
            Backend::Kernel => Live::Kernel,
            #[cfg(target_os = "linux")]
            Backend::Userspace => Live::Userspace(b.dev.take().ok_or("boringtun did not start")?),
            #[cfg(not(target_os = "linux"))]
            Backend::Userspace => return Err("Linux only".into()),
        });
    }
    match live.as_ref() {
        Some(Live::Kernel) => {
            run("wg", &["set", IFACE, "private-key", &key_file.to_string_lossy(), "listen-port", &WG_PORT.to_string()])?;
        }
        #[cfg(target_os = "linux")]
        Some(Live::Userspace(d)) => {
            let have = uapi::parse_get(uapi::check(&d.request(uapi::GET)?)?.trim_end());
            let want = uapi::b64_to_hex(&public);
            // Re-setting the port rebinds boringtun's sockets, so only when it differs.
            if have.public_key != want || have.listen_port != WG_PORT {
                let hex: String = private.iter().map(|b| format!("{b:02x}")).collect();
                uapi::check(&d.request(&uapi::set_device(&hex, WG_PORT))?).map_err(|e| format!("boringtun: setting the key and port: {e}"))?;
            }
        }
        None => {}
    }
    let backend = live.as_ref().map(Live::backend).ok_or("no WireGuard interface")?;
    drop(live);
    run("ip", &["address", "replace", ADDR, "dev", IFACE])?;
    run("ip", &["link", "set", IFACE, "mtu", &MTU.to_string(), "up"])?;
    Ok(backend)
}

const IP_FORWARD: &str = "/proc/sys/net/ipv4/ip_forward";

fn forward_record_file() -> std::path::PathBuf {
    dir().join("ip_forward.before")
}

/// The ip_forward value to keep on record before turning forwarding on. Off
/// now means off is what a disable must return to, whatever an older record
/// says (after a reboot, say). On now keeps an existing record: on a re-apply
/// that "1" is the agent's own, and the record holds what was there before.
fn forward_to_record(current: &str, recorded: Option<&str>) -> String {
    match (current.trim(), recorded.map(str::trim)) {
        ("0", _) => "0".into(),
        (_, Some(r)) => r.into(),
        (cur, None) => cur.into(),
    }
}

/// What a disable writes back: "0" only when forwarding was off before the
/// agent turned it on. If it was already on, or there is no record, it is left
/// alone (a Docker host needs it).
fn forward_to_restore(recorded: Option<&str>) -> Option<&'static str> {
    (recorded.map(str::trim) == Some("0")).then_some("0")
}

/// Records the current ip_forward before the agent turns it on. Returns
/// whether the agent is the reason forwarding is on, in which case only
/// `itai-wg` traffic may be forwarded.
fn record_forwarding() -> Result<bool, String> {
    let current = std::fs::read_to_string(IP_FORWARD).map_err(|e| format!("{IP_FORWARD}: {e}"))?;
    let recorded = std::fs::read_to_string(forward_record_file()).ok();
    let keep = forward_to_record(&current, recorded.as_deref());
    let _ = std::fs::create_dir_all(dir());
    std::fs::write(forward_record_file(), &keep).map_err(|e| format!("recording ip_forward: {e}"))?;
    restrict(&forward_record_file());
    Ok(forward_to_restore(Some(&keep)).is_some())
}

fn forwarding_isolated() -> bool {
    forward_to_restore(std::fs::read_to_string(forward_record_file()).ok().as_deref()).is_some()
}

fn restore_forwarding() {
    if let Some(v) = forward_to_restore(std::fs::read_to_string(forward_record_file()).ok().as_deref()) {
        let _ = std::fs::write(IP_FORWARD, v);
    }
    let _ = std::fs::remove_file(forward_record_file());
}

/// The chains this module writes to, as (table, chain).
const CHAINS: &[(&str, &str)] = &[("filter", "FORWARD"), ("filter", "INPUT"), ("nat", "POSTROUTING"), ("mangle", "FORWARD")];

/// (table, chain, rule), each chain's rules listed top to bottom. Every rule
/// carries the module's comment tag so it can be found and removed exactly,
/// without touching anyone else's rules. `isolate`: the agent turned forwarding
/// on, so nothing but `itai-wg` traffic may be forwarded. The FORWARD policy
/// itself is never changed.
fn rules(wan: &str, isolate: bool) -> Vec<(&'static str, &'static str, Vec<String>)> {
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    let port = WG_PORT.to_string();
    // The drops come first so they win over the accepts.
    let mut r = vec![("filter", "FORWARD", s(&["-i", IFACE, "-o", IFACE, "-j", "DROP"]))];
    for net in BLOCKED_NETS {
        r.push(("filter", "FORWARD", s(&["-i", IFACE, "-d", net, "-j", "DROP"])));
    }
    r.extend([
        ("filter", "FORWARD", s(&["-i", IFACE, "-o", wan, "-j", "ACCEPT"])),
        ("filter", "FORWARD", s(&["-i", wan, "-o", IFACE, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"])),
        // Anything else to or from the tunnel is refused, whatever the FORWARD policy.
        ("filter", "FORWARD", s(&["-i", IFACE, "-j", "DROP"])),
        ("filter", "FORWARD", s(&["-o", IFACE, "-j", "DROP"])),
    ]);
    if isolate {
        r.push(("filter", "FORWARD", s(&["!", "-i", IFACE, "!", "-o", IFACE, "-j", "DROP"])));
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

/// `iptables` arguments that delete every rule carrying the module's tag, read
/// from `iptables -t <table> -S <chain>`. Whatever WAN those rules named.
fn delete_tagged(table: &str, listing: &str) -> Vec<Vec<String>> {
    let quoted = format!("\"{TAG}\"");
    listing
        .lines()
        .filter_map(|line| {
            let mut t: Vec<String> = line.split_whitespace().map(String::from).collect();
            let tagged = t.windows(2).any(|w| w[0] == "--comment" && (w[1] == TAG || w[1] == quoted));
            if t.len() < 2 || t[0] != "-A" || !tagged {
                return None;
            }
            t[0] = "-D".into();
            for x in t.iter_mut().filter(|x| **x == quoted) {
                *x = TAG.into();
            }
            Some(["-w", "-t", table].iter().map(|x| x.to_string()).chain(t).collect())
        })
        .collect()
}

/// The whole apply, as `iptables` argument lists: delete every tagged rule in
/// every chain first, then insert the full set at explicit positions 1..n, so
/// each chain ends up in exactly `rules()`'s order, above everyone else's.
/// `listings` holds `iptables -S` output per (table, chain).
fn apply_plan(wan: &str, isolate: bool, listings: &[(&str, &str, String)]) -> Vec<Vec<String>> {
    let mut plan: Vec<Vec<String>> = listings.iter().flat_map(|(t, _, l)| delete_tagged(t, l)).collect();
    let mut pos: HashMap<(&str, &str), usize> = HashMap::new();
    for (t, c, r) in rules(wan, isolate) {
        let n = pos.entry((t, c)).or_insert(0);
        *n += 1;
        plan.push(["-w", "-t", t, "-I", c, &n.to_string()].iter().map(|x| x.to_string()).chain(r).collect());
    }
    plan
}

fn listings() -> Vec<(&'static str, &'static str, String)> {
    CHAINS.iter().map(|(t, c)| (*t, *c, run("iptables", &["-w", "-t", t, "-S", c]).unwrap_or_default())).collect()
}

fn ensure_rules(wan: &str, isolate: bool) -> Result<(), String> {
    for cmd in apply_plan(wan, isolate, &listings()) {
        let args: Vec<&str> = cmd.iter().map(String::as_str).collect();
        let done = run("iptables", &args);
        // A delete may race a rule that is already gone; an insert must land.
        if args[3] == "-I" {
            done.map_err(|e| format!("iptables: could not add {e}"))?;
        }
    }
    Ok(())
}

fn remove_rules() {
    for (t, _, l) in listings() {
        for cmd in delete_tagged(t, &l) {
            let args: Vec<&str> = cmd.iter().map(String::as_str).collect();
            let _ = run("iptables", &args);
        }
    }
}

fn current_peers() -> Vec<String> {
    run("wg", &["show", IFACE, "peers"]).map(|s| s.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect()).unwrap_or_default()
}

/// Err when a peer could not be added, changed or removed.
fn reconcile_peers(peers: &[Peer]) -> Result<(), String> {
    let live = wg();
    match live.as_ref() {
        Some(Live::Kernel) => {
            drop(live);
            reconcile_kernel_peers(peers)
        }
        #[cfg(target_os = "linux")]
        Some(Live::Userspace(d)) => uapi::reconcile(d, peers),
        None => Err("no WireGuard interface".into()),
    }
}

fn reconcile_kernel_peers(peers: &[Peer]) -> Result<(), String> {
    let mut failed = vec![];
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
                failed.push(e);
            }
            let _ = std::fs::remove_file(&f);
        } else {
            failed.push(format!("writing the preshared key for {}", p.allowed_ips));
        }
    }
    if failed.is_empty() {
        Ok(())
    } else {
        Err(failed.join("; "))
    }
}

fn apply_desired(d: Desired) -> Result<Value, String> {
    validate(&d)?;
    ensure_prereqs()?;
    ensure_iface()?;
    let wan = wan_iface().ok_or("no default route — is the device online?")?;
    // Record ip_forward and put the rules in place before forwarding goes on.
    let isolate = record_forwarding()?;
    ensure_rules(&wan, isolate)?;
    let _ = std::fs::write(IP_FORWARD, "1");
    let mut d = d;
    d.peers = live_peers(&d.peers, now_secs());
    let peers = reconcile_peers(&d.peers);
    shim_ensure(&d.relay, hex_decode(&d.secret).unwrap_or_default());
    // Saved even when a peer change failed: this is what the hub wants, and what the
    // watchdog rebuilds a broken device with.
    let generation = {
        let mut s = state().lock().unwrap_or_else(|e| e.into_inner());
        save_desired(&d);
        s.desired = Some(d);
        s.wan = wan;
        s.last_error = None;
        s.watch.fresh_apply();
        s.generation
    };
    ensure_watchdog();
    // Checked right away, so a device that is already broken is not reported as applied.
    let health = SysExit.check();
    if let Some(Err(h)) = &health {
        // To the watchdog at once: it rebuilds the device with what was just saved.
        let mut s = state().lock().unwrap_or_else(|e| e.into_inner());
        s.watch.failed(now_secs(), generation, h.clone());
        drop(s);
        kick_watchdog();
    }
    match (peers, health) {
        (Ok(()), None | Some(Ok(()))) => Ok(status()),
        (Err(e), _) => Err(e),
        (Ok(()), Some(Err(h))) => Err(format!("the built-in WireGuard is not healthy after the apply ({h}); the agent is rebuilding it")),
    }
}

// ---- the userspace backend's watchdog -----------------------------------------------

/// The running device, for `health::step`.
struct SysExit;

impl health::Userspace for SysExit {
    fn check(&mut self) -> Option<Result<(), String>> {
        #[cfg(target_os = "linux")]
        if let Some(Live::Userspace(d)) = wg().as_ref() {
            return Some(health::check(d));
        }
        None
    }
    fn teardown(&mut self) {
        iface_down(&mut wg());
    }
    /// The same key and port as always (the key file), and the desired state's live peers.
    /// The firewall rules name the interface, so they hold for the new one.
    fn rebuild(&mut self, d: &Desired) -> Result<(), String> {
        ensure_iface()?;
        reconcile_peers(&live_peers(&d.peers, now_secs()))
    }
}

/// Whether the watchdog thread runs. Changed only under `op()`.
static WATCHING: AtomicBool = AtomicBool::new(false);

fn kick() -> &'static (Mutex<bool>, Condvar) {
    static K: OnceLock<(Mutex<bool>, Condvar)> = OnceLock::new();
    K.get_or_init(Default::default)
}

/// Wakes the watchdog now instead of at its next check.
fn kick_watchdog() {
    let (m, c) = kick();
    *m.lock().unwrap_or_else(|e| e.into_inner()) = true;
    c.notify_all();
}

/// Starts the watchdog unless it runs. Call under `op()` once the exit is enabled; it ends
/// on its own after a disable.
fn ensure_watchdog() {
    if !WATCHING.swap(true, Ordering::SeqCst) && std::thread::Builder::new().name("itai-vpn-watch".into()).spawn(watchdog).is_err() {
        WATCHING.store(false, Ordering::SeqCst);
    }
}

fn watchdog() {
    let mut wait = health::CHECK_EVERY;
    loop {
        {
            let (m, c) = kick();
            let g = m.lock().unwrap_or_else(|e| e.into_inner());
            *c.wait_timeout_while(g, wait, |kicked| !*kicked).unwrap_or_else(|e| e.into_inner()).0 = false;
        }
        // Under op(), like apply and disable: a recovery never interleaves with either.
        let _op = op();
        let (generation, desired, mut w) = {
            let s = state().lock().unwrap_or_else(|e| e.into_inner());
            if s.desired.is_none() {
                WATCHING.store(false, Ordering::SeqCst);
                return;
            }
            (s.generation, s.desired.clone(), s.watch.clone())
        };
        let outcome = health::step(&mut w, generation, desired.as_ref(), &mut SysExit, now_secs());
        let mut s = state().lock().unwrap_or_else(|e| e.into_inner());
        let reason = w.last_failure.as_ref().map(|(_, r)| r.clone()).unwrap_or_default();
        wait = match outcome {
            health::Outcome::Idle => health::CHECK_EVERY,
            health::Outcome::Retry(t) => {
                println!("[vpn] built-in WireGuard is unhealthy ({reason}); rebuilding it in {}s", t.as_secs());
                t
            }
            health::Outcome::Recovered => {
                println!("[vpn] built-in WireGuard rebuilt (restart {})", w.restarts);
                // It now runs the hub's desired state in full.
                s.last_error = None;
                health::CHECK_EVERY
            }
            health::Outcome::GaveUp(e) => {
                let msg = format!("the built-in WireGuard failed {} times within {} minutes and was stopped: {e}", health::GIVE_UP_AFTER, health::WINDOW_SECS / 60);
                println!("[vpn] {msg}");
                s.last_error = Some(msg);
                health::CHECK_EVERY
            }
        };
        s.watch = w;
    }
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

/// Per peer: base64 public key, allowed IPs, last handshake as a Unix time (0 = never), bytes.
fn live_peers_status(live: &Live) -> Vec<Value> {
    match live {
        // wg dump, per peer: pubkey psk endpoint allowed-ips handshake rx tx keepalive
        Live::Kernel => run("wg", &["show", IFACE, "dump"])
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
            .collect(),
        #[cfg(target_os = "linux")]
        Live::Userspace(d) => {
            let now = now_secs();
            d.request(uapi::GET)
                .and_then(|r| uapi::check(&r).map(uapi::parse_get))
                .map(|dev| dev.peers)
                .unwrap_or_default()
                .into_iter()
                .map(|p| json!({
                    "publicKey": uapi::hex_to_b64(&p.public_key).unwrap_or_default(),
                    "allowedIps": p.allowed_ips.join(","),
                    // boringtun reports seconds since the handshake; wg dump a Unix time.
                    "latestHandshake": p.handshake_ago_secs.map(|ago| now.saturating_sub(ago)).unwrap_or(0),
                    "rx": p.rx, "tx": p.tx,
                }))
                .collect()
        }
    }
}

pub fn status() -> Value {
    let supported = cfg!(target_os = "linux");
    let s = state().lock().unwrap_or_else(|e| e.into_inner());
    let enabled = s.desired.is_some();
    let live = wg();
    let backend = live.as_ref().map(|l| l.backend().name());
    let (public_key, peers) = if supported && iface_up() {
        let pk = server_key().map(|(_, _, p)| p).unwrap_or_default();
        (pk, live.as_ref().map(live_peers_status).unwrap_or_default())
    } else {
        (String::new(), vec![])
    };
    drop(live);
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
        "backend": backend,
        "publicKey": public_key,
        "mtu": MTU,
        "wan": s.wan,
        "relayConnected": relay_ok,
        "sessions": sessions,
        "peers": peers,
        "error": s.last_error,
        "health": s.watch.health.name(),
        "restarts": s.watch.restarts,
        "last_failure": s.watch.last_failure.as_ref().map(|(at, reason)| json!({"at": at, "reason": reason})),
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
    let _op = op();
    state().lock().unwrap_or_else(|e| e.into_inner()).supersede();
    match apply_desired(d) {
        Ok(st) => (json!({"ok": true, "status": st}), 200),
        Err(e) => {
            state().lock().unwrap_or_else(|e| e.into_inner()).last_error = Some(e.clone());
            (json!({"ok": false, "error": e}), 500)
        }
    }
}

pub fn disable_ep() -> (Value, u16) {
    let _op = op();
    shim_stop();
    {
        // The saved file goes under the same lock as the in-memory state, so a
        // ticker step can never write it back after this.
        let mut s = state().lock().unwrap_or_else(|e| e.into_inner());
        let _ = std::fs::remove_file(dir().join("desired.json"));
        s.disable();
    }
    // Forwarding goes back off before the isolation rule goes away.
    restore_forwarding();
    remove_rules();
    iface_down(&mut wg());
    // The watchdog sees nothing desired and ends.
    kick_watchdog();
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

    fn enabled_state(peers: &[(&str, u64)]) -> State {
        let key = "A2+2dpchy903HY/kmF70XH8jsgBgj1Vvf4+64neJqwI=".to_string();
        let peers = peers.iter().map(|(ip, exp)| Peer { public_key: key.clone(), preshared_key: key.clone(), allowed_ips: (*ip).into(), expires_at: *exp }).collect();
        let d = Desired { relay: "relay.example:31820".into(), secret: "ab".repeat(16), peers };
        State { desired: Some(d), wan: "eth0".into(), last_error: None, generation: 1, watch: Default::default() }
    }

    #[test]
    fn a_disable_between_the_tickers_read_and_write_stays_disabled() {
        let mut s = enabled_state(&[("10.77.0.2/32", 10), ("10.77.0.3/32", 20)]);
        let (generation, next) = s.expiry_plan(15).expect("one peer expired");
        s.disable();
        assert!(!s.commit_expiry(generation, next), "the stale write must be refused");
        assert!(s.desired.is_none(), "the disable must not be undone");

        // Disable then a fresh apply: the old pass list must not overwrite the new one.
        let mut s = enabled_state(&[("10.77.0.2/32", 10), ("10.77.0.3/32", 20)]);
        let (generation, next) = s.expiry_plan(15).unwrap();
        s.disable();
        s.supersede();
        s.desired = enabled_state(&[("10.77.0.9/32", 99)]).desired;
        assert!(!s.commit_expiry(generation, next));
        assert_eq!(s.desired.as_ref().unwrap().peers[0].allowed_ips, "10.77.0.9/32");

        // Control: with nothing in between, the expired peer is dropped.
        let mut s = enabled_state(&[("10.77.0.2/32", 10), ("10.77.0.3/32", 20)]);
        let (generation, next) = s.expiry_plan(15).unwrap();
        assert!(s.commit_expiry(generation, next));
        assert_eq!(s.desired.as_ref().unwrap().peers.len(), 1);
        assert!(s.expiry_plan(15).is_none(), "nothing left to expire");
    }

    #[test]
    fn a_hub_disable_or_apply_stops_the_boot_resume() {
        let mut s = enabled_state(&[("10.77.0.2/32", 10)]);
        let seen = s.generation;
        assert!(s.is_current(seen));
        s.disable();
        assert!(!s.is_current(seen), "disable must stop the resume loop");
        let seen = s.generation;
        s.supersede();
        assert!(!s.is_current(seen), "a hub apply must stop the resume loop");
    }

    /// What 3.8.0 left behind for `eth0`, between Docker's rules, as `iptables -S` prints it.
    fn old_listings() -> Vec<(&'static str, &'static str, String)> {
        let fwd = "-P FORWARD DROP\n\
            -A FORWARD -i itai-wg -d 10.0.0.0/8 -m comment --comment it-ai-vpn -j DROP\n\
            -A FORWARD -j DOCKER-USER\n\
            -A FORWARD -i itai-wg -o eth0 -m comment --comment it-ai-vpn -j ACCEPT\n\
            -A FORWARD -i eth0 -o itai-wg -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment \"it-ai-vpn\" -j ACCEPT\n\
            -A FORWARD -m comment --comment \"not it-ai-vpn\" -j ACCEPT\n";
        let nat = "-P POSTROUTING ACCEPT\n\
            -A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE\n\
            -A POSTROUTING -s 10.77.0.0/24 -o eth0 -m comment --comment it-ai-vpn -j MASQUERADE\n";
        vec![("filter", "FORWARD", fwd.into()), ("filter", "INPUT", "-P INPUT ACCEPT\n".into()), ("nat", "POSTROUTING", nat.into()), ("mangle", "FORWARD", String::new())]
    }

    #[test]
    fn firewall_plan_deletes_every_tagged_rule_before_inserting() {
        let plan = apply_plan("wlan0", false, &old_listings());
        let first_insert = plan.iter().position(|c| c[3] == "-I").expect("inserts");
        assert!(plan[..first_insert].iter().all(|c| c[3] == "-D"), "deletes come first");
        assert!(plan[first_insert..].iter().all(|c| c[3] == "-I"), "no delete after an insert");

        let deletes: Vec<String> = plan[..first_insert].iter().map(|c| c.join(" ")).collect();
        assert_eq!(deletes.len(), 4, "every tagged rule, and nothing else: {deletes:#?}");
        assert!(deletes.contains(&"-w -t filter -D FORWARD -i itai-wg -o eth0 -m comment --comment it-ai-vpn -j ACCEPT".into()), "the old WAN's accept goes");
        assert!(deletes.contains(&"-w -t nat -D POSTROUTING -s 10.77.0.0/24 -o eth0 -m comment --comment it-ai-vpn -j MASQUERADE".into()), "the old WAN's NAT goes");
        assert!(deletes.iter().all(|d| d.contains("--comment it-ai-vpn ")), "a quoted tag is unquoted for -D");
        assert!(!deletes.iter().any(|d| d.contains("DOCKER") || d.contains("docker0") || d.contains("not")), "other rules are left alone");
    }

    #[test]
    fn firewall_plan_orders_drops_above_accepts_for_a_changed_wan() {
        for isolate in [false, true] {
            let plan = apply_plan("wlan0", isolate, &old_listings());
            assert!(plan.iter().all(|c| !c.contains(&"-P".to_string())), "the FORWARD policy is never touched");
            let inserts: Vec<&Vec<String>> = plan.iter().filter(|c| c[3] == "-I").collect();
            assert!(inserts.iter().all(|c| !c.contains(&"eth0".to_string())), "nothing names the old WAN");
            for (table, chain) in CHAINS {
                let at: Vec<String> = inserts.iter().filter(|c| c[2] == *table && c[4] == *chain).map(|c| c[5].clone()).collect();
                let want: Vec<String> = (1..=at.len()).map(|n| n.to_string()).collect();
                assert_eq!(at, want, "{table}/{chain} is inserted at explicit positions 1..n");
            }
            let fwd: Vec<String> = inserts.iter().filter(|c| c[2] == "filter" && c[4] == "FORWARD").map(|c| c[6..].join(" ")).collect();
            let first_accept = fwd.iter().position(|r| r.contains("-j ACCEPT")).unwrap();
            let last_accept = fwd.iter().rposition(|r| r.contains("-j ACCEPT")).unwrap();
            assert_eq!(last_accept - first_accept, 1, "{fwd:#?}");
            assert!(fwd[first_accept].starts_with("-i itai-wg -o wlan0 ") && fwd[last_accept].starts_with("-i wlan0 -o itai-wg "), "{fwd:#?}");
            // Above the accepts: peer-to-peer and private ranges.
            assert_eq!(fwd[..first_accept].len(), 1 + BLOCKED_NETS.len());
            assert!(fwd[..first_accept].iter().all(|r| r.starts_with("-i itai-wg ") && r.contains("-j DROP")), "{fwd:#?}");
            // Below them: the tunnel's default deny, plus everything else when the agent turned forwarding on.
            let mut below = vec!["-i itai-wg -j DROP", "-o itai-wg -j DROP"];
            if isolate {
                below.push("! -i itai-wg ! -o itai-wg -j DROP");
            }
            let got: Vec<String> = fwd[last_accept + 1..].iter().map(|r| r.trim_end_matches(" -m comment --comment it-ai-vpn").to_string()).collect();
            assert_eq!(got, below, "isolate={isolate}");
        }
    }

    #[test]
    fn ip_forward_is_restored_only_when_the_agent_turned_it_on() {
        assert_eq!(forward_to_restore(Some("0\n")), Some("0"), "it was 0: restore 0");
        assert_eq!(forward_to_restore(Some("1\n")), None, "it was 1: leave it alone");
        assert_eq!(forward_to_restore(None), None, "no record: leave it alone");

        assert_eq!(forward_to_record("0\n", None), "0");
        assert_eq!(forward_to_record("1\n", None), "1");
        assert_eq!(forward_to_record("1", Some("0")), "0", "a re-apply must not record the agent's own 1");
        assert_eq!(forward_to_record("0", Some("1")), "0", "forwarding is off now (a reboot): off is what to return to");
        // End to end: off before, two applies, then disable restores off.
        let first = forward_to_record("0", None);
        let second = forward_to_record("1", Some(&first));
        assert_eq!(forward_to_restore(Some(&second)), Some("0"));
    }

    #[test]
    fn the_server_key_is_derived_without_wg() {
        // RFC 7748 §6.1, Alice: the same X25519 as `wg pubkey`.
        let private: [u8; 32] = hex_decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a").unwrap().try_into().unwrap();
        let public: String = public_key_of(&private).iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(public, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        // `wg genkey` clamping.
        let k = clamp([0xff; 32]);
        assert_eq!((k[0], k[31]), (0xf8, 0x7f));
        assert_eq!(clamp([0; 32])[31], 0x40);
    }

    /// For the e2e test: holds one boringtun device's worker inside boringtun's own tracing
    /// calls, a genuine stuck worker, without patching boringtun.
    #[cfg(target_os = "linux")]
    mod stall {
        use std::sync::{Mutex, Once};
        use tracing::{span, Event, Metadata, Subscriber};

        static HELD: Mutex<Option<String>> = Mutex::new(None);

        struct Stall;

        impl Subscriber for Stall {
            fn enabled(&self, _: &Metadata<'_>) -> bool {
                true
            }
            fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
                span::Id::from_u64(1)
            }
            fn record(&self, _: &span::Id, _: &span::Record<'_>) {}
            fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}
            fn event(&self, _: &Event<'_>) {
                let me = std::fs::read_to_string("/proc/thread-self/comm").unwrap_or_default();
                if HELD.lock().unwrap().as_deref() == Some(me.trim_end()) {
                    // Never released: the test ends with this thread still here.
                    loop {
                        std::thread::park();
                    }
                }
            }
            fn enter(&self, _: &span::Id) {}
            fn exit(&self, _: &span::Id) {}
        }

        /// From now on, the next tracing event on the threads named `mark` never returns.
        pub fn hold(mark: &str) {
            static ONCE: Once = Once::new();
            ONCE.call_once(|| tracing::subscriber::set_global_default(Stall).unwrap());
            *HELD.lock().unwrap() = Some(mark.to_string());
        }
    }

    /// The exit end to end, on the real apply/status/disable entry points, against a stock
    /// kernel WireGuard client in another container. Driven by `scripts/vpn-e2e.sh`; needs
    /// root, CAP_NET_ADMIN and /dev/net/tun. The hub relay is NOT in the path: the client
    /// reaches a loopback forwarder standing in for the shim, because the exit's own firewall
    /// rule drops UDP to the WireGuard port from anywhere but loopback.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "needs root, /dev/net/tun and a WireGuard client container (scripts/vpn-e2e.sh)"]
    fn e2e_exit_serves_a_stock_wireguard_client() {
        let dir = std::path::PathBuf::from(std::env::var("E2E_DIR").expect("E2E_DIR"));
        let wait_for = |name: &str, secs: u64| -> String {
            for _ in 0..secs * 10 {
                if let Some(s) = std::fs::read_to_string(dir.join(name)).ok().filter(|s| !s.trim().is_empty()) {
                    return s.trim().to_string();
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            panic!("timed out waiting for {name}");
        };
        let count = |p: &str| std::fs::read_dir(p).unwrap().count();
        let fd_targets = || {
            let mut v: Vec<String> = std::fs::read_dir("/proc/self/fd").unwrap().filter_map(|e| e.ok()).map(|e| std::fs::read_link(e.path()).map(|t| t.to_string_lossy().into_owned()).unwrap_or_default()).collect();
            v.sort();
            v
        };
        let tagged = || CHAINS.iter().map(|(t, c)| run("iptables", &["-w", "-t", t, "-S", c]).unwrap_or_default().matches(TAG).count()).sum::<usize>();

        // Stand-in for the shim: UDP in on :51821, out to WireGuard from a loopback socket.
        let outside = Arc::new(UdpSocket::bind(("0.0.0.0", 51821)).unwrap());
        let inside = Arc::new(UdpSocket::bind(("127.0.0.1", 0)).unwrap());
        inside.connect(("127.0.0.1", WG_PORT)).unwrap();
        let client_addr: Arc<Mutex<Option<SocketAddr>>> = Arc::default();
        let (o, i, c) = (outside.clone(), inside.clone(), client_addr.clone());
        std::thread::spawn(move || loop {
            let mut b = [0u8; 2048];
            if let Ok((n, from)) = o.recv_from(&mut b) {
                *c.lock().unwrap() = Some(from);
                let _ = i.send(&b[..n]);
            }
        });
        let (o, i, c) = (outside.clone(), inside.clone(), client_addr.clone());
        std::thread::spawn(move || loop {
            let mut b = [0u8; 2048];
            if let Ok(n) = i.recv(&mut b) {
                if let Some(to) = *c.lock().unwrap() {
                    let _ = o.send_to(&b[..n], to);
                }
            }
        });

        let (threads_before, fds_before, targets_before) = (count("/proc/self/task"), count("/proc/self/fd"), fd_targets());
        let client = wait_for("client.pub", 180);
        let psk = wait_for("client.psk", 5);
        let pass = |ip: &str| json!({"relay": "127.0.0.1:9", "secret": "ab".repeat(16), "peers": [{"publicKey": client, "presharedKey": psk, "allowedIps": ip, "expiresAt": now_secs() + 3600}]}).to_string();

        // First apply creates the device; the second changes the pass (remove + add in
        // boringtun); the third repeats it (no peer request at all). boringtun 0.7 panics
        // on a set for an existing peer, so any of these going wrong would show here.
        for (n, ip) in [(1, "10.77.0.3/32"), (2, "10.77.0.2/32"), (3, "10.77.0.2/32")] {
            let (r, code) = apply_ep(&pass(ip));
            println!("[e2e] apply #{n} ({ip}): HTTP {code} backend={} peers={}", r["status"]["backend"], r["status"]["peers"]);
            assert_eq!(code, 200, "{r}");
        }
        let st = status();
        let want_backend = std::env::var("E2E_BACKEND").unwrap_or_else(|_| "userspace".into());
        assert_eq!(st["backend"], want_backend.as_str(), "{st}");
        assert_eq!(st["peers"].as_array().unwrap().len(), 1, "{st}");
        assert_eq!(st["peers"][0]["allowedIps"], "10.77.0.2/32", "{st}");
        println!("[e2e] ip -d link: {}", run("ip", &["-d", "link", "show", IFACE]).unwrap_or_default().trim());
        println!("[e2e] tagged iptables rules while up: {}", tagged());
        std::fs::write(dir.join("server.pub"), st["publicKey"].as_str().unwrap()).unwrap();

        let mut shook = Value::Null;
        for _ in 0..90 {
            let st = status();
            if st["peers"][0]["latestHandshake"].as_u64().unwrap_or(0) > 0 {
                shook = st;
                break;
            }
            std::thread::sleep(Duration::from_secs(1));
        }
        assert!(!shook.is_null(), "no handshake within 90s: {}", status());
        println!("[e2e] handshake seen by the exit: now={} peers={}", now_secs(), shook["peers"]);
        wait_for("client.done", 180);
        let end = status();
        println!("[e2e] after the client's traffic: {}", end["peers"]);
        assert!(end["peers"][0]["rx"].as_u64().unwrap() > 0 && end["peers"][0]["tx"].as_u64().unwrap() > 0, "{end}");

        // Crash recovery. The watchdog must bring the exit back by itself: no apply from
        // anyone (the generation must not move), and the client reconfigures nothing.
        let round = |n: u32, what: &str| {
            std::fs::write(dir.join(format!("round{n}")), what).unwrap();
            if what != "end" {
                wait_for(&format!("round{n}.done"), 180);
            }
        };
        let recovered = |what: &str, generation: u64| -> Value {
            let t0 = std::time::Instant::now();
            let (mut last, mut seen) = (String::new(), vec![]);
            let healed = loop {
                let st = status();
                let line = format!("health={} restarts={} up={} peers={} last_failure={}", st["health"], st["restarts"], st["up"], st["peers"].as_array().map_or(0, Vec::len), st["last_failure"]);
                if line != last {
                    println!("[e2e] {what} +{:.1}s {line}", t0.elapsed().as_secs_f32());
                    last = line;
                }
                seen.push(st["health"].as_str().unwrap_or("").to_string());
                if st["health"] == "ok" && st["restarts"] == 1 {
                    break st;
                }
                assert!(t0.elapsed() < Duration::from_secs(90), "{what}: no recovery within 90s: {st}");
                std::thread::sleep(Duration::from_millis(200));
            };
            assert!(seen.iter().any(|h| h == "recovering"), "{what}: {seen:?}");
            assert_eq!(healed["peers"][0]["allowedIps"], "10.77.0.2/32", "{what}: rebuilt with the same pass: {healed}");
            assert_eq!(state().lock().unwrap().generation, generation, "{what}: no apply happened in between");
            println!("[e2e] {what}: recovered in {:.1}s without an apply (generation still {generation}); backend={} up={}", t0.elapsed().as_secs_f32(), healed["backend"], healed["up"]);
            healed
        };
        let traffic_counted = |what: &str| {
            let st = status();
            println!("[e2e] {what}: health={} restarts={} peers={}", st["health"], st["restarts"], st["peers"]);
            assert!(st["peers"][0]["rx"].as_u64().unwrap() > 0 && st["peers"][0]["tx"].as_u64().unwrap() > 0, "{st}");
        };
        let comms = || std::fs::read_dir("/proc/self/task").unwrap().filter_map(|t| std::fs::read_to_string(t.ok()?.path().join("comm")).ok()).map(|c| c.trim_end().to_string()).collect::<Vec<_>>();
        let disable = || -> (usize, usize) {
            let (r, code) = disable_ep();
            assert_eq!(code, 200, "{r}");
            assert!(!iface_up(), "{IFACE} must be gone after disable");
            assert!(wg().is_none());
            assert_eq!(tagged(), 0, "every tagged rule removed");
            // The shim and watchdog threads notice within a second.
            let (mut threads, mut fds) = (0, 0);
            for _ in 0..50 {
                (threads, fds) = (count("/proc/self/task"), count("/proc/self/fd"));
                if threads == threads_before && fds == fds_before {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            println!("[e2e] after disable: {IFACE} present={} tagged rules={} watchdog running={} threads {threads_before}->{threads} {:?} fds {fds_before}->{fds}", iface_up(), tagged(), WATCHING.load(Ordering::SeqCst), comms());
            (threads, fds)
        };
        let on_device = |f: &dyn Fn(&userspace::Device)| match wg().as_ref() {
            Some(Live::Userspace(d)) => f(d),
            _ => panic!("not the userspace backend"),
        };

        if want_backend == "userspace" {
            assert_eq!((end["health"].as_str(), end["restarts"].as_u64()), (Some("ok"), Some(0)), "{end}");

            // 1. A worker panic, the way boringtun 0.7.1 really dies.
            let generation = state().lock().unwrap().generation;
            on_device(&|d| d.inject_worker_panic().unwrap());
            println!("[e2e] injected a worker panic: a set=1 for the peer boringtun already has (0.7.1 panics on it)");
            let healed = recovered("worker panic", generation);
            let reason = healed["last_failure"]["reason"].as_str().unwrap_or("");
            assert!(reason.contains("Modifying existing peers is not yet supported"), "{healed}");
            round(1, "after a worker panic");
            traffic_counted("worker panic: after the client's traffic on the rebuilt device");
            let left = disable();
            assert_eq!(left, (threads_before, fds_before), "no boringtun thread or fd left behind after a recovery plus disable; fds before {targets_before:?} after {:?}", fd_targets());

            // 2. A worker that hangs: held inside one of boringtun's own tracing calls while
            //    it adds a peer, so its UAPI never answers and it cannot be stopped or joined.
            let (r, code) = apply_ep(&pass("10.77.0.2/32"));
            assert_eq!(code, 200, "{r}");
            let generation = state().lock().unwrap().generation;
            on_device(&|d| stall::hold(d.mark()));
            let newcomer: String = public_key_of(&clamp([7; 32])).iter().map(|b| format!("{b:02x}")).collect();
            on_device(&|d| d.send_unanswered(&format!("set=1\npublic_key={newcomer}\nallowed_ip=10.77.0.9/32\n\n")).unwrap());
            println!("[e2e] injected a hang: boringtun's worker is held inside its own tracing::info!(\"Peer added\")");
            let healed = recovered("hung worker", generation);
            let reason = healed["last_failure"]["reason"].as_str().unwrap_or("");
            assert!(reason.contains("no answer from boringtun's UAPI"), "{healed}");
            round(2, "after a hung worker");
            traffic_counted("hung worker: after the client's traffic on the rebuilt device");
            let (threads, fds) = disable();
            let mut extra = fd_targets();
            for t in &targets_before {
                if let Some(i) = extra.iter().position(|x| x == t) {
                    extra.remove(i);
                }
            }
            println!("[e2e] hung worker: left behind by design: {} thread(s), {} fd(s) {extra:?}", threads - threads_before, fds - fds_before);
            assert_eq!(threads, threads_before + 2, "the held worker, and the stop helper still waiting to join it: {:?}", comms());
            // The held worker's epoll stays open (it may still wait on it); everything the
            // device used (TUN queue, UDP sockets, UAPI end, timers) is a /dev/null placeholder.
            assert_eq!(extra.iter().filter(|t| *t == "anon_inode:[eventpoll]").count(), 1, "{extra:?}");
            assert!(fds == fds_before + extra.len() && extra.iter().all(|t| t == "/dev/null" || t == "anon_inode:[eventpoll]"), "{extra:?}");
            assert!(!extra.iter().any(|t| t.starts_with("socket:") || t == "/dev/net/tun"), "no socket or TUN queue kept: {extra:?}");
            round(3, "end");
        } else {
            round(1, "end");
            let left = disable();
            assert_eq!(left, (threads_before, fds_before), "no thread or fd left behind; fds before {targets_before:?} after {:?}", fd_targets());
        }
        std::fs::write(dir.join("exit.done"), "ok").unwrap();
    }

    #[test]
    fn a_peer_with_a_bad_preshared_key_is_refused() {
        let key = "A2+2dpchy903HY/kmF70XH8jsgBgj1Vvf4+64neJqwI=".to_string();
        let with_psk = |psk: &str| Desired {
            relay: "crane.glick.run:31820".into(),
            secret: "ab".repeat(16),
            peers: vec![Peer { public_key: key.clone(), preshared_key: psk.into(), allowed_ips: "10.77.0.2/32".into(), expires_at: 10 }],
        };
        assert!(validate(&with_psk(&key)).is_ok(), "control: a valid PSK passes");
        for bad in ["", "not-a-key", "A2+2dpchy903HY/kmF70XH8jsgBgj1Vvf4+64neJqw=", "A2+2dpchy903HY/kmF70XH8jsgBgj1Vvf4+64neJqwI=\nAllowedIPs=0.0.0.0/0"] {
            assert!(validate(&with_psk(bad)).is_err(), "PSK {bad:?} must be refused");
        }
    }
}
