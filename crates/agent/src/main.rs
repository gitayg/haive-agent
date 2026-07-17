// HaiveControl — LAN remote control & screen sharing with an AI/MCP interface.
// Copyright (C) 2026 The HaiveControl Authors.
// SPDX-License-Identifier: AGPL-3.0-or-later
mod analysis;
mod capture;
mod config;
mod discovery;
mod http;
mod input;
mod persistence;
mod wakelock;
mod presence;
mod relay;
mod schedule;
mod shell;
mod tls;
#[cfg(target_os = "linux")]
mod wayland;
#[cfg(windows)]
mod winsession;

use std::sync::{mpsc, Arc};
use std::time::Duration;

use clap::Parser;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
#[command(name = "HaiveControl", version = VERSION,
    about = "HaiveControl agent — screen + control + shell over HTTPS on the LAN")]
struct Args {
    /// the id shown by the Mac hub
    mac_id: Option<String>,
    /// optional — if set, connecting prompts for it
    password: Option<String>,
    /// friendly device name shown in the hub (default: hostname)
    #[arg(long)]
    name: Option<String>,
    /// hub Mac ID for mDNS fallback when the target is a direct IP
    #[arg(long)]
    id: Option<String>,
    /// install autostart so it survives reboot (per-user: Run key / LaunchAgent)
    #[arg(long, conflicts_with = "ttl")]
    persist: bool,
    /// install as a boot/logon service (Scheduled Task / LaunchDaemon / systemd);
    /// more robust than --persist and restarts the agent if it dies. Run elevated.
    #[arg(long, conflicts_with = "ttl")]
    install: bool,
    /// run for MIN minutes, then auto-exit (dissolve)
    #[arg(long, value_name = "MIN")]
    ttl: Option<f64>,
    /// remove autostart and exit
    #[arg(long)]
    uninstall: bool,
    /// dial OUT to a (possibly cloud) hub relay URL (e.g. https://hub.example.com),
    /// so the hub can reach this device through NAT
    #[arg(long, value_name = "URL")]
    relay: Option<String>,
    /// token required by a token-protected relay (or set HIVE_RELAY_TOKEN)
    #[arg(long, value_name = "TOKEN")]
    relay_token: Option<String>,
    /// owner id this device belongs to (multi-user hub); or set HIVE_OWNER
    #[arg(long, value_name = "ID")]
    owner: Option<String>,
    /// re-launch detached and exit, so you can close this window
    #[arg(long)]
    background: bool,
    /// internal: grab one screen frame to this file (JPEG) and exit. Used by the
    /// Windows session-0 service to capture from the active user's session.
    #[arg(long, hide = true, value_name = "FILE")]
    capture_once: Option<String>,
}

/// If `--background` was given, re-spawn ourselves detached (no console, no
/// inherited stdio) and return true so the caller exits — leaving the real agent
/// running after this window closes. HAIVE_DETACHED guards against re-spawning.
fn relaunch_detached() -> bool {
    if std::env::var("HAIVE_DETACHED").is_ok() {
        return false;
    }
    let Ok(exe) = std::env::current_exe() else { return false };
    let rest: Vec<String> = std::env::args().skip(1).collect();
    let mut c = std::process::Command::new(exe);
    c.args(&rest)
        .env("HAIVE_DETACHED", "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let spawned;
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB.
        // Breakaway is the fix for the child dying the instant the launching shell
        // exits: Windows OpenSSH sessions (and some terminals) run the shell inside a
        // kill-on-close job object, and a merely "detached" child is still a member of
        // that job — so it gets terminated with the shell. Breaking away escapes it.
        // If the job forbids breakaway, fall back to a plain detached spawn.
        const BASE: u32 = 0x0000_0008 | 0x0000_0200;
        c.creation_flags(BASE | 0x0100_0000);
        spawned = match c.spawn() {
            Ok(ch) => Some(ch),
            Err(_) => {
                c.creation_flags(BASE);
                c.spawn().ok()
            }
        };
    }
    #[cfg(not(windows))]
    {
        spawned = c.spawn().ok();
    }
    if spawned.is_some() {
        println!("HaiveControl is now running in the background — you can close this window.");
        true
    } else {
        false
    }
}

/// A stable per-machine suffix (deterministic hash of hostname + user + OS), so a
/// restart keeps the SAME relay id — the hub reuses the device's entry (and its
/// retained analysis) instead of piling up a new ghost per launch. DefaultHasher
/// uses fixed keys, so this is stable across runs.
fn agent_direct_token(relay_token: &str, relay_id: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(relay_token.as_bytes());
    h.update(b":");
    h.update(relay_id.as_bytes());
    h.update(b":haive-direct");
    format!("{:x}", h.finalize())
}

/// A stable, machine-UNIQUE identifier: the OS's own machine id where available
/// (unique per install, survives renames), falling back to hostname+os. Used so
/// the device id is tied to the box, not its name.
fn machine_id() -> String {
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        for p in ["/etc/machine-id", "/var/lib/dbus/machine-id"] {
            if let Ok(s) = std::fs::read_to_string(p) {
                let s = s.trim();
                if !s.is_empty() {
                    return s.to_string();
                }
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Ok(o) = std::process::Command::new("ioreg").args(["-rd1", "-c", "IOPlatformExpertDevice"]).output() {
            let text = String::from_utf8_lossy(&o.stdout);
            if let Some(line) = text.lines().find(|l| l.contains("IOPlatformUUID")) {
                if let Some(uuid) = line.split('"').nth(3) {
                    if !uuid.is_empty() {
                        return uuid.to_string();
                    }
                }
            }
        }
    }
    #[cfg(windows)]
    {
        use winreg::enums::*;
        use winreg::RegKey;
        if let Ok(k) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(r"SOFTWARE\Microsoft\Cryptography") {
            if let Ok(g) = k.get_value::<String, _>("MachineGuid") {
                if !g.is_empty() {
                    return g;
                }
            }
        }
    }
    format!("{}:{}", hostname(), std::env::consts::OS)
}

/// A stable per-machine suffix — hash of the machine id, so a box gets ONE device
/// id regardless of which account/session/NAME runs the agent. Machine-unique
/// (avoids hostname collisions) and name-INDEPENDENT (renaming or re-enrolling
/// under a different --name no longer creates a second inventory row).
fn stable_suffix() -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    machine_id().hash(&mut h);
    format!("{:08x}", h.finish() as u32)
}

/// The device's relay id. Name-independent: `hc-<machinehash>`, so the same box is
/// always the same id (the friendly name is carried separately, for display only).
fn relay_id() -> String {
    format!("hc-{}", stable_suffix())
}

/// The args to persist for autostart: the current invocation minus the one-shot
/// persistence/detach flags, so the installed command re-runs in the same mode
/// (relay or LAN) without re-triggering install or backgrounding.
/// The release asset name for this platform + arch (matches build.yml suffixes),
/// so auto-update pulls the right binary — e.g. an aarch64 Linux box (a Radxa/Pi)
/// gets HaiveControl-linux-arm64, not the x86_64 one.
fn agent_asset() -> String {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("windows", _) => "HaiveControl-windows.exe",
        ("macos", _) => "HaiveControl-macos",
        ("linux", "aarch64") => "HaiveControl-linux-arm64",
        _ => "HaiveControl-linux",
    }
    .to_string()
}

pub(crate) fn persist_args() -> Vec<String> {
    std::env::args()
        .skip(1)
        .filter(|a| !matches!(a.as_str(), "--install" | "--persist" | "--background" | "--uninstall"))
        .collect()
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn hostname() -> String {
    let mut hc = std::process::Command::new("hostname");
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        hc.creation_flags(0x0800_0000);
    }
    if let Ok(o) = hc.output() {
        let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if !s.is_empty() {
            return s;
        }
    }
    std::env::var("COMPUTERNAME").unwrap_or_else(|_| "device".to_string())
}

fn collect_sysinfo() -> serde_json::Value {
    use sysinfo::System;
    let mut sys = System::new_all();
    sys.refresh_memory();
    let os = System::long_os_version().unwrap_or_else(|| std::env::consts::OS.to_string());
    let host = System::host_name().unwrap_or_default();
    let cpu = sys.cpus().first().map(|c| c.brand().trim().to_string()).unwrap_or_default();
    let cores = sys.cpus().len();
    let mem_gb = ((sys.total_memory() as f64 / 1_073_741_824.0) * 10.0).round() / 10.0;
    let user = std::env::var("USER").or_else(|_| std::env::var("USERNAME")).unwrap_or_default();
    let nets = sysinfo::Networks::new_with_refreshed_list();
    let mut interfaces: Vec<serde_json::Value> = Vec::new();
    for (name, data) in &nets {
        for ipn in data.ip_networks() {
            interfaces.push(serde_json::json!({"name": name, "addr": ipn.addr.to_string()}));
        }
    }
    let (cameras, microphones) = media_devices();
    serde_json::json!({
        "os": os,
        "arch": std::env::consts::ARCH,
        "platform": std::env::consts::OS,
        "install_mode": persistence::current_mode(),
        "agent_version": VERSION,
        "hostname": host,
        "user": user,
        "cpu": cpu,
        "cores": cores,
        "mem_gb": mem_gb,
        "interfaces": interfaces,
        "cameras": cameras,
        "microphones": microphones,
    })
}

/// Live, per-cycle metrics (re-sampled on every re-registration): CPU load % and
/// free RAM. Kept separate from the static sysinfo gathered once at startup.
pub(crate) fn live_metrics() -> serde_json::Value {
    use sysinfo::System;
    let mut sys = System::new();
    sys.refresh_cpu_all();
    std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
    sys.refresh_cpu_all();
    let cpus = sys.cpus();
    let cpu_pct = if cpus.is_empty() {
        0.0
    } else {
        (cpus.iter().map(|c| c.cpu_usage() as f64).sum::<f64>() / cpus.len() as f64 * 10.0).round() / 10.0
    };
    sys.refresh_memory();
    let free_gb = (sys.available_memory() as f64 / 1_073_741_824.0 * 10.0).round() / 10.0;
    let mut m = serde_json::json!({ "cpu_pct": cpu_pct, "free_gb": free_gb });
    // Merge in who's-at-the-machine (logged_in / session_user / idle_secs / active).
    if let (Some(obj), Some(p)) = (m.as_object_mut(), presence::snapshot().as_object()) {
        for (k, v) in p {
            obj.insert(k.clone(), v.clone());
        }
    }
    m
}

#[cfg(target_os = "macos")]
fn media_devices() -> (Vec<String>, Vec<String>) {
    (macos_cameras(), macos_mics())
}
#[cfg(target_os = "macos")]
fn sp_json(dtype: &str) -> Option<serde_json::Value> {
    let out = std::process::Command::new("system_profiler").args(["-json", dtype]).output().ok()?;
    serde_json::from_slice(&out.stdout).ok()
}
#[cfg(target_os = "macos")]
fn macos_cameras() -> Vec<String> {
    sp_json("SPCameraDataType")
        .and_then(|v| v.get("SPCameraDataType").and_then(|x| x.as_array()).cloned())
        .map(|arr| arr.iter().filter_map(|i| i.get("_name").and_then(|n| n.as_str()).map(String::from)).collect())
        .unwrap_or_default()
}
#[cfg(target_os = "macos")]
fn macos_mics() -> Vec<String> {
    let mut mics = Vec::new();
    if let Some(v) = sp_json("SPAudioDataType") {
        if let Some(arr) = v.get("SPAudioDataType").and_then(|x| x.as_array()) {
            for group in arr {
                if let Some(items) = group.get("_items").and_then(|x| x.as_array()) {
                    for d in items {
                        if d.get("coreaudio_device_input").is_some() {
                            if let Some(n) = d.get("_name").and_then(|n| n.as_str()) {
                                mics.push(n.to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    mics
}

#[cfg(target_os = "windows")]
fn media_devices() -> (Vec<String>, Vec<String>) {
    (
        ps_lines("Get-PnpDevice -Class Camera -PresentOnly -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FriendlyName"),
        ps_lines("Get-PnpDevice -Class AudioEndpoint -PresentOnly -ErrorAction SilentlyContinue | Where-Object {$_.FriendlyName -match 'microphone|mic'} | Select-Object -ExpandProperty FriendlyName"),
    )
}
#[cfg(target_os = "windows")]
fn ps_lines(cmd: &str) -> Vec<String> {
    use std::os::windows::process::CommandExt;
    match std::process::Command::new("powershell").args(["-NoProfile", "-Command", cmd]).creation_flags(0x0800_0000).output() {
        Ok(o) => String::from_utf8_lossy(&o.stdout).lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect(),
        Err(_) => Vec::new(),
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
fn media_devices() -> (Vec<String>, Vec<String>) {
    let mut cams: Vec<String> = Vec::new();
    if let Ok(rd) = std::fs::read_dir("/sys/class/video4linux") {
        for e in rd.flatten() {
            if let Ok(name) = std::fs::read_to_string(e.path().join("name")) {
                let n = name.trim().to_string();
                if !n.is_empty() && !cams.contains(&n) {
                    cams.push(n);
                }
            }
        }
    }
    let mut mics: Vec<String> = Vec::new();
    if let Ok(o) = std::process::Command::new("arecord").arg("-l").output() {
        for line in String::from_utf8_lossy(&o.stdout).lines() {
            if line.starts_with("card ") {
                if let Some(pos) = line.find(": ") {
                    let name = line[pos + 2..].split('[').next().unwrap_or("").trim().to_string();
                    if !name.is_empty() && !mics.contains(&name) {
                        mics.push(name);
                    }
                }
            }
        }
    }
    (cams, mics)
}

fn main() {
    let args = Args::parse();

    if args.background && relaunch_detached() {
        return;
    }

    if args.uninstall {
        persistence::uninstall();
        println!("HaiveControl autostart removed.");
        return;
    }

    // One-shot capture mode: grab a single frame to a file and exit. The Windows
    // session-0 service invokes this inside the active user's session (which can
    // reach the desktop) and reads back the file.
    if let Some(file) = args.capture_once.clone() {
        let quality: u8 = env_or("SCREEN_QUALITY", "60").parse().unwrap_or(60);
        let max_width: u32 = env_or("SCREEN_MAXW", "1600").parse().unwrap_or(1600);
        let monitor: usize = env_or("SCREEN_MONITOR", "0").parse().unwrap_or(0);
        let g = capture::Grabber { index: monitor };
        match g.grab(quality, max_width) {
            Ok(bytes) => {
                let _ = std::fs::write(&file, bytes);
                std::process::exit(0);
            }
            Err(_) => std::process::exit(1),
        }
    }

    let mac_id = args.mac_id.clone().or_else(|| std::env::var("SCREEN_HUB").ok());
    if mac_id.is_none() && args.relay.is_none() {
        eprintln!("usage: HaiveControl <mac-id> [password] [--name N] [--persist | --ttl MIN] [--relay HOST[:PORT]]");
        std::process::exit(2);
    }
    let mac_id_disp = mac_id.clone().unwrap_or_default();

    // Keep the host reachable: stop the OS idle-sleeping while the agent runs.
    // Applies on every real run (including a plain --background enroll), needs no
    // elevation, and clears when we exit. Persist-mode adds a powercfg/pmset scheme
    // change on top for lid-close/hibernate coverage.
    wakelock::hold();

    let password = args.password.clone().unwrap_or_else(|| env_or("SCREEN_PW", ""));
    let port: u16 = env_or("SCREEN_PORT", "8765").parse().unwrap_or(8765);
    let quality: u8 = env_or("SCREEN_QUALITY", "60").parse().unwrap_or(60);
    let max_width: u32 = env_or("SCREEN_MAXW", "1600").parse().unwrap_or(1600);
    let monitor: usize = env_or("SCREEN_MONITOR", "0").parse().unwrap_or(0);
    let exec_enabled = env_or("SCREEN_EXEC", "1") != "0";
    let mut tls = env_or("SCREEN_TLS", "1") != "0";
    let share = env_or("SCREEN_SHARE", "");
    let name = args
        .name
        .clone()
        .or_else(|| std::env::var("SCREEN_NAME").ok())
        .unwrap_or_else(hostname);

    let grabber = capture::Grabber { index: monitor };
    let geo = grabber.geometry();

    let lifetime = if args.install {
        persistence::install_service(&persist_args());
        "installed (service — starts at logon/boot, self-restarting)".to_string()
    } else if args.persist {
        persistence::install(&persist_args());
        "persistent (autostart at login)".to_string()
    } else if let Some(mins) = args.ttl {
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs_f64(mins * 60.0));
            persistence::uninstall();
            std::process::exit(0);
        });
        format!("{mins} min then auto-exit")
    } else {
        "one-time (until closed)".to_string()
    };

    let mut cert = if tls {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_default();
        let dir = format!("{home}/.haive");
        let c = tls::ensure_cert(&dir, &discovery::local_ip(), &[hostname(), "haive.local".to_string()]);
        if c.is_none() {
            eprintln!("cert generation failed; falling back to plain HTTP");
            tls = false;
        }
        c
    } else {
        None
    };
    let scheme: &'static str = if tls { "https" } else { "http" };

    let (tx, rx) = mpsc::channel::<input::Ev>();
    std::thread::spawn(move || input::run(rx, geo));

    let mut sysinfo = collect_sysinfo();
    if let Some(owner) = args.owner.clone().or_else(|| std::env::var("HIVE_OWNER").ok()).filter(|s| !s.is_empty()) {
        if let Some(o) = sysinfo.as_object_mut() {
            o.insert("owner".into(), serde_json::json!(owner));
        }
    }
    if let Some(mid) = mac_id.clone() {
        let (primary, fid, nm, si) = (mid.clone(), args.id.clone(), name.clone(), sysinfo.clone());
        std::thread::spawn(move || discovery::register_loop(primary, fid, nm, port, scheme, si));
        let asset = agent_asset();
        let fid = args.id.clone();
        std::thread::spawn(move || discovery::auto_update_loop(mid, fid, asset));
    }
    let mut direct_token = String::new();
    if let Some(relay_addr) = args.relay.clone() {
        let rid = relay_id();
        let (nm, si) = (name.clone(), sysinfo.clone());
        let token = args.relay_token.clone().or_else(|| std::env::var("HIVE_RELAY_TOKEN").ok()).unwrap_or_default();
        direct_token = agent_direct_token(&token, &rid);
        // LAN-direct: get a hub-signed leaf cert (SANs = our LAN IPs + a stable
        // name) so a same-LAN controller can validate a direct connection to us
        // against the hub CA. Falls back to the self-signed cert on failure.
        if tls {
            let mut sans: Vec<String> = sysinfo
                .get("interfaces")
                .and_then(|x| x.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|i| i.get("addr").and_then(|s| s.as_str()))
                        .filter(|a| a.parse::<std::net::Ipv4Addr>().map(|ip| !ip.is_loopback() && !ip.is_link_local()).unwrap_or(false))
                        .map(String::from)
                        .collect()
                })
                .unwrap_or_default();
            sans.push(format!("{rid}.haive.lan"));
            if let Some(c) = config::fetch_hub_cert(&relay_addr, &rid, &token, sans) {
                println!("   lan-direct: using hub-signed cert");
                cert = Some(c);
            }
        }
        println!("   relay: dialing {relay_addr} as {rid}");
        config::start_poll(relay_addr.clone(), if token.is_empty() { None } else { Some(token.clone()) });
        analysis::start(relay_addr.clone(), rid.clone(), token.clone());
        let asset = agent_asset();
        discovery::auto_update_relay(relay_addr.clone(), asset);
        std::thread::spawn(move || relay::relay_loop(relay_addr, rid, nm, si, token));
    }

    let registering = if mac_id.is_some() { format!("registering to '{mac_id_disp}'") } else { "relay-only".to_string() };
    println!("HaiveControl {VERSION} — serving '{name}' on {scheme}://…:{port}, {registering}");
    println!("   lifetime: {lifetime}");
    println!(
        "   tls: {} | password: {} | exec: {}",
        if tls { "on" } else { "off" },
        if password.is_empty() { "none" } else { "required" },
        if exec_enabled { "enabled" } else { "disabled" }
    );

    let cfg = Arc::new(http::Config {
        password,
        port,
        quality,
        max_width,
        exec_enabled,
        tls,
        share,
        grabber,
        cert,
        direct_token,
    });
    schedule::run_scheduler();
    http::serve(cfg, tx);
}
