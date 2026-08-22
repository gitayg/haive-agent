// IT-AI — LAN remote control & screen sharing with an AI/MCP interface.
// Copyright (C) 2026 The IT-AI Authors.
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
#[cfg(windows)]
mod tray;
mod schedule;
mod shell;
mod tls;
#[cfg(target_os = "linux")]
mod wayland;
#[cfg(windows)]
mod winsession;
#[cfg(windows)]
mod winprobe;
#[cfg(windows)]
mod winbootstrap;
#[cfg(windows)]
mod winupdate;

use std::sync::{mpsc, Arc};
use std::time::Duration;

use clap::Parser;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
#[command(name = "IT-AI", version = VERSION,
    about = "IT-AI agent — screen + control + shell over HTTPS on the LAN")]
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

/// Where a detached agent's stdout/stderr land, so "it just vanished" is always
/// answerable. Lives beside the agent's certs in ~/.it-ai.
fn log_path() -> std::path::PathBuf {
    std::path::PathBuf::from(persistence::home()).join(".it-ai").join("agent.log")
}

/// Append handle to the log, creating ~/.it-ai as needed. Truncated once past
/// ~1 MB so an agent that restart-loops for months can't fill the disk.
fn log_file() -> Option<std::fs::File> {
    let p = log_path();
    if let Some(dir) = p.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if std::fs::metadata(&p).map(|m| m.len() > 1_000_000).unwrap_or(false) {
        let _ = std::fs::remove_file(&p);
    }
    std::fs::OpenOptions::new().create(true).append(true).open(&p).ok()
}

/// If `--background` was given, re-spawn ourselves detached (no console, stdio to
/// ~/.it-ai/agent.log) and return true so the caller exits — leaving the real agent
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
        .stdin(std::process::Stdio::null());
    // Detached output used to go to /dev/null, so an agent that died right after
    // printing "running in the background" left NO trace — a panic, a failed bind
    // and a rejected token all looked identical (the device just never appeared).
    // Point stdout+stderr at ~/.it-ai/agent.log so a silent death is self-diagnosing.
    match (log_file(), log_file()) {
        (Some(out), Some(err)) => {
            c.stdout(std::process::Stdio::from(out)).stderr(std::process::Stdio::from(err));
        }
        _ => {
            c.stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
        }
    }
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
        use std::os::unix::process::CommandExt;
        // Unix analog of the Windows job-breakaway above. A plain spawn leaves the
        // child in the launching shell's session, so closing the window/SSH — which
        // the success message literally tells the user to do — sends SIGHUP to the
        // whole session and kills the "backgrounded" agent before it stays
        // registered. setsid() makes the child its own session leader, detached from
        // the controlling terminal, so SIGHUP never reaches it. pre_exec runs
        // post-fork/pre-exec in the child (not a group leader there), so setsid
        // always succeeds.
        unsafe {
            c.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
        spawned = c.spawn().ok();
    }
    if spawned.is_some() {
        println!("IT-AI is now running in the background — you can close this window.");
        println!("  log: {}", log_path().display());
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
/// gets it-ai-linux-arm64, not the x86_64 one.
fn agent_asset() -> String {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("windows", _) => "it-ai-windows.exe",
        ("macos", _) => "it-ai-macos",
        ("linux", "aarch64") => "it-ai-linux-arm64",
        _ => "it-ai-linux",
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
    let (cameras, cameras_present, microphones) = media_devices();
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
        "cameras_present": cameras_present,
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

/// Cameras + microphones, enumerated NATIVELY — no shelling out to PowerShell,
/// system_profiler, or arecord. Returns `(capturable, present, microphones)`:
///
/// * `capturable` — cameras the capture backend (nokhwa: MediaFoundation on
///   Windows, AVFoundation on macOS, v4l2 on Linux) can actually OPEN. This is
///   the index-stable list the snapshot/live path indexes into — do not reorder
///   or pad it.
/// * `present` — every physical camera the OS reports, annotated with live state.
///   A webcam that EXISTS but is turned off (closed privacy shutter / kill-switch
///   / disabled in Device Manager) is invisible to the capture backend, so
///   `capturable` is empty and the dashboard would otherwise say "no camera" on a
///   laptop that plainly has one. This list keeps it visible as "Camera — off (…)".
///   Windows-only; empty elsewhere (nokhwa already reflects presence there).
/// * microphones — cpal's default host (WASAPI / CoreAudio / ALSA).
fn media_devices() -> (Vec<String>, Vec<String>, Vec<String>) {
    let (capturable, present) = cameras();
    (capturable, present, mics())
}

/// `(capturable, present)` — see `media_devices`.
fn cameras() -> (Vec<String>, Vec<String>) {
    let mut capturable: Vec<String> = nokhwa::query(nokhwa::utils::ApiBackend::Auto)
        .map(|list| list.into_iter().map(|c| c.human_name()).collect())
        .unwrap_or_default();
    capturable.retain(|n| !n.trim().is_empty());
    capturable.dedup();
    let present = camera_presence(&capturable);
    (capturable, present)
}

/// Display-only list of ALL physical cameras with their live state, so an off
/// webcam still shows instead of collapsing to "no camera". Pure Windows probe
/// (Win32_PnPEntity via WMI); empty on other OSes where nokhwa already reflects
/// presence. Never indexed by the snapshot path — that uses `capturable`.
#[cfg(windows)]
fn camera_presence(capturable: &[String]) -> Vec<String> {
    // Normalise for fuzzy matching between nokhwa's friendly name and the PnP
    // device name (they differ in spacing/case): keep alphanumerics, lowercase.
    fn norm(s: &str) -> String {
        s.chars()
            .filter(|c| c.is_alphanumeric())
            .flat_map(|c| c.to_lowercase())
            .collect()
    }
    let cap_norm: Vec<String> = capturable.iter().map(|s| norm(s)).collect();
    let mut out: Vec<String> = Vec::new();
    for (name, code) in crate::winprobe::camera_devices() {
        let n = norm(&name);
        let matched = cap_norm.iter().any(|c| c == &n || c.contains(&n) || n.contains(c));
        if code == 0 && matched {
            out.push(name); // present, enabled, and capturable
        } else if code != 0 {
            out.push(format!("{name} — off ({})", crate::winprobe::cm_error_reason(code)));
        } else {
            // Enabled but the backend can't open it: another app holds it, or
            // "let desktop apps access your camera" is off.
            out.push(format!("{name} — unavailable (in use or camera access blocked)"));
        }
    }
    out.dedup();
    out
}

#[cfg(not(windows))]
fn camera_presence(_capturable: &[String]) -> Vec<String> {
    Vec::new()
}

/// Microphone names via cpal's default host (WASAPI on Windows, CoreAudio on
/// macOS). NOT compiled on Linux — cpal links libasound.so.2 there, a hard
/// load-time dependency that breaks minimal hosts; see the Linux variant below.
#[cfg(not(target_os = "linux"))]
fn mics() -> Vec<String> {
    use cpal::traits::{DeviceTrait, HostTrait};
    let mut names: Vec<String> = match cpal::default_host().input_devices() {
        Ok(it) => it.filter_map(|d| d.name().ok()).collect(),
        Err(_) => Vec::new(),
    };
    names.retain(|n| !n.trim().is_empty());
    names.dedup();
    names
}

/// Microphone names on Linux WITHOUT cpal, so the binary carries no
/// libasound.so.2 dependency and starts on WSL/containers/headless hosts. Reads
/// the kernel's ALSA proc interface (populated by the snd driver, independent of
/// the userspace libasound package): each `/proc/asound/pcm` line is
/// `NN-MM: <id> : <name> : playback P : capture C` — we keep the capture-capable
/// ones. No sound driver (typical WSL) → the file is absent → empty list, and the
/// agent runs fine with no microphones reported.
#[cfg(target_os = "linux")]
fn mics() -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    if let Ok(pcm) = std::fs::read_to_string("/proc/asound/pcm") {
        for line in pcm.lines() {
            if !line.contains("capture") {
                continue;
            }
            let fields: Vec<&str> = line.split(':').map(|s| s.trim()).collect();
            if let Some(name) = fields.get(1).filter(|s| !s.is_empty()) {
                names.push((*name).to_string());
            }
        }
    }
    names.retain(|n| !n.trim().is_empty());
    names.dedup();
    names
}

fn main() {
    let args = Args::parse();

    if args.background && relaunch_detached() {
        return;
    }

    if args.uninstall {
        persistence::uninstall();
        println!("IT-AI autostart removed.");
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
            // Exit 2 = "there is no display to capture", so the session-0 service
            // that spawned us can report that precisely instead of a bare
            // "helper exited 1". Any other failure stays exit 1.
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(if e == capture::NO_DISPLAY { 2 } else { 1 });
            }
        }
    }

    let mac_id = args.mac_id.clone().or_else(|| std::env::var("SCREEN_HUB").ok());
    if mac_id.is_none() && args.relay.is_none() {
        eprintln!("usage: IT-AI <mac-id> [password] [--name N] [--persist | --ttl MIN] [--relay HOST[:PORT]]");
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

    if args.install {
        // Install the elevated logon task, start it now (so it's running without
        // waiting for the next logon), then EXIT — the task owns the long-running
        // agent from here. Staying to also run in the foreground blocked the shell
        // and left two instances fighting over the tunnel.
        persistence::install_service(&persist_args());
        println!("IT-AI installed as an elevated service — starts at logon, self-restarting, and started now. You can close this window.");
        return;
    }
    let lifetime = if args.persist {
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
        let dir = format!("{home}/.it-ai");
        let c = tls::ensure_cert(&dir, &discovery::local_ip(), &[hostname(), "it-ai.local".to_string()]);
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
        // A token is mandatory: the agent will not enroll un-owned. The hub also
        // rejects a tokenless /relay/hello, but refuse up front so it fails loudly
        // here instead of silently never appearing on the hub.
        if token.is_empty() {
            eprintln!(
                "error: relay mode requires an enrollment token.\n\
                 pass --relay-token htok_… (or set HIVE_RELAY_TOKEN). Mint one from the\n\
                 hub dashboard's \"Register a device\" panel — the device enrolls under your account."
            );
            std::process::exit(2);
        }
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
            sans.push(format!("{rid}.it-ai.lan"));
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
        // Give the loopback /ai/chat handler what it needs to reach the hub's
        // relay AI endpoint on the user's behalf (the tray chat talks to this).
        http::set_ai_relay(&relay_addr, &rid, &token);
        std::thread::spawn(move || relay::relay_loop(relay_addr, rid, nm, si, token));
    }

    let registering = if mac_id.is_some() { format!("registering to '{mac_id_disp}'") } else { "relay-only".to_string() };
    println!("IT-AI {VERSION} — serving '{name}' on {scheme}://…:{port}, {registering}");
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
    // Windows-only tray icon + embedded chat window. Spawns its own thread and
    // waits for the loopback server (below) to bind; a no-desktop session just
    // ends that thread. Headless/other platforms: no-op.
    #[cfg(windows)]
    tray::spawn();
    http::serve(cfg, tx);
}
