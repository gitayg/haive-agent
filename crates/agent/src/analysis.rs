// Periodic full-device analysis. Every INTERVAL the agent runs its whole set of
// report + security commands, diffs the result against the previous snapshot,
// and pushes ONLY the changed sections to the hub — so the dashboard always has
// current data with no manual clicks, and the wire only carries deltas.
use std::collections::BTreeMap;
use std::sync::mpsc;
use std::time::Duration;

use base64::Engine;

const INTERVAL: Duration = Duration::from_secs(300);
/// Re-send everything on this cadence even without changes, so a hub that
/// restarted (losing its in-memory store) recovers within one full cycle.
const FULL_EVERY: u32 = 6; // 6 * 5min = 30min

/// Wrap a PowerShell one-liner as `-EncodedCommand` (base64 of UTF-16LE) so its
/// quotes and pipes survive the cmd shell intact. A bare `-Command "…|…"` gets
/// mangled through the shell layers and echoed back instead of executed.
fn ps(script: &str) -> String {
    let utf16: Vec<u8> = script.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    let b64 = base64::engine::general_purpose::STANDARD.encode(utf16);
    format!("powershell -NoProfile -EncodedCommand {b64}")
}

/// The (section, command) set for this OS. Mirrors the hub's manual reports.
fn commands() -> Vec<(&'static str, String)> {
    match std::env::consts::OS {
        "windows" => vec![
            ("hardware", "systeminfo".into()),
            ("packages", "winget list".into()),
            ("services", ps("Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object Name,DisplayName | Format-Table -Auto")),
            ("processes", "tasklist".into()),
            ("network", "arp -a".into()),
            ("updates", "winget upgrade".into()),
            ("encryption", "manage-bde -status C:".into()),
            ("firewall", "netsh advfirewall show allprofiles state".into()),
            ("av", ps("Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated,AMRunningMode | Format-List")),
        ],
        "macos" => vec![
            ("hardware", "system_profiler SPHardwareDataType".into()),
            ("packages", "brew list --versions 2>/dev/null || ls /Applications".into()),
            ("services", "launchctl list | head -40".into()),
            ("processes", "ps aux 2>/dev/null | sort -rk3 | head -25".into()),
            ("network", "arp -a".into()),
            ("updates", "softwareupdate -l 2>&1 | head -40".into()),
            ("encryption", "fdesetup status".into()),
            ("firewall", "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate".into()),
            ("av", "echo 'Gatekeeper:'; spctl --status".into()),
        ],
        _ => vec![
            ("hardware", "lscpu; echo; free -h; echo; lsblk".into()),
            ("packages", "apt list --installed 2>/dev/null | head -60 || dpkg -l | head -60".into()),
            ("services", "systemctl list-units --type=service --state=running --no-pager | head -40".into()),
            ("processes", "ps aux 2>/dev/null | sort -rk3 | head -25".into()),
            ("network", "ip neigh".into()),
            ("updates", "apt list --upgradable 2>/dev/null".into()),
            ("encryption", "lsblk -o NAME,FSTYPE,MOUNTPOINT | grep -i crypt || echo 'no LUKS volumes detected'".into()),
            ("firewall", "ufw status 2>/dev/null || echo \"ufw is $(systemctl is-active ufw 2>/dev/null || echo not-installed)\"".into()),
            ("av", "clamscan --version 2>/dev/null || echo 'no clamav installed'".into()),
        ],
    }
}

/// Run one command, capturing stdout+stderr, bounded by a timeout so a hung
/// command can't stall the whole analysis cycle.
fn run(cmd: &str) -> String {
    let (prog, flag) = if cfg!(windows) { ("cmd", "/C") } else { ("sh", "-c") };
    let mut c = std::process::Command::new(prog);
    c.arg(flag)
        .arg(cmd)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        c.creation_flags(0x0800_0000); // CREATE_NO_WINDOW — no flashing console per command
    }
    let child = c.spawn();
    let child = match child {
        Ok(c) => c,
        Err(e) => return format!("[error] {e}"),
    };
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(child.wait_with_output());
    });
    match rx.recv_timeout(Duration::from_secs(45)) {
        Ok(Ok(o)) => {
            let mut s = String::from_utf8_lossy(&o.stdout).to_string();
            s.push_str(&String::from_utf8_lossy(&o.stderr));
            s.trim().to_string()
        }
        _ => "[error] timed out".to_string(),
    }
}

fn snapshot() -> BTreeMap<String, String> {
    commands().into_iter().map(|(k, cmd)| (k.to_string(), run(&cmd))).collect()
}

fn base_of(hub: &str) -> String {
    let h = hub.trim_end_matches('/');
    if h.starts_with("http://") || h.starts_with("https://") {
        h.to_string()
    } else {
        format!("http://{h}")
    }
}

/// POST the given sections to the hub. Returns whether the hub wants a full
/// snapshot (it has no record for us — e.g. it restarted).
fn post(base: &str, relay_id: &str, token: &str, sections: &BTreeMap<String, String>, full: bool) -> bool {
    let mut url = format!("{base}/relay/analysis?id={relay_id}");
    if !token.is_empty() {
        url.push_str(&format!("&tok={token}"));
    }
    let body = serde_json::json!({ "relay_id": relay_id, "sections": sections, "full": full });
    match ureq::post(&url).timeout(Duration::from_secs(20)).send_json(body) {
        Ok(r) => r
            .into_json::<serde_json::Value>()
            .ok()
            .and_then(|v| v.get("want_full").and_then(|x| x.as_bool()))
            .unwrap_or(false),
        Err(_) => false,
    }
}

/// Spawn the analysis loop: full snapshot now, then every INTERVAL push deltas.
pub fn start(hub: String, relay_id: String, token: String) {
    std::thread::spawn(move || {
        let base = base_of(&hub);
        let mut last: BTreeMap<String, String> = BTreeMap::new();
        let mut cycle: u32 = 0;
        loop {
            let snap = snapshot();
            let full_due = last.is_empty() || cycle % FULL_EVERY == 0;
            let changed: BTreeMap<String, String> = if full_due {
                snap.clone()
            } else {
                snap.iter()
                    .filter(|(k, v)| last.get(*k) != Some(*v))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect()
            };
            // Always POST at least once (an empty ping still lets the hub ask for
            // a full resync if it lost our record); resend full if it does.
            let want_full = post(&base, &relay_id, &token, &changed, full_due);
            if want_full && !full_due {
                post(&base, &relay_id, &token, &snap, true);
            }
            last = snap;
            cycle = cycle.wrapping_add(1);
            std::thread::sleep(INTERVAL);
        }
    });
}
