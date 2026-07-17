// Agent-owned scheduling: the hub pushes a resolved command + a recurrence to
// the agent, which persists it locally and fires it at the set time — so a
// schedule runs even while the device is disconnected from the hub.
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn path() -> std::path::PathBuf {
    let home = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")).unwrap_or_else(|_| ".".into());
    std::path::PathBuf::from(format!("{home}/.haive/schedules.json"))
}

fn store() -> &'static Mutex<Vec<serde_json::Value>> {
    static S: std::sync::OnceLock<Mutex<Vec<serde_json::Value>>> = std::sync::OnceLock::new();
    S.get_or_init(|| Mutex::new(load()))
}

fn load() -> Vec<serde_json::Value> {
    std::fs::read_to_string(path()).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
}

fn save(v: &[serde_json::Value]) {
    if let Some(p) = path().parent() {
        let _ = std::fs::create_dir_all(p);
    }
    let _ = std::fs::write(path(), serde_json::to_string_pretty(v).unwrap_or_default());
}

/// Next fire time (epoch secs) for a recurrence spec: once / interval / daily (UTC).
fn next_run(when: &serde_json::Value) -> u64 {
    let now = now_secs();
    match when.get("type").and_then(|x| x.as_str()).unwrap_or("once") {
        "interval" => now + when.get("mins").and_then(|x| x.as_u64()).unwrap_or(60).max(1) * 60,
        "daily" => {
            let hhmm = when.get("hhmm").and_then(|x| x.as_str()).unwrap_or("00:00");
            let mut it = hhmm.split(':');
            let h: u64 = it.next().and_then(|s| s.trim().parse().ok()).unwrap_or(0);
            let m: u64 = it.next().and_then(|s| s.trim().parse().ok()).unwrap_or(0);
            let tgt = (h * 3600 + m * 60) % 86400;
            let mut r = now - (now % 86400) + tgt;
            if r <= now {
                r += 86400;
            }
            r
        }
        _ => now + when.get("mins").and_then(|x| x.as_u64()).unwrap_or(0) * 60,
    }
}

/// Add or replace a schedule: {id, command, when}.
pub fn add(v: serde_json::Value) {
    let id = v.get("id").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let command = v.get("command").and_then(|x| x.as_str()).unwrap_or("").to_string();
    if id.is_empty() || command.is_empty() {
        return;
    }
    let when = v.get("when").cloned().unwrap_or_default();
    let rec = serde_json::json!({"id": id, "command": command, "when": when.clone(), "next_run": next_run(&when)});
    let mut s = store().lock().unwrap();
    s.retain(|x| x.get("id").and_then(|y| y.as_str()) != rec["id"].as_str());
    s.push(rec);
    save(&s);
}

pub fn del(id: &str) {
    let mut s = store().lock().unwrap();
    s.retain(|x| x.get("id").and_then(|y| y.as_str()) != Some(id));
    save(&s);
}

pub fn list() -> serde_json::Value {
    serde_json::json!({"ok": true, "schedules": store().lock().unwrap().clone()})
}

/// Run a scheduled command locally, fire-and-forget (stdio → null so a GUI child
/// can't hold a pipe; new process group; no console window on Windows).
fn run_cmd(command: &str) {
    let (prog, flag) = if cfg!(windows) { ("cmd", "/C") } else { ("sh", "-c") };
    let mut c = std::process::Command::new(prog);
    c.arg(flag).arg(command).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        c.creation_flags(0x0800_0000 | 0x0000_0200);
    }
    let _ = c.spawn();
}

/// Background tick: fire due schedules, re-arm recurring, drop one-shots.
pub fn run_scheduler() {
    std::thread::spawn(|| loop {
        std::thread::sleep(Duration::from_secs(30));
        let now = now_secs();
        let mut s = store().lock().unwrap();
        let mut changed = false;
        let mut i = 0;
        while i < s.len() {
            if s[i].get("next_run").and_then(|x| x.as_u64()).unwrap_or(u64::MAX) > now {
                i += 1;
                continue;
            }
            if let Some(cmd) = s[i].get("command").and_then(|x| x.as_str()) {
                run_cmd(cmd);
            }
            let when = s[i].get("when").cloned().unwrap_or_default();
            if when.get("type").and_then(|x| x.as_str()).unwrap_or("once") == "once" {
                s.remove(i);
            } else {
                if let Some(o) = s[i].as_object_mut() {
                    o.insert("next_run".into(), serde_json::json!(next_run(&when)));
                    o.insert("last_run".into(), serde_json::json!(now));
                }
                i += 1;
            }
            changed = true;
        }
        if changed {
            save(&s);
        }
    });
}
