// Who's at the machine right now: is a user logged into a graphical session, and
// have they touched it recently. Sampled every heartbeat (it changes over time),
// so it lives alongside the live CPU/RAM metrics rather than the static sysinfo.
use std::process::Command;

/// { logged_in, session_user, idle_secs, active, locked } — active = touched in
/// the last 5 min. idle_secs / active are null when the platform can't report idle
/// time (e.g. a headless service with no session bus); locked is null where we
/// can't tell. Being logged in is NOT the same as being at the machine: a locked
/// box reports logged_in with a session user, so surface `locked` separately and
/// never call a locked machine "active".
pub fn snapshot() -> serde_json::Value {
    let (logged_in, user, idle) = probe();
    let locked = locked();
    let active = if locked == Some(true) { Some(false) } else { idle.map(|s| s < 300) };
    serde_json::json!({
        "logged_in": logged_in,
        "session_user": user,
        "idle_secs": idle,
        "active": active,
        "locked": locked,
    })
}

/// Whether the screen is locked, where we can tell.
#[cfg(windows)]
fn locked() -> Option<bool> {
    Some(crate::winsession::workstation_locked())
}

/// GNOME reports lock/blank state on the session bus; other desktops vary, so
/// treat an unavailable service as "unknown" rather than "unlocked".
#[cfg(all(unix, not(target_os = "macos")))]
fn locked() -> Option<bool> {
    use zbus::blocking::{Connection, Proxy};
    let conn = Connection::session().ok()?;
    let p = Proxy::new(&conn, "org.gnome.ScreenSaver", "/org/gnome/ScreenSaver", "org.gnome.ScreenSaver").ok()?;
    p.call("GetActive", &()).ok()
}

#[cfg(target_os = "macos")]
fn locked() -> Option<bool> {
    None
}

#[cfg(target_os = "macos")]
fn probe() -> (bool, Option<String>, Option<u64>) {
    // The GUI user owns /dev/console.
    let user = Command::new("stat")
        .args(["-f", "%Su", "/dev/console"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && s != "root");
    // HIDIdleTime is nanoseconds since the last HID event.
    let idle = Command::new("sh")
        .args(["-c", "ioreg -c IOHIDSystem | awk '/HIDIdleTime/ {print $NF; exit}'"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse::<u128>().ok())
        .map(|ns| (ns / 1_000_000_000) as u64);
    (user.is_some(), user, idle)
}

#[cfg(all(unix, not(target_os = "macos")))]
fn probe() -> (bool, Option<String>, Option<u64>) {
    let user = linux_graphical_user();
    let idle = linux_idle_secs();
    (user.is_some(), user, idle)
}

/// The user of the active graphical (seat0) login session, via loginctl.
#[cfg(all(unix, not(target_os = "macos")))]
fn linux_graphical_user() -> Option<String> {
    let out = Command::new("loginctl").args(["list-sessions", "--no-legend"]).output().ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    for line in s.lines() {
        // Columns: SESSION UID USER SEAT [TTY]. A graphical login has seat0.
        if line.contains("seat0") {
            if let Some(user) = line.split_whitespace().nth(2) {
                return Some(user.to_string());
            }
        }
    }
    None
}

/// Idle seconds from GNOME's Mutter IdleMonitor (works on X11 + Wayland). Needs
/// the session bus (present when the agent runs in the user's session); None if
/// unavailable (no session bus, or a non-GNOME compositor).
#[cfg(all(unix, not(target_os = "macos")))]
fn linux_idle_secs() -> Option<u64> {
    use zbus::blocking::{Connection, Proxy};
    let conn = Connection::session().ok()?;
    let p = Proxy::new(
        &conn,
        "org.gnome.Mutter.IdleMonitor",
        "/org/gnome/Mutter/IdleMonitor/Core",
        "org.gnome.Mutter.IdleMonitor",
    )
    .ok()?;
    let ms: u64 = p.call("GetIdletime", &()).ok()?;
    Some(ms / 1000)
}

#[cfg(windows)]
fn probe() -> (bool, Option<String>, Option<u64>) {
    use std::os::windows::process::CommandExt;
    // `query user` gives username + STATE (Active/Disc) + IDLE TIME in one shot.
    let out = Command::new("query")
        .args(["user"])
        .creation_flags(0x0800_0000) // CREATE_NO_WINDOW — no console flash
        .output()
        .ok();
    let text = out.and_then(|o| String::from_utf8(o.stdout).ok()).unwrap_or_default();
    // Prefer the Active session; fall back to any session.
    let mut fallback: Option<(String, Option<u64>)> = None;
    for line in text.lines().skip(1) {
        let raw = line.trim_start();
        if raw.is_empty() {
            continue;
        }
        // Leading '>' marks the current session; strip it for the username.
        let cleaned = raw.trim_start_matches('>').trim_start();
        let cols: Vec<&str> = cleaned.split_whitespace().collect();
        if cols.is_empty() {
            continue;
        }
        let user = cols[0].to_string();
        let active = cols.iter().any(|c| c.eq_ignore_ascii_case("Active"));
        // IDLE TIME is the column before LOGON TIME (date). Parse the token that
        // looks like an idle spec ("none"/"."/"N"/"HH:MM"/"D+HH:MM").
        let idle = cols.iter().find_map(|c| parse_idle(c));
        if active {
            return (true, Some(user), Some(idle.unwrap_or(0)));
        }
        if fallback.is_none() {
            fallback = Some((user, idle));
        }
    }
    match fallback {
        Some((user, idle)) => (true, Some(user), idle),
        None => (false, None, None),
    }
}

/// Parse a `query user` IDLE TIME cell to seconds: "none"/"." → 0, "N" → minutes,
/// "HH:MM" → h:m, "D+HH:MM" → days+h:m. Anything else → None.
#[cfg(windows)]
fn parse_idle(tok: &str) -> Option<u64> {
    if tok == "none" || tok == "." {
        return Some(0);
    }
    if let Some((d, hm)) = tok.split_once('+') {
        let days: u64 = d.parse().ok()?;
        let (h, m) = hm.split_once(':')?;
        return Some(days * 86400 + h.parse::<u64>().ok()? * 3600 + m.parse::<u64>().ok()? * 60);
    }
    if let Some((h, m)) = tok.split_once(':') {
        return Some(h.parse::<u64>().ok()? * 3600 + m.parse::<u64>().ok()? * 60);
    }
    tok.parse::<u64>().ok().map(|mins| mins * 60)
}
