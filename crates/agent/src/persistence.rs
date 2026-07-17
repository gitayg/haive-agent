// Standard, visible autostart per OS. Nothing hidden; uninstall removes it.
use std::env;
#[allow(unused_imports)]
use std::path::{Path, PathBuf};

pub fn install(args: &[String]) {
    let exe = env::current_exe().unwrap_or_default();
    #[cfg(windows)]
    win_install(&exe, args);
    #[cfg(target_os = "macos")]
    mac_install(&exe, args);
    #[cfg(all(unix, not(target_os = "macos")))]
    linux_install(&exe, args);
    let _ = (&exe, args);
    // A persistent device should stay reachable — don't let it sleep on AC power.
    keep_awake_on_ac();
}

/// Boot/logon-level autostart — a Scheduled Task (Windows), LaunchDaemon (macOS)
/// or systemd system service (Linux). More robust than `install` (per-user Run
/// key / LaunchAgent): survives reboots and restarts the agent if it dies.
/// Requires elevation to create; run the enrollment command as admin/root.
pub fn install_service(args: &[String]) {
    let exe = env::current_exe().unwrap_or_default();
    #[cfg(windows)]
    win_install_service(&exe, args);
    #[cfg(target_os = "macos")]
    mac_install_service(&exe, args);
    #[cfg(all(unix, not(target_os = "macos")))]
    linux_install_service(&exe, args);
    let _ = (&exe, args);
    keep_awake_on_ac();
}

/// How this agent will come back after a reboot, by checking which autostart
/// artifact exists: "service" (boot/logon daemon), "autostart" (per-user), or
/// "ephemeral" (nothing — dies with the session). Surfaced in the inventory.
pub fn current_mode() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        if daemon_path().exists() {
            return "service";
        }
        if plist_path().exists() {
            return "autostart";
        }
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if unit_path().exists() {
            return "service";
        }
        if desktop_path().exists() {
            return "autostart";
        }
    }
    #[cfg(windows)]
    {
        if win_task_exists() {
            return "service";
        }
        if win_run_exists() {
            return "autostart";
        }
    }
    "ephemeral"
}

#[cfg(windows)]
fn win_task_exists() -> bool {
    use std::os::windows::process::CommandExt;
    std::process::Command::new("schtasks")
        .args(["/Query", "/TN", "HaiveControl"])
        .creation_flags(0x0800_0000) // CREATE_NO_WINDOW — no console flash
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(windows)]
fn win_run_exists() -> bool {
    use winreg::enums::*;
    use winreg::RegKey;
    RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey(r"Software\Microsoft\Windows\CurrentVersion\Run")
        .and_then(|k| k.get_value::<String, _>("HaiveControl"))
        .is_ok()
}

pub fn uninstall() {
    #[cfg(windows)]
    {
        win_uninstall();
        win_service_uninstall();
    }
    #[cfg(target_os = "macos")]
    {
        mac_uninstall();
        mac_service_uninstall();
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        linux_uninstall();
        linux_service_uninstall();
    }
    // Undo the keep-awake we set at install time.
    restore_sleep();
}

fn home() -> String {
    env::var("HOME")
        .or_else(|_| env::var("USERPROFILE"))
        .unwrap_or_default()
}

// ---- macOS: LaunchAgent ----
#[cfg(target_os = "macos")]
fn plist_path() -> PathBuf {
    PathBuf::from(home()).join("Library/LaunchAgents/com.haive.agent.plist")
}

#[cfg(target_os = "macos")]
fn mac_install(exe: &Path, args: &[String]) {
    let mut pa = format!("      <string>{}</string>\n", exe.display());
    for a in args {
        pa.push_str(&format!("      <string>{a}</string>\n"));
    }
    let plist = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n  <key>Label</key><string>com.haive.agent</string>\n  <key>ProgramArguments</key><array>\n{pa}  </array>\n  <key>RunAtLoad</key><true/>\n  <key>KeepAlive</key><true/>\n</dict></plist>\n"
    );
    let p = plist_path();
    if let Some(dir) = p.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(&p, plist);
    let _ = std::process::Command::new("launchctl")
        .args(["load", &p.to_string_lossy()])
        .status();
}

#[cfg(target_os = "macos")]
fn mac_uninstall() {
    let p = plist_path();
    let _ = std::process::Command::new("launchctl")
        .args(["unload", &p.to_string_lossy()])
        .status();
    let _ = std::fs::remove_file(&p);
}

// ---- Linux: XDG autostart ----
#[cfg(all(unix, not(target_os = "macos")))]
fn desktop_path() -> PathBuf {
    PathBuf::from(home()).join(".config/autostart/haivecontrol.desktop")
}

#[cfg(all(unix, not(target_os = "macos")))]
fn linux_install(exe: &Path, args: &[String]) {
    let mut ex = format!("{}", exe.display());
    for a in args {
        ex.push(' ');
        ex.push_str(a);
    }
    let entry = format!(
        "[Desktop Entry]\nType=Application\nName=HaiveControl\nExec={ex}\nX-GNOME-Autostart-enabled=true\n"
    );
    let p = desktop_path();
    if let Some(dir) = p.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(&p, entry);
}

#[cfg(all(unix, not(target_os = "macos")))]
fn linux_uninstall() {
    let _ = std::fs::remove_file(desktop_path());
}

// ---- Windows: HKCU Run ----
#[cfg(windows)]
fn win_install(exe: &Path, args: &[String]) {
    use winreg::enums::*;
    use winreg::RegKey;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    if let Ok(key) = hkcu.open_subkey_with_flags(
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        KEY_SET_VALUE,
    ) {
        let mut cmd = format!("\"{}\"", exe.display());
        for a in args {
            cmd.push_str(&format!(" \"{a}\""));
        }
        let _ = key.set_value("HaiveControl", &cmd);
    }
}

#[cfg(windows)]
fn win_uninstall() {
    use winreg::enums::*;
    use winreg::RegKey;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    if let Ok(key) = hkcu.open_subkey_with_flags(
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        KEY_SET_VALUE,
    ) {
        let _ = key.delete_value("HaiveControl");
    }
}

// ---- Windows: Scheduled Task (starts at logon, elevated) ----
#[cfg(windows)]
fn win_install_service(exe: &Path, args: &[String]) {
    let mut tr = format!("\"{}\"", exe.display());
    for a in args {
        tr.push(' ');
        tr.push_str(a);
    }
    let _ = std::process::Command::new("schtasks")
        .args(["/Create", "/TN", "HaiveControl", "/TR", &tr, "/SC", "ONLOGON", "/RL", "HIGHEST", "/F"])
        .status();
}

#[cfg(windows)]
fn win_service_uninstall() {
    let _ = std::process::Command::new("schtasks")
        .args(["/Delete", "/TN", "HaiveControl", "/F"])
        .status();
}

// ---- macOS: LaunchDaemon (starts at boot, root) ----
#[cfg(target_os = "macos")]
fn daemon_path() -> PathBuf {
    PathBuf::from("/Library/LaunchDaemons/com.haive.agent.plist")
}

#[cfg(target_os = "macos")]
fn mac_install_service(exe: &Path, args: &[String]) {
    let mut pa = format!("      <string>{}</string>\n", exe.display());
    for a in args {
        pa.push_str(&format!("      <string>{a}</string>\n"));
    }
    let plist = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n  <key>Label</key><string>com.haive.agent</string>\n  <key>ProgramArguments</key><array>\n{pa}  </array>\n  <key>RunAtLoad</key><true/>\n  <key>KeepAlive</key><true/>\n</dict></plist>\n"
    );
    let p = daemon_path();
    let _ = std::fs::write(&p, plist);
    let _ = std::process::Command::new("launchctl").args(["load", &p.to_string_lossy()]).status();
}

#[cfg(target_os = "macos")]
fn mac_service_uninstall() {
    let p = daemon_path();
    let _ = std::process::Command::new("launchctl").args(["unload", &p.to_string_lossy()]).status();
    let _ = std::fs::remove_file(&p);
}

// ---- Linux: systemd system service (starts at boot, root) ----
#[cfg(all(unix, not(target_os = "macos")))]
fn unit_path() -> PathBuf {
    PathBuf::from("/etc/systemd/system/haivecontrol.service")
}

#[cfg(all(unix, not(target_os = "macos")))]
fn linux_install_service(exe: &Path, args: &[String]) {
    let mut ex = format!("{}", exe.display());
    for a in args {
        ex.push(' ');
        ex.push_str(a);
    }
    let unit = format!(
        "[Unit]\nDescription=HaiveControl agent\nAfter=network.target\n\n[Service]\nExecStart={ex}\nRestart=always\nRestartSec=5\n\n[Install]\nWantedBy=multi-user.target\n"
    );
    let _ = std::fs::write(unit_path(), unit);
    let _ = std::process::Command::new("systemctl").arg("daemon-reload").status();
    let _ = std::process::Command::new("systemctl").args(["enable", "--now", "haivecontrol.service"]).status();
}

#[cfg(all(unix, not(target_os = "macos")))]
fn linux_service_uninstall() {
    let _ = std::process::Command::new("systemctl").args(["disable", "--now", "haivecontrol.service"]).status();
    let _ = std::fs::remove_file(unit_path());
}

// ---- AC keep-awake ----------------------------------------------------------
// A managed device should stay reachable, so on install we stop it sleeping while
// on AC power (battery is left alone), saving the prior setting so dissolve can
// restore it. Best-effort + per-OS; each needs the relevant privilege (GNOME
// gsettings is per-user; Windows powercfg / macOS pmset generally want elevation).

fn sleep_prior_file() -> PathBuf {
    PathBuf::from(home()).join(".haive").join("sleep_prior")
}

pub fn keep_awake_on_ac() {
    let _ = std::fs::create_dir_all(PathBuf::from(home()).join(".haive"));
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        // GNOME: remember the current AC idle action, then set it to do nothing.
        if let Some(prev) = gsettings_get("sleep-inactive-ac-type") {
            let prev = prev.trim();
            if prev != "nothing" && !prev.is_empty() {
                let _ = std::fs::write(sleep_prior_file(), prev);
            }
            gsettings_set("sleep-inactive-ac-type", "nothing");
        }
    }
    #[cfg(windows)]
    {
        if let Some(mins) = powercfg_ac_standby() {
            let _ = std::fs::write(sleep_prior_file(), mins.to_string());
        }
        let _ = pc(&["/change", "standby-timeout-ac", "0"]);
        // Also stop hibernate and lid-close sleep on AC — a closed laptop lid would
        // otherwise sleep the machine regardless of the idle timeout. Best-effort;
        // needs elevation, so a non-admin enroll silently leaves these as-is and
        // relies on the runtime wake lock instead.
        let _ = pc(&["/change", "hibernate-timeout-ac", "0"]);
        let _ = pc(&["/setacvalueindex", "SCHEME_CURRENT", "SUB_BUTTONS", "LIDACTION", "0"]);
        let _ = pc(&["/setactive", "SCHEME_CURRENT"]);
    }
    #[cfg(target_os = "macos")]
    {
        if let Some(mins) = pmset_ac_sleep() {
            let _ = std::fs::write(sleep_prior_file(), mins.to_string());
        }
        let _ = std::process::Command::new("pmset").args(["-c", "sleep", "0"]).status();
    }
}

pub fn restore_sleep() {
    let prior = std::fs::read_to_string(sleep_prior_file()).ok();
    let _ = &prior;
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        // Default back to GNOME's out-of-the-box 'suspend' if we never saved one.
        let v = prior.as_deref().map(str::trim).filter(|s| !s.is_empty()).unwrap_or("suspend");
        gsettings_set("sleep-inactive-ac-type", v);
    }
    #[cfg(windows)]
    {
        let mins = prior.and_then(|s| s.trim().parse::<u32>().ok()).unwrap_or(30);
        let _ = pc(&["/change", "standby-timeout-ac", &mins.to_string()]);
    }
    #[cfg(target_os = "macos")]
    {
        let mins = prior.and_then(|s| s.trim().parse::<u32>().ok()).unwrap_or(10);
        let _ = std::process::Command::new("pmset").args(["-c", "sleep", &mins.to_string()]).status();
    }
    let _ = std::fs::remove_file(sleep_prior_file());
}

#[cfg(all(unix, not(target_os = "macos")))]
const GNOME_POWER: &str = "org.gnome.settings-daemon.plugins.power";

#[cfg(all(unix, not(target_os = "macos")))]
fn gsettings_get(key: &str) -> Option<String> {
    let out = std::process::Command::new("gsettings").args(["get", GNOME_POWER, key]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    // gsettings prints e.g. 'suspend' (with quotes) — strip them.
    Some(String::from_utf8_lossy(&out.stdout).trim().trim_matches('\'').to_string())
}

#[cfg(all(unix, not(target_os = "macos")))]
fn gsettings_set(key: &str, val: &str) {
    let _ = std::process::Command::new("gsettings").args(["set", GNOME_POWER, key, val]).status();
}

#[cfg(windows)]
fn pc(args: &[&str]) -> std::io::Result<std::process::ExitStatus> {
    use std::os::windows::process::CommandExt;
    std::process::Command::new("powercfg").args(args).creation_flags(0x0800_0000).status()
}

/// Current AC standby timeout in minutes (from the active scheme), if readable.
#[cfg(windows)]
fn powercfg_ac_standby() -> Option<u32> {
    use std::os::windows::process::CommandExt;
    let out = std::process::Command::new("powercfg")
        .args(["/query", "SCHEME_CURRENT", "SUB_SLEEP", "STANDBYIDLE"])
        .creation_flags(0x0800_0000)
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    // "Current AC Power Setting Index: 0x0000012c" → seconds → minutes.
    for line in text.lines() {
        let l = line.trim();
        if l.starts_with("Current AC Power Setting Index:") {
            let hex = l.rsplit(':').next()?.trim().trim_start_matches("0x");
            let secs = u32::from_str_radix(hex, 16).ok()?;
            return Some(secs / 60);
        }
    }
    None
}

/// Current AC "sleep" minutes from `pmset -g custom`, if readable.
#[cfg(target_os = "macos")]
fn pmset_ac_sleep() -> Option<u32> {
    let out = std::process::Command::new("pmset").args(["-g", "custom"]).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    // The AC block comes first ("AC Power:"), then a " sleep   N" line.
    let mut in_ac = false;
    for line in text.lines() {
        if line.contains("AC Power:") {
            in_ac = true;
        } else if line.contains("Battery Power:") {
            in_ac = false;
        } else if in_ac {
            let t = line.trim();
            if let Some(rest) = t.strip_prefix("sleep ") {
                return rest.trim().split_whitespace().next()?.parse().ok();
            }
        }
    }
    None
}
