// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

// Standard, visible autostart per OS. Nothing hidden; uninstall removes it.
use std::env;
#[allow(unused_imports)]
use std::path::{Path, PathBuf};

pub fn install(args: &[String], cli: bool) {
    crate::prepare_persist_cred(&PathBuf::from(home()), cli);
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
    let svc_home = service_home();
    crate::prepare_persist_cred(&svc_home, true);
    let exe = env::current_exe().unwrap_or_default();
    #[cfg(windows)]
    win_install_service(&exe, args);
    #[cfg(target_os = "macos")]
    mac_install_service(&exe, args, &svc_home);
    #[cfg(all(unix, not(target_os = "macos")))]
    linux_install_service(&exe, args, &svc_home);
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
        .args(["/Query", "/TN", "IT-AI"])
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
        .and_then(|k| k.get_value::<String, _>("IT-AI"))
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

pub(crate) fn home() -> String {
    env::var("HOME")
        .or_else(|_| env::var("USERPROFILE"))
        .unwrap_or_default()
}

/// The home a boot/logon SERVICE runs with, which is also where its relay.cred
/// goes. A root service may start with no HOME at all (systemd without `User=`)
/// or a different one from the `sudo` that installed it, so on unix this is the
/// passwd entry of the effective uid; the inherited HOME is only a fallback if
/// that lookup fails. Windows: schtasks runs as the installing user — `home()`.
pub(crate) fn service_home() -> PathBuf {
    #[cfg(unix)]
    {
        let inherited = env::var("HOME").ok();
        let pw = passwd_home(unsafe { libc::geteuid() });
        if pw.is_none() {
            eprintln!("warn: no passwd entry for this uid — using the inherited HOME for the service");
        }
        pick_service_home(inherited.as_deref(), pw)
    }
    #[cfg(not(unix))]
    {
        PathBuf::from(home())
    }
}

#[cfg(unix)]
fn pick_service_home(inherited: Option<&str>, passwd: Option<PathBuf>) -> PathBuf {
    passwd.unwrap_or_else(|| PathBuf::from(inherited.unwrap_or_default()))
}

#[cfg(unix)]
fn passwd_home(uid: libc::uid_t) -> Option<PathBuf> {
    // SAFETY: getpwuid returns a pointer into static storage (or null); we copy
    // pw_dir out before any other passwd call can overwrite it.
    unsafe {
        let pw = libc::getpwuid(uid);
        if pw.is_null() || (*pw).pw_dir.is_null() {
            return None;
        }
        let dir = std::ffi::CStr::from_ptr((*pw).pw_dir).to_string_lossy().into_owned();
        (!dir.is_empty()).then(|| PathBuf::from(dir))
    }
}

// ---- macOS: LaunchAgent ----
#[cfg(target_os = "macos")]
fn plist_path() -> PathBuf {
    PathBuf::from(home()).join("Library/LaunchAgents/com.itai.agent.plist")
}

#[cfg(target_os = "macos")]
fn mac_install(exe: &Path, args: &[String]) {
    let mut pa = format!("      <string>{}</string>\n", exe.display());
    for a in args {
        pa.push_str(&format!("      <string>{a}</string>\n"));
    }
    let plist = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n  <key>Label</key><string>com.itai.agent</string>\n  <key>ProgramArguments</key><array>\n{pa}  </array>\n  <key>RunAtLoad</key><true/>\n  <key>KeepAlive</key><true/>\n</dict></plist>\n"
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
    PathBuf::from(home()).join(".config/autostart/it-ai.desktop")
}

#[cfg(all(unix, not(target_os = "macos")))]
fn linux_install(exe: &Path, args: &[String]) {
    let mut ex = format!("{}", exe.display());
    for a in args {
        ex.push(' ');
        ex.push_str(a);
    }
    let entry = format!(
        "[Desktop Entry]\nType=Application\nName=IT-AI\nExec={ex}\nX-GNOME-Autostart-enabled=true\n"
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
        // Re-add --background for the login launch. The Run key starts a
        // console-subsystem binary directly, so without this Windows pops a visible
        // console window on every login. With it, the launched process immediately
        // re-spawns itself DETACHED_PROCESS and exits, so no console ever appears.
        // (persist_args strips --background because on macOS/Linux the autostart
        // launch is already windowless; only Windows needs it back.)
        cmd.push_str(" \"--background\"");
        let _ = key.set_value("IT-AI", &cmd);
        // Migration: installs predating the IT-AI rebrand left a Run key named
        // "HaiveControl" (pointing at the old airm-*.exe). Remove it so a machine
        // re-enrolled across the rename doesn't launch TWO agents at every login.
        let _ = key.delete_value("HaiveControl");
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
        let _ = key.delete_value("IT-AI");
        let _ = key.delete_value("HaiveControl"); // legacy name (pre-rebrand)
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
    // Same reason as the Run key above: a console-subsystem binary launched by the
    // task shows a console window at logon. --background makes it re-spawn itself
    // DETACHED_PROCESS and exit, so the task completes and no window appears.
    tr.push_str(" --background");
    let _ = std::process::Command::new("schtasks")
        .args(["/Create", "/TN", "IT-AI", "/TR", &tr, "/SC", "ONLOGON", "/RL", "HIGHEST", "/F"])
        .status();
    // Start it now so the agent runs immediately (elevated, in the current user
    // session), not only after the next logon. Best-effort.
    let _ = std::process::Command::new("schtasks")
        .args(["/Run", "/TN", "IT-AI"])
        .status();
}

#[cfg(windows)]
fn win_service_uninstall() {
    let _ = std::process::Command::new("schtasks")
        .args(["/Delete", "/TN", "IT-AI", "/F"])
        .status();
}

// ---- macOS: LaunchDaemon (starts at boot, root) ----
#[cfg(target_os = "macos")]
fn daemon_path() -> PathBuf {
    PathBuf::from("/Library/LaunchDaemons/com.itai.agent.plist")
}

/// The LaunchDaemon plist, with HOME pinned to the service home (see `service_home`).
#[cfg(any(target_os = "macos", test))]
fn daemon_plist(exe: &Path, args: &[String], home: &Path) -> String {
    let mut pa = format!("      <string>{}</string>\n", exe.display());
    for a in args {
        pa.push_str(&format!("      <string>{a}</string>\n"));
    }
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n  <key>Label</key><string>com.itai.agent</string>\n  <key>ProgramArguments</key><array>\n{pa}  </array>\n  <key>RunAtLoad</key><true/>\n  <key>KeepAlive</key><true/>\n  <key>EnvironmentVariables</key><dict>\n    <key>HOME</key><string>{}</string>\n  </dict>\n</dict></plist>\n",
        home.display()
    )
}

#[cfg(target_os = "macos")]
fn mac_install_service(exe: &Path, args: &[String], home: &Path) {
    let plist = daemon_plist(exe, args, home);
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
    PathBuf::from("/etc/systemd/system/it-ai.service")
}

/// The systemd unit, with HOME pinned to the service home (see `service_home`).
#[cfg(any(all(unix, not(target_os = "macos")), test))]
fn service_unit(exe: &Path, args: &[String], home: &Path) -> String {
    let mut ex = format!("{}", exe.display());
    for a in args {
        ex.push(' ');
        ex.push_str(a);
    }
    // Quoted only when needed: systemd splits an unquoted Environment= on spaces.
    let home = home.display().to_string();
    let env = if home.contains(char::is_whitespace) { format!("\"HOME={home}\"") } else { format!("HOME={home}") };
    format!(
        "[Unit]\nDescription=IT-AI agent\nAfter=network.target\n\n[Service]\nEnvironment={env}\nExecStart={ex}\nRestart=always\nRestartSec=5\n\n[Install]\nWantedBy=multi-user.target\n"
    )
}

#[cfg(all(unix, not(target_os = "macos")))]
fn linux_install_service(exe: &Path, args: &[String], home: &Path) {
    let unit = service_unit(exe, args, home);
    let _ = std::fs::write(unit_path(), unit);
    let _ = std::process::Command::new("systemctl").arg("daemon-reload").status();
    let _ = std::process::Command::new("systemctl").args(["enable", "--now", "it-ai.service"]).status();
}

#[cfg(all(unix, not(target_os = "macos")))]
fn linux_service_uninstall() {
    let _ = std::process::Command::new("systemctl").args(["disable", "--now", "it-ai.service"]).status();
    let _ = std::fs::remove_file(unit_path());
}

// ---- AC keep-awake ----------------------------------------------------------
// A managed device should stay reachable, so on install we stop it sleeping while
// on AC power (battery is left alone), saving the prior setting so dissolve can
// restore it. Best-effort + per-OS; each needs the relevant privilege (GNOME
// gsettings is per-user; Windows powercfg / macOS pmset generally want elevation).

fn sleep_prior_file() -> PathBuf {
    PathBuf::from(home()).join(".it-ai").join("sleep_prior")
}

pub fn keep_awake_on_ac() {
    let _ = std::fs::create_dir_all(PathBuf::from(home()).join(".it-ai"));
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

#[cfg(test)]
mod service_home_tests {
    use super::*;

    fn args() -> Vec<String> {
        vec!["--relay".into(), "https://hub.example".into()]
    }

    #[test]
    fn systemd_unit_pins_home() {
        let u = service_unit(Path::new("/usr/local/bin/it-ai"), &args(), Path::new("/root"));
        assert!(u.lines().any(|l| l == "Environment=HOME=/root"), "unit has no pinned HOME:\n{u}");
        assert!(u.contains("ExecStart=/usr/local/bin/it-ai --relay https://hub.example\n"));
    }

    #[test]
    fn launchdaemon_plist_pins_home() {
        let p = daemon_plist(Path::new("/usr/local/bin/it-ai"), &args(), Path::new("/var/root"));
        let compact: String = p.split_whitespace().collect();
        assert!(
            compact.contains("<key>EnvironmentVariables</key><dict><key>HOME</key><string>/var/root</string></dict>"),
            "plist has no pinned HOME:\n{p}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn service_home_ignores_an_inherited_home() {
        let real = PathBuf::from("/var/root");
        assert_eq!(pick_service_home(Some("/home/sudo-user"), Some(real.clone())), real);
        assert_eq!(pick_service_home(None, Some(real.clone())), real);
        // Lookup failure is the only time the inherited HOME is used.
        assert_eq!(pick_service_home(Some("/fallback"), None), PathBuf::from("/fallback"));
        // And the real lookup works for this uid.
        let me = passwd_home(unsafe { libc::geteuid() }).expect("passwd entry for the test uid");
        assert!(me.is_absolute(), "{me:?}");
        // The real entry point agrees, whatever HOME this process inherited.
        assert_eq!(service_home(), me, "inherited HOME={:?}", env::var("HOME"));
    }
}
