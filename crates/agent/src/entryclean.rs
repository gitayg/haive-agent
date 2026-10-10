// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

//! Remove the enrollment token from this agent's OWN autostart/service entry.
//!
//! Since 3.7.0 new entries carry no `--relay-token` (the agent holds its device
//! secret in `relay.cred`), but an entry an older agent wrote still does, and a
//! self-update never rewrites it. At startup, once the agent holds a device secret
//! for this hub, each of our entries that still carries the token is rewritten
//! without it, ONLY when the rewritten entry provably finds the same `relay.cred`:
//! the HOME it will run with is worked out from the entry itself (`entrytoken`)
//! and its `relay.cred` must be the very file the secret was loaded from. If not,
//! HOME is pinned in the entry where that is safe and representable, or the entry
//! is left alone with a log line.
//!
//! Write-only: an entry is written (files atomically, keeping mode and owner,
//! never through a symlink and only where no one else can write: `securefs`) and
//! nothing is started, stopped or loaded. The one exception is `systemctl
//! daemon-reload` after a unit is rewritten, which only re-reads unit files.

use std::path::{Path, PathBuf};

use crate::entrytoken::{self as et, EntryHome};
use crate::relaycred;

#[derive(Debug, PartialEq)]
pub(crate) enum Plan {
    /// The entry as it is already finds the credential: just drop the token.
    Strip,
    /// Drop the token and pin HOME to this directory.
    Pin(PathBuf),
}

/// `<home>` of a `<home>/.it-ai/relay.cred` path.
pub(crate) fn cred_home(loaded: &Path) -> Option<PathBuf> {
    let dir = loaded.parent()?;
    if loaded.file_name()? != "relay.cred" || dir.file_name()? != ".it-ai" {
        return None;
    }
    dir.parent().map(Path::to_path_buf)
}

/// The safety rule. `same(a, b)`: are these the same file.
pub(crate) fn decide(home: &EntryHome, loaded: &Path, pinnable: bool, same: &dyn Fn(&Path, &Path) -> bool) -> Result<Plan, String> {
    let pin = |why: String| match (pinnable, cred_home(loaded)) {
        (true, Some(h)) => Ok(Plan::Pin(h)),
        _ => Err(why),
    };
    match home {
        EntryHome::Pinned(h) if same(&relaycred::path_in(h), loaded) => Ok(Plan::Strip),
        EntryHome::Pinned(h) => Err(format!("it pins HOME={} but the credential is {}", h.display(), loaded.display())),
        EntryHome::Default(h) if same(&relaycred::path_in(h), loaded) => Ok(Plan::Strip),
        EntryHome::Default(h) => pin(format!(
            "it would look for {} but the credential is {}, and HOME cannot be pinned in it",
            relaycred::path_in(h).display(),
            loaded.display()
        )),
        EntryHome::Unknown => pin("the HOME it runs with is not known, and cannot be pinned in it".into()),
    }
}

/// Each OS constructs only its own two kinds.
#[allow(dead_code)]
#[derive(Debug, PartialEq, Clone, Copy)]
pub(crate) enum Kind {
    Desktop,
    Unit,
    AgentPlist,
    DaemonPlist,
}

#[cfg_attr(windows, allow(dead_code))]
pub(crate) fn file_has_token(kind: Kind, text: &str) -> bool {
    file_strip(kind, text).is_some()
}

#[cfg_attr(windows, allow(dead_code))]
fn file_strip(kind: Kind, text: &str) -> Option<String> {
    match kind {
        Kind::Desktop => et::desktop_strip(text),
        Kind::Unit => et::unit_strip(text),
        Kind::AgentPlist | Kind::DaemonPlist => et::plist_is_ours(text).then(|| et::plist_strip(text))?,
    }
}

/// The HOME the entry at `path` runs with. A per-user entry lives under the home
/// of the user it runs as: `<home>/.config/autostart/it-ai.desktop`,
/// `<home>/Library/LaunchAgents/com.itai.agent.plist`.
#[cfg_attr(windows, allow(dead_code))]
pub(crate) fn entry_home(kind: Kind, text: &str, path: &Path) -> Result<EntryHome, String> {
    let up3 = || path.parent().and_then(Path::parent).and_then(Path::parent).map(Path::to_path_buf);
    match kind {
        Kind::Desktop => up3().map(EntryHome::Default).ok_or_else(|| "no home above the entry".into()),
        Kind::Unit => et::unit_home(text),
        Kind::AgentPlist => Ok(match et::plist_home(text)? {
            Some(h) => EntryHome::Pinned(h),
            None => up3().map(EntryHome::Default).unwrap_or(EntryHome::Unknown),
        }),
        Kind::DaemonPlist => Ok(et::plist_home(text)?.map(EntryHome::Pinned).unwrap_or(EntryHome::Unknown)),
    }
}

#[cfg_attr(windows, allow(dead_code))]
fn file_pin(kind: Kind, text: &str, home: &Path) -> Option<String> {
    match kind {
        Kind::Desktop => None,
        Kind::Unit => et::unit_pin_home(text, home),
        Kind::AgentPlist | Kind::DaemonPlist => et::plist_pin_home(text, home),
    }
}

/// The rewritten file entry and the HOME it pins, Ok(None) when it carries no
/// token (or is not ours), Err(why) when it must be left alone. `pin_to` turns
/// the credential's home into the home to pin, or refuses (`pin_target`). Whatever comes
/// back is checked by reading the new text again: no token, and its HOME finds
/// the loaded credential.
#[cfg_attr(windows, allow(dead_code))]
pub(crate) fn plan_file(
    kind: Kind,
    text: &str,
    path: &Path,
    loaded: &Path,
    pinnable: bool,
    same: &dyn Fn(&Path, &Path) -> bool,
    pin_to: &dyn Fn(&Path) -> Result<PathBuf, String>,
) -> Result<Option<(String, Option<PathBuf>)>, String> {
    let Some(stripped) = file_strip(kind, text) else { return Ok(None) };
    let (new, pinned) = match decide(&entry_home(kind, text, path)?, loaded, pinnable, same)? {
        Plan::Strip => (stripped, None),
        Plan::Pin(h) => {
            let h = pin_to(&h)?;
            (file_pin(kind, &stripped, &h).ok_or_else(|| format!("HOME={} cannot be written into it", h.display()))?, Some(h))
        }
    };
    if file_has_token(kind, &new) {
        return Err("the token survived the rewrite".into());
    }
    match entry_home(kind, &new, path)? {
        EntryHome::Pinned(h) | EntryHome::Default(h) if same(&relaycred::path_in(&h), loaded) => Ok(Some((new, pinned))),
        other => Err(format!("the rewritten entry would not find the credential ({other:?})")),
    }
}

/// A command-line entry (Windows Run value, scheduled task arguments), where HOME
/// cannot be pinned: rewritten only when it already finds the credential.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn plan_cmdline(
    cmd: &str,
    home: &EntryHome,
    loaded: &Path,
    same: &dyn Fn(&Path, &Path) -> bool,
) -> Result<Option<String>, String> {
    let Some(new) = et::strip_cmdline(cmd, false) else { return Ok(None) };
    match decide(home, loaded, false, same)? {
        Plan::Strip => Ok(Some(new)),
        Plan::Pin(_) => Err("HOME cannot be pinned in a command line".into()),
    }
}

/// Same file on disk (both must exist).
pub(crate) fn same_file(a: &Path, b: &Path) -> bool {
    matches!((std::fs::canonicalize(a), std::fs::canonicalize(b)), (Ok(x), Ok(y)) if x == y)
}

/// Whether `loaded` holds a device secret for `hub` right now.
fn holds_device(hub: &str, loaded: &Path) -> bool {
    let hub = relaycred::normalize_hub(hub);
    relaycred::load(loaded).is_some_and(|c| c.hub == hub && c.device.as_deref().is_some_and(|d| !d.is_empty()))
}

const LEFT_FOR_LATER: &str = "left as is until this device holds its own secret";

/// Run at startup in relay mode. `loaded`: the `relay.cred` the credential came
/// from; `is_device`: whether it is a device secret. Returns whether any of our
/// entries still carries the token afterwards (hello sysinfo `autostart_token`).
pub(crate) fn run(hub: &str, loaded: &Path, is_device: bool) -> bool {
    let ready = is_device && holds_device(hub, loaded);
    let mut still = false;
    #[cfg(unix)]
    for (kind, path, pinnable) in unix::entries() {
        still |= unix::clean(kind, &path, loaded, pinnable, ready);
    }
    #[cfg(windows)]
    {
        still |= win::clean_run_value(loaded, ready);
        still |= win::clean_task(loaded, ready);
    }
    let _ = (loaded, ready);
    still
}

#[cfg(unix)]
pub(crate) mod securefs;

/// The home to pin into an entry whose own HOME would miss the credential kept
/// in `cred_home`: the service account's passwd home when the credential is found
/// there, else `cred_home` itself. Either way only a directory, and its `.it-ai`,
/// that no one but root or this agent (or its private group) can change, checked from `/` down
/// (`securefs::check_trusted_dir`): a root service pinned to a directory a user
/// can write would load a credential, certs, jobs and schedules that user
/// planted. Otherwise the entry is left alone. Credentials are never moved or
/// copied.
#[cfg(unix)]
pub(crate) fn pin_target(
    cred_home: &Path,
    loaded: &Path,
    service_home: &Path,
    euid: u32,
    same: &dyn Fn(&Path, &Path) -> bool,
) -> Result<PathBuf, String> {
    let h = if same(&relaycred::path_in(service_home), loaded) { service_home.to_path_buf() } else { cred_home.to_path_buf() };
    for d in [h.clone(), h.join(".it-ai")] {
        securefs::check_trusted_dir(&d, euid, &securefs::SysGroups).map_err(|why| format!("HOME={} is not safe to pin: {why}", h.display()))?;
    }
    Ok(h)
}

#[cfg(unix)]
pub(crate) mod unix {
    use super::securefs;
    use super::*;

    fn abs(p: PathBuf) -> PathBuf {
        std::path::absolute(&p).unwrap_or(p)
    }

    /// Our entries on this OS, with whether HOME may be pinned in each: in a
    /// per-user entry always (it runs as us), in a root service only when we are
    /// root (only root may say where root's agent looks).
    pub(super) fn entries() -> Vec<(Kind, PathBuf, bool)> {
        let root = securefs::euid() == 0;
        let mut v = Vec::new();
        #[cfg(target_os = "macos")]
        {
            v.push((Kind::AgentPlist, abs(crate::persistence::plist_path()), true));
            v.push((Kind::DaemonPlist, crate::persistence::daemon_path(), root));
        }
        #[cfg(not(target_os = "macos"))]
        {
            v.push((Kind::Desktop, abs(crate::persistence::desktop_path()), false));
            v.push((Kind::Unit, crate::persistence::unit_path(), root));
        }
        v
    }

    /// Read the entry without following symlinks (`securefs::open`), and rewrite it
    /// only when it carries the token, this device holds its secret, this process
    /// may replace it (`Entry::check`) and the safety rule allows it (`plan_file`).
    pub(super) fn clean(kind: Kind, path: &Path, loaded: &Path, pinnable: bool, ready: bool) -> bool {
        let left = |why: &str| {
            eprintln!("autostart: {} still carries the enrollment token — {why}", path.display());
            true
        };
        let entry = match securefs::open(path) {
            Ok(Some(e)) => e,
            Ok(None) => return false,
            Err(why) => {
                // Not read, so whether it carries the token is unknown: say so, and
                // report it as still carrying it.
                eprintln!("autostart: {} was not inspected — {why}", path.display());
                return true;
            }
        };
        if !file_has_token(kind, &entry.text) {
            return false;
        }
        if !ready {
            return left(LEFT_FOR_LATER);
        }
        if let Err(why) = entry.check(securefs::euid(), &securefs::SysGroups) {
            return left(&format!("left as is: {why}"));
        }
        let pin_to = |h: &Path| pin_target(h, loaded, &crate::persistence::service_home(), securefs::euid(), &same_file);
        let (new, pinned) = match plan_file(kind, &entry.text, path, loaded, pinnable, &same_file, &pin_to) {
            Ok(Some(p)) => p,
            Ok(None) => return false,
            Err(why) => return left(&format!("left as is: {why}")),
        };
        if let Err(e) = entry.replace(&new) {
            return left(&format!("could not rewrite it: {e}"));
        }
        let pin = pinned.map(|h| format!(", HOME pinned to {}", h.display())).unwrap_or_default();
        let reload = if kind == Kind::Unit {
            match std::process::Command::new("systemctl").arg("daemon-reload").status() {
                Ok(s) if s.success() => "; systemd reloaded".to_string(),
                Ok(s) => format!("; systemctl daemon-reload failed ({s})"),
                Err(e) => format!("; systemctl daemon-reload failed ({e})"),
            }
        } else {
            String::new()
        };
        println!(
            "autostart: removed the enrollment token from {}{pin}; it uses {}{reload}",
            path.display(),
            loaded.display()
        );
        false
    }
}

#[cfg(windows)]
mod win {
    use super::*;
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};

    const NO_WINDOW: u32 = 0x0800_0000;
    const RUN: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

    fn tool(exe: &str, args: &[&str]) -> Option<(bool, String)> {
        let o = Command::new(exe).args(args).creation_flags(NO_WINDOW).stdin(Stdio::null()).output().ok()?;
        let mut text = et::decode_output(&o.stdout);
        if !o.status.success() {
            text.push_str(&et::decode_output(&o.stderr));
        }
        Some((o.status.success(), text))
    }

    /// The home a Run-key or scheduled-task launch of THIS user runs with: the
    /// agent's `home()` is HOME, else USERPROFILE. Such a launch gets the user's
    /// registered environment, so HOME is the one in HKCU\Environment (or the
    /// machine's), not whatever this process inherited; USERPROFILE is the user's
    /// profile, the same for every process of the user.
    fn user_home() -> EntryHome {
        use winreg::enums::*;
        use winreg::RegKey;
        let reg_home = [
            (HKEY_CURRENT_USER, r"Environment"),
            (HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"),
        ]
        .iter()
        .find_map(|(root, sub)| RegKey::predef(*root).open_subkey(sub).and_then(|k| k.get_value::<String, _>("HOME")).ok());
        match reg_home {
            Some(h) if h.contains('%') || h.is_empty() => EntryHome::Unknown,
            Some(h) => EntryHome::Default(h.into()),
            None => std::env::var("USERPROFILE").map(|p| EntryHome::Default(p.into())).unwrap_or(EntryHome::Unknown),
        }
    }

    pub(super) fn clean_run_value(loaded: &Path, ready: bool) -> bool {
        use winreg::enums::*;
        use winreg::RegKey;
        let Ok(key) = RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(RUN, KEY_QUERY_VALUE | KEY_SET_VALUE) else {
            return false;
        };
        let Ok(cmd) = key.get_value::<String, _>("IT-AI") else { return false };
        if et::strip_cmdline(&cmd, false).is_none() {
            return false;
        }
        let left = |why: &str| {
            eprintln!("autostart: the Run value IT-AI still carries the enrollment token — {why}");
            true
        };
        if !ready {
            return left(LEFT_FOR_LATER);
        }
        match plan_cmdline(&cmd, &user_home(), loaded, &same_file) {
            Ok(Some(new)) => match key.set_value("IT-AI", &new) {
                Ok(()) => {
                    println!("autostart: removed the enrollment token from the Run value IT-AI; it uses {}", loaded.display());
                    false
                }
                Err(e) => left(&format!("could not rewrite it: {e}")),
            },
            Ok(None) => false,
            Err(why) => left(&format!("left as is: {why}")),
        }
    }

    fn query_task() -> Option<et::TaskXml> {
        match tool("schtasks", &["/Query", "/TN", "IT-AI", "/XML"])? {
            (true, xml) => et::parse_task_xml(&xml),
            _ => None,
        }
    }

    pub(super) fn clean_task(loaded: &Path, ready: bool) -> bool {
        let Some(task) = query_task() else { return false };
        let Some(args) = et::strip_cmdline(&task.arguments, false) else { return false };
        let left = |why: &str| {
            eprintln!("autostart: the scheduled task IT-AI still carries the enrollment token — {why}");
            true
        };
        if !ready {
            return left(LEFT_FOR_LATER);
        }
        // /Change keeps the principal and run level when /RU, /RP and /RL are not
        // given. Only an InteractiveToken task stores no password, so only then can
        // it be changed without one.
        if task.logon_type.as_deref() != Some("InteractiveToken") {
            return left(&format!("left as is: it logs on as {:?}, and changing it may need a password", task.logon_type));
        }
        let Some((name, sid)) = tool("whoami", &["/user", "/fo", "csv", "/nh"]).and_then(|(_, o)| et::parse_whoami(&o)) else {
            return left("left as is: could not tell who this process runs as");
        };
        if !task.user_id.as_deref().is_some_and(|u| et::user_matches(u, &name, &sid)) {
            return left(&format!("left as is: it runs as {:?}, not as this user ({name})", task.user_id));
        }
        match plan_cmdline(&task.arguments, &user_home(), loaded, &same_file) {
            Ok(Some(_)) => {}
            Ok(None) => return false,
            Err(why) => return left(&format!("left as is: {why}")),
        }
        let tr = et::task_tr(&task.command, &args);
        match tool("schtasks", &["/Change", "/TN", "IT-AI", "/TR", &tr]) {
            Some((true, _)) => {}
            Some((false, out)) => return left(&format!("schtasks /Change failed: {}", out.trim())),
            None => return left("could not run schtasks"),
        }
        match query_task() {
            Some(t) if et::strip_cmdline(&t.arguments, false).is_none() && t.logon_type == task.logon_type => {
                println!("autostart: removed the enrollment token from the scheduled task IT-AI; it uses {}", loaded.display());
                false
            }
            other => left(&format!("schtasks /Change ran, but the task now reads {other:?}")),
        }
    }
}

#[cfg(test)]
mod tests;
