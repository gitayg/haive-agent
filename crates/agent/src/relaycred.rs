// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

// The relay credential: which token every `/relay/*` call carries, and the
// private file that keeps it across restarts (docs/DEVICE-SECRETS.md, "Agent").
//
// The enrollment token (`htok_…`) is used once, to enroll; the hub then issues
// this device its own secret (`hdev_…`). Every relay caller reads the token from
// ONE shared `RelayCred`, so when the secret arrives mid-run the switch reaches
// hello/poll/reply, config, analysis and the AI relay at once.
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, RwLock};

use serde::{Deserialize, Serialize};

pub const ENV_TOKEN: &str = "HIVE_RELAY_TOKEN";
pub const FLAG: &str = "--relay-token";

/// `~/.it-ai/relay.cred`: `{hub, enroll?, device?}`.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CredFile {
    pub hub: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enroll: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
}

/// Absolute: with no HOME (a systemd service without `User=`) `home()` is empty
/// and the file is relative to the working directory, so resolve it once here and
/// `RelayCred::file` names the file actually used.
pub fn default_path() -> PathBuf {
    let p = path_in(Path::new(&crate::persistence::home()));
    std::path::absolute(&p).unwrap_or(p)
}

pub fn path_in(home: &Path) -> PathBuf {
    home.join(".it-ai").join("relay.cred")
}

/// Accept `http://host:port`, `host:port`, or a bare host (→ http://host). The
/// cred file's `hub` is compared against `--relay` in this form.
pub fn normalize_hub(hub: &str) -> String {
    let h = hub.trim_end_matches('/');
    if h.starts_with("http://") || h.starts_with("https://") {
        h.to_string()
    } else {
        format!("http://{h}")
    }
}

pub fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// `id=<rid>` plus `&tok=<t>` when there is a token — the query every relay URL carries.
pub fn auth_query(relay_id: &str, token: &str) -> String {
    let mut q = format!("id={}", urlencode(relay_id));
    if !token.is_empty() {
        q.push_str(&format!("&tok={}", urlencode(token)));
    }
    q
}

pub fn load(path: &Path) -> Option<CredFile> {
    let meta = std::fs::metadata(path).ok()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            // Readable beyond its owner: tighten and say so, as the hub's
            // secretfile does — the exposure already happened, refusing would
            // only add an outage to it.
            if std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).is_ok() {
                eprintln!(
                    "SECURITY: {} was mode {mode:04o} and has been tightened to 0600; treat its tokens as exposed.",
                    path.display()
                );
            } else {
                eprintln!("SECURITY: {} is mode {mode:04o} and could not be tightened — ignoring it.", path.display());
                return None;
            }
        }
    }
    let _ = meta;
    serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()
}

/// Write the cred file owner-only (0600) inside an owner-only (0700) directory.
/// On Windows there is no mode: the file inherits the ACL of the user profile.
pub fn save(path: &Path, cred: &CredFile) -> io::Result<()> {
    use std::io::Write;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    let body = serde_json::to_string(cred).map_err(io::Error::other)?;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(body.as_bytes())?;
    f.sync_all()?;
    // `.mode()` only applies when open(2) creates the file; an existing one
    // keeps its old mode, so set it explicitly.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// The token a relay call uses at startup.
#[derive(Debug, PartialEq)]
pub struct Resolved {
    pub token: String,
    pub is_device: bool,
    /// The enrollment token supplied on THIS start (flag or env) — the only one
    /// a rejected device secret may fall back to.
    pub supplied_enroll: Option<String>,
}

/// Contract order: (1) the cred file's `device`, if its `hub` is this hub;
/// (2) `--relay-token`, then `HIVE_RELAY_TOKEN`, then the cred file's `enroll`.
/// A cred file for a different hub is ignored entirely. None → no token at all.
pub fn resolve(hub: &str, flag: Option<&str>, env: Option<&str>, file: Option<&CredFile>) -> Option<Resolved> {
    let nonempty = |s: Option<&str>| s.filter(|t| !t.is_empty()).map(String::from);
    let hub = normalize_hub(hub);
    let file = file.filter(|c| c.hub == hub);
    let supplied_enroll = nonempty(flag).or_else(|| nonempty(env));
    if let Some(device) = file.and_then(|c| nonempty(c.device.as_deref())) {
        return Some(Resolved { token: device, is_device: true, supplied_enroll });
    }
    let enroll = supplied_enroll.clone().or_else(|| file.and_then(|c| nonempty(c.enroll.as_deref())))?;
    Some(Resolved { token: enroll, is_device: false, supplied_enroll })
}

/// Before an autostart/service entry (which no longer carries the token) is
/// written, store `{hub, enroll}` so the entry works after a reboot that comes
/// before the first hello. `reenroll` (an enrollment run from the command line:
/// `--persist` / `--install` with a token on this invocation) replaces a stored
/// device secret — that is how a revoked device re-enrolls. Otherwise (POST
/// /persist, the restart after a self-update) a device secret for this hub is
/// kept. Returns whether it wrote.
pub fn save_enroll_for_persist(path: &Path, hub: &str, enroll: Option<&str>, reenroll: bool) -> io::Result<bool> {
    let hub = normalize_hub(hub);
    let Some(enroll) = enroll.filter(|t| !t.is_empty()) else { return Ok(false) };
    let has_device = load(path).is_some_and(|c| c.hub == hub && c.device.as_deref().is_some_and(|d| !d.is_empty()));
    if has_device && !reenroll {
        return Ok(false);
    }
    save(path, &CredFile { hub, enroll: Some(enroll.to_string()), device: None })?;
    Ok(true)
}

/// Args minus the one-shot persistence/detach flags and BOTH forms of the relay
/// token (`--relay-token <v>`, `--relay-token=<v>`).
pub fn strip_persist_args<I: IntoIterator<Item = String>>(args: I) -> Vec<String> {
    let (rest, _) = split_token(args);
    rest.into_iter()
        .filter(|a| !matches!(a.as_str(), "--install" | "--persist" | "--background" | "--uninstall"))
        .collect()
}

/// Split the relay token out of an argv: (argv without it, its value). Used to
/// relaunch a child with the token in its environment instead of its argv.
pub fn split_token<I: IntoIterator<Item = String>>(args: I) -> (Vec<String>, Option<String>) {
    let mut out = Vec::new();
    let mut tok = None;
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        if a == FLAG {
            tok = it.next().or(tok);
        } else if let Some(v) = a.strip_prefix("--relay-token=") {
            tok = Some(v.to_string());
        } else {
            out.push(a);
        }
    }
    (out, tok)
}

/// A child process of this agent (detached relaunch, post-update restart): the
/// same args, with the token moved from argv to `HIVE_RELAY_TOKEN`.
pub fn child_command(exe: &Path, args: Vec<String>) -> std::process::Command {
    let (argv, tok) = split_token(args);
    let mut c = std::process::Command::new(exe);
    c.args(&argv);
    if let Some(t) = tok.filter(|t| !t.is_empty()) {
        c.env(ENV_TOKEN, t);
    }
    c
}

/// Set only on the process a self-update re-executes. It inherits `--persist`
/// and the enrollment token of the original start, but re-running its persist
/// step is not an enrollment and must not drop the device secret it holds.
pub const ENV_RESTART: &str = "IT_AI_SELF_RESTART";

/// `child_command`, marked as a self-update restart.
pub fn restart_command(exe: &Path, args: Vec<String>) -> std::process::Command {
    let mut c = child_command(exe, args);
    c.env(ENV_RESTART, "1");
    c
}

struct Current {
    token: String,
    is_device: bool,
}

/// The one shared relay credential. Clone the `Arc`, never the token.
pub struct RelayCred {
    hub: String,
    relay_id: String,
    file: PathBuf,
    current: RwLock<Current>,
    supplied_enroll: Option<String>,
    /// Fixed at startup and never re-derived: the loopback gate
    /// (`http::Config::direct_token`) holds this value for the whole run, so the
    /// token the relay presents to it must not follow the credential switch.
    direct_token: String,
    /// Serializes hellos, so two concurrent ones can't both mint a secret and
    /// leave us holding the one the hub already replaced.
    pub(crate) hello_lock: Mutex<()>,
}

impl RelayCred {
    pub fn new(hub: &str, relay_id: &str, file: PathBuf, r: Resolved) -> Self {
        let direct_token = crate::agent_direct_token(&r.token, relay_id);
        RelayCred {
            hub: normalize_hub(hub),
            relay_id: relay_id.to_string(),
            file,
            current: RwLock::new(Current { token: r.token, is_device: r.is_device }),
            supplied_enroll: r.supplied_enroll,
            direct_token,
            hello_lock: Mutex::new(()),
        }
    }

    pub fn token(&self) -> String {
        self.current.read().unwrap().token.clone()
    }

    pub fn is_device(&self) -> bool {
        self.current.read().unwrap().is_device
    }

    pub fn relay_id(&self) -> &str {
        &self.relay_id
    }

    pub fn direct_token(&self) -> &str {
        &self.direct_token
    }

    /// The `relay.cred` this credential was loaded from and is saved to.
    pub fn file(&self) -> &Path {
        &self.file
    }

    /// The hub issued `secret`: persist `{hub, device}` (dropping `enroll`) and
    /// switch every caller to it. The in-memory switch happens even if the write
    /// fails — the hub already holds the secret — and the error is returned.
    pub fn issued(&self, secret: &str) -> io::Result<()> {
        let saved = save(&self.file, &CredFile { hub: self.hub.clone(), enroll: None, device: Some(secret.to_string()) });
        *self.current.write().unwrap() = Current { token: secret.to_string(), is_device: true };
        saved
    }

    /// A call made with the device secret got 401. Falls back to the enrollment
    /// token supplied on this start, if any (returns true); otherwise keeps the
    /// secret and the caller retries slowly.
    pub fn rejected(&self) -> bool {
        match &self.supplied_enroll {
            Some(e) => {
                *self.current.write().unwrap() = Current { token: e.clone(), is_device: false };
                true
            }
            None => false,
        }
    }
}

/// `device_secret` from a hello reply, if this is a 200 that carries one.
pub fn parse_issued(status: u16, body: &str) -> Option<String> {
    if status != 200 {
        return None;
    }
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    v.get("device_secret")?.as_str().filter(|s| s.starts_with("hdev_") && s.len() > 5).map(String::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("it-ai-relaycred-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn persist_args_strip_both_token_forms_and_keep_the_rest() {
        let got = strip_persist_args(s(&[
            "--relay", "https://hub.example", "--relay-token", "htok_a", "--name", "box",
            "--relay-token=htok_b", "--persist", "--owner", "o1", "--background",
        ]));
        assert_eq!(got, s(&["--relay", "https://hub.example", "--name", "box", "--owner", "o1"]));
        assert!(!got.iter().any(|a| a.contains("htok_")));
    }

    #[test]
    fn resolution_follows_contract_order() {
        let hub = "https://hub.example/";
        let full = CredFile { hub: "https://hub.example".into(), enroll: Some("htok_file".into()), device: Some("hdev_file".into()) };
        let enroll_only = CredFile { device: None, ..full.clone() };
        // 1. device for this hub wins over everything, flag still kept for fallback
        let r = resolve(hub, Some("htok_flag"), Some("htok_env"), Some(&full)).unwrap();
        assert_eq!((r.token.as_str(), r.is_device), ("hdev_file", true));
        assert_eq!(r.supplied_enroll.as_deref(), Some("htok_flag"));
        // 2a. flag
        let r = resolve(hub, Some("htok_flag"), Some("htok_env"), Some(&enroll_only)).unwrap();
        assert_eq!((r.token.as_str(), r.is_device), ("htok_flag", false));
        // 2b. env
        let r = resolve(hub, None, Some("htok_env"), Some(&enroll_only)).unwrap();
        assert_eq!(r.token, "htok_env");
        // 2c. file enroll — not a "supplied" token
        let r = resolve(hub, Some(""), None, Some(&enroll_only)).unwrap();
        assert_eq!((r.token.as_str(), r.supplied_enroll), ("htok_file", None));
        // none
        assert_eq!(resolve(hub, None, None, None), None);
    }

    #[test]
    fn cred_for_a_different_hub_is_ignored() {
        let other = CredFile { hub: "https://other.example".into(), enroll: Some("htok_other".into()), device: Some("hdev_other".into()) };
        assert_eq!(resolve("https://hub.example", None, None, Some(&other)), None);
        let r = resolve("https://hub.example", None, Some("htok_env"), Some(&other)).unwrap();
        assert_eq!((r.token.as_str(), r.is_device), ("htok_env", false));
    }

    #[test]
    fn issuance_drops_enroll_and_writes_owner_only() {
        let dir = tmpdir("issue");
        let path = dir.join("relay.cred");
        assert!(save_enroll_for_persist(&path, "https://hub.example", Some("htok_e"), true).unwrap());
        assert_eq!(load(&path).unwrap().enroll.as_deref(), Some("htok_e"));
        let r = resolve("https://hub.example", None, None, load(&path).as_ref()).unwrap();
        let cred = RelayCred::new("https://hub.example", "hc-1", path.clone(), r);
        cred.issued("hdev_new").unwrap();
        // Mode first: `load` tightens a loose file, which would hide a bad write.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
            assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
        }
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("enroll"), "enroll survived issuance: {raw}");
        assert_eq!(load(&path).unwrap(), CredFile { hub: "https://hub.example".into(), enroll: None, device: Some("hdev_new".into()) });
        // A persist that is not an enrollment (POST /persist, the restart after a
        // self-update) keeps the device secret for this hub.
        assert!(!save_enroll_for_persist(&path, "https://hub.example", Some("htok_e2"), false).unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn explicit_enroll_replaces_a_stored_device_secret() {
        let dir = tmpdir("reenroll");
        let path = dir.join("relay.cred");
        let hub = "https://hub.example";
        let stored = CredFile { hub: hub.into(), enroll: None, device: Some("hdev_revoked".into()) };
        save(&path, &stored).unwrap();
        // No enrollment token on this invocation: the file is left alone.
        assert!(!save_enroll_for_persist(&path, hub, None, true).unwrap());
        assert_eq!(load(&path).unwrap(), stored);
        // One supplied on this invocation means re-enroll: {hub, enroll}, no device.
        assert!(save_enroll_for_persist(&path, hub, Some("htok_new"), true).unwrap());
        assert_eq!(load(&path).unwrap(), CredFile { hub: hub.into(), enroll: Some("htok_new".into()), device: None });
        // So the next start enrolls with it, and its hello mints a fresh secret.
        let r = resolve(hub, None, None, load(&path).as_ref()).unwrap();
        assert_eq!((r.token.as_str(), r.is_device), ("htok_new", false));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_self_update_restart_is_marked() {
        let c = restart_command(Path::new("/bin/it-ai"), s(&["--relay", "h", "--persist"]));
        assert!(c.get_envs().any(|(k, v)| k == ENV_RESTART && v.is_some()));
    }

    /// Set only in the child `exec_restart_keeps_stdout_and_stderr` spawns.
    #[cfg(unix)]
    const EXEC_PROBE: &str = "IT_AI_TEST_EXEC_PROBE";

    /// The child half: exec through `restart_command` exactly as `apply_update`
    /// does on unix. Does nothing in a normal test run.
    #[cfg(unix)]
    #[test]
    fn exec_probe_child() {
        use std::os::unix::process::CommandExt;
        if std::env::var_os(EXEC_PROBE).is_none() {
            return;
        }
        let args = s(&["-c", "echo exec-out; echo exec-err >&2"]);
        let e = restart_command(Path::new("/bin/sh"), args).exec();
        panic!("exec failed: {e}");
    }

    /// A unix self-update `exec`s the new binary, which keeps this process's
    /// stdout and stderr: whatever they pointed at (agent.log for a --background
    /// start, launchd's StandardOutPath, the journal) the new agent writes there.
    #[cfg(unix)]
    #[test]
    fn exec_restart_keeps_stdout_and_stderr() {
        let dir = tmpdir("exec");
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("agent.log");
        let open = || std::fs::OpenOptions::new().create(true).append(true).open(&log).unwrap();
        let st = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["relaycred::tests::exec_probe_child", "--exact", "--nocapture", "--test-threads=1"])
            .env(EXEC_PROBE, "1")
            .stdout(open())
            .stderr(open())
            .status()
            .unwrap();
        assert!(st.success(), "{st}");
        let text = std::fs::read_to_string(&log).unwrap();
        assert!(text.contains("exec-out\n") && text.contains("exec-err\n"), "{text}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn switch_is_seen_by_a_second_reader_and_direct_token_is_stable() {
        let dir = tmpdir("switch");
        let r = Resolved { token: "htok_e".into(), is_device: false, supplied_enroll: Some("htok_e".into()) };
        let cred = Arc::new(RelayCred::new("https://hub.example", "hc-1", dir.join("relay.cred"), r));
        let dtok = cred.direct_token().to_string();
        let reader = Arc::clone(&cred);
        let (go, wait) = std::sync::mpsc::channel::<()>();
        let t = std::thread::spawn(move || {
            wait.recv().unwrap();
            (reader.token(), reader.is_device(), reader.direct_token().to_string())
        });
        cred.issued("hdev_x").unwrap();
        go.send(()).unwrap();
        assert_eq!(t.join().unwrap(), ("hdev_x".to_string(), true, dtok.clone()));
        // Rejected → falls back to the enrollment token supplied on this start.
        assert!(cred.rejected());
        assert_eq!((cred.token(), cred.is_device()), ("htok_e".to_string(), false));
        assert_eq!(cred.direct_token(), dtok);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn child_gets_the_token_in_env_not_argv() {
        let c = child_command(Path::new("/bin/it-ai"), s(&["--relay", "h", "--relay-token", "htok_a", "--background"]));
        let argv: Vec<String> = c.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
        assert_eq!(argv, s(&["--relay", "h", "--background"]));
        let env: Vec<(String, Option<String>)> = c
            .get_envs()
            .map(|(k, v)| (k.to_string_lossy().into_owned(), v.map(|v| v.to_string_lossy().into_owned())))
            .collect();
        assert_eq!(env, vec![(ENV_TOKEN.to_string(), Some("htok_a".to_string()))]);
        let c = child_command(Path::new("/bin/it-ai"), s(&["--relay-token=htok_b"]));
        assert_eq!(c.get_args().count(), 0);
        assert_eq!(c.get_envs().next().unwrap().1.unwrap(), "htok_b");
    }

    #[test]
    fn hello_reply_parsing() {
        assert_eq!(parse_issued(200, r#"{"device_secret":"hdev_ab"}"#).as_deref(), Some("hdev_ab"));
        assert_eq!(parse_issued(204, ""), None);
        assert_eq!(parse_issued(200, r#"{"device_secret":"htok_ab"}"#), None);
        assert_eq!(parse_issued(200, "ok"), None);
    }
}
