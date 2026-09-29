// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

// Background jobs: a long-running command started in its own process group, its
// stdout+stderr appended to `<data dir>/jobs/<id>.log`, read back in pages and
// stopped by id. Contract: docs/JOBS-API.md ("Agent").
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

pub const MAX_JOBS: usize = 50;
pub const DEFAULT_READ: u64 = 65536;
pub const MAX_READ: u64 = 1_048_576;
const STOP_GRACE: Duration = Duration::from_secs(5);

struct Job {
    id: String,
    cmd: String,
    pid: u32,
    started: u64,
    exit: Arc<Mutex<Option<i32>>>,
}

impl Job {
    fn exit_code(&self) -> Option<i32> {
        *self.exit.lock().unwrap()
    }
}

pub struct Registry {
    dir: PathBuf,
    jobs: Mutex<Vec<Job>>,
}

fn registry() -> &'static Registry {
    static R: OnceLock<Registry> = OnceLock::new();
    R.get_or_init(|| Registry::new(PathBuf::from(crate::persistence::home()).join(".it-ai").join("jobs")))
}

pub fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

fn new_id() -> String {
    static SEQ: OnceLock<AtomicU32> = OnceLock::new();
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let seq = SEQ.get_or_init(|| AtomicU32::new(now.subsec_nanos())).fetch_add(1, Ordering::Relaxed);
    format!("j{}{:04x}", now.as_millis(), seq & 0xffff)
}

fn bad_id() -> (Value, u16) {
    (json!({"ok": false, "error": "invalid job id"}), 400)
}

fn unknown() -> (Value, u16) {
    (json!({"ok": false, "error": "unknown job"}), 404)
}

#[cfg(unix)]
fn exit_code_of(s: std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    s.code().or_else(|| s.signal().map(|g| 128 + g)).unwrap_or(-1)
}

#[cfg(not(unix))]
fn exit_code_of(s: std::process::ExitStatus) -> i32 {
    s.code().unwrap_or(-1)
}

impl Registry {
    pub fn new(dir: PathBuf) -> Self {
        Registry { dir, jobs: Mutex::new(Vec::new()) }
    }

    /// Drop the oldest finished jobs past MAX_JOBS. Running jobs are never dropped:
    /// forgetting one would leave it running with no way to stop it.
    fn prune(jobs: &mut Vec<Job>) {
        while jobs.len() > MAX_JOBS {
            match jobs.iter().position(|j| j.exit_code().is_some()) {
                Some(i) => {
                    jobs.remove(i);
                }
                None => break,
            }
        }
    }

    pub fn start(&self, body: &str, shell: fn(&str) -> Command) -> (Value, u16) {
        let v: Value = serde_json::from_str(body).unwrap_or_default();
        let cmd = v.get("cmd").and_then(|c| c.as_str()).unwrap_or_default().trim().to_string();
        if cmd.is_empty() {
            return (json!({"ok": false, "error": "empty command"}), 400);
        }
        let cwd = v.get("cwd").and_then(|c| c.as_str()).filter(|s| !s.is_empty());
        if let Err(e) = std::fs::create_dir_all(&self.dir) {
            return (json!({"ok": false, "error": e.to_string()}), 500);
        }
        let id = new_id();
        let log = self.dir.join(format!("{id}.log"));
        let out = match std::fs::OpenOptions::new().create(true).append(true).open(&log) {
            Ok(f) => f,
            Err(e) => return (json!({"ok": false, "error": e.to_string()}), 500),
        };
        let err = match out.try_clone() {
            Ok(f) => f,
            Err(e) => return (json!({"ok": false, "error": e.to_string()}), 500),
        };
        let mut c = shell(&cmd);
        c.stdin(Stdio::null()).stdout(out).stderr(err);
        if let Some(d) = cwd {
            c.current_dir(d);
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            c.process_group(0);
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            c.creation_flags(0x0800_0000 | 0x0000_0200); // CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP
        }
        let mut child = match c.spawn() {
            Ok(ch) => ch,
            Err(e) => return (json!({"ok": false, "error": e.to_string()}), 500),
        };
        let pid = child.id();
        let exit = Arc::new(Mutex::new(None));
        let exit_w = exit.clone();
        std::thread::spawn(move || {
            let code = child.wait().map(exit_code_of).unwrap_or(-1);
            *exit_w.lock().unwrap() = Some(code);
        });
        let started = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let mut jobs = self.jobs.lock().unwrap();
        jobs.push(Job { id: id.clone(), cmd, pid, started, exit });
        Self::prune(&mut jobs);
        (json!({"ok": true, "id": id, "pid": pid, "log": log.to_string_lossy()}), 200)
    }

    fn exit_of(&self, id: &str) -> Option<(u32, Arc<Mutex<Option<i32>>>)> {
        self.jobs.lock().unwrap().iter().find(|j| j.id == id).map(|j| (j.pid, j.exit.clone()))
    }

    pub fn logs(&self, id: &str, offset: Option<&str>, max: Option<&str>) -> (Value, u16) {
        if !valid_id(id) {
            return bad_id();
        }
        let Some((_, exit)) = self.exit_of(id) else {
            return unknown();
        };
        let offset = offset.and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
        let max = max.and_then(|s| s.parse::<u64>().ok()).unwrap_or(DEFAULT_READ).min(MAX_READ);
        // Exit state is sampled BEFORE the size, so an exited job's size is final and
        // `eof` can't be claimed while output is still arriving.
        let exit_code = *exit.lock().unwrap();
        let log = self.dir.join(format!("{id}.log"));
        let mut data = Vec::new();
        let size = match std::fs::File::open(&log) {
            Ok(mut f) => {
                let size = f.metadata().map(|m| m.len()).unwrap_or(0);
                if offset < size && f.seek(SeekFrom::Start(offset)).is_ok() {
                    let _ = f.take(max).read_to_end(&mut data);
                }
                size
            }
            Err(_) => 0,
        };
        let next = offset + data.len() as u64;
        (
            json!({
                "ok": true,
                "id": id,
                "running": exit_code.is_none(),
                "exit_code": exit_code,
                "offset": next,
                "size": size,
                "eof": exit_code.is_some() && next >= size,
                "data": String::from_utf8_lossy(&data),
            }),
            200,
        )
    }

    pub fn stop(&self, id: &str) -> (Value, u16) {
        if !valid_id(id) {
            return bad_id();
        }
        let Some((pid, exit)) = self.exit_of(id) else {
            return unknown();
        };
        let running = exit.lock().unwrap().is_none();
        if running {
            terminate(pid, &exit);
        }
        let exit_code = *exit.lock().unwrap();
        (json!({"ok": true, "id": id, "stopped": running, "exit_code": exit_code}), 200)
    }

    pub fn list(&self) -> (Value, u16) {
        let mut jobs = self.jobs.lock().unwrap();
        Self::prune(&mut jobs);
        let rows: Vec<Value> = jobs
            .iter()
            .map(|j| {
                let code = j.exit_code();
                json!({"id": j.id, "cmd": j.cmd, "pid": j.pid, "started": j.started, "running": code.is_none(), "exit_code": code})
            })
            .collect();
        (json!({"ok": true, "jobs": rows}), 200)
    }
}

fn wait_exit(exit: &Mutex<Option<i32>>, within: Duration) -> bool {
    let t = Instant::now();
    loop {
        if exit.lock().unwrap().is_some() {
            return true;
        }
        if t.elapsed() >= within {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// SIGTERM the job's process group, SIGKILL it if anything in the group is still
/// alive after the grace period.
#[cfg(unix)]
fn terminate(pid: u32, exit: &Mutex<Option<i32>>) {
    let pg = pid as libc::pid_t;
    unsafe { libc::killpg(pg, libc::SIGTERM) };
    let t = Instant::now();
    while t.elapsed() < STOP_GRACE {
        if exit.lock().unwrap().is_some() && unsafe { libc::killpg(pg, 0) } != 0 {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    unsafe { libc::killpg(pg, libc::SIGKILL) };
    wait_exit(exit, Duration::from_secs(2));
}

#[cfg(windows)]
fn terminate(pid: u32, exit: &Mutex<Option<i32>>) {
    use std::os::windows::process::CommandExt;
    let _ = Command::new("taskkill")
        .args(["/T", "/F", "/PID", &pid.to_string()])
        .creation_flags(0x0800_0000)
        .output();
    wait_exit(exit, STOP_GRACE);
}

pub fn start_ep(body: &str, shell: fn(&str) -> Command) -> (Value, u16) {
    registry().start(body, shell)
}

pub fn logs_ep(id: &str, offset: Option<&str>, max: Option<&str>) -> (Value, u16) {
    registry().logs(id, offset, max)
}

pub fn stop_ep(id: &str) -> (Value, u16) {
    registry().stop(id)
}

pub fn list_ep() -> (Value, u16) {
    registry().list()
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn sh(cmd: &str) -> Command {
        let mut c = Command::new("sh");
        c.arg("-c").arg(cmd);
        c
    }

    fn scratch(name: &str) -> Registry {
        let d = std::env::temp_dir().join(format!("it-ai-jobs-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        Registry::new(d)
    }

    fn start(r: &Registry, cmd: &str) -> String {
        let (v, code) = r.start(&json!({"cmd": cmd}).to_string(), sh);
        assert_eq!(code, 200, "{v}");
        v["id"].as_str().unwrap().to_string()
    }

    fn wait_done(r: &Registry, id: &str) {
        let (_, exit) = r.exit_of(id).unwrap();
        assert!(wait_exit(&exit, Duration::from_secs(10)), "job {id} did not exit");
    }

    #[test]
    fn jobs_start_then_logs_to_eof_with_exit_code() {
        let r = scratch("eof");
        let id = start(&r, "echo out; echo err 1>&2; exit 3");
        assert!(id.starts_with('j') && valid_id(&id) && id.len() == 1 + 13 + 4, "{id}");
        wait_done(&r, &id);
        let (v, code) = r.logs(&id, None, None);
        assert_eq!(code, 200);
        assert_eq!(v["running"], false);
        assert_eq!(v["exit_code"], 3);
        assert_eq!(v["eof"], true);
        assert_eq!(v["size"], 8);
        assert_eq!(v["offset"], 8);
        let data = v["data"].as_str().unwrap();
        assert!(data.contains("out\n") && data.contains("err\n"), "{data:?}");
    }

    #[test]
    fn jobs_logs_offset_paging() {
        let r = scratch("page");
        let id = start(&r, "printf abcdefghij");
        wait_done(&r, &id);
        let (a, _) = r.logs(&id, Some("0"), Some("4"));
        assert_eq!((a["data"].as_str(), a["offset"].as_u64(), a["eof"].as_bool()), (Some("abcd"), Some(4), Some(false)));
        let (b, _) = r.logs(&id, Some("4"), Some("4"));
        assert_eq!((b["data"].as_str(), b["offset"].as_u64(), b["eof"].as_bool()), (Some("efgh"), Some(8), Some(false)));
        let (c, _) = r.logs(&id, Some("8"), Some("4"));
        assert_eq!((c["data"].as_str(), c["offset"].as_u64(), c["eof"].as_bool()), (Some("ij"), Some(10), Some(true)));
        assert_eq!(c["size"], 10);
    }

    #[test]
    fn jobs_stop_ends_a_running_job_and_its_children() {
        let r = scratch("stop");
        let id = start(&r, "sleep 300 & echo $! ; wait");
        let t = Instant::now();
        let child_pid = loop {
            let (v, _) = r.logs(&id, None, None);
            if let Ok(p) = v["data"].as_str().unwrap().trim().parse::<i32>() {
                break p;
            }
            assert!(t.elapsed() < Duration::from_secs(5), "child pid never logged");
            std::thread::sleep(Duration::from_millis(20));
        };
        assert_eq!(r.logs(&id, None, None).0["running"], true);
        let t = Instant::now();
        let (v, code) = r.stop(&id);
        // SIGTERM to the group is enough here; needing the SIGKILL fallback means
        // the signal did not reach the whole group.
        assert!(t.elapsed() < STOP_GRACE, "stop took {:?}", t.elapsed());
        assert_eq!(code, 200);
        assert_eq!(v["stopped"], true);
        assert!(v["exit_code"].is_i64(), "{v}");
        assert_eq!(r.logs(&id, None, None).0["running"], false);
        // The grandchild is in the job's process group, so it went too.
        assert_ne!(unsafe { libc::kill(child_pid, 0) }, 0, "grandchild {child_pid} survived stop");
    }

    #[test]
    fn jobs_invalid_id_is_rejected() {
        let r = scratch("badid");
        for bad in ["", "../etc", "J123", "j12-3", "j1/2", "j1.log"] {
            assert_eq!(r.logs(bad, None, None).1, 400, "logs {bad:?}");
            assert_eq!(r.stop(bad).1, 400, "stop {bad:?}");
        }
        let (v, code) = r.logs("j0000", None, None);
        assert_eq!((code, v["error"].as_str()), (404, Some("unknown job")));
    }

    #[test]
    fn jobs_registry_is_capped_at_50() {
        let r = scratch("cap");
        let started: Vec<(String, Arc<Mutex<Option<i32>>>)> = (0..MAX_JOBS + 5)
            .map(|_| {
                let id = start(&r, "true");
                let exit = r.exit_of(&id).unwrap().1;
                (id, exit)
            })
            .collect();
        for (id, exit) in &started {
            assert!(wait_exit(exit, Duration::from_secs(10)), "job {id} did not exit");
        }
        let ids: Vec<String> = started.into_iter().map(|(id, _)| id).collect();
        let (v, _) = r.list();
        let listed: Vec<&str> = v["jobs"].as_array().unwrap().iter().map(|j| j["id"].as_str().unwrap()).collect();
        assert_eq!(listed.len(), MAX_JOBS);
        let expect: Vec<&str> = ids[5..].iter().map(String::as_str).collect();
        assert_eq!(listed, expect);
        assert_eq!(r.logs(&ids[0], None, None).1, 404);
        assert!(r.dir.join(format!("{}.log", ids[0])).exists(), "dropped job's log must remain");
    }
}
