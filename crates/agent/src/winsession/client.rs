// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

// Service side of the SYSTEM screen helper: keep ONE helper running in the active
// console session and talk to it over authenticated loopback HTTP.
//
// The helper is a child the service can lose without losing the device: the
// service itself never moves out of session 0, and every failure here returns
// Err so the caller falls back to the one-shot user-token capture.

use std::ffi::OsString;
use std::os::windows::ffi::OsStrExt;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, WAIT_OBJECT_0};
use windows_sys::Win32::Security::{
    DuplicateTokenEx, SecurityImpersonation, SetTokenInformation, TokenPrimary, TokenSessionId, TOKEN_ALL_ACCESS,
    TOKEN_DUPLICATE, TOKEN_QUERY,
};
use windows_sys::Win32::System::RemoteDesktop::WTSGetActiveConsoleSessionId;
use windows_sys::Win32::System::Threading::{
    CreateProcessAsUserW, GetCurrentProcess, GetCurrentProcessId, GetExitCodeProcess, OpenProcessToken,
    TerminateProcess, WaitForSingleObject, CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION,
    STARTUPINFOW,
};

use crate::securedesk::auth::{self, KEY_LEN};
use crate::securedesk::logic::{counts_as_failure, decide, Decision};
use crate::securedesk::spec::{HelperSpec, KEY_ENV};

/// How long a new helper gets to answer its first authenticated /hello.
const START_TIMEOUT: Duration = Duration::from_secs(5);
/// The helper exits after this long without a request (it is respawned on demand).
const IDLE_SECS: u64 = 600;
/// Upper bound on a helper response body (a key frame at 3840 px is far below).
const MAX_BODY: u64 = 64 * 1024 * 1024;

struct Live {
    process: isize,
    port: u16,
    key: [u8; KEY_LEN],
    session: u32,
}

#[derive(Default)]
struct Slot {
    live: Option<Live>,
    fails: u32,
    last_fail: Option<Instant>,
    last_err: String,
}

fn slot() -> std::sync::MutexGuard<'static, Slot> {
    static SLOT: OnceLock<Mutex<Slot>> = OnceLock::new();
    SLOT.get_or_init(Default::default).lock().unwrap_or_else(|e| e.into_inner())
}

fn console_session() -> Option<u32> {
    let s = unsafe { WTSGetActiveConsoleSessionId() };
    (s != u32::MAX).then_some(s)
}

/// Exit code when the process has exited, None while it runs. Never blocks.
fn exit_code(process: isize) -> Option<u32> {
    unsafe {
        if WaitForSingleObject(process as HANDLE, 0) != WAIT_OBJECT_0 {
            return None;
        }
        let mut code = 1u32;
        GetExitCodeProcess(process as HANDLE, &mut code);
        Some(code)
    }
}

fn kill(process: isize) {
    unsafe {
        TerminateProcess(process as HANDLE, 1);
        WaitForSingleObject(process as HANDLE, 2_000);
        CloseHandle(process as HANDLE);
    }
}

fn record_failure(s: &mut Slot, err: String) {
    s.fails = s.fails.saturating_add(1);
    s.last_fail = Some(Instant::now());
    s.last_err = err;
}

/// A running, verified helper for the current console session: (port, key).
/// Spawns or replaces one as needed. Holding the lock while spawning makes
/// concurrent callers wait for the same helper instead of starting two.
fn ensure() -> Result<(u16, [u8; KEY_LEN]), String> {
    let mut s = slot();
    if let Some(code) = s.live.as_ref().and_then(|l| exit_code(l.process)) {
        let l = s.live.take().expect("checked above");
        unsafe { CloseHandle(l.process as HANDLE) };
        if counts_as_failure(code) {
            record_failure(&mut s, format!("screen helper exited with code {code}"));
        }
    }
    let since = s.last_fail.map(|t| t.elapsed());
    match decide(s.live.as_ref().map(|l| l.session), console_session(), s.fails, since) {
        Decision::Reuse => {
            let l = s.live.as_ref().expect("Reuse implies live");
            return Ok((l.port, l.key));
        }
        Decision::NoSession => return Err("no active console session".into()),
        Decision::Backoff(left) => {
            return Err(format!("screen helper unavailable ({}); next try in {}s", s.last_err, left.as_secs().max(1)))
        }
        Decision::Replace => {
            if let Some(l) = s.live.take() {
                kill(l.process);
            }
        }
        Decision::Spawn => {}
    }
    let session = console_session().ok_or("no active console session")?;
    match unsafe { spawn(session) } {
        Ok(l) => {
            let out = (l.port, l.key);
            s.live = Some(l);
            s.fails = 0;
            s.last_fail = None;
            Ok(out)
        }
        Err(e) => {
            record_failure(&mut s, e.clone());
            Err(e)
        }
    }
}

/// The helper stopped answering properly: stop it so the next call starts fresh.
fn discard(port: u16, why: &str) {
    let mut s = slot();
    if s.live.as_ref().is_some_and(|l| l.port == port) {
        let l = s.live.take().expect("checked above");
        kill(l.process);
        record_failure(&mut s, why.to_string());
    }
}

fn free_port() -> Result<u16, String> {
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .map_err(|e| format!("no free loopback port: {e}"))
}

fn env_num<T: std::str::FromStr>(k: &str, d: T) -> T {
    std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d)
}

/// The service's own environment plus the helper key, as a sorted UTF-16 block.
fn env_block(key_hex: &str) -> Vec<u16> {
    let mut vars: Vec<(OsString, OsString)> =
        std::env::vars_os().filter(|(k, _)| !k.to_string_lossy().eq_ignore_ascii_case(KEY_ENV)).collect();
    vars.push((KEY_ENV.into(), key_hex.into()));
    vars.sort_by_key(|(k, _)| k.to_string_lossy().to_uppercase());
    let mut block = Vec::new();
    for (k, v) in vars {
        block.extend(k.encode_wide());
        block.push(b'=' as u16);
        block.extend(v.encode_wide());
        block.push(0);
    }
    block.push(0);
    block
}

fn wide(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

/// Start the helper in `session` as LocalSystem: our own token, duplicated, with
/// its TokenSessionId set to the console session (needs SeTcbPrivilege, which
/// LocalSystem holds). The binary is our own installed exe — never the %PUBLIC%
/// staged copy the user-token path uses, which any user can overwrite.
unsafe fn spawn(session: u32) -> Result<Live, String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let port = free_port()?;
    let key = auth::random_bytes::<KEY_LEN>()?;
    let spec = HelperSpec {
        ppid: GetCurrentProcessId(),
        port,
        monitor: env_num("SCREEN_MONITOR", 0usize),
        quality: env_num("SCREEN_QUALITY", 60u8),
        max_width: env_num("SCREEN_MAXW", 1600u32),
        idle_secs: IDLE_SECS,
    }
    .format();

    let mut own: HANDLE = std::ptr::null_mut();
    if OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &mut own) == 0 {
        return Err(format!("OpenProcessToken failed [err {}]", GetLastError()));
    }
    let mut primary: HANDLE = std::ptr::null_mut();
    let dup = DuplicateTokenEx(own, TOKEN_ALL_ACCESS, std::ptr::null(), SecurityImpersonation, TokenPrimary, &mut primary);
    CloseHandle(own);
    if dup == 0 || primary.is_null() {
        return Err(format!("DuplicateTokenEx failed [err {}]", GetLastError()));
    }
    let sid = session;
    if SetTokenInformation(primary, TokenSessionId, (&sid as *const u32).cast(), 4) == 0 {
        let err = GetLastError();
        CloseHandle(primary);
        return Err(format!("SetTokenInformation(TokenSessionId={session}) failed [err {err}] (needs LocalSystem)"));
    }

    let mut env = env_block(&auth::hex(&key));
    let mut si: STARTUPINFOW = std::mem::zeroed();
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut desktop = wide("winsta0\\default");
    si.lpDesktop = desktop.as_mut_ptr();
    let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
    let mut cl = wide(&format!("\"{}\" --screen-helper {spec}", exe.display()));
    let started = CreateProcessAsUserW(
        primary,
        std::ptr::null(),
        cl.as_mut_ptr(),
        std::ptr::null(),
        std::ptr::null(),
        0,
        CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
        env.as_mut_ptr().cast(),
        std::ptr::null(),
        &si,
        &mut pi,
    );
    let spawn_err = GetLastError();
    CloseHandle(primary);
    // Scrub our copy of the key-bearing block.
    env.iter_mut().for_each(|c| *c = 0);
    if started == 0 {
        return Err(format!("CreateProcessAsUser (SYSTEM, session {session}) failed [err {spawn_err}]"));
    }
    CloseHandle(pi.hThread);
    let process = pi.hProcess as isize;

    let deadline = Instant::now() + START_TIMEOUT;
    loop {
        if let Some(code) = exit_code(process) {
            CloseHandle(process as HANDLE);
            return Err(format!("screen helper exited with code {code} while starting"));
        }
        if request(port, &key, "GET", "/hello", b"", Duration::from_millis(500)).is_ok_and(|r| r.0 == 204) {
            return Ok(Live { process, port, key, session });
        }
        if Instant::now() >= deadline {
            kill(process);
            return Err(format!("screen helper did not answer within {}s", START_TIMEOUT.as_secs()));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn agent() -> &'static ureq::Agent {
    static A: OnceLock<ureq::Agent> = OnceLock::new();
    // No proxy (ureq only uses one when told to), no redirects: loopback only.
    A.get_or_init(|| ureq::AgentBuilder::new().redirects(0).timeout_connect(Duration::from_secs(2)).build())
}

/// One authenticated round trip: (status, content-type, body). Err = transport
/// failure or an answer that doesn't prove it came from our helper.
fn request(port: u16, key: &[u8], method: &str, path: &str, body: &[u8], timeout: Duration) -> Result<(u16, String, Vec<u8>), String> {
    use std::io::Read;
    let nonce = auth::hex(&auth::random_bytes::<16>()?);
    let tag = auth::request_tag(key, method, path, &nonce, body);
    let req = agent()
        .request(method, &format!("http://127.0.0.1:{port}{path}"))
        .timeout(timeout)
        .set("X-Itai-N", &nonce)
        .set("X-Itai-A", &tag);
    let res = if body.is_empty() { req.call() } else { req.send_bytes(body) };
    let resp = match res {
        Ok(r) | Err(ureq::Error::Status(_, r)) => r,
        Err(e) => return Err(format!("screen helper unreachable: {e}")),
    };
    let status = resp.status();
    if !auth::verify_response(key, &nonce, status, resp.header("X-Itai-P").unwrap_or("")) {
        return Err("screen helper answer failed authentication".into());
    }
    let ctype = resp.content_type().to_string();
    let mut out = Vec::new();
    resp.into_reader().take(MAX_BODY).read_to_end(&mut out).map_err(|e| format!("reading helper answer: {e}"))?;
    Ok((status, ctype, out))
}

/// Ensure a helper and send one request to it. A broken helper is discarded so
/// the next call respawns it.
pub fn call(method: &str, path: &str, body: &[u8], timeout: Duration) -> Result<(u16, String, Vec<u8>), String> {
    let (port, key) = ensure()?;
    request(port, &key, method, path, body, timeout).inspect_err(|e| discard(port, e))
}
