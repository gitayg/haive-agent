// Interactive shell sessions over a real PTY. A pipe-based shell block-buffers
// its output (programs only line-buffer when stdout is a TTY), so nothing streams
// until the buffer fills — useless for interactivity. A PTY makes the shell think
// it's on a terminal, so prompts and output flow immediately, and full-screen
// programs work. portable-pty gives us openpty on Unix and ConPTY on Windows.
use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::Duration;

use portable_pty::{native_pty_system, Child, CommandBuilder, MasterPty, PtySize};

struct Out {
    buf: Mutex<Vec<u8>>,
    cv: Condvar,
    done: AtomicBool,
}

struct Session {
    writer: Mutex<Box<dyn Write + Send>>,
    out: Arc<Out>,
    child: Mutex<Box<dyn Child + Send + Sync>>,
    master: Mutex<Box<dyn MasterPty + Send>>,
}

fn sessions() -> &'static Mutex<HashMap<String, Arc<Session>>> {
    static S: OnceLock<Mutex<HashMap<String, Arc<Session>>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
}

fn next_sid() -> String {
    static N: AtomicU64 = AtomicU64::new(1);
    format!("s{}", N.fetch_add(1, Ordering::Relaxed))
}

fn shell_path() -> String {
    #[cfg(windows)]
    {
        std::env::var("COMSPEC").unwrap_or_else(|_| "cmd.exe".into())
    }
    #[cfg(not(windows))]
    {
        std::env::var("SHELL").unwrap_or_else(|_| "/bin/bash".into())
    }
}

/// Start a shell inside a PTY; returns its session id.
pub fn open() -> Option<String> {
    let pair = native_pty_system()
        .openpty(PtySize { rows: 30, cols: 120, pixel_width: 0, pixel_height: 0 })
        .ok()?;
    let mut cmd = CommandBuilder::new(shell_path());
    cmd.env("TERM", "xterm-256color");
    let child = pair.slave.spawn_command(cmd).ok()?;
    drop(pair.slave); // parent doesn't need the slave side
    let reader = pair.master.try_clone_reader().ok()?;
    let writer = pair.master.take_writer().ok()?;

    let out = Arc::new(Out { buf: Mutex::new(Vec::new()), cv: Condvar::new(), done: AtomicBool::new(false) });
    pump(reader, out.clone());

    let sid = next_sid();
    sessions().lock().unwrap().insert(
        sid.clone(),
        Arc::new(Session {
            writer: Mutex::new(writer),
            out,
            child: Mutex::new(child),
            master: Mutex::new(pair.master),
        }),
    );
    Some(sid)
}

fn pump(mut r: Box<dyn Read + Send>, out: Arc<Out>) {
    std::thread::spawn(move || {
        let mut buf = [0u8; 8192];
        while let Ok(n) = r.read(&mut buf) {
            if n == 0 {
                break;
            }
            let mut b = out.buf.lock().unwrap();
            b.extend_from_slice(&buf[..n]);
            out.cv.notify_all();
        }
        out.done.store(true, Ordering::Relaxed);
        out.cv.notify_all();
    });
}

pub fn input(sid: &str, data: &[u8]) -> bool {
    let s = match sessions().lock().unwrap().get(sid).cloned() {
        Some(s) => s,
        None => return false,
    };
    let mut w = s.writer.lock().unwrap();
    w.write_all(data).and_then(|_| w.flush()).is_ok()
}

pub fn resize(sid: &str, cols: u16, rows: u16) -> bool {
    let s = match sessions().lock().unwrap().get(sid).cloned() {
        Some(s) => s,
        None => return false,
    };
    let m = s.master.lock().unwrap();
    m.resize(PtySize { rows, cols, pixel_width: 0, pixel_height: 0 }).is_ok()
}

pub fn close(sid: &str) {
    if let Some(s) = sessions().lock().unwrap().remove(sid) {
        let _ = s.child.lock().unwrap().kill();
        s.out.done.store(true, Ordering::Relaxed);
        s.out.cv.notify_all();
    }
}

/// Long-poll the session's terminal output from byte offset `from`. Returns the
/// new bytes (possibly empty after `timeout`), or None if the session is gone.
/// Long-poll (finite response per call) rather than an endless stream, because a
/// blocking chunked body stalls in tiny_http's write buffer until it fills.
pub fn read_from(sid: &str, from: usize, timeout: Duration) -> Option<Vec<u8>> {
    let s = sessions().lock().unwrap().get(sid).cloned()?;
    let mut b = s.out.buf.lock().unwrap();
    if from >= b.len() && !s.out.done.load(Ordering::Relaxed) {
        let (g, _) = s.out.cv.wait_timeout(b, timeout).unwrap();
        b = g;
    }
    let start = from.min(b.len());
    Some(b[start..].to_vec())
}
