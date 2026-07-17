// HTTP(S) server: routing, auth, and the browser viewer page.
use std::path::PathBuf;
use std::sync::mpsc::Sender;
use std::sync::Arc;

use base64::Engine;
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};

use crate::capture::Grabber;
use crate::input::Ev;

type Resp = Response<std::io::Cursor<Vec<u8>>>;

/// Port of the plaintext loopback server (127.0.0.1 only) the relay self-calls.
/// 0 until `serve` has bound it.
static LOOPBACK_PORT: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0);

pub fn loopback_port() -> u16 {
    LOOPBACK_PORT.load(std::sync::atomic::Ordering::Relaxed)
}

pub struct Config {
    pub password: String,
    pub port: u16,
    pub quality: u8,
    pub max_width: u32,
    pub exec_enabled: bool,
    pub tls: bool,
    pub share: String,
    pub grabber: Grabber,
    pub cert: Option<(Vec<u8>, Vec<u8>)>,
    pub direct_token: String,
}

pub fn serve(cfg: Arc<Config>, input_tx: Sender<Ev>) {
    // A plaintext, loopback-only twin of the main server. It reuses the same
    // handler, so the relay can self-call every endpoint over 127.0.0.1 without
    // dealing with the self-signed TLS cert. Bound to 127.0.0.1 → not remotely
    // reachable; loopback requests are treated as authorized in `handle`.
    if let Ok(lb) = Server::http("127.0.0.1:0") {
        if let Some(addr) = lb.server_addr().to_ip() {
            LOOPBACK_PORT.store(addr.port(), std::sync::atomic::Ordering::Relaxed);
        }
        let lb = Arc::new(lb);
        for _ in 0..16 {
            let (s, c, tx) = (lb.clone(), cfg.clone(), input_tx.clone());
            std::thread::spawn(move || loop {
                match s.recv() {
                    Ok(req) => handle(req, &c, &tx),
                    Err(_) => break,
                }
            });
        }
    }

    let server = Arc::new(build_server(&cfg));
    let mut handles = Vec::new();
    for _ in 0..8 {
        let (s, c, tx) = (server.clone(), cfg.clone(), input_tx.clone());
        handles.push(std::thread::spawn(move || loop {
            match s.recv() {
                Ok(req) => handle(req, &c, &tx),
                Err(_) => break,
            }
        }));
    }
    for h in handles {
        let _ = h.join();
    }
}

fn build_server(cfg: &Config) -> Server {
    let addr = format!("0.0.0.0:{}", cfg.port);
    if cfg.tls {
        let (c, k) = cfg.cert.clone().expect("tls enabled without cert");
        Server::https(
            addr,
            tiny_http::SslConfig { certificate: c, private_key: k },
        )
        .expect("bind https")
    } else {
        Server::http(addr).expect("bind http")
    }
}

fn hdr(k: &str, v: &str) -> Header {
    Header::from_bytes(k.as_bytes(), v.as_bytes()).unwrap()
}

fn header_value(req: &Request, name: &'static str) -> Option<String> {
    req.headers()
        .iter()
        .find(|h| h.field.equiv(name))
        .map(|h| h.value.as_str().to_string())
}

fn authorized(req: &Request, cfg: &Config) -> bool {
    // LAN-direct: a request carrying the hub-issued per-device token is authorized
    // (lets an MCP the hub trusts drive us directly, even behind a password).
    if !cfg.direct_token.is_empty() {
        if let Some(q) = req.url().split('?').nth(1) {
            if q.split('&').any(|kv| kv.strip_prefix("dtok=").map(|v| v == cfg.direct_token).unwrap_or(false)) {
                return true;
            }
        }
    }
    if cfg.password.is_empty() {
        return true;
    }
    if let Some(v) = header_value(req, "Authorization") {
        if let Some(b64) = v.strip_prefix("Basic ") {
            if let Ok(dec) = base64::engine::general_purpose::STANDARD.decode(b64.trim()) {
                if let Ok(s) = String::from_utf8(dec) {
                    if let Some((_, pass)) = s.split_once(':') {
                        return pass == cfg.password;
                    }
                }
            }
        }
    }
    false
}

fn json_resp(v: &serde_json::Value, code: u16) -> Resp {
    Response::from_string(v.to_string())
        .with_status_code(code)
        .with_header(hdr("Content-Type", "application/json"))
}

fn handle(mut req: Request, cfg: &Config, tx: &Sender<Ev>) {
    // Loopback (the relay self-call and local tools) is implicitly trusted.
    let is_local = req.remote_addr().map(|a| a.ip().is_loopback()).unwrap_or(false);
    if !is_local && !authorized(&req, cfg) {
        let _ = req.respond(
            Response::from_string("Authentication required")
                .with_status_code(401)
                .with_header(hdr("WWW-Authenticate", "Basic realm=\"HaiveControl\"")),
        );
        return;
    }
    let method = req.method().clone();
    let url = req.url().to_string();
    let path = url.split('?').next().unwrap_or("/").to_string();
    // Live MJPEG streams have their own body type (a Read that never ends), so
    // they can't flow through the `Resp` (Cursor) match below — respond directly.
    if method == Method::Get && path == "/stream" {
        stream_screen(req, cfg);
        return;
    }
    if method == Method::Get && path == "/camstream" {
        let index = query_index(&url);
        stream_camera(req, cfg, index);
        return;
    }
    let resp = match (&method, path.as_str()) {
        (Method::Get, "/") => Response::from_string(PAGE).with_header(hdr("Content-Type", "text/html")),
        (Method::Get, "/frame") => frame_ep(cfg),
        (Method::Get, "/camera") => camera_ep(&url, cfg),
        (Method::Post, "/input") => {
            input_ep(&mut req, tx);
            Response::from_string("").with_status_code(204)
        }
        (Method::Post, "/exec") => exec_ep(&mut req, cfg),
        (Method::Post, "/schedule/add") => {
            let mut b = String::new();
            let _ = req.as_reader().read_to_string(&mut b);
            crate::schedule::add(serde_json::from_str(&b).unwrap_or_default());
            json_resp(&serde_json::json!({"ok": true}), 200)
        }
        (Method::Post, "/schedule/del") => {
            let mut b = String::new();
            let _ = req.as_reader().read_to_string(&mut b);
            let id = serde_json::from_str::<serde_json::Value>(&b).ok().and_then(|v| v.get("id").and_then(|x| x.as_str()).map(String::from)).unwrap_or_default();
            crate::schedule::del(&id);
            json_resp(&serde_json::json!({"ok": true}), 200)
        }
        (Method::Get, "/schedule/list") => json_resp(&crate::schedule::list(), 200),
        (Method::Post, "/shell/open") => shell_open_ep(cfg),
        (Method::Get, "/shell/read") => shell_read_ep(&url),
        (Method::Post, "/shell/input") => shell_input_ep(&mut req, &url),
        (Method::Post, "/shell/resize") => {
            let sid = query_val(&url, "sid").unwrap_or_default();
            let cols = query_val(&url, "cols").and_then(|v| v.parse().ok()).unwrap_or(120);
            let rows = query_val(&url, "rows").and_then(|v| v.parse().ok()).unwrap_or(30);
            crate::shell::resize(&sid, cols, rows);
            Response::from_string("").with_status_code(204)
        }
        (Method::Post, "/shell/close") => {
            crate::shell::close(&query_val(&url, "sid").unwrap_or_default());
            Response::from_string("closed")
        }
        (Method::Post, "/update") => update_ep(&mut req),
        (Method::Post, "/dissolve") => dissolve_ep(),
        (Method::Post, "/persist") => persist_ep(),
        (Method::Get, "/download") => download_ep(&url, cfg),
        (Method::Get, "/list") => list_ep(&url, cfg),
        (Method::Post, "/upload") => upload_ep(&mut req, cfg),
        _ => Response::from_string("not found").with_status_code(404),
    };
    let _ = req.respond(resp);
}

fn update_ep(req: &mut Request) -> Resp {
    let mut body = String::new();
    let _ = req.as_reader().read_to_string(&mut body);
    let url = serde_json::from_str::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| v.get("url").and_then(|u| u.as_str()).map(String::from));
    let url = match url {
        Some(u) => u,
        None => return Response::from_string("no url").with_status_code(400),
    };
    let bytes = match download_bytes(&url) {
        Some(b) if !b.is_empty() => b,
        _ => return Response::from_string("download failed").with_status_code(502),
    };
    if !apply_update(&bytes) {
        return Response::from_string("update failed").with_status_code(500);
    }
    std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_millis(700));
        std::process::exit(0);
    });
    Response::from_string(format!("updated ({} bytes); restarting", bytes.len()))
}

/// Replace the running executable with `bytes` and restart it (same args). On
/// Unix this `execv`s in place (same PID, inherited env + fds; the old listening
/// socket closes on exec) — which avoids the spawn-then-exit race where the new
/// process tried to bind :8765 before the old one released it and panicked with
/// AddrInUse. On Windows it spawns a fresh process; the caller then exits.
pub(crate) fn apply_update(bytes: &[u8]) -> bool {
    // Resolve our own path BEFORE self_replace. Afterwards, on Linux, the running
    // binary's inode is unlinked and current_exe() returns a stale
    // ".../airm (deleted)" path — exec/spawn against that fail with ENOENT, so we'd
    // be unable to restart. Capturing it here keeps a valid path that resolves to
    // the freshly written binary. (This is what killed an unsupervised agent on
    // 2.24.1→2.24.3: relaunch silently failed, yet the caller still exited.)
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("update: current_exe failed: {e}");
            return false;
        }
    };
    let tmp = std::env::temp_dir().join("airm-update.bin");
    if std::fs::write(&tmp, bytes).is_err() {
        return false;
    }
    if self_replace::self_replace(&tmp).is_err() {
        return false;
    }
    let _ = std::fs::remove_file(&tmp);
    let args: Vec<String> = std::env::args().skip(1).collect();
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // exec() replaces the process on success and never returns; if it returns,
        // it failed — fall through and spawn a fresh process instead.
        let e = std::process::Command::new(&exe).args(&args).exec();
        eprintln!("update: exec failed ({e}); spawning a replacement instead");
    }
    // Report whether the replacement actually launched. Callers must NOT exit the
    // still-running process when this is false — a failed relaunch with no
    // supervisor would otherwise leave the device dead.
    match std::process::Command::new(&exe).args(&args).spawn() {
        Ok(_) => true,
        Err(e) => {
            eprintln!("update: relaunch failed: {e}; staying on the current version");
            false
        }
    }
}

fn dissolve_ep() -> Resp {
    std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_millis(500));
        crate::persistence::uninstall();
        std::process::exit(0);
    });
    Response::from_string("dissolving — removing autostart and exiting")
}

/// POST /persist — promote this running agent to a persistent autostart install
/// (per-user autostart with the current relay args), and keep it awake on AC.
fn persist_ep() -> Resp {
    crate::persistence::install(&crate::persist_args());
    Response::from_string(format!("made persistent — {} (keep-awake on AC enabled)", crate::persistence::current_mode()))
}

fn download_bytes(url: &str) -> Option<Vec<u8>> {
    let mut reader = ureq::get(url).call().ok()?.into_reader();
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).ok()?;
    Some(buf)
}

fn query_index(url: &str) -> u32 {
    url.split('?')
        .nth(1)
        .unwrap_or("")
        .split('&')
        .find_map(|kv| kv.strip_prefix("index="))
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(0)
}

fn query_val(url: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    url.split('?').nth(1)?.split('&').find_map(|kv| kv.strip_prefix(&prefix)).map(|s| s.to_string())
}

fn shell_open_ep(cfg: &Config) -> Resp {
    if !cfg.exec_enabled {
        return json_resp(&serde_json::json!({"ok": false, "error": "shell disabled"}), 403);
    }
    match crate::shell::open() {
        Some(sid) => json_resp(&serde_json::json!({"ok": true, "sid": sid}), 200),
        None => json_resp(&serde_json::json!({"ok": false, "error": "failed to start shell"}), 500),
    }
}

fn shell_input_ep(req: &mut Request, url: &str) -> Resp {
    let sid = query_val(url, "sid").unwrap_or_default();
    let mut body = Vec::new();
    let _ = req.as_reader().read_to_end(&mut body);
    if crate::shell::input(&sid, &body) {
        Response::from_string("").with_status_code(204)
    } else {
        Response::from_string("no session").with_status_code(404)
    }
}

fn shell_read_ep(url: &str) -> Resp {
    let sid = query_val(url, "sid").unwrap_or_default();
    let from = query_val(url, "from").and_then(|v| v.parse::<usize>().ok()).unwrap_or(0);
    match crate::shell::read_from(&sid, from, std::time::Duration::from_secs(10)) {
        Some(bytes) => Response::from_data(bytes).with_header(hdr("Content-Type", "text/plain; charset=utf-8")),
        None => Response::from_string("no shell session").with_status_code(404),
    }
}

/// GET /frame → JPEG. On a Windows session-0 service (no desktop access) the grab
/// is delegated to the active user's session; otherwise we capture directly. The
/// service stays online either way — only the screenshot fails if delegation can't.
fn frame_ep(cfg: &Config) -> Resp {
    #[cfg(windows)]
    if crate::winsession::is_session0() {
        return match crate::winsession::capture_once() {
            Ok(bytes) => Response::from_data(bytes).with_header(hdr("Content-Type", "image/jpeg")),
            Err(reason) => Response::from_string(format!("Windows session 0 capture: {reason}")).with_status_code(500),
        };
    }
    match cfg.grabber.grab(cfg.quality, cfg.max_width) {
        Ok(bytes) => Response::from_data(bytes).with_header(hdr("Content-Type", "image/jpeg")),
        Err(reason) => Response::from_string(reason).with_status_code(500),
    }
}

/// Boundary header for one JPEG frame in a multipart/x-mixed-replace stream.
fn frame_head(len: usize) -> Vec<u8> {
    format!("--frame\r\nContent-Type: image/jpeg\r\nContent-Length: {len}\r\n\r\n").into_bytes()
}

fn mjpeg_headers() -> Vec<Header> {
    vec![hdr("Content-Type", "multipart/x-mixed-replace; boundary=frame")]
}

/// A Read that yields an endless MJPEG stream of screen captures (~14 fps).
struct ScreenStream {
    grabber: Grabber,
    quality: u8,
    max_width: u32,
    buf: Vec<u8>,
    pos: usize,
}
impl std::io::Read for ScreenStream {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if self.pos >= self.buf.len() {
            std::thread::sleep(std::time::Duration::from_millis(70));
            let jpeg = self.grabber.grab_jpeg(self.quality, self.max_width).unwrap_or_default();
            self.buf = frame_head(jpeg.len());
            self.buf.extend_from_slice(&jpeg);
            self.buf.extend_from_slice(b"\r\n");
            self.pos = 0;
        }
        let n = (self.buf.len() - self.pos).min(out.len());
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// A Read that yields an endless MJPEG stream from an open camera.
struct CameraStream {
    cam: nokhwa::Camera,
    quality: u8,
    buf: Vec<u8>,
    pos: usize,
}
impl std::io::Read for CameraStream {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if self.pos >= self.buf.len() {
            let jpeg = crate::capture::frame_to_jpeg(&mut self.cam, self.quality).unwrap_or_default();
            self.buf = frame_head(jpeg.len());
            self.buf.extend_from_slice(&jpeg);
            self.buf.extend_from_slice(b"\r\n");
            self.pos = 0;
        }
        let n = (self.buf.len() - self.pos).min(out.len());
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

fn stream_screen(req: Request, cfg: &Config) {
    let reader = ScreenStream {
        grabber: cfg.grabber.clone(),
        quality: cfg.quality,
        max_width: cfg.max_width,
        buf: Vec::new(),
        pos: 0,
    };
    let resp = Response::new(StatusCode(200), mjpeg_headers(), reader, None, None);
    let _ = req.respond(resp);
}

fn stream_camera(req: Request, cfg: &Config, index: u32) {
    match crate::capture::open_camera(index) {
        Some(cam) => {
            let reader = CameraStream { cam, quality: cfg.quality, buf: Vec::new(), pos: 0 };
            let resp = Response::new(StatusCode(200), mjpeg_headers(), reader, None, None);
            let _ = req.respond(resp);
        }
        None => {
            let _ = req.respond(Response::from_string("camera open failed").with_status_code(500));
        }
    }
}

fn camera_ep(url: &str, cfg: &Config) -> Resp {
    let index = query_index(url);
    let quality = cfg.quality;
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(crate::capture::camera_snapshot(index, quality));
    });
    match rx.recv_timeout(std::time::Duration::from_secs(12)) {
        Ok(Some(bytes)) => Response::from_data(bytes).with_header(hdr("Content-Type", "image/jpeg")),
        _ => Response::from_string("camera capture failed or timed out").with_status_code(500),
    }
}

fn input_ep(req: &mut Request, tx: &Sender<Ev>) {
    let mut body = String::new();
    let _ = req.as_reader().read_to_string(&mut body);
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
        if let Some(ev) = parse_ev(&v) {
            let _ = tx.send(ev);
        }
    }
}

fn parse_ev(v: &serde_json::Value) -> Option<Ev> {
    let t = v.get("type")?.as_str()?;
    let x = v.get("x").and_then(|n| n.as_f64()).unwrap_or(0.0);
    let y = v.get("y").and_then(|n| n.as_f64()).unwrap_or(0.0);
    let btn = v.get("button").and_then(|n| n.as_u64()).unwrap_or(0) as u8;
    Some(match t {
        "move" => Ev::Move(x, y),
        "down" => Ev::Down(btn, x, y),
        "up" => Ev::Up(btn),
        "scroll" => Ev::Scroll(v.get("dy").and_then(|n| n.as_i64()).unwrap_or(0) as i32),
        "key" => Ev::Key(
            v.get("action").and_then(|a| a.as_str()) == Some("down"),
            v.get("key").and_then(|k| k.as_str()).unwrap_or("").to_string(),
        ),
        _ => return None,
    })
}

/// Kill a process tree by PID (used when a captured command exceeds its timeout).
fn kill_pid(id: u32) {
    #[cfg(windows)]
    let _ = std::process::Command::new("taskkill").args(["/PID", &id.to_string(), "/T", "/F"]).output();
    #[cfg(not(windows))]
    let _ = std::process::Command::new("kill").args(["-9", &id.to_string()]).output();
}

fn exec_ep(req: &mut Request, cfg: &Config) -> Resp {
    if !cfg.exec_enabled {
        return json_resp(&serde_json::json!({"ok": false, "error": "remote exec disabled"}), 403);
    }
    let mut body = String::new();
    let _ = req.as_reader().read_to_string(&mut body);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
    let cmd = v.get("cmd").and_then(|c| c.as_str()).unwrap_or_default().trim().to_string();
    if cmd.is_empty() {
        return json_resp(&serde_json::json!({"ok": false, "error": "empty command"}), 400);
    }
    // Fire-and-forget launch (e.g. a GUI app) must NOT block the exec/relay channel.
    let detach = v.get("detach").and_then(|x| x.as_bool()).unwrap_or(false);
    // Cap captured commands so a hung/GUI-spawning process can't wedge the channel.
    let timeout = v.get("timeout").and_then(|x| x.as_u64()).unwrap_or(60).clamp(1, 300);
    let (prog, flag) = if cfg!(windows) { ("cmd", "/C") } else { ("sh", "-c") };

    if detach {
        // Spawn detached and return immediately — the child is orphaned, not waited
        // on. Redirect stdio to NUL so a launched GUI grandchild can't inherit an
        // exec pipe write-end (which would wedge a captured command's read-to-EOF).
        let mut c = std::process::Command::new(prog);
        c.arg(flag).arg(&cmd).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            // CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP — hide cmd's console and
            // isolate the process group. (DETACHED_PROCESS dropped: it makes
            // CREATE_NO_WINDOW a no-op and muddies the console semantics; null
            // stdio + these two are what a fire-and-forget GUI launch actually
            // needs, and a GUI app opens its own window regardless.)
            c.creation_flags(0x0800_0000 | 0x0000_0200);
        }
        return match c.spawn() {
            Ok(child) => json_resp(&serde_json::json!({"ok": true, "detached": true, "pid": child.id()}), 200),
            Err(e) => json_resp(&serde_json::json!({"ok": false, "error": e.to_string()}), 500),
        };
    }

    // Run-and-capture, but bounded: wait on a worker thread and time out + kill.
    let mut capc = std::process::Command::new(prog);
    capc.arg(flag)
        .arg(&cmd)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        capc.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    let child = capc.spawn();
    let child = match child {
        Ok(c) => c,
        Err(e) => return json_resp(&serde_json::json!({"ok": false, "error": e.to_string()}), 500),
    };
    let id = child.id();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(child.wait_with_output());
    });
    match rx.recv_timeout(std::time::Duration::from_secs(timeout)) {
        Ok(Ok(o)) => json_resp(
            &serde_json::json!({
                "ok": true,
                "code": o.status.code().unwrap_or(-1),
                "stdout": String::from_utf8_lossy(&o.stdout),
                "stderr": String::from_utf8_lossy(&o.stderr),
            }),
            200,
        ),
        Ok(Err(e)) => json_resp(&serde_json::json!({"ok": false, "error": e.to_string()}), 500),
        Err(_) => {
            kill_pid(id);
            json_resp(&serde_json::json!({"ok": false, "timed_out": true, "error": format!("command exceeded {timeout}s and was terminated (use detach for GUI apps / long tasks)")}), 200)
        }
    }
}

fn resolve_path(cfg: &Config, path: &str) -> Option<PathBuf> {
    if !cfg.share.is_empty() {
        if path.contains("..") {
            return None;
        }
        Some(PathBuf::from(expand_tilde(&cfg.share)).join(path))
    } else {
        Some(PathBuf::from(expand_tilde(path)))
    }
}

fn list_ep(url: &str, cfg: &Config) -> Resp {
    let query = url.split('?').nth(1).unwrap_or("");
    let mut path = String::new();
    for kv in query.split('&') {
        if let Some(v) = kv.strip_prefix("path=") {
            path = percent_decode(v);
        }
    }
    if path.is_empty() {
        path = if !cfg.share.is_empty() {
            cfg.share.clone()
        } else {
            std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")).unwrap_or_else(|_| "/".to_string())
        };
    }
    let full = match resolve_path(cfg, &path) {
        Some(f) => f,
        None => return json_resp(&serde_json::json!({"ok": false, "error": "forbidden"}), 403),
    };
    let mut entries: Vec<serde_json::Value> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&full) {
        for e in rd.flatten() {
            let md = e.metadata().ok();
            let dir = md.as_ref().map(|m| m.is_dir()).unwrap_or(false);
            let size = md.as_ref().map(|m| m.len()).unwrap_or(0);
            entries.push(serde_json::json!({"name": e.file_name().to_string_lossy(), "dir": dir, "size": size}));
        }
    }
    entries.sort_by(|a, b| {
        let (ad, bd) = (a["dir"].as_bool().unwrap_or(false), b["dir"].as_bool().unwrap_or(false));
        bd.cmp(&ad).then_with(|| {
            a["name"].as_str().unwrap_or("").to_lowercase().cmp(&b["name"].as_str().unwrap_or("").to_lowercase())
        })
    });
    let parent = full.parent().map(|p| p.to_string_lossy().to_string());
    json_resp(
        &serde_json::json!({"ok": true, "path": full.to_string_lossy(), "parent": parent, "entries": entries}),
        200,
    )
}

fn expand_tilde(p: &str) -> String {
    if let Some(rest) = p.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")) {
            return format!("{home}/{rest}");
        }
    }
    p.to_string()
}

fn download_ep(url: &str, cfg: &Config) -> Resp {
    let query = url.split('?').nth(1).unwrap_or("");
    let mut path = String::new();
    for kv in query.split('&') {
        if let Some(v) = kv.strip_prefix("path=") {
            path = percent_decode(v);
        }
    }
    match resolve_path(cfg, &path) {
        Some(full) if full.is_file() => match std::fs::read(&full) {
            Ok(bytes) => {
                let fname = full
                    .file_name()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| "download".to_string());
                Response::from_data(bytes)
                    .with_header(hdr("Content-Type", "application/octet-stream"))
                    .with_header(hdr(
                        "Content-Disposition",
                        &format!("attachment; filename=\"{fname}\""),
                    ))
            }
            Err(_) => json_resp(&serde_json::json!({"ok": false, "error": "read failed"}), 500),
        },
        _ => json_resp(&serde_json::json!({"ok": false, "error": "not a file"}), 404),
    }
}

fn upload_ep(req: &mut Request, cfg: &Config) -> Resp {
    let boundary = header_value(req, "Content-Type")
        .and_then(|ct| ct.split("boundary=").nth(1).map(|s| s.to_string()));
    let boundary = match boundary {
        Some(b) => b,
        None => return json_resp(&serde_json::json!({"ok": false, "error": "no multipart boundary"}), 400),
    };
    let mut body = Vec::new();
    let _ = req.as_reader().read_to_end(&mut body);
    let (file, dir) = parse_multipart(&body, &boundary);
    let (fname, data) = match file {
        Some(f) => f,
        None => return json_resp(&serde_json::json!({"ok": false, "error": "no file"}), 400),
    };
    let target = dir.filter(|d| !d.is_empty()).unwrap_or_else(|| {
        if cfg.share.is_empty() {
            std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")).unwrap_or_default()
        } else {
            cfg.share.clone()
        }
    });
    let dest_dir = match resolve_path(cfg, &target) {
        Some(d) if d.is_dir() => d,
        _ => return json_resp(&serde_json::json!({"ok": false, "error": "target dir not found"}), 400),
    };
    let basename = std::path::Path::new(&fname)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or(fname);
    let dest = dest_dir.join(basename);
    match std::fs::write(&dest, &data) {
        Ok(_) => json_resp(&serde_json::json!({"ok": true, "saved": dest.to_string_lossy()}), 200),
        Err(e) => json_resp(&serde_json::json!({"ok": false, "error": e.to_string()}), 500),
    }
}

fn parse_multipart(body: &[u8], boundary: &str) -> (Option<(String, Vec<u8>)>, Option<String>) {
    let delim = format!("--{boundary}").into_bytes();
    let mut file = None;
    let mut dir = None;
    for part in split_on(body, &delim) {
        let part = part.strip_prefix(b"\r\n").unwrap_or(part);
        if let Some(idx) = find(part, b"\r\n\r\n") {
            let (head, rest) = part.split_at(idx);
            let content = &rest[4..];
            let content = content.strip_suffix(b"\r\n").unwrap_or(content);
            let head_s = String::from_utf8_lossy(head);
            if head_s.contains("name=\"file\"") {
                let fname = head_s
                    .split("filename=\"")
                    .nth(1)
                    .and_then(|s| s.split('"').next())
                    .unwrap_or("upload.bin")
                    .to_string();
                file = Some((fname, content.to_vec()));
            } else if head_s.contains("name=\"dir\"") {
                dir = Some(String::from_utf8_lossy(content).trim().to_string());
            }
        }
    }
    (file, dir)
}

fn split_on<'a>(data: &'a [u8], sep: &[u8]) -> Vec<&'a [u8]> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i + sep.len() <= data.len() {
        if &data[i..i + sep.len()] == sep {
            parts.push(&data[start..i]);
            i += sep.len();
            start = i;
        } else {
            i += 1;
        }
    }
    parts.push(&data[start..]);
    parts
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(n) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(n);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

pub const PAGE: &str = r####"<!doctype html><html><head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>HaiveControl</title>
<style>
 html,body{margin:0;background:#111;color:#ddd;font-family:system-ui,sans-serif}
 #screen{display:block;max-width:100%;height:auto;cursor:crosshair;margin:0 auto}
 #bar{position:fixed;left:0;right:0;bottom:0;display:flex;gap:8px;align-items:center;
      padding:6px;background:#000c;backdrop-filter:blur(4px)}
 #cmd{flex:1;background:#1c1c1c;color:#eee;border:1px solid #444;padding:7px;
      font-family:ui-monospace,monospace;border-radius:4px}
 #out{position:fixed;right:8px;bottom:50px;max-width:46%;max-height:42%;overflow:auto;
      background:#000d;color:#4ade80;font-family:ui-monospace,monospace;font-size:12px;
      padding:10px;white-space:pre-wrap;border-radius:6px;display:none}
 button,label{background:#2a2a2a;color:#eee;border:1px solid #555;padding:7px 11px;
      border-radius:4px;cursor:pointer;font-size:13px}
</style></head><body>
<img id="screen" src="/frame">
<pre id="out"></pre>
<div id="bar">
  <label><input type="checkbox" id="ctrl" checked> control</label>
  <input id="cmd" placeholder="remote command (Enter to run)…" autocomplete="off">
  <input type="file" id="file" style="max-width:150px">
  <button id="upbtn">upload</button>
  <input id="dlpath" placeholder="download path…" autocomplete="off" style="max-width:150px">
  <button id="dlbtn">get</button>
  <button id="outbtn">output</button>
</div>
<script>
const img=document.getElementById('screen'),cmd=document.getElementById('cmd'),
      out=document.getElementById('out'),ctrl=document.getElementById('ctrl');
const on=()=>ctrl.checked;
function refresh(){const n=new Image();
  n.onload=()=>{img.src=n.src;setTimeout(refresh,90);};
  n.onerror=()=>setTimeout(refresh,600);
  n.src='/frame?t='+Date.now();}
refresh();
function norm(e){const r=img.getBoundingClientRect();
  return {x:Math.min(1,Math.max(0,(e.clientX-r.left)/r.width)),
          y:Math.min(1,Math.max(0,(e.clientY-r.top)/r.height))};}
function send(ev){fetch('/input',{method:'POST',
  headers:{'Content-Type':'application/json'},body:JSON.stringify(ev)});}
let last=0;
img.addEventListener('mousemove',e=>{if(!on())return;const t=Date.now();
  if(t-last<45)return;last=t;const p=norm(e);send({type:'move',x:p.x,y:p.y});});
img.addEventListener('mousedown',e=>{if(!on())return;e.preventDefault();const p=norm(e);
  send({type:'down',button:e.button,x:p.x,y:p.y});});
img.addEventListener('mouseup',e=>{if(!on())return;e.preventDefault();const p=norm(e);
  send({type:'up',button:e.button,x:p.x,y:p.y});});
img.addEventListener('contextmenu',e=>e.preventDefault());
img.addEventListener('wheel',e=>{if(!on())return;e.preventDefault();
  send({type:'scroll',dy:-Math.sign(e.deltaY)*3});},{passive:false});
document.addEventListener('keydown',e=>{if(!on()||document.activeElement===cmd)return;
  e.preventDefault();send({type:'key',action:'down',key:e.key});});
document.addEventListener('keyup',e=>{if(!on()||document.activeElement===cmd)return;
  e.preventDefault();send({type:'key',action:'up',key:e.key});});
cmd.addEventListener('keydown',e=>{if(e.key==='Enter'){const c=cmd.value;cmd.value='';run(c);}});
document.getElementById('outbtn').onclick=()=>{
  out.style.display=out.style.display==='none'?'block':'none';};
document.getElementById('upbtn').onclick=async()=>{
  const f=document.getElementById('file').files[0];if(!f)return;
  out.style.display='block';out.textContent='uploading '+f.name+'…';
  const fd=new FormData();fd.append('file',f);
  try{const r=await fetch('/upload',{method:'POST',body:fd});const j=await r.json();
    out.textContent=j.ok?('uploaded → '+j.saved):('[error] '+(j.error||'failed'));}
  catch(err){out.textContent='[error] '+err;}};
document.getElementById('dlbtn').onclick=()=>{
  const p=document.getElementById('dlpath').value.trim();if(!p)return;
  window.open('/download?path='+encodeURIComponent(p),'_blank');};
async function run(c){if(!c)return;out.style.display='block';out.textContent='$ '+c+'\n…';
  try{const r=await fetch('/exec',{method:'POST',
    headers:{'Content-Type':'application/json'},body:JSON.stringify({cmd:c})});
  const j=await r.json();
  out.textContent='$ '+c+'\n'+(j.ok?((j.stdout||'')+(j.stderr||'')||'(exit '+j.code+')')
    :('[error] '+(j.error||'failed')));}
  catch(err){out.textContent='$ '+c+'\n[error] '+err;}}
</script></body></html>"####;
