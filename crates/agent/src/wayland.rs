// Wayland screen capture for compositors without wlr-screencopy (GNOME, KDE),
// where xcap can't help. We drive the xdg-desktop-portal ScreenCast API over
// D-Bus (zbus, blocking) to get a PipeWire node + fd, then pull a single frame
// with the pipewire crate and hand back an RGB image.
//
// The portal requires a one-time interactive consent ("share your screen"). We
// ask for persist_mode=persistent and stash the returned restore_token, so after
// the user approves once every later capture is silent. Until then — or if the
// dialog is left unanswered (e.g. headless) — capture reports ConsentPending
// rather than blocking /frame forever (a worker thread + timeout + cooldown).
#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use zbus::blocking::{Connection, Proxy};
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};

/// Why a Wayland capture didn't produce a frame.
pub enum CaptureErr {
    /// The portal is waiting for the user to approve screen sharing at the console.
    ConsentPending,
    /// Genuinely unavailable (no session bus, no portal, compositor error).
    Unavailable(String),
}

impl CaptureErr {
    pub fn message(&self) -> String {
        match self {
            CaptureErr::ConsentPending => "Wayland screen-share consent pending — approve the \
                one-time \"Share your screen\" dialog on this device's display; capture is silent \
                after that".to_string(),
            CaptureErr::Unavailable(e) => format!("Wayland capture unavailable: {e}"),
        }
    }
}

/// True when we're on a Wayland session (so the X11 path won't work).
pub fn is_wayland() -> bool {
    std::env::var("XDG_SESSION_TYPE").map(|s| s == "wayland").unwrap_or(false)
        || std::env::var("WAYLAND_DISPLAY").map(|s| !s.is_empty()).unwrap_or(false)
}

fn token_path() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    std::path::Path::new(&home).join(".haive").join("screencast.token")
}
fn load_restore_token() -> Option<String> {
    std::fs::read_to_string(token_path()).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}
fn save_restore_token(tok: &str) {
    let p = token_path();
    if let Some(dir) = p.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(p, tok);
}

// Don't re-trigger the consent dialog on every frame: after a pending/failed
// attempt, sit in a cooldown and report the same error cheaply.
fn cooldown() -> &'static Mutex<Option<(Instant, bool)>> {
    static C: OnceLock<Mutex<Option<(Instant, bool)>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(None))
}
fn in_cooldown() -> Option<CaptureErr> {
    let g = cooldown().lock().unwrap();
    if let Some((at, pending)) = *g {
        if at.elapsed() < Duration::from_secs(30) {
            return Some(if pending { CaptureErr::ConsentPending } else { CaptureErr::Unavailable("recent failure".into()) });
        }
    }
    None
}
fn set_cooldown(pending: bool) {
    *cooldown().lock().unwrap() = Some((Instant::now(), pending));
}
fn clear_cooldown() {
    *cooldown().lock().unwrap() = None;
}

// One capture at a time (the portal session + pipewire loop aren't reentrant).
fn capture_lock() -> &'static Mutex<()> {
    static L: OnceLock<Mutex<()>> = OnceLock::new();
    L.get_or_init(|| Mutex::new(()))
}

/// Capture one frame of the primary monitor as RGB8 `(width, height, rgb)`.
/// Runs the whole portal+pipewire flow on a worker thread and gives up after
/// `deadline` (the consent dialog can block indefinitely on a headless box).
pub fn capture_rgb() -> Result<(u32, u32, Vec<u8>), CaptureErr> {
    if let Some(e) = in_cooldown() {
        return Err(e);
    }
    // If a capture is already running, don't stack another portal request.
    let Ok(_guard) = capture_lock().try_lock() else {
        return Err(CaptureErr::ConsentPending);
    };

    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(capture_rgb_inner());
    });
    // Fast when a restore_token already exists (no dialog); slow only on first consent.
    match rx.recv_timeout(Duration::from_secs(8)) {
        Ok(Ok(frame)) => {
            clear_cooldown();
            Ok(frame)
        }
        Ok(Err(e)) => {
            set_cooldown(matches!(e, CaptureErr::ConsentPending));
            Err(e)
        }
        Err(_) => {
            // Still waiting — almost certainly the consent dialog is up.
            set_cooldown(true);
            Err(CaptureErr::ConsentPending)
        }
    }
}

fn err<E: std::fmt::Display>(e: E) -> CaptureErr {
    CaptureErr::Unavailable(e.to_string())
}

/// The synchronous portal + pipewire flow (runs on the worker thread).
fn capture_rgb_inner() -> Result<(u32, u32, Vec<u8>), CaptureErr> {
    let conn = Connection::session().map_err(err)?;
    let portal = Proxy::new(
        &conn,
        "org.freedesktop.portal.Desktop",
        "/org/freedesktop/portal/desktop",
        "org.freedesktop.portal.ScreenCast",
    )
    .map_err(err)?;

    // Request/Response object paths embed our unique bus name (dots→underscores).
    let unique = conn
        .inner()
        .unique_name()
        .map(|n| n.as_str().trim_start_matches(':').replace('.', "_"))
        .unwrap_or_default();
    let mut counter: u32 = 0;
    let mut new_token = |prefix: &str| {
        counter += 1;
        format!("haive_{prefix}_{counter}")
    };

    // --- CreateSession -------------------------------------------------------
    let sess_token = new_token("s");
    let ht = new_token("r");
    let mut opts: HashMap<&str, Value> = HashMap::new();
    opts.insert("handle_token", Value::from(ht.clone()));
    opts.insert("session_handle_token", Value::from(sess_token));
    let results = portal_request(&conn, &portal, &unique, &ht, "CreateSession", &(opts,))?;
    let session: String = results
        .get("session_handle")
        .and_then(|v| String::try_from(v.try_clone().ok()?).ok())
        .ok_or_else(|| CaptureErr::Unavailable("no session_handle".into()))?;
    let session_path = OwnedObjectPath::try_from(session).map_err(err)?;

    // Run SelectSources/Start/capture, then ALWAYS close the session — GNOME 46's
    // portal SEGV-crashes if a new ScreenCast session is created while a prior one
    // is still open, so a leaked session breaks every later capture.
    let mut counter = 100u32;
    let outcome = run_capture(&conn, &portal, &unique, &session_path, &mut counter);
    close_session(&conn, &session_path);
    drop(conn);
    outcome
}

/// SelectSources → Start (raises the consent dialog first time) → OpenPipeWireRemote
/// → one PipeWire frame. Split out so the caller can always close the session after.
fn run_capture(
    conn: &Connection,
    portal: &Proxy,
    unique: &str,
    session_path: &OwnedObjectPath,
    counter: &mut u32,
) -> Result<(u32, u32, Vec<u8>), CaptureErr> {
    let mut new_token = |prefix: &str| {
        *counter += 1;
        format!("haive_{prefix}_{}", *counter)
    };

    // --- SelectSources (monitor, embedded cursor, persistent) ----------------
    let ht = new_token("r");
    let restore = load_restore_token();
    let mut opts: HashMap<&str, Value> = HashMap::new();
    opts.insert("handle_token", Value::from(ht.clone()));
    opts.insert("types", Value::from(1u32)); // 1 = MONITOR
    opts.insert("multiple", Value::from(false));
    opts.insert("cursor_mode", Value::from(2u32)); // 2 = embedded
    opts.insert("persist_mode", Value::from(2u32)); // 2 = persistent
    if let Some(ref t) = restore {
        opts.insert("restore_token", Value::from(t.clone()));
    }
    portal_request(conn, portal, unique, &ht, "SelectSources", &(session_path, opts))?;

    // --- Start (this is what raises the consent dialog the first time) --------
    let ht = new_token("r");
    let mut opts: HashMap<&str, Value> = HashMap::new();
    opts.insert("handle_token", Value::from(ht.clone()));
    let results = portal_request(conn, portal, unique, &ht, "Start", &(session_path, "", opts))?;

    // Persist the restore_token so the next capture skips the dialog.
    if let Some(tok) = results.get("restore_token").and_then(|v| String::try_from(v.try_clone().ok()?).ok()) {
        save_restore_token(&tok);
    }
    // streams: a(ua{sv}) — take the first node id.
    let node_id = first_stream_node(results.get("streams"))
        .ok_or_else(|| CaptureErr::Unavailable("no stream node".into()))?;

    // --- OpenPipeWireRemote → an fd we stream the node from ------------------
    let fd: zbus::zvariant::OwnedFd = portal
        .call("OpenPipeWireRemote", &(session_path, HashMap::<&str, Value>::new()))
        .map_err(err)?;

    pw_capture_one(fd, node_id)
}

/// Best-effort close of a portal session so GNOME doesn't accumulate (and crash on)
/// dangling ScreenCast sessions.
fn close_session(conn: &Connection, session_path: &OwnedObjectPath) {
    if let Ok(p) = Proxy::new(
        conn,
        "org.freedesktop.portal.Desktop",
        session_path.as_ref(),
        "org.freedesktop.portal.Session",
    ) {
        let _ = p.call::<_, _, ()>("Close", &());
    }
}

/// Call a portal method that returns a Request handle, then block for its
/// `Response(u, a{sv})` signal and return the results map. Response code 0 = ok,
/// 1 = cancelled (consent denied), 2 = ended.
fn portal_request<B>(
    conn: &Connection,
    portal: &Proxy,
    unique: &str,
    handle_token: &str,
    method: &str,
    body: &B,
) -> Result<HashMap<String, OwnedValue>, CaptureErr>
where
    B: serde::ser::Serialize + zbus::zvariant::DynamicType,
{
    let req_path = format!("/org/freedesktop/portal/desktop/request/{unique}/{handle_token}");
    let req = Proxy::new(
        conn,
        "org.freedesktop.portal.Desktop",
        ObjectPath::try_from(req_path).map_err(err)?,
        "org.freedesktop.portal.Request",
    )
    .map_err(err)?;
    let mut signal = req.receive_signal("Response").map_err(err)?;

    let _handle: OwnedObjectPath = portal.call(method, body).map_err(err)?;

    let msg = signal.next().ok_or_else(|| CaptureErr::Unavailable("no portal response".into()))?;
    let (response, results): (u32, HashMap<String, OwnedValue>) = msg.body().deserialize().map_err(err)?;
    match response {
        0 => Ok(results),
        1 => Err(CaptureErr::ConsentPending), // user cancelled / not granted yet
        _ => Err(CaptureErr::Unavailable(format!("portal {method} ended (code {response})"))),
    }
}

/// Extract the first PipeWire node id from the Start results' `streams` value,
/// typed `a(ua{sv})`.
fn first_stream_node(streams: Option<&OwnedValue>) -> Option<u32> {
    let v = streams?;
    let arr = zbus::zvariant::Array::try_from(v.try_clone().ok()?).ok()?;
    for item in arr.iter() {
        if let Ok(s) = zbus::zvariant::Structure::try_from(item.try_clone().ok()?) {
            if let Some(first) = s.fields().first() {
                if let Ok(id) = u32::try_from(first.try_clone().ok()?) {
                    return Some(id);
                }
            }
        }
    }
    None
}

// --- PipeWire: pull exactly one frame from the node --------------------------
use std::cell::RefCell;
use std::rc::Rc;

#[derive(Default)]
struct CapState {
    width: u32,
    height: u32,
    format: u32, // spa VideoFormat raw
    stride: i32,
    frame: Option<Vec<u8>>,
}

fn pw_capture_one(fd: zbus::zvariant::OwnedFd, node_id: u32) -> Result<(u32, u32, Vec<u8>), CaptureErr> {
    use pipewire as pw;
    use pw::spa;
    use std::os::fd::OwnedFd;

    pw::init();
    let mainloop = pw::main_loop::MainLoopRc::new(None).map_err(err)?;
    let context = pw::context::ContextRc::new(&mainloop, None).map_err(err)?;
    // The portal fd owns a connection to the PipeWire remote.
    let owned: OwnedFd = fd.into();
    let core = context.connect_fd_rc(owned, None).map_err(err)?;

    let stream = pw::stream::StreamRc::new(
        core,
        "haive-screencap",
        pw::properties::properties! {
            *pw::keys::MEDIA_TYPE => "Video",
            *pw::keys::MEDIA_CATEGORY => "Capture",
            *pw::keys::MEDIA_ROLE => "Screen",
        },
    )
    .map_err(err)?;

    let state = Rc::new(RefCell::new(CapState::default()));
    // MainLoopWeak isn't Clone, so take a fresh weak ref per callback that quits.
    let weak_p = mainloop.downgrade();
    let weak_t = mainloop.downgrade();

    let st_pc = state.clone();
    let st_pr = state.clone();
    let _listener = stream
        .add_local_listener_with_user_data(())
        .param_changed(move |_stream, _ud, id, param| {
            if id != pw::spa::param::ParamType::Format.as_raw() {
                return;
            }
            let Some(param) = param else { return };
            let Ok((mtype, msubtype)) = pw::spa::param::format_utils::parse_format(param) else { return };
            if mtype != pw::spa::param::format::MediaType::Video
                || msubtype != pw::spa::param::format::MediaSubtype::Raw
            {
                return;
            }
            let mut info = pw::spa::param::video::VideoInfoRaw::new();
            if info.parse(param).is_ok() {
                let mut s = st_pc.borrow_mut();
                s.width = info.size().width;
                s.height = info.size().height;
                s.format = info.format().as_raw();
            }
        })
        .process(move |stream, _ud| {
            let Some(mut buffer) = stream.dequeue_buffer() else { return };
            let datas = buffer.datas_mut();
            let Some(d) = datas.first_mut() else { return };
            // The valid frame lives at chunk offset for `size` bytes; `data()`
            // returns the whole mapped region.
            let stride = d.chunk().stride();
            let offset = d.chunk().offset() as usize;
            let size = d.chunk().size() as usize;
            let bytes = d.data().map(|b| {
                let start = offset.min(b.len());
                let end = (offset + size).min(b.len());
                b[start..end].to_vec()
            });
            if let Some(bytes) = bytes {
                let mut s = st_pr.borrow_mut();
                if s.frame.is_none() && !bytes.is_empty() {
                    s.stride = stride;
                    s.frame = Some(bytes);
                    if let Some(m) = weak_p.upgrade() {
                        m.quit();
                    }
                }
            }
        })
        .register()
        .map_err(err)?;

    // Offer common 32-bit packed formats and any reasonable size; omitting the
    // modifier property keeps buffers CPU-mappable (no DMA-BUF negotiation).
    let obj = pw::spa::pod::object!(
        pw::spa::utils::SpaTypes::ObjectParamFormat,
        pw::spa::param::ParamType::EnumFormat,
        pw::spa::pod::property!(pw::spa::param::format::FormatProperties::MediaType, Id, pw::spa::param::format::MediaType::Video),
        pw::spa::pod::property!(pw::spa::param::format::FormatProperties::MediaSubtype, Id, pw::spa::param::format::MediaSubtype::Raw),
        pw::spa::pod::property!(
            pw::spa::param::format::FormatProperties::VideoFormat,
            Choice, Enum, Id,
            pw::spa::param::video::VideoFormat::BGRx,
            pw::spa::param::video::VideoFormat::RGBx,
            pw::spa::param::video::VideoFormat::BGRA,
            pw::spa::param::video::VideoFormat::RGBA,
            pw::spa::param::video::VideoFormat::BGR,
            pw::spa::param::video::VideoFormat::RGB
        ),
        pw::spa::pod::property!(
            pw::spa::param::format::FormatProperties::VideoSize,
            Choice, Range, Rectangle,
            pw::spa::utils::Rectangle { width: 1920, height: 1080 },
            pw::spa::utils::Rectangle { width: 1, height: 1 },
            pw::spa::utils::Rectangle { width: 8192, height: 8192 }
        ),
        pw::spa::pod::property!(
            pw::spa::param::format::FormatProperties::VideoFramerate,
            Choice, Range, Fraction,
            pw::spa::utils::Fraction { num: 30, denom: 1 },
            pw::spa::utils::Fraction { num: 0, denom: 1 },
            pw::spa::utils::Fraction { num: 120, denom: 1 }
        ),
    );
    let values: Vec<u8> = pw::spa::pod::serialize::PodSerializer::serialize(
        std::io::Cursor::new(Vec::new()),
        &pw::spa::pod::Value::Object(obj),
    )
    .map_err(err)?
    .0
    .into_inner();
    let mut params = [pw::spa::pod::Pod::from_bytes(&values).ok_or_else(|| CaptureErr::Unavailable("bad format pod".into()))?];

    stream
        .connect(
            spa::utils::Direction::Input,
            Some(node_id),
            pw::stream::StreamFlags::AUTOCONNECT | pw::stream::StreamFlags::MAP_BUFFERS,
            &mut params,
        )
        .map_err(err)?;

    // A safety timer so a stream that never produces (denied/ended) doesn't hang.
    let timer = mainloop.loop_().add_timer(move |_| {
        if let Some(m) = weak_t.upgrade() {
            m.quit();
        }
    });
    let _ = timer.update_timer(Some(Duration::from_secs(6)), None);

    mainloop.run();
    let _ = stream.disconnect();

    let s = state.borrow();
    match &s.frame {
        Some(bytes) if s.width > 0 && s.height > 0 => {
            let rgb = to_rgb(bytes, s.width, s.height, s.stride, s.format);
            Ok((s.width, s.height, rgb))
        }
        _ => Err(CaptureErr::Unavailable("no frame produced (consent denied or stream ended)".into())),
    }
}

/// Convert a packed 24/32-bit SPA frame (respecting stride padding) to RGB8.
fn to_rgb(buf: &[u8], w: u32, h: u32, stride: i32, format: u32) -> Vec<u8> {
    use pipewire::spa::param::video::VideoFormat;
    let (w, h) = (w as usize, h as usize);
    let stride = if stride > 0 { stride as usize } else { w * 4 };
    let bpp: usize = match VideoFormat::from_raw(format) {
        VideoFormat::RGB | VideoFormat::BGR => 3,
        _ => 4,
    };
    // Which byte offsets are R,G,B within a pixel, per format.
    let (ri, gi, bi) = match VideoFormat::from_raw(format) {
        VideoFormat::RGBx | VideoFormat::RGBA | VideoFormat::RGB => (0, 1, 2),
        VideoFormat::BGRx | VideoFormat::BGRA | VideoFormat::BGR => (2, 1, 0),
        _ => (2, 1, 0), // default assume BGRx (the common portal format)
    };
    let mut out = Vec::with_capacity(w * h * 3);
    for y in 0..h {
        let row = y * stride;
        for x in 0..w {
            let p = row + x * bpp;
            if p + bi < buf.len() {
                out.push(buf[p + ri]);
                out.push(buf[p + gi]);
                out.push(buf[p + bi]);
            } else {
                out.extend_from_slice(&[0, 0, 0]);
            }
        }
    }
    out
}
