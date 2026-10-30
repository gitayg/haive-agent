// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

// Delta-encoded live screen (`GET /screen`). Wire format: docs/SCREEN-PROTOCOL.md.
use crate::capture::Grabber;
use image::RgbImage;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

mod tiles;
mod wire;

#[cfg(test)]
mod tests;

pub struct Reply {
    pub status: u16,
    pub ctype: &'static str,
    pub body: Vec<u8>,
}

const MAX_SESSIONS: usize = 8;
const IDLE: Duration = Duration::from_secs(60);
const POLL_EVERY: Duration = Duration::from_millis(70);
const POLL_MAX: Duration = Duration::from_millis(1000);
const NO_H264: &str = "h264 encoder unavailable on this device — sending tiles";

/// Serve one `/screen` request. `query` is the raw query string (no leading `?`).
pub fn handle(grabber: &Grabber, default_q: u8, default_w: u32, query: &str) -> Reply {
    let p = match parse(query, default_q, default_w) {
        Ok(p) => p,
        Err(e) => return text(400, e),
    };
    let session = {
        let mut table = TABLE.lock().unwrap_or_else(|e| e.into_inner());
        session_for(&mut table, &p.sid, Instant::now())
    };
    let mut s = session.lock().unwrap_or_else(|e| e.into_inner());
    let mut capture = |max_w: u32| -> Result<Shot, String> {
        let desktop = crate::securedesk::follow_input_desktop();
        let f = grabber.grab_rgb(max_w)?;
        let cursor = crate::cursor::position(grabber.index);
        let cursor = crate::cursor::to_output(cursor, (f.src_w, f.src_h), f.img.dimensions());
        Ok(Shot { img: f.img, cursor, desktop })
    };
    let mut env = Env {
        capture: &mut capture,
        h264_available: crate::h264::available(),
        new_encoder: &os_encoder,
        poll_every: POLL_EVERY,
        poll_max: POLL_MAX,
    };
    respond(&mut s, &p, &mut env)
}

/// The hello `info.screen` capability object.
pub fn capabilities() -> serde_json::Value {
    let mut codecs = vec!["tiles"];
    if crate::h264::available() {
        codecs.push("h264");
    }
    serde_json::json!({"proto": 1, "codecs": codecs, "sas": crate::securedesk::sas_available()})
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Codec {
    Tiles,
    H264,
}

impl Codec {
    fn name(self) -> &'static str {
        match self {
            Codec::Tiles => "tiles",
            Codec::H264 => "h264",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Params {
    sid: String,
    ack: u64,
    codec: Codec,
    q: u8,
    w: u32,
}

fn parse(query: &str, default_q: u8, default_w: u32) -> Result<Params, String> {
    let (mut sid, mut ack, mut codec) = (None, 0u64, Codec::Tiles);
    let mut q = default_q.clamp(20, 90);
    let mut w = if default_w == 0 { 3840 } else { default_w.clamp(320, 3840) };
    for pair in query.split('&').filter(|s| !s.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        match k {
            "sid" => sid = Some(v),
            "ack" => ack = v.parse().map_err(|_| format!("bad ack {v:?}: expected an unsigned integer"))?,
            "codec" => {
                codec = match v {
                    "tiles" | "" => Codec::Tiles,
                    "h264" => Codec::H264,
                    _ => return Err(format!("bad codec {v:?}: expected tiles or h264")),
                }
            }
            "q" => q = v.parse::<u32>().map_err(|_| format!("bad q {v:?}"))?.clamp(20, 90) as u8,
            "w" => w = v.parse::<u32>().map_err(|_| format!("bad w {v:?}"))?.clamp(320, 3840),
            _ => {}
        }
    }
    let sid = sid.unwrap_or("");
    let ok = (1..=64).contains(&sid.len()) && sid.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if !ok {
        return Err("bad sid: 1-64 characters of [A-Za-z0-9_-] required".into());
    }
    Ok(Params { sid: sid.to_string(), ack, codec, q, w })
}

/// An encoder for the h264 codec. A trait so tests can stand in for the OS one.
trait VideoEncoder: Send {
    fn encode(&mut self, frame: &RgbImage, force_key: bool) -> Result<Vec<u8>, String>;
}

struct OsEncoder(crate::h264::Encoder);

// SAFETY: an encoder lives in one session and is only touched while that
// session's mutex is held, so it is never used from two threads at once — but
// successive requests run on different HTTP worker threads. The OS encoders
// (Media Foundation MFT in the MTA, VideoToolbox compression session) allow
// that kind of serialized cross-thread use.
unsafe impl Send for OsEncoder {}

impl VideoEncoder for OsEncoder {
    fn encode(&mut self, frame: &RgbImage, force_key: bool) -> Result<Vec<u8>, String> {
        self.0.encode(frame, force_key)
    }
}

fn os_encoder(w: u32, h: u32, q: u8) -> Result<Box<dyn VideoEncoder>, String> {
    Ok(Box::new(OsEncoder(crate::h264::Encoder::new(w, h, q)?)))
}

/// One capture at output size, with the pointer already mapped into it.
struct Shot {
    img: RgbImage,
    cursor: Option<(i32, i32)>,
    desktop: Option<String>,
}

/// Everything `respond` needs from the outside world (real screen or a test).
struct Env<'a> {
    capture: &'a mut dyn FnMut(u32) -> Result<Shot, String>,
    h264_available: bool,
    new_encoder: &'a NewEncoder,
    poll_every: Duration,
    poll_max: Duration,
}

#[derive(Default)]
struct Session {
    seq: u64,
    /// The last frame sent, at output size.
    prev: Option<RgbImage>,
    codec: Option<Codec>,
    cursor: Option<(i32, i32)>,
    /// The h264 encoder and the (even) size it was made for.
    enc: Option<(Box<dyn VideoEncoder>, u32, u32)>,
    /// Set when the h264 encoder failed: the session sends tiles from then on.
    h264_failed: Option<String>,
}

struct Entry {
    sid: String,
    last: Instant,
    session: Arc<Mutex<Session>>,
}

static TABLE: Mutex<Vec<Entry>> = Mutex::new(Vec::new());

/// Find or create the session for `sid`: drop sessions idle for 60 s, and when
/// the table is full evict the least recently used one.
fn session_for(table: &mut Vec<Entry>, sid: &str, now: Instant) -> Arc<Mutex<Session>> {
    table.retain(|e| now.saturating_duration_since(e.last) < IDLE);
    if let Some(e) = table.iter_mut().find(|e| e.sid == sid) {
        e.last = now;
        return e.session.clone();
    }
    if table.len() >= MAX_SESSIONS {
        if let Some(i) = table.iter().enumerate().min_by_key(|(_, e)| e.last).map(|(i, _)| i) {
            table.remove(i);
        }
    }
    let session = Arc::new(Mutex::new(Session::default()));
    table.push(Entry { sid: sid.to_string(), last: now, session: session.clone() });
    session
}

fn text(status: u16, msg: impl Into<String>) -> Reply {
    Reply { status, ctype: "text/plain; charset=utf-8", body: msg.into().into_bytes() }
}

/// True when an Annex-B access unit contains an IDR slice (NAL type 5).
fn has_idr(au: &[u8]) -> bool {
    au.windows(4).any(|w| w[0] == 0 && w[1] == 0 && w[2] == 1 && w[3] & 0x1f == 5)
}

/// Build one response for session `s`. Long-polls while nothing changed.
fn respond(s: &mut Session, p: &Params, env: &mut Env) -> Reply {
    let t0 = Instant::now();
    let mut wait = Duration::ZERO;
    let (mut codec, mut note) = match p.codec {
        Codec::H264 if !env.h264_available => (Codec::Tiles, Some(NO_H264.to_string())),
        Codec::H264 => match &s.h264_failed {
            Some(e) => (Codec::Tiles, Some(format!("h264 encoder failed ({e}) — sending tiles"))),
            None => (Codec::H264, None),
        },
        Codec::Tiles => (Codec::Tiles, None),
    };
    // Capture until something changed, the pointer moved, or the poll ran out.
    let (shot, mut key, changed) = loop {
        let shot = match (env.capture)(p.w) {
            Ok(shot) => shot,
            Err(e) => return text(500, e),
        };
        let same_size = s.prev.as_ref().map(|i| i.dimensions()) == Some(shot.img.dimensions());
        if p.ack == 0 || p.ack != s.seq || s.codec != Some(codec) || !same_size {
            break (shot, true, Vec::new());
        }
        let changed = tiles::diff(s.prev.as_ref().unwrap(), &shot.img);
        if changed.iter().any(|&c| c) {
            break (shot, false, changed);
        }
        if shot.cursor != s.cursor || t0.elapsed() + env.poll_every > env.poll_max {
            s.cursor = shot.cursor;
            let (w, h) = sent_size(codec, &shot.img);
            let header = header(s.seq, false, codec, (w, h), Vec::new(), true, &shot, t0, wait, note);
            return ok(&header, &[]);
        }
        let slept = Instant::now();
        std::thread::sleep(env.poll_every);
        wait += slept.elapsed();
    };

    let mut payload = Vec::new();
    let mut rects = Vec::new();
    let (w, h) = sent_size(codec, &shot.img);
    if codec == Codec::H264 {
        match encode_h264(s, env.new_encoder, &shot.img, (w, h), p.q, key) {
            Ok((au, idr)) => {
                payload = au;
                key = key || idr;
            }
            Err(e) => {
                s.enc = None;
                note = Some(format!("h264 encoder failed ({e}) — sending tiles"));
                s.h264_failed = Some(e);
                codec = Codec::Tiles;
                key = true;
            }
        }
    }
    let (w, h) = sent_size(codec, &shot.img);
    if codec == Codec::Tiles {
        let full = [tiles::PxRect { x: 0, y: 0, w, h }];
        let list = if key || tiles::mostly_changed(&changed) {
            key = true;
            full.to_vec()
        } else {
            tiles::merge(&changed, w, h)
        };
        let (encoded, bytes) = tiles::encode(&shot.img, &list, p.q);
        payload = bytes;
        rects = encoded
            .into_iter()
            .map(|(r, off, len)| wire::Rect { x: r.x, y: r.y, w: r.w, h: r.h, off, len })
            .collect();
    }
    s.seq += 1;
    s.codec = Some(codec);
    s.cursor = shot.cursor;
    let header = header(s.seq, key, codec, (w, h), rects, false, &shot, t0, wait, note);
    s.prev = Some(shot.img);
    ok(&header, &payload)
}

/// Output size on the wire: h264 needs even dimensions, so it drops the odd edge.
fn sent_size(codec: Codec, img: &RgbImage) -> (u32, u32) {
    match codec {
        Codec::H264 => (img.width() & !1, img.height() & !1),
        Codec::Tiles => img.dimensions(),
    }
}

/// Encode one frame with the session's encoder, (re)creating it when the size
/// changed. A quality change alone does not recreate it (that would cost an IDR
/// on every adaptive step). Returns the access unit and whether it holds an IDR.
type NewEncoder = dyn Fn(u32, u32, u8) -> Result<Box<dyn VideoEncoder>, String>;

fn encode_h264(
    s: &mut Session,
    new_encoder: &NewEncoder,
    img: &RgbImage,
    (w, h): (u32, u32),
    q: u8,
    key: bool,
) -> Result<(Vec<u8>, bool), String> {
    if w < 2 || h < 2 {
        return Err(format!("frame {w}x{h} too small"));
    }
    let mut force = key;
    if !matches!(&s.enc, Some((_, ew, eh)) if (*ew, *eh) == (w, h)) {
        s.enc = None;
        s.enc = Some((new_encoder(w, h, q)?, w, h));
        force = true;
    }
    let enc = &mut s.enc.as_mut().unwrap().0;
    let au = if img.dimensions() == (w, h) {
        enc.encode(img, force)?
    } else {
        enc.encode(&image::imageops::crop_imm(img, 0, 0, w, h).to_image(), force)?
    };
    let idr = has_idr(&au);
    Ok((au, force || idr))
}

#[allow(clippy::too_many_arguments)]
fn header(
    seq: u64,
    key: bool,
    codec: Codec,
    (w, h): (u32, u32),
    rects: Vec<wire::Rect>,
    unchanged: bool,
    shot: &Shot,
    t0: Instant,
    wait: Duration,
    note: Option<String>,
) -> wire::Header {
    wire::Header {
        seq,
        key,
        codec: codec.name().to_string(),
        w,
        h,
        rects,
        unchanged,
        cursor: shot.cursor.map(|(x, y)| wire::Point { x, y }),
        desktop: shot.desktop.clone(),
        enc_ms: t0.elapsed().as_millis() as u64,
        wait_ms: wait.as_millis() as u64,
        note,
    }
}

fn ok(header: &wire::Header, payload: &[u8]) -> Reply {
    Reply { status: 200, ctype: wire::CONTENT_TYPE, body: wire::encode(header, payload) }
}
