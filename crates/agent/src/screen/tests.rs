// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

use super::tiles::{self, PxRect};
use super::*;
use image::Rgb;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};

fn img(w: u32, h: u32) -> RgbImage {
    RgbImage::from_pixel(w, h, Rgb([10, 20, 30]))
}

/// Paint a block so the tiles it covers change.
fn paint(mut i: RgbImage, x: u32, y: u32, w: u32, h: u32) -> RgbImage {
    for yy in y..y + h {
        for xx in x..x + w {
            i.put_pixel(xx, yy, Rgb([200, (xx % 255) as u8, (yy % 255) as u8]));
        }
    }
    i
}

fn fill(mut i: RgbImage, x: u32, y: u32, w: u32, h: u32, c: [u8; 3]) -> RgbImage {
    for yy in y..y + h {
        for xx in x..x + w {
            i.put_pixel(xx, yy, Rgb(c));
        }
    }
    i
}

fn shot(i: RgbImage) -> Shot {
    Shot { img: i, cursor: Some((5, 6)), desktop: None }
}

fn no_encoder(_: u32, _: u32, _: u8) -> Result<Box<dyn VideoEncoder>, String> {
    Err("no encoder in this test".into())
}

/// Run `respond` against a scripted sequence of captures (the last one repeats).
fn run(s: &mut Session, query: &str, frames: Vec<Shot>, h264: bool, enc: &NewEncoder) -> (wire::Header, Vec<u8>) {
    let mut q: VecDeque<Shot> = frames.into();
    let mut capture = |_w: u32| -> Result<Shot, String> {
        let s = if q.len() > 1 { q.pop_front().unwrap() } else { q.front().map(|s| Shot { img: s.img.clone(), cursor: s.cursor, desktop: s.desktop.clone() }).unwrap() };
        Ok(s)
    };
    let mut env = Env {
        capture: &mut capture,
        h264_available: h264,
        new_encoder: enc,
        poll_every: Duration::from_millis(1),
        poll_max: Duration::from_millis(5),
    };
    let p = parse(query, 60, 1600).expect("valid query");
    let r = respond(s, &p, &mut env);
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.ctype, "application/x-itai-screen");
    let (h, payload) = wire::decode(&r.body).expect("decodes");
    (h, payload.to_vec())
}

// ---- params -------------------------------------------------------------

#[test]
fn sid_validation() {
    for bad in ["", "sid=", "sid=a%20b", "sid=a.b", "sid=a/b", "ack=1", "sid=ü"] {
        assert!(parse(bad, 60, 1600).is_err(), "{bad:?} should be rejected");
    }
    let long = format!("sid={}", "a".repeat(65));
    assert!(parse(&long, 60, 1600).is_err());
    let max = format!("sid={}", "a".repeat(64));
    assert!(parse(&max, 60, 1600).is_ok());
    assert_eq!(parse("sid=Ab_9-z", 60, 1600).unwrap().sid, "Ab_9-z");
    // handle() answers 400 before touching the screen.
    let r = handle(&Grabber { index: 0 }, 60, 1600, "sid=bad!&ack=0");
    assert_eq!(r.status, 400);
    assert!(String::from_utf8_lossy(&r.body).contains("bad sid"));
}

#[test]
fn params_clamp_and_default() {
    let p = parse("sid=a", 60, 1600).unwrap();
    assert_eq!(p, Params { sid: "a".into(), ack: 0, codec: Codec::Tiles, q: 60, w: 1600 });
    let p = parse("sid=a&ack=7&codec=h264&q=5&w=99999&t=123", 95, 0).unwrap();
    assert_eq!((p.ack, p.codec, p.q, p.w), (7, Codec::H264, 20, 3840));
    let p = parse("sid=a&q=200&w=10", 60, 1600).unwrap();
    assert_eq!((p.q, p.w), (90, 320));
    assert_eq!(parse("sid=a", 10, 0).unwrap().q, 20);
    assert!(parse("sid=a&codec=vp9", 60, 1600).is_err());
    assert!(parse("sid=a&ack=-1", 60, 1600).is_err());
    assert!(parse("sid=a&q=x", 60, 1600).is_err());
}

// ---- tiles --------------------------------------------------------------

#[test]
fn tile_diff_marks_only_touched_tiles() {
    let a = img(200, 130); // 4x3 grid, edge tiles 8 wide / 2 high
    let mut b = a.clone();
    b.put_pixel(70, 140 - 12, Rgb([0, 0, 0])); // tile (1, 2)
    b.put_pixel(199, 0, Rgb([0, 0, 0])); // tile (3, 0) — the narrow edge tile
    let d = tiles::diff(&a, &b);
    assert_eq!(tiles::grid(200, 130), (4, 3));
    let on: Vec<usize> = d.iter().enumerate().filter(|(_, &c)| c).map(|(i, _)| i).collect();
    assert_eq!(on, vec![3, 2 * 4 + 1]);
    assert!(tiles::diff(&a, &a).iter().all(|&c| !c));
}

#[test]
fn rect_merge_runs_then_identical_spans() {
    // 5x4 grid over 300x250 (edge tiles 44 wide, 58 high).
    let (w, h) = (300, 250);
    let mut c = vec![false; 20];
    let set = |c: &mut Vec<bool>, col: usize, row: usize| c[row * 5 + col] = true;
    // Rows 0-1, cols 1-2: one 2x2 block → one rect.
    for (col, row) in [(1, 0), (2, 0), (1, 1), (2, 1)] {
        set(&mut c, col, row);
    }
    // Row 0 col 4 (edge) alone; row 1 col 4 too → stacked, same span → one rect.
    set(&mut c, 4, 0);
    set(&mut c, 4, 1);
    // Row 3: cols 0-1 (bottom edge row) — different span from anything above.
    set(&mut c, 0, 3);
    set(&mut c, 1, 3);
    // Row 2: col 0 only — span differs from row 3's 0-1, so not merged.
    set(&mut c, 0, 2);
    let r = tiles::merge(&c, w, h);
    assert_eq!(
        r,
        vec![
            PxRect { x: 64, y: 0, w: 128, h: 128 },
            PxRect { x: 256, y: 0, w: 44, h: 128 },
            PxRect { x: 0, y: 128, w: 64, h: 64 },
            PxRect { x: 0, y: 192, w: 128, h: 58 },
        ]
    );
    // Covered area == changed tiles' area.
    assert!(tiles::merge(&[false; 20], w, h).is_empty());
    let all = tiles::merge(&[true; 20], w, h);
    assert_eq!(all, vec![PxRect { x: 0, y: 0, w: 300, h: 250 }]);
}

#[test]
fn mostly_changed_threshold_is_sixty_percent() {
    let mut c = vec![false; 10];
    c[..6].iter_mut().for_each(|x| *x = true);
    assert!(!tiles::mostly_changed(&c), "exactly 60% is not more than 60%");
    c[6] = true;
    assert!(tiles::mostly_changed(&c));
}

// ---- key-frame rules -----------------------------------------------------

#[test]
fn first_response_is_a_full_key_frame_then_deltas() {
    let mut s = Session::default();
    let base = img(320, 200);
    let (h, payload) = run(&mut s, "sid=a&ack=0", vec![shot(base.clone())], false, &no_encoder);
    assert!(h.key && !h.unchanged);
    assert_eq!((h.seq, h.w, h.h, h.codec.as_str()), (1, 320, 200, "tiles"));
    assert_eq!(h.rects.len(), 1);
    assert_eq!((h.rects[0].x, h.rects[0].y, h.rects[0].w, h.rects[0].h), (0, 0, 320, 200));
    assert_eq!(h.rects[0].len, payload.len());
    assert_eq!(h.cursor, Some(wire::Point { x: 5, y: 6 }));

    let next = paint(base, 70, 70, 10, 10); // tile (1,1)
    let (h, _) = run(&mut s, "sid=a&ack=1", vec![shot(next)], false, &no_encoder);
    assert!(!h.key && !h.unchanged);
    assert_eq!(h.seq, 2);
    assert_eq!(h.rects.len(), 1);
    assert_eq!((h.rects[0].x, h.rects[0].y, h.rects[0].w, h.rects[0].h), (64, 64, 64, 64));
}

#[test]
fn ack_mismatch_forces_a_key_frame() {
    let mut s = Session::default();
    let base = img(320, 200);
    run(&mut s, "sid=a&ack=0", vec![shot(base.clone())], false, &no_encoder);
    let next = paint(base.clone(), 0, 0, 5, 5);
    // The viewer never got seq 1 (still acks 0) → key frame.
    let (h, _) = run(&mut s, "sid=a&ack=0", vec![shot(next.clone())], false, &no_encoder);
    assert!(h.key);
    assert_eq!(h.rects.len(), 1);
    assert_eq!((h.rects[0].w, h.rects[0].h), (320, 200));
    // A stale / unknown ack too, even with nothing changed.
    let (h, _) = run(&mut s, "sid=a&ack=1", vec![shot(next)], false, &no_encoder);
    assert!(h.key && !h.unchanged);
    assert_eq!(h.seq, 3);
}

#[test]
fn size_change_forces_a_key_frame() {
    let mut s = Session::default();
    run(&mut s, "sid=a&ack=0", vec![shot(img(320, 200))], false, &no_encoder);
    let (h, _) = run(&mut s, "sid=a&ack=1", vec![shot(img(640, 400))], false, &no_encoder);
    assert!(h.key);
    assert_eq!((h.w, h.h), (640, 400));
    assert_eq!((h.rects[0].w, h.rects[0].h), (640, 400));
}

#[test]
fn more_than_sixty_percent_changed_sends_one_full_frame() {
    let mut s = Session::default();
    let base = img(320, 256); // 5x4 = 20 tiles
    run(&mut s, "sid=a&ack=0", vec![shot(base.clone())], false, &no_encoder);
    let next = paint(base, 0, 0, 320, 64 * 3 + 1); // 15 of 20 tiles + bottom row one pixel = all 20
    let (h, _) = run(&mut s, "sid=a&ack=1", vec![shot(next.clone())], false, &no_encoder);
    assert!(h.key);
    assert_eq!(h.rects.len(), 1);
    assert_eq!((h.rects[0].w, h.rects[0].h), (320, 256));
    // 12 of 20 = 60% → still a delta.
    let next2 = fill(next, 0, 0, 192, 256, [1, 2, 3]);
    let (h, _) = run(&mut s, "sid=a&ack=2", vec![shot(next2)], false, &no_encoder);
    assert!(!h.key, "60% exactly stays a delta");
    assert_eq!(h.rects.len(), 1);
    assert_eq!((h.rects[0].w, h.rects[0].h), (192, 256));
}

#[test]
fn unchanged_long_polls_then_repeats_seq() {
    let mut s = Session::default();
    let base = img(320, 200);
    run(&mut s, "sid=a&ack=0", vec![shot(base.clone())], false, &no_encoder);
    let t = Instant::now();
    let (h, payload) = run(&mut s, "sid=a&ack=1", vec![shot(base.clone())], false, &no_encoder);
    assert!(h.unchanged && !h.key);
    assert_eq!(h.seq, 1);
    assert!(h.rects.is_empty() && payload.is_empty());
    assert!(t.elapsed() >= Duration::from_millis(4), "polled until poll_max");
    assert!(h.wait_ms >= 2, "wait_ms {}", h.wait_ms);
    // A change on a later poll ends the wait with a delta.
    let later = paint(base, 300, 195, 5, 5);
    let (h, _) = run(&mut s, "sid=a&ack=1", vec![shot(img(320, 200)), shot(img(320, 200)), shot(later)], false, &no_encoder);
    assert!(!h.unchanged && !h.key);
    assert_eq!(h.seq, 2);
    assert_eq!((h.rects[0].x, h.rects[0].y), (256, 192));
}

#[test]
fn pointer_move_ends_the_long_poll_early() {
    let mut s = Session::default();
    let base = img(320, 200);
    run(&mut s, "sid=a&ack=0", vec![shot(base.clone())], false, &no_encoder);
    let moved = Shot { img: base, cursor: Some((100, 50)), desktop: Some("default".into()) };
    let (h, _) = run(&mut s, "sid=a&ack=1", vec![moved], false, &no_encoder);
    assert!(h.unchanged);
    assert_eq!(h.seq, 1);
    assert_eq!(h.wait_ms, 0);
    assert_eq!(h.cursor, Some(wire::Point { x: 100, y: 50 }));
    assert_eq!(h.desktop.as_deref(), Some("default"));
}

#[test]
fn capture_failure_is_500_with_the_reason() {
    let mut s = Session::default();
    let mut capture = |_w: u32| -> Result<Shot, String> { Err(crate::capture::NO_DISPLAY.to_string()) };
    let mut env = Env {
        capture: &mut capture,
        h264_available: false,
        new_encoder: &no_encoder,
        poll_every: Duration::from_millis(1),
        poll_max: Duration::from_millis(5),
    };
    let r = respond(&mut s, &parse("sid=a", 60, 1600).unwrap(), &mut env);
    assert_eq!(r.status, 500);
    assert_eq!(String::from_utf8(r.body).unwrap(), crate::capture::NO_DISPLAY);
    assert_eq!(s.seq, 0);
}

// ---- wire ------------------------------------------------------------------

#[test]
fn wire_round_trip_and_rect_payloads_decode() {
    let mut s = Session::default();
    let base = img(320, 200);
    run(&mut s, "sid=a&ack=0", vec![shot(base.clone())], false, &no_encoder);
    let next = paint(paint(base, 0, 0, 10, 10), 300, 150, 10, 10);
    let mut capture_once = Some(shot(next));
    let mut capture = |_w: u32| -> Result<Shot, String> { capture_once.take().ok_or_else(|| "once".to_string()) };
    let mut env = Env {
        capture: &mut capture,
        h264_available: false,
        new_encoder: &no_encoder,
        poll_every: Duration::from_millis(1),
        poll_max: Duration::from_millis(5),
    };
    let r = respond(&mut s, &parse("sid=a&ack=1&q=80", 60, 1600).unwrap(), &mut env);
    let body = r.body;
    assert_eq!(&body[..4], b"ITS1");
    let n = u32::from_le_bytes(body[4..8].try_into().unwrap()) as usize;
    let json: serde_json::Value = serde_json::from_slice(&body[8..8 + n]).unwrap();
    for k in ["seq", "key", "codec", "w", "h", "rects", "unchanged", "cursor", "desktop", "enc_ms", "note"] {
        assert!(json.get(k).is_some(), "header lacks {k}: {json}");
    }
    assert!(json["note"].is_null() && json["desktop"].is_null());
    let (h, payload) = wire::decode(&body).unwrap();
    assert_eq!(h.rects.len(), 2);
    let mut end = 0;
    for r in &h.rects {
        assert_eq!(r.off, end, "rects are packed back to back");
        end = r.off + r.len;
        let jpeg = image::load_from_memory_with_format(&payload[r.off..r.off + r.len], image::ImageFormat::Jpeg).unwrap();
        assert_eq!((jpeg.width(), jpeg.height()), (r.w, r.h));
    }
    assert_eq!(end, payload.len());
    // Encoder side round trip of an arbitrary header.
    let hdr = wire::Header { note: Some("x — y".into()), ..h.clone() };
    let enc = wire::encode(&hdr, b"abc");
    let (back, p) = wire::decode(&enc).unwrap();
    assert_eq!(back, hdr);
    assert_eq!(p, b"abc");
}

// ---- sessions --------------------------------------------------------------

#[test]
fn session_table_evicts_idle_then_lru() {
    let mut t = Vec::new();
    let t0 = Instant::now();
    let a = session_for(&mut t, "a", t0);
    a.lock().unwrap().seq = 42;
    for i in 1..8 {
        session_for(&mut t, &format!("s{i}"), t0 + Duration::from_secs(i));
    }
    assert_eq!(t.len(), 8);
    // Touch "a" so s1 becomes least recently used.
    assert_eq!(session_for(&mut t, "a", t0 + Duration::from_secs(10)).lock().unwrap().seq, 42);
    session_for(&mut t, "new", t0 + Duration::from_secs(11));
    assert_eq!(t.len(), 8);
    assert!(t.iter().all(|e| e.sid != "s1"), "LRU s1 evicted");
    assert!(t.iter().any(|e| e.sid == "a"));
    // 60 s idle: everything but the session touched now goes.
    session_for(&mut t, "a", t0 + Duration::from_secs(70));
    let mut left: Vec<&str> = t.iter().map(|e| e.sid.as_str()).collect();
    left.sort();
    assert_eq!(left, vec!["a", "new"]);
    session_for(&mut t, "late", t0 + Duration::from_secs(131));
    let left: Vec<&str> = t.iter().map(|e| e.sid.as_str()).collect();
    assert_eq!(left, vec!["late"], "a and new idle 61 s / 120 s");
    // An evicted sid comes back fresh (seq 0 → its next answer is a key frame).
    assert_eq!(session_for(&mut t, "a", t0 + Duration::from_secs(132)).lock().unwrap().seq, 0);
}

// ---- h264 --------------------------------------------------------------------

const IDR_AU: &[u8] = &[0, 0, 0, 1, 0x67, 1, 0, 0, 0, 1, 0x68, 2, 0, 0, 1, 0x65, 3];
const P_AU: &[u8] = &[0, 0, 0, 1, 0x41, 9];

struct Fake {
    fail: bool,
}

impl VideoEncoder for Fake {
    fn encode(&mut self, frame: &RgbImage, force_key: bool) -> Result<Vec<u8>, String> {
        assert!(frame.width().is_multiple_of(2) && frame.height().is_multiple_of(2), "odd frame reached the encoder");
        if self.fail {
            return Err("MFT said no".into());
        }
        Ok(if force_key { IDR_AU.to_vec() } else { P_AU.to_vec() })
    }
}

static MADE: AtomicUsize = AtomicUsize::new(0);

fn fake(_: u32, _: u32, _: u8) -> Result<Box<dyn VideoEncoder>, String> {
    MADE.fetch_add(1, Ordering::SeqCst);
    Ok(Box::new(Fake { fail: false }))
}

fn failing(_: u32, _: u32, _: u8) -> Result<Box<dyn VideoEncoder>, String> {
    Ok(Box::new(Fake { fail: true }))
}

#[test]
fn h264_unavailable_answers_tiles_with_a_note() {
    let mut s = Session::default();
    let (h, _) = run(&mut s, "sid=a&codec=h264", vec![shot(img(320, 200))], false, &fake);
    assert_eq!(h.codec, "tiles");
    assert_eq!(h.note.as_deref(), Some(NO_H264));
    assert_eq!(h.rects.len(), 1);
}

#[test]
fn h264_session_idr_then_p_then_key_on_ack_mismatch() {
    let before = MADE.load(Ordering::SeqCst);
    let mut s = Session::default();
    let base = img(321, 201); // odd → encoded at 320x200
    let (h, p) = run(&mut s, "sid=a&codec=h264", vec![shot(base.clone())], true, &fake);
    assert_eq!((h.codec.as_str(), h.key, h.w, h.h), ("h264", true, 320, 200));
    assert!(h.rects.is_empty() && h.note.is_none());
    assert_eq!(p, IDR_AU);
    let next = paint(base.clone(), 0, 0, 4, 4);
    let (h, p) = run(&mut s, "sid=a&ack=1&codec=h264", vec![shot(next.clone())], true, &fake);
    assert_eq!((h.key, h.seq), (false, 2));
    assert_eq!(p, P_AU);
    // Unchanged → long poll, empty.
    let (h, p) = run(&mut s, "sid=a&ack=2&codec=h264", vec![shot(next.clone())], true, &fake);
    assert!(h.unchanged && p.is_empty() && h.seq == 2);
    // Lost response → IDR from the same encoder.
    let (h, p) = run(&mut s, "sid=a&ack=1&codec=h264", vec![shot(next.clone())], true, &fake);
    assert!(h.key);
    assert_eq!(p, IDR_AU);
    assert_eq!(MADE.load(Ordering::SeqCst) - before, 1, "one encoder so far");
    // Size change → new encoder, IDR.
    let (h, p) = run(&mut s, "sid=a&ack=4&codec=h264", vec![shot(img(640, 400))], true, &fake);
    assert!(h.key && (h.w, h.h) == (640, 400));
    assert_eq!(p, IDR_AU);
    assert_eq!(MADE.load(Ordering::SeqCst) - before, 2);
    // Switching to tiles is a codec change → key frame.
    let (h, _) = run(&mut s, "sid=a&ack=5", vec![shot(img(640, 400))], true, &fake);
    assert!(h.key && h.codec == "tiles");
}

#[test]
fn h264_encoder_error_falls_back_to_tiles_for_the_session() {
    let mut s = Session::default();
    let (h, p) = run(&mut s, "sid=a&codec=h264", vec![shot(img(320, 200))], true, &failing);
    assert_eq!(h.codec, "tiles");
    assert!(h.key);
    assert!(h.note.as_deref().unwrap().contains("MFT said no"), "{:?}", h.note);
    assert_eq!(h.rects.len(), 1);
    assert_eq!(h.rects[0].len, p.len());
    // Sticky: the session keeps sending tiles (as deltas) without retrying h264.
    let next = paint(img(320, 200), 0, 0, 4, 4);
    let (h, _) = run(&mut s, "sid=a&ack=1&codec=h264", vec![shot(next)], true, &fake);
    assert_eq!(h.codec, "tiles");
    assert!(!h.key);
    assert!(h.note.as_deref().unwrap().contains("MFT said no"));
    // Encoder creation failure behaves the same.
    let mut s = Session::default();
    let (h, _) = run(&mut s, "sid=a&codec=h264", vec![shot(img(320, 200))], true, &no_encoder);
    assert_eq!(h.codec, "tiles");
    assert!(h.note.as_deref().unwrap().contains("no encoder in this test"));
}

#[test]
fn idr_detection() {
    assert!(has_idr(IDR_AU));
    assert!(!has_idr(P_AU));
    assert!(!has_idr(&[]));
}

#[test]
fn capabilities_list_h264_only_when_available() {
    let c = capabilities();
    assert_eq!(c["proto"], 1);
    let codecs: Vec<&str> = c["codecs"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
    assert_eq!(codecs.contains(&"h264"), crate::h264::available());
    assert_eq!(codecs[0], "tiles");
}

// ---- real screen (manual) ----------------------------------------------------

/// `cargo test -p it-ai-agent live_screen_sizes -- --ignored --nocapture`
#[test]
#[ignore]
fn live_screen_sizes() {
    let g = Grabber { index: 0 };
    let sid = format!("live{}", std::process::id());
    let t = Instant::now();
    let r1 = handle(&g, 60, 1600, &format!("sid={sid}&ack=0"));
    assert_eq!(r1.status, 200, "{}", String::from_utf8_lossy(&r1.body));
    let (h1, _) = wire::decode(&r1.body).unwrap();
    println!("KEY   : {} bytes, {}x{}, rects {}, enc_ms {}, cursor {:?}, wall {:?}", r1.body.len(), h1.w, h1.h, h1.rects.len(), h1.enc_ms, h1.cursor, t.elapsed());
    let mut seq = h1.seq;
    for i in 0..3 {
        let t = Instant::now();
        let r = handle(&g, 60, 1600, &format!("sid={sid}&ack={seq}"));
        let (h, _) = wire::decode(&r.body).unwrap();
        seq = h.seq;
        println!(
            "DELTA{}: {} bytes, seq {}, key {}, unchanged {}, rects {}, enc_ms {}, wait_ms {}, cursor {:?}, wall {:?}",
            i, r.body.len(), h.seq, h.key, h.unchanged, h.rects.len(), h.enc_ms, h.wait_ms, h.cursor, t.elapsed()
        );
    }
    // The same with codec=h264 (tiles + note when this device has no encoder).
    let sid = format!("live264{}", std::process::id());
    let mut seq = 0;
    for i in 0..4 {
        let t = Instant::now();
        let r = handle(&g, 60, 1600, &format!("sid={sid}&ack={seq}&codec=h264"));
        let (h, _) = wire::decode(&r.body).unwrap();
        seq = h.seq;
        println!(
            "H264-{}: {} bytes, codec {}, seq {}, key {}, unchanged {}, {}x{}, enc_ms {}, wait_ms {}, note {:?}, wall {:?}",
            i, r.body.len(), h.codec, h.seq, h.key, h.unchanged, h.w, h.h, h.enc_ms, h.wait_ms, h.note, t.elapsed()
        );
    }
    let jpeg = g.grab(60, 1600).unwrap();
    std::fs::write("/private/tmp/claude-502/frame-arrow.jpg", &jpeg).unwrap();
    println!("FRAME : {} bytes (with arrow) at cursor {:?}", jpeg.len(), crate::cursor::position(0));
}
