// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

// H.264 through the operating system's own encoder (Media Foundation on Windows,
// VideoToolbox on macOS). Elsewhere `available()` is false and `/screen` sends tiles.
//
// Output is Baseline profile (Constrained Baseline where the OS offers it), no
// B-frames, one Annex-B access unit per frame, SPS+PPS before every IDR, an IDR
// on request or every GOP frames. The viewer takes its WebCodecs codec string
// from the SPS of the first key frame (`annexb::codec_string`).

mod annexb;
mod convert;
#[cfg(target_os = "macos")]
mod mac;
#[cfg(windows)]
mod win;
#[cfg(test)]
mod tests;

use std::sync::OnceLock;

/// Frames between forced IDRs when the caller never asks for one.
#[cfg_attr(not(any(target_os = "macos", windows)), allow(dead_code))]
const GOP: u32 = 300;

#[cfg(target_os = "macos")]
type Backend = mac::MacEncoder;
#[cfg(windows)]
type Backend = win::WinEncoder;

/// True when this device can create an encoder. The first call creates a small
/// probe encoder and encodes one frame; the answer is cached.
pub fn available() -> bool {
    static PROBE: OnceLock<bool> = OnceLock::new();
    *PROBE.get_or_init(|| {
        Encoder::new(256, 144, 50)
            .and_then(|mut e| e.encode(&image::RgbImage::new(256, 144), true))
            .map(|au| annexb::is_idr(&au))
            .unwrap_or(false)
    })
}

pub struct Encoder {
    #[cfg(any(target_os = "macos", windows))]
    inner: Backend,
}

impl Encoder {
    /// `width` and `height` must be even. `quality` is the clamped 20..=90 hint.
    pub fn new(width: u32, height: u32, quality: u8) -> Result<Encoder, String> {
        if width == 0 || height == 0 || !width.is_multiple_of(2) || !height.is_multiple_of(2) {
            return Err(format!("h264 needs even, non-zero dimensions (got {width}x{height})"));
        }
        #[cfg(any(target_os = "macos", windows))]
        {
            Ok(Encoder { inner: Backend::new(width, height, quality.clamp(20, 90))? })
        }
        #[cfg(not(any(target_os = "macos", windows)))]
        {
            let _ = quality;
            Err(NO_ENCODER.into())
        }
    }

    /// Encode one frame → one Annex-B access unit (start codes; SPS+PPS before
    /// every IDR). `force_key` makes this frame an IDR.
    pub fn encode(&mut self, frame: &image::RgbImage, force_key: bool) -> Result<Vec<u8>, String> {
        #[cfg(any(target_os = "macos", windows))]
        {
            self.inner.encode(frame, force_key)
        }
        #[cfg(not(any(target_os = "macos", windows)))]
        {
            let _ = (frame, force_key);
            Err(NO_ENCODER.into())
        }
    }

    /// Which OS encoder this is, e.g. "VideoToolbox (hardware, low-latency)".
    #[allow(dead_code)]
    pub fn name(&self) -> String {
        #[cfg(any(target_os = "macos", windows))]
        {
            self.inner.name.clone()
        }
        #[cfg(not(any(target_os = "macos", windows)))]
        {
            String::new()
        }
    }
}

#[cfg(not(any(target_os = "macos", windows)))]
const NO_ENCODER: &str = "no OS H.264 encoder on this platform";

/// `--h264-selftest <FILE>`: capture and encode a few seconds of the primary
/// screen to `out` (Annex-B), returning a one-line summary.
pub fn selftest(out: &str) -> Result<String, String> {
    if !cfg!(any(target_os = "macos", windows)) {
        return Err("no OS H.264 encoder on this platform".into());
    }
    let grabber = crate::capture::Grabber { index: 0 };
    let first = grab_rgb(&grabber)?;
    let (w, h) = (first.width(), first.height());
    run_selftest(out, w, h, 30, std::time::Duration::from_millis(100), |i| {
        if i == 0 {
            Ok(first.clone())
        } else {
            let f = grab_rgb(&grabber)?;
            // Keep the size the encoder was built for (the screen may change mid-run).
            Ok(if f.width() == w && f.height() == h { f } else { image::imageops::resize(&f, w, h, image::imageops::FilterType::Triangle) })
        }
    })
}

/// Screen → RGB at up to 1920 wide, cropped to even dimensions.
fn grab_rgb(g: &crate::capture::Grabber) -> Result<image::RgbImage, String> {
    let jpeg = g.grab(90, 1920)?;
    let img = image::load_from_memory_with_format(&jpeg, image::ImageFormat::Jpeg)
        .map_err(|e| format!("decode captured JPEG: {e}"))?
        .to_rgb8();
    Ok(even(img))
}

fn even(img: image::RgbImage) -> image::RgbImage {
    let (w, h) = (img.width() & !1, img.height() & !1);
    if (w, h) == (img.width(), img.height()) {
        img
    } else {
        image::imageops::crop_imm(&img, 0, 0, w, h).to_image()
    }
}

/// Encode `frames` frames from `next` at roughly one per `interval`, forcing an
/// IDR on frame 0, appending every access unit to `out`. Shared by the screen
/// self-test and the synthetic tests.
fn run_selftest(
    out: &str,
    w: u32,
    h: u32,
    frames: u32,
    interval: std::time::Duration,
    mut next: impl FnMut(u32) -> Result<image::RgbImage, String>,
) -> Result<String, String> {
    use std::io::Write;
    let mut enc = Encoder::new(w, h, 60)?;
    let mut file = std::fs::File::create(out).map_err(|e| format!("create {out}: {e}"))?;
    let (mut bytes, mut idrs, mut enc_time) = (0usize, 0u32, std::time::Duration::ZERO);
    let mut codec = None;
    for i in 0..frames {
        let tick = std::time::Instant::now();
        let frame = next(i)?;
        let t = std::time::Instant::now();
        let au = enc.encode(&frame, i == 0)?;
        enc_time += t.elapsed();
        if i == 0 && !annexb::is_idr(&au) {
            return Err("frame 0 was forced to an IDR but the encoder did not produce one".into());
        }
        if annexb::is_idr(&au) {
            idrs += 1;
            if !(annexb::has_nal(&au, annexb::NAL_SPS) && annexb::has_nal(&au, annexb::NAL_PPS)) {
                return Err(format!("IDR at frame {i} has no SPS/PPS in front"));
            }
            codec = codec.or_else(|| annexb::codec_string(&au));
        }
        bytes += au.len();
        file.write_all(&au).map_err(|e| format!("write {out}: {e}"))?;
        if let Some(rest) = interval.checked_sub(tick.elapsed()) {
            std::thread::sleep(rest);
        }
    }
    Ok(format!(
        "h264 selftest: {frames} frames {w}x{h}, {bytes} bytes, {idrs} IDR, codec {}, encoder {}, {:.1} ms/frame encode → {out}",
        codec.unwrap_or_else(|| "?".into()),
        enc.name(),
        enc_time.as_secs_f64() * 1000.0 / frames.max(1) as f64,
    ))
}
