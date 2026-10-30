// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

// Screen capture → JPEG. Origin is assumed (0,0) (primary/single monitor);
// dimensions come from a real capture so coordinate mapping stays exact.
use image::codecs::jpeg::JpegEncoder;
use xcap::Monitor;

#[derive(Clone)]
pub struct Grabber {
    pub index: usize,
}

/// One capture scaled to the output width, with the size it was captured at (for
/// mapping the pointer, which is read in captured pixels).
pub struct Frame {
    pub img: image::RgbImage,
    pub src_w: u32,
    pub src_h: u32,
}

/// Why a capture failed when the machine simply has no screen to copy. Windows
/// composes the desktop through a display output; with the lid shut, the panel
/// powered off, or no monitor attached at all, Desktop Duplication has nothing to
/// duplicate and every grab fails — while the rest of the agent (telemetry, shell,
/// files) keeps working, which otherwise looks like a baffling "screen is broken".
/// Exit code 2 from `--capture-once` carries this same case up to a session-0
/// service, so the operator sees THIS instead of "helper exited 1".
pub const NO_DISPLAY: &str = "no active display — the screen is off, the laptop lid is closed, or no monitor is attached, so Windows has no desktop image to capture. Open the lid or attach a display, then retry. (Everything else on this device still works.)";

/// Last-resort Windows capture: a plain GDI BitBlt of the screen DC.
///
/// xcap uses DXGI Desktop Duplication, which refuses to produce frames in cases
/// GDI still copes with (drivers that drop duplication when the panel powers off,
/// some RDP/virtual-display setups). It's slower and misses hardware overlays, so
/// it runs ONLY after the fast path fails — it can add a working screenshot, never
/// downgrade one. An all-black result is treated as failure: on a truly screenless
/// box GDI returns a black rectangle, and a clear "no display" message beats
/// silently showing the operator a black screen that looks like a working capture.
#[cfg(windows)]
fn gdi_grab() -> Option<image::RgbImage> {
    use std::ffi::c_void;
    use windows_sys::Win32::Graphics::Gdi::{
        BitBlt, CreateCompatibleBitmap, CreateCompatibleDC, DeleteDC, DeleteObject, GetDC,
        GetDIBits, GetDeviceCaps, ReleaseDC, SelectObject, BITMAPINFO, BITMAPINFOHEADER, BI_RGB,
        DIB_RGB_COLORS, HORZRES, SRCCOPY, VERTRES,
    };
    unsafe {
        let screen = GetDC(std::ptr::null_mut());
        if screen.is_null() {
            return None;
        }
        let (w, h) = (GetDeviceCaps(screen, HORZRES as i32), GetDeviceCaps(screen, VERTRES as i32));
        let mut out = None;
        if w > 0 && h > 0 {
            let mem = CreateCompatibleDC(screen);
            let bmp = CreateCompatibleBitmap(screen, w, h);
            if !mem.is_null() && !bmp.is_null() {
                let old = SelectObject(mem, bmp as _);
                if BitBlt(mem, 0, 0, w, h, screen, 0, 0, SRCCOPY) != 0 {
                    let mut bi: BITMAPINFO = std::mem::zeroed();
                    bi.bmiHeader.biSize = std::mem::size_of::<BITMAPINFOHEADER>() as u32;
                    bi.bmiHeader.biWidth = w;
                    bi.bmiHeader.biHeight = -h; // negative = top-down rows
                    bi.bmiHeader.biPlanes = 1;
                    bi.bmiHeader.biBitCount = 32;
                    bi.bmiHeader.biCompression = BI_RGB;
                    let mut buf = vec![0u8; (w as usize) * (h as usize) * 4];
                    if GetDIBits(mem, bmp, 0, h as u32, buf.as_mut_ptr() as *mut c_void, &mut bi, DIB_RGB_COLORS) != 0
                        && buf.iter().any(|&b| b != 0)
                    {
                        // GDI hands back BGRA; drop alpha and reorder to RGB.
                        let mut rgb = Vec::with_capacity((w as usize) * (h as usize) * 3);
                        for px in buf.chunks_exact(4) {
                            rgb.extend_from_slice(&[px[2], px[1], px[0]]);
                        }
                        out = image::RgbImage::from_raw(w as u32, h as u32, rgb);
                    }
                }
                SelectObject(mem, old);
            }
            if !bmp.is_null() {
                DeleteObject(bmp as _);
            }
            if !mem.is_null() {
                DeleteDC(mem);
            }
        }
        ReleaseDC(std::ptr::null_mut(), screen);
        out
    }
}

/// True when no physical display is attached (see `winprobe::no_display`). WMI is
/// machine-wide, so this is valid from any session — including a session-0
/// service, unlike the desktop-scoped GetSystemMetrics(SM_CMONITORS), which still
/// counts a logical monitor when the panel is off and so missed this case.
#[cfg(windows)]
pub fn no_display() -> bool {
    crate::winprobe::no_display()
}

/// Run a capture-stack call, turning a PANIC into None.
///
/// xcap's Wayland backend (libwayshot) panics instead of returning Err on
/// compositors it doesn't support — WSLg panics with `UnsupportedVersion`. Our
/// callers already handle `Err` (`Monitor::all().ok()?`), but a Result can't catch
/// a panic, so it unwound into `thread 'main'` (geometry() runs at startup) and
/// killed the whole agent before it could register. Screen capture is optional;
/// the relay is not — so contain it here, at the one choke point every capture
/// path goes through.
fn no_panic<T>(f: impl FnOnce() -> Option<T>) -> Option<T> {
    // catch_unwind CONTAINS the panic but does not silence it: the default hook
    // still prints the full "thread 'main' panicked …" block, which reads exactly
    // like a crash even though we recovered — the first thing you see in
    // agent.log is a scary trace for a device that is actually fine. Swap in a
    // quiet hook for the duration and report one honest line instead.
    //
    // The hook is process-global, so a panic on another thread during this short
    // window would also lose its message. Capture calls are brief and rare
    // (startup geometry + per screenshot), and the panic itself still propagates
    // normally there — only the printout is affected.
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    std::panic::set_hook(prev);
    match r {
        Ok(v) => v,
        Err(_) => {
            eprintln!("capture unavailable: the screen-capture backend panicked (unsupported compositor — e.g. WSLg). Continuing without screen capture; relay and exec are unaffected.");
            None
        }
    }
}

impl Grabber {
    fn monitor(&self) -> Option<Monitor> {
        no_panic(|| {
            Monitor::all()
                .ok()?
                .into_iter()
                .nth(self.index)
                .or_else(|| Monitor::all().ok().and_then(|m| m.into_iter().next()))
        })
    }

    /// Capture → JPEG without the pointer arrow (the MJPEG `/stream`).
    pub fn grab_jpeg(&self, quality: u8, max_width: u32) -> Option<Vec<u8>> {
        self.grab_rgb(max_width).ok().map(|f| jpeg(&f.img, quality))
    }

    /// Capture → JPEG, or a human-readable reason it couldn't. Draws a small arrow
    /// at the pointer when it can be read, so the model reading `/frame` sees where
    /// the mouse is. Same fallbacks and messages as `grab_rgb`.
    pub fn grab(&self, quality: u8, max_width: u32) -> Result<Vec<u8>, String> {
        let frame = self.grab_rgb(max_width)?;
        let pos = crate::cursor::position(self.index);
        Ok(jpeg(&with_arrow(frame, pos), quality))
    }

    /// Capture → RGB scaled down to `max_width` (0 = no limit), plus the size it was
    /// captured at. Tries xcap first (X11 + wlroots-Wayland); on a Wayland session
    /// where that fails (GNOME/KDE have no wlr-screencopy), falls back to the
    /// xdg-desktop-portal ScreenCast path, whose reason (e.g. "consent pending") is
    /// surfaced to the caller.
    pub fn grab_rgb(&self, max_width: u32) -> Result<Frame, String> {
        let raw = self.grab_full()?;
        let (src_w, src_h) = raw.dimensions();
        Ok(Frame { img: scale(raw, max_width), src_w, src_h })
    }

    fn grab_full(&self) -> Result<image::RgbImage, String> {
        if let Some(img) = no_panic(|| self.monitor().and_then(|m| m.capture_image().ok())) {
            return Ok(image::DynamicImage::ImageRgba8(img).to_rgb8());
        }
        #[cfg(target_os = "linux")]
        if crate::wayland::is_wayland() {
            return match crate::wayland::capture_rgb() {
                Ok((w, h, rgb)) => image::RgbImage::from_raw(w, h, rgb).ok_or_else(|| "malformed Wayland frame".to_string()),
                Err(e) => Err(e.message()),
            };
        }
        // Windows: DXGI (via xcap) just failed — try the older GDI path, which
        // still works on some setups DXGI gives up on.
        #[cfg(windows)]
        if let Some(img) = no_panic(gdi_grab) {
            return Ok(img);
        }
        #[cfg(windows)]
        if no_display() {
            return Err(NO_DISPLAY.to_string());
        }
        Err("capture failed".to_string())
    }

    /// (origin_x, origin_y, width, height) — origin assumed 0,0.
    pub fn geometry(&self) -> (i32, i32, u32, u32) {
        match no_panic(|| self.monitor().and_then(|m| m.capture_image().ok())) {
            Some(img) => (0, 0, img.width(), img.height()),
            None => (0, 0, 1920, 1080),
        }
    }
}

/// Geometry of the monitor `Grabber { index }` captures (falling back to the first,
/// as `Grabber::monitor` does): (x, y, width, height, scale_factor), in the
/// platform's desktop coordinates — points on macOS, pixels on Windows and X11.
pub fn monitor_geometry(index: usize) -> Option<(i32, i32, u32, u32, f32)> {
    let m = Grabber { index }.monitor()?;
    no_panic(|| Some((m.x().ok()?, m.y().ok()?, m.width().ok()?, m.height().ok()?, m.scale_factor().unwrap_or(1.0))))
}

/// Grab a single frame from the given camera index → JPEG. Grabs a few frames
/// first so the camera has time to auto-expose (the first frame is often dark).
pub fn open_camera(index: u32) -> Option<nokhwa::Camera> {
    use nokhwa::pixel_format::RgbFormat;
    use nokhwa::utils::{CameraIndex, RequestedFormat, RequestedFormatType};
    use nokhwa::Camera;
    // Some cameras — notably Windows "Camera AI Effect" / Studio-Effects webcam
    // fronts (Dell/Lenovo laptops) — open but never deliver a frame when asked for
    // the absolute highest resolution. Try a streamable frame-rate mode first, then
    // fall back to highest resolution, and only accept a camera that actually yields
    // a warm frame — so a mode that opens but doesn't stream is rejected, not returned
    // as a hung "working" camera.
    // Highest resolution first (preserve quality for cameras that work), then a
    // more streamable frame-rate mode as a fallback for fronts that open but never
    // deliver a full-res frame.
    let attempts = [
        RequestedFormatType::AbsoluteHighestResolution,
        RequestedFormatType::AbsoluteHighestFrameRate,
    ];
    for rt in attempts {
        let requested = RequestedFormat::new::<RgbFormat>(rt);
        let Ok(mut cam) = Camera::new(CameraIndex::Index(index), requested) else {
            continue;
        };
        if cam.open_stream().is_err() {
            continue;
        }
        // First frames are often dark/empty; a working stream produces one within a
        // few tries. If none arrives, this mode doesn't stream — try the next.
        let mut streamed = false;
        for _ in 0..8 {
            if cam.frame().map(|f| !f.buffer().is_empty()).unwrap_or(false) {
                streamed = true;
                break;
            }
        }
        if streamed {
            return Some(cam);
        }
    }
    None
}

/// One frame from an already-open camera → JPEG. MJPEG frames are already JPEG
/// (returned as-is, avoiding the mozjpeg decoder); others decode in pure Rust.
pub fn frame_to_jpeg(cam: &mut nokhwa::Camera, quality: u8) -> Option<Vec<u8>> {
    use nokhwa::pixel_format::RgbFormat;
    use nokhwa::utils::FrameFormat;
    let frame = cam.frame().ok()?;
    if frame.source_frame_format() == FrameFormat::MJPEG {
        return Some(frame.buffer().to_vec());
    }
    let img = frame.decode_image::<RgbFormat>().ok()?;
    let mut out = Vec::new();
    let mut enc = JpegEncoder::new_with_quality(&mut out, quality);
    enc.encode(img.as_raw(), img.width(), img.height(), image::ExtendedColorType::Rgb8).ok()?;
    Some(out)
}

/// Resize down to `max_width` keeping aspect ratio (never up; 0 = no limit).
pub fn scale(rgb: image::RgbImage, max_width: u32) -> image::RgbImage {
    if max_width > 0 && rgb.width() > max_width {
        let h = rgb.height() * max_width / rgb.width();
        return image::imageops::resize(&rgb, max_width, h, image::imageops::FilterType::Triangle);
    }
    rgb
}

/// JPEG-encode an RGB image.
pub fn jpeg(rgb: &image::RgbImage, quality: u8) -> Vec<u8> {
    let mut out = Vec::new();
    let mut enc = JpegEncoder::new_with_quality(&mut out, quality);
    let _ = enc.encode(rgb.as_raw(), rgb.width(), rgb.height(), image::ExtendedColorType::Rgb8);
    out
}

/// The `/frame` image: the scaled capture with the pointer arrow drawn at `pos`
/// (physical pixels on the captured monitor), when it is on screen.
fn with_arrow(frame: Frame, pos: Option<(i32, i32)>) -> image::RgbImage {
    let mut img = frame.img;
    let out = img.dimensions();
    if let Some((x, y)) = crate::cursor::to_output(pos, (frame.src_w, frame.src_h), out) {
        crate::cursor::draw_arrow(&mut img, x, y);
    }
    img
}

pub fn camera_snapshot(index: u32, quality: u8) -> Option<Vec<u8>> {
    let mut cam = open_camera(index)?;
    for _ in 0..3 {
        let _ = cam.frame();
    }
    frame_to_jpeg(&mut cam, quality)
}

#[cfg(test)]
mod capture_panic_tests {
    use super::no_panic;

    /// The WSLg case: the capture backend panics (libwayshot → UnsupportedVersion)
    /// instead of returning Err. It must degrade to None, not unwind into the
    /// caller — geometry() runs on thread 'main' at startup, so an escaping panic
    /// killed the agent before it could register.
    #[test]
    fn panicking_backend_degrades_to_none() {
        let got: Option<u32> = no_panic(|| panic!("UnsupportedVersion"));
        assert!(got.is_none(), "panic must be contained, not propagated");
    }

    #[test]
    fn working_backend_still_returns_its_value() {
        assert_eq!(no_panic(|| Some(42u32)), Some(42));
        assert_eq!(no_panic(|| None::<u32>), None);
    }
}

#[cfg(test)]
mod frame_arrow_tests {
    use super::{with_arrow, Frame};
    use image::{Rgb, RgbImage};

    fn frame(w: u32, h: u32, src_w: u32, src_h: u32) -> Frame {
        Frame { img: RgbImage::from_pixel(w, h, Rgb([128, 128, 128])), src_w, src_h }
    }

    /// `/frame` draws the arrow at the pointer, mapped from captured pixels into
    /// the scaled output (2x retina capture shown at half size here).
    #[test]
    fn frame_gets_the_arrow_at_the_scaled_pointer() {
        let img = with_arrow(frame(800, 500, 1600, 1000), Some((400, 300)));
        assert_eq!(img.get_pixel(200, 150).0, [0, 0, 0], "arrow tip at the scaled pointer");
        assert_eq!(img.get_pixel(201, 153).0, [255, 255, 255], "white body below-right of the tip");
        let marked = img.pixels().filter(|p| p.0 != [128, 128, 128]).count();
        assert!(marked > 80, "only {marked} px drawn");
    }

    #[test]
    fn no_pointer_or_off_monitor_leaves_the_frame_alone() {
        for pos in [None, Some((1600, 10)), Some((-3, 4))] {
            let img = with_arrow(frame(800, 500, 1600, 1000), pos);
            assert!(img.pixels().all(|p| p.0 == [128, 128, 128]), "{pos:?} drew");
        }
    }
}
