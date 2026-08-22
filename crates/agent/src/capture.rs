// Screen capture → JPEG. Origin is assumed (0,0) (primary/single monitor);
// dimensions come from a real capture so coordinate mapping stays exact.
use image::codecs::jpeg::JpegEncoder;
use xcap::Monitor;

#[derive(Clone)]
pub struct Grabber {
    pub index: usize,
}

/// Why a capture failed when the machine simply has no screen to copy. Windows
/// composes the desktop through a display output; with the lid shut, the panel
/// powered off, or no monitor attached at all, Desktop Duplication has nothing to
/// duplicate and every grab fails — while the rest of the agent (telemetry, shell,
/// files) keeps working, which otherwise looks like a baffling "screen is broken".
/// Exit code 2 from `--capture-once` carries this same case up to a session-0
/// service, so the operator sees THIS instead of "helper exited 1".
pub const NO_DISPLAY: &str = "no active display — the screen is off, the laptop lid is closed, or no monitor is attached, so Windows has no desktop image to capture. Open the lid or attach a display, then retry. (Everything else on this device still works.)";

/// True when the session has zero display monitors. MUST be called from the
/// session that owns the desktop: a session-0 service always sees 0, which would
/// be a false positive — hence it's only consulted on a failed grab in the
/// capturing session (the `--capture-once` helper, or a user-session agent).
#[cfg(windows)]
pub fn no_display() -> bool {
    // SM_CMONITORS: number of display monitors on the desktop.
    unsafe { windows_sys::Win32::UI::WindowsAndMessaging::GetSystemMetrics(windows_sys::Win32::UI::WindowsAndMessaging::SM_CMONITORS) == 0 }
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

    pub fn grab_jpeg(&self, quality: u8, max_width: u32) -> Option<Vec<u8>> {
        self.grab(quality, max_width).ok()
    }

    /// Capture → JPEG, or a human-readable reason it couldn't. Tries xcap first
    /// (X11 + wlroots-Wayland); on a Wayland session where that fails (GNOME/KDE
    /// have no wlr-screencopy), falls back to the xdg-desktop-portal ScreenCast
    /// path, whose reason (e.g. "consent pending") is surfaced to the caller.
    pub fn grab(&self, quality: u8, max_width: u32) -> Result<Vec<u8>, String> {
        if let Some(img) = no_panic(|| self.monitor().and_then(|m| m.capture_image().ok())) {
            return Ok(encode_rgb(image::DynamicImage::ImageRgba8(img).to_rgb8(), quality, max_width));
        }
        #[cfg(target_os = "linux")]
        if crate::wayland::is_wayland() {
            return match crate::wayland::capture_rgb() {
                Ok((w, h, rgb)) => {
                    let buf = image::RgbImage::from_raw(w, h, rgb)
                        .ok_or_else(|| "malformed Wayland frame".to_string())?;
                    Ok(encode_rgb(buf, quality, max_width))
                }
                Err(e) => Err(e.message()),
            };
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

/// Resize (if wider than max_width) and JPEG-encode an RGB image.
fn encode_rgb(mut rgb: image::RgbImage, quality: u8, max_width: u32) -> Vec<u8> {
    if max_width > 0 && rgb.width() > max_width {
        let h = rgb.height() * max_width / rgb.width();
        rgb = image::imageops::resize(&rgb, max_width, h, image::imageops::FilterType::Triangle);
    }
    let (w, h) = (rgb.width(), rgb.height());
    let mut out = Vec::new();
    let mut enc = JpegEncoder::new_with_quality(&mut out, quality);
    let _ = enc.encode(rgb.as_raw(), w, h, image::ExtendedColorType::Rgb8);
    out
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
