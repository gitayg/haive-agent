// Screen capture → JPEG. Origin is assumed (0,0) (primary/single monitor);
// dimensions come from a real capture so coordinate mapping stays exact.
use image::codecs::jpeg::JpegEncoder;
use xcap::Monitor;

#[derive(Clone)]
pub struct Grabber {
    pub index: usize,
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
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).ok().flatten()
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
    let requested = RequestedFormat::new::<RgbFormat>(RequestedFormatType::AbsoluteHighestResolution);
    let mut cam = Camera::new(CameraIndex::Index(index), requested).ok()?;
    cam.open_stream().ok()?;
    for _ in 0..3 {
        let _ = cam.frame(); // warm up (first frames are often dark)
    }
    Some(cam)
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
