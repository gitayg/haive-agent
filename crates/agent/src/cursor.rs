// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

// Pointer position, for the live viewer's cursor overlay and the arrow drawn into `/frame`.

/// Pointer position in physical pixels relative to the top-left of monitor
/// `monitor_index` (the one `Grabber { index }` captures), or None when it can't
/// be read or is on another monitor.
pub fn position(monitor_index: usize) -> Option<(i32, i32)> {
    platform::position(monitor_index)
}

/// Map a pointer position in captured pixels (`src` = captured size) into the
/// output frame (`out` = size after scaling). None when unknown or off the frame.
pub fn to_output(pos: Option<(i32, i32)>, src: (u32, u32), out: (u32, u32)) -> Option<(i32, i32)> {
    let (x, y) = pos?;
    if x < 0 || y < 0 || x as u32 >= src.0 || y as u32 >= src.1 || src.0 == 0 || src.1 == 0 {
        return None;
    }
    let ox = (x as u64 * out.0 as u64 / src.0 as u64) as i32;
    let oy = (y as u64 * out.1 as u64 / src.1 as u64) as i32;
    Some((ox, oy))
}

/// A point in desktop units relative to a monitor's origin, converted to pixels.
/// None when the point is outside the monitor (`size`, in the same units).
#[cfg_attr(not(any(target_os = "macos", windows, target_os = "linux")), allow(dead_code))]
fn to_pixels(pt: (f64, f64), origin: (f64, f64), size: (f64, f64), px_per_unit: (f64, f64)) -> Option<(i32, i32)> {
    let (rx, ry) = (pt.0 - origin.0, pt.1 - origin.1);
    if rx < 0.0 || ry < 0.0 || rx >= size.0 || ry >= size.1 {
        return None;
    }
    Some(((rx * px_per_unit.0).floor() as i32, (ry * px_per_unit.1).floor() as i32))
}

// The classic arrow, tip at (0,0): B = black outline, W = white fill.
const ARROW: [&str; 19] = [
    "B...........",
    "BB..........",
    "BWB.........",
    "BWWB........",
    "BWWWB.......",
    "BWWWWB......",
    "BWWWWWB.....",
    "BWWWWWWB....",
    "BWWWWWWWB...",
    "BWWWWWWWWB..",
    "BWWWWWWWWWB.",
    "BWWWWWWBBBBB",
    "BWWWBWWB....",
    "BWWBBWWB....",
    "BWB..BWWB...",
    "BB...BWWB...",
    "B.....BWWB..",
    "......BWWB..",
    ".......BB...",
];

/// Draw a small arrow with its tip at (x, y) into `img`, clipped to the image.
pub fn draw_arrow(img: &mut image::RgbImage, x: i32, y: i32) {
    let (w, h) = (img.width() as i64, img.height() as i64);
    for (dy, row) in ARROW.iter().enumerate() {
        for (dx, c) in row.bytes().enumerate() {
            let px = match c {
                b'B' => [0, 0, 0],
                b'W' => [255, 255, 255],
                _ => continue,
            };
            let (ix, iy) = (x as i64 + dx as i64, y as i64 + dy as i64);
            if ix >= 0 && iy >= 0 && ix < w && iy < h {
                img.put_pixel(ix as u32, iy as u32, image::Rgb(px));
            }
        }
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use std::ffi::c_void;

    #[repr(C)]
    struct CGPoint {
        x: f64,
        y: f64,
    }

    #[link(name = "CoreGraphics", kind = "framework")]
    extern "C" {
        fn CGEventCreate(source: *const c_void) -> *mut c_void;
        fn CGEventGetLocation(event: *mut c_void) -> CGPoint;
    }

    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        fn CFRelease(cf: *const c_void);
    }

    /// CoreGraphics reports the pointer in global points (origin top-left of the
    /// main display), the same space xcap's monitor bounds use; the monitor's
    /// scale factor turns points into captured pixels.
    pub fn position(index: usize) -> Option<(i32, i32)> {
        let loc = unsafe {
            let ev = CGEventCreate(std::ptr::null());
            if ev.is_null() {
                return None;
            }
            let p = CGEventGetLocation(ev);
            CFRelease(ev);
            p
        };
        let (mx, my, mw, mh, scale) = crate::capture::monitor_geometry(index)?;
        let s = scale as f64;
        super::to_pixels((loc.x, loc.y), (mx as f64, my as f64), (mw as f64, mh as f64), (s, s))
    }
}

#[cfg(windows)]
mod platform {
    use windows_sys::Win32::Foundation::{BOOL, LPARAM, RECT};
    use windows_sys::Win32::Graphics::Gdi::{EnumDisplayMonitors, GetMonitorInfoW, HDC, HMONITOR, MONITORINFO};
    use windows_sys::Win32::UI::WindowsAndMessaging::{GetCursorInfo, CURSORINFO, CURSOR_SHOWING};

    unsafe extern "system" fn collect(m: HMONITOR, _: HDC, _: *mut RECT, data: LPARAM) -> BOOL {
        (*(data as *mut Vec<HMONITOR>)).push(m);
        1
    }

    /// GetCursorInfo and GetMonitorInfo report in the same (possibly
    /// DPI-virtualized) coordinates, so the pointer is located on the monitor in
    /// those, then scaled to the monitor's physical pixels (what DXGI captures) —
    /// right whether or not the process is DPI aware. A hidden pointer is None.
    pub fn position(index: usize) -> Option<(i32, i32)> {
        unsafe {
            let mut ci: CURSORINFO = std::mem::zeroed();
            ci.cbSize = std::mem::size_of::<CURSORINFO>() as u32;
            if GetCursorInfo(&mut ci) == 0 || ci.flags & CURSOR_SHOWING == 0 {
                return None;
            }
            let mut mons: Vec<HMONITOR> = Vec::new();
            EnumDisplayMonitors(std::ptr::null_mut(), std::ptr::null(), Some(collect), &mut mons as *mut _ as LPARAM);
            let hmon = *mons.get(index).or(mons.first())?;
            let mut mi: MONITORINFO = std::mem::zeroed();
            mi.cbSize = std::mem::size_of::<MONITORINFO>() as u32;
            if GetMonitorInfoW(hmon, &mut mi) == 0 {
                return None;
            }
            let rc = mi.rcMonitor;
            let (lw, lh) = ((rc.right - rc.left) as f64, (rc.bottom - rc.top) as f64);
            if lw <= 0.0 || lh <= 0.0 {
                return None;
            }
            let (_, _, pw, ph, _) = crate::capture::monitor_geometry(index)?;
            super::to_pixels(
                (ci.ptScreenPos.x as f64, ci.ptScreenPos.y as f64),
                (rc.left as f64, rc.top as f64),
                (lw, lh),
                (pw as f64 / lw, ph as f64 / lh),
            )
        }
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use enigo::{Enigo, Mouse, Settings};
    use std::cell::RefCell;

    thread_local! {
        static CON: RefCell<Option<Enigo>> = const { RefCell::new(None) };
    }

    /// X11 only: enigo's pure-Rust x11rb backend (already linked for input) asks
    /// the server for the pointer in root-window pixels, the space xrandr monitor
    /// bounds use. On Wayland the X root pointer is XWayland's stale view, so None.
    pub fn position(index: usize) -> Option<(i32, i32)> {
        if crate::wayland::is_wayland() {
            return None;
        }
        let loc = CON.with(|c| {
            let mut c = c.borrow_mut();
            if c.is_none() {
                *c = Enigo::new(&Settings::default()).ok();
            }
            let r = c.as_ref()?.location();
            if r.is_err() {
                *c = None;
            }
            r.ok()
        })?;
        let (mx, my, mw, mh, _) = crate::capture::monitor_geometry(index)?;
        super::to_pixels((loc.0 as f64, loc.1 as f64), (mx as f64, my as f64), (mw as f64, mh as f64), (1.0, 1.0))
    }
}

#[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
mod platform {
    pub fn position(_index: usize) -> Option<(i32, i32)> {
        None
    }
}

#[cfg(test)]
mod tests;
