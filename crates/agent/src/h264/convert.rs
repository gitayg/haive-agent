// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

// Pixel conversions feeding the OS encoders, and the quality → bitrate map.

// Each OS backend uses a different subset of these.
#![allow(dead_code)]

/// Packed RGB24 → NV12 (full-size Y plane, then interleaved Cb/Cr at half
/// resolution), BT.709 limited range. `w` and `h` must be even. Each chroma
/// sample is the average of its 2x2 block.
pub fn rgb_to_nv12(rgb: &[u8], w: usize, h: usize, out: &mut Vec<u8>) {
    debug_assert!(w.is_multiple_of(2) && h.is_multiple_of(2) && rgb.len() >= w * h * 3);
    out.clear();
    out.resize(w * h * 3 / 2, 0);
    let (y_plane, uv_plane) = out.split_at_mut(w * h);
    for y in 0..h {
        let row = &rgb[y * w * 3..(y + 1) * w * 3];
        let dst = &mut y_plane[y * w..(y + 1) * w];
        for x in 0..w {
            let (r, g, b) = (row[x * 3] as i32, row[x * 3 + 1] as i32, row[x * 3 + 2] as i32);
            dst[x] = (16 + ((47 * r + 157 * g + 16 * b + 128) >> 8)) as u8;
        }
    }
    for cy in 0..h / 2 {
        let r0 = &rgb[(2 * cy) * w * 3..(2 * cy + 1) * w * 3];
        let r1 = &rgb[(2 * cy + 1) * w * 3..(2 * cy + 2) * w * 3];
        let dst = &mut uv_plane[cy * w..(cy + 1) * w];
        for cx in 0..w / 2 {
            let i = cx * 6;
            let r = r0[i] as i32 + r0[i + 3] as i32 + r1[i] as i32 + r1[i + 3] as i32;
            let g = r0[i + 1] as i32 + r0[i + 4] as i32 + r1[i + 1] as i32 + r1[i + 4] as i32;
            let b = r0[i + 2] as i32 + r0[i + 5] as i32 + r1[i + 2] as i32 + r1[i + 5] as i32;
            // Sums of four samples: shift by 10 (= /4 then >>8).
            dst[cx * 2] = (128 + ((-26 * r - 86 * g + 112 * b + 512) >> 10)).clamp(16, 240) as u8;
            dst[cx * 2 + 1] = (128 + ((112 * r - 102 * g - 10 * b + 512) >> 10)).clamp(16, 240) as u8;
        }
    }
}

/// Packed RGB24 → BGRA rows of `stride` bytes (alpha 255).
pub fn rgb_to_bgra(rgb: &[u8], w: usize, h: usize, dst: &mut [u8], stride: usize) {
    debug_assert!(stride >= w * 4 && dst.len() >= stride * (h - 1) + w * 4);
    for y in 0..h {
        let src = &rgb[y * w * 3..(y + 1) * w * 3];
        let row = &mut dst[y * stride..y * stride + w * 4];
        for (s, d) in src.chunks_exact(3).zip(row.chunks_exact_mut(4)) {
            d[0] = s[2];
            d[1] = s[1];
            d[2] = s[0];
            d[3] = 255;
        }
    }
}

/// Frame rate the rate controllers are told to expect. `/screen` only encodes
/// frames that changed, so the real rate is usually lower and each frame gets
/// more bits than this nominal budget.
pub const NOMINAL_FPS: u32 = 15;

/// Quality hint 20..=90 → average bitrate in bits/s. Bits per pixel per frame
/// grow exponentially from 0.02 (q=20) to 0.15 (q=90) at the nominal frame
/// rate: 1920x1080 is ~0.6 Mbit/s at q=20, ~2 Mbit/s at q=60, ~4.7 Mbit/s at q=90.
pub fn bitrate_for(w: u32, h: u32, quality: u8) -> u32 {
    let q = quality.clamp(20, 90) as f64;
    let bpp = 0.02 * (0.15f64 / 0.02).powf((q - 20.0) / 70.0);
    let bps = w as f64 * h as f64 * bpp * NOMINAL_FPS as f64;
    bps.clamp(200_000.0, 25_000_000.0) as u32
}
