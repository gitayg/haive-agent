// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

// Tile diff and rectangle merge for the `tiles` codec.
use image::RgbImage;

/// Detection grid size in output pixels (edge tiles are smaller).
pub const TILE: u32 = 64;

/// A rectangle in output pixels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PxRect {
    pub x: u32,
    pub y: u32,
    pub w: u32,
    pub h: u32,
}

/// (columns, rows) of the tile grid over a `w`x`h` frame.
pub fn grid(w: u32, h: u32) -> (usize, usize) {
    (w.div_ceil(TILE) as usize, h.div_ceil(TILE) as usize)
}

/// Which tiles differ between two frames of the same size, row-major.
pub fn diff(prev: &RgbImage, cur: &RgbImage) -> Vec<bool> {
    debug_assert_eq!(prev.dimensions(), cur.dimensions());
    let (w, h) = cur.dimensions();
    let (cols, rows) = grid(w, h);
    let mut changed = vec![false; cols * rows];
    let stride = w as usize * 3;
    let (a, b) = (prev.as_raw(), cur.as_raw());
    for y in 0..h as usize {
        let r = y / TILE as usize;
        let row = y * stride;
        for c in 0..cols {
            let i = r * cols + c;
            if changed[i] {
                continue;
            }
            let x0 = row + c * TILE as usize * 3;
            let x1 = (x0 + TILE as usize * 3).min(row + stride);
            if a[x0..x1] != b[x0..x1] {
                changed[i] = true;
            }
        }
    }
    changed
}

/// Merge changed tiles into rectangles: horizontal runs within each tile row,
/// then runs with an identical column span on consecutive rows become one
/// rectangle. Clipped to the `w`x`h` frame, ordered top-to-bottom, left-to-right.
pub fn merge(changed: &[bool], w: u32, h: u32) -> Vec<PxRect> {
    let (cols, rows) = grid(w, h);
    // (first col, last col, first row) of rectangles the next row may extend.
    let mut open: Vec<(usize, usize, usize)> = Vec::new();
    let mut spans: Vec<(usize, usize, usize, usize)> = Vec::new();
    for r in 0..rows {
        let mut next = Vec::new();
        let mut c = 0;
        while c < cols {
            if !changed[r * cols + c] {
                c += 1;
                continue;
            }
            let c0 = c;
            while c + 1 < cols && changed[r * cols + c + 1] {
                c += 1;
            }
            match open.iter().position(|o| o.0 == c0 && o.1 == c) {
                Some(i) => next.push(open.swap_remove(i)),
                None => next.push((c0, c, r)),
            }
            c += 1;
        }
        spans.extend(open.drain(..).map(|(c0, c1, r0)| (c0, c1, r0, r - 1)));
        open = next;
    }
    spans.extend(open.drain(..).map(|(c0, c1, r0)| (c0, c1, r0, rows - 1)));
    let mut out: Vec<PxRect> = spans
        .into_iter()
        .map(|(c0, c1, r0, r1)| {
            let (x, y) = (c0 as u32 * TILE, r0 as u32 * TILE);
            PxRect { x, y, w: ((c1 as u32 + 1) * TILE).min(w) - x, h: ((r1 as u32 + 1) * TILE).min(h) - y }
        })
        .collect();
    out.sort_by_key(|r| (r.y, r.x));
    out
}

/// True when more than 60% of tiles changed (one full JPEG is then cheaper).
pub fn mostly_changed(changed: &[bool]) -> bool {
    let n = changed.iter().filter(|&&c| c).count();
    n * 100 > changed.len() * 60
}

/// JPEG-encode each rectangle of `img`; returns (rect, payload offset, length)
/// per rectangle and the concatenated payload.
pub fn encode(img: &RgbImage, rects: &[PxRect], quality: u8) -> (Vec<(PxRect, usize, usize)>, Vec<u8>) {
    let mut payload = Vec::new();
    let mut out = Vec::with_capacity(rects.len());
    for r in rects {
        let jpeg = if (r.x, r.y, r.w, r.h) == (0, 0, img.width(), img.height()) {
            crate::capture::jpeg(img, quality)
        } else {
            crate::capture::jpeg(&image::imageops::crop_imm(img, r.x, r.y, r.w, r.h).to_image(), quality)
        };
        out.push((*r, payload.len(), jpeg.len()));
        payload.extend_from_slice(&jpeg);
    }
    (out, payload)
}
