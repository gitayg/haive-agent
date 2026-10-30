// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

use super::*;
use image::{Rgb, RgbImage};

fn grey(w: u32, h: u32) -> RgbImage {
    RgbImage::from_pixel(w, h, Rgb([128, 128, 128]))
}

fn changed(img: &RgbImage) -> Vec<(u32, u32)> {
    img.enumerate_pixels().filter(|(_, _, p)| p.0 != [128, 128, 128]).map(|(x, y, _)| (x, y)).collect()
}

#[test]
fn arrow_tip_is_black_and_body_white() {
    let mut img = grey(40, 40);
    draw_arrow(&mut img, 10, 10);
    assert_eq!(img.get_pixel(10, 10).0, [0, 0, 0], "tip");
    assert_eq!(img.get_pixel(11, 13).0, [255, 255, 255], "fill");
    let px = changed(&img);
    assert!(px.iter().all(|&(x, y)| (10..22).contains(&x) && (10..29).contains(&y)), "stays in its 12x19 box");
    assert!(px.len() > 80, "drew {} px", px.len());
}

#[test]
fn arrow_clips_at_every_edge() {
    // Past the right/bottom edge: only the in-bounds part, no panic.
    let mut img = grey(20, 20);
    draw_arrow(&mut img, 15, 15);
    let px = changed(&img);
    assert!(!px.is_empty());
    assert!(px.iter().all(|&(x, y)| x >= 15 && y >= 15));
    // Tip above/left of the image: the lower-right part of the arrow shows.
    let mut img = grey(20, 20);
    draw_arrow(&mut img, -5, -10);
    let px = changed(&img);
    assert!(!px.is_empty());
    assert!(px.iter().all(|&(x, y)| x < 7 && y < 9));
    // Fully off-image in every direction: nothing drawn, no panic.
    for (x, y) in [(-100, 0), (0, -100), (100, 0), (0, 100), (i32::MIN, i32::MIN), (i32::MAX, i32::MAX)] {
        let mut img = grey(20, 20);
        draw_arrow(&mut img, x, y);
        assert!(changed(&img).is_empty(), "({x},{y}) drew pixels");
    }
    // A 1x1 image.
    let mut img = grey(1, 1);
    draw_arrow(&mut img, 0, 0);
    assert_eq!(img.get_pixel(0, 0).0, [0, 0, 0]);
}

#[test]
fn cursor_scales_into_the_output_frame() {
    // 3024x1964 retina capture scaled to 1600 wide → 1600x1039.
    assert_eq!(to_output(Some((1512, 982)), (3024, 1964), (1600, 1039)), Some((800, 519)));
    assert_eq!(to_output(Some((0, 0)), (3024, 1964), (1600, 1039)), Some((0, 0)));
    assert_eq!(to_output(Some((3023, 1963)), (3024, 1964), (1600, 1039)), Some((1599, 1038)));
    // Unscaled.
    assert_eq!(to_output(Some((7, 9)), (100, 100), (100, 100)), Some((7, 9)));
    // Off the captured frame or unknown.
    assert_eq!(to_output(Some((3024, 10)), (3024, 1964), (1600, 1039)), None);
    assert_eq!(to_output(Some((-1, 10)), (3024, 1964), (1600, 1039)), None);
    assert_eq!(to_output(None, (3024, 1964), (1600, 1039)), None);
    assert_eq!(to_output(Some((0, 0)), (0, 0), (0, 0)), None);
}

#[test]
fn desktop_point_to_monitor_pixels() {
    // macOS: second display to the right of the main one, 2x scale.
    let mon = ((1512.0, 0.0), (1920.0, 1080.0));
    assert_eq!(to_pixels((1512.0 + 100.5, 50.25), mon.0, mon.1, (2.0, 2.0)), Some((201, 100)));
    // Pointer on the main display → not on this monitor.
    assert_eq!(to_pixels((700.0, 50.0), mon.0, mon.1, (2.0, 2.0)), None);
    assert_eq!(to_pixels((1512.0 + 1920.0, 50.0), mon.0, mon.1, (2.0, 2.0)), None);
    // Monitor left of the primary (negative origin), Windows DPI-virtualized 150%.
    assert_eq!(to_pixels((-1280.0 + 640.0, 360.0), (-1280.0, 0.0), (1280.0, 720.0), (1.5, 1.5)), Some((960, 540)));
}
