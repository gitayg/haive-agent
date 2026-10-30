// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

use super::annexb::*;
use super::convert::*;

const SPS: [u8; 6] = [0x67, 0x42, 0xe0, 0x1f, 0xda, 0x01];
const PPS: [u8; 3] = [0x68, 0xce, 0x3c];

fn annexb_of(nals: &[&[u8]]) -> Vec<u8> {
    let mut v = Vec::new();
    for n in nals {
        v.extend_from_slice(&START_CODE);
        v.extend_from_slice(n);
    }
    v
}

#[test]
fn avcc_to_annexb_replaces_length_prefixes() {
    let avcc = [0, 0, 0, 3, 0x65, 0x88, 0x84, 0, 0, 0, 2, 0x41, 0x9a];
    let mut out = Vec::new();
    avcc_to_annexb(&avcc, 4, &mut out).unwrap();
    assert_eq!(out, vec![0, 0, 0, 1, 0x65, 0x88, 0x84, 0, 0, 0, 1, 0x41, 0x9a]);

    let mut out2 = Vec::new();
    avcc_to_annexb(&[0, 2, 0x41, 0x9a, 0, 1, 0x06], 2, &mut out2).unwrap();
    assert_eq!(out2, vec![0, 0, 0, 1, 0x41, 0x9a, 0, 0, 0, 1, 0x06]);
}

#[test]
fn avcc_to_annexb_rejects_truncated_input() {
    let mut out = Vec::new();
    assert!(avcc_to_annexb(&[0, 0, 0, 9, 0x65, 0x88], 4, &mut out).is_err());
    assert!(avcc_to_annexb(&[0, 0], 4, &mut out).is_err());
    assert!(avcc_to_annexb(&[0, 0, 0, 0], 4, &mut out).is_err());
    assert!(avcc_to_annexb(&[1, 0x65], 5, &mut out).is_err());
}

#[test]
fn nal_spans_handles_3_and_4_byte_start_codes() {
    let au = [0, 0, 0, 1, 0x09, 0xf0, 0, 0, 1, 0x67, 0x42, 0, 0, 0, 1, 0x65, 0x88];
    let n = nals(&au);
    assert_eq!(n, vec![&[0x09, 0xf0][..], &[0x67, 0x42][..], &[0x65, 0x88][..]]);
    assert!(is_idr(&au));
    assert!(!is_idr(&annexb_of(&[&[0x41, 0x9a]])));
}

#[test]
fn param_sets_are_inserted_before_an_idr_that_lacks_them() {
    let params = annexb_of(&[&SPS, &PPS]);
    let idr = annexb_of(&[&[0x09, 0x10], &[0x65, 0x88, 0x84]]);
    let fixed = with_param_sets(idr, &params);
    assert_eq!(fixed, annexb_of(&[&[0x09, 0x10], &SPS, &PPS, &[0x65, 0x88, 0x84]]));

    let already = annexb_of(&[&SPS, &PPS, &[0x65, 0x88]]);
    assert_eq!(with_param_sets(already.clone(), &params), already);

    let p_frame = annexb_of(&[&[0x41, 0x9a]]);
    assert_eq!(with_param_sets(p_frame.clone(), &params), p_frame);

    assert_eq!(param_sets(&annexb_of(&[&[0x09, 0x10], &SPS, &PPS, &[0x65, 0x88]])), params);
}

#[test]
fn codec_string_comes_from_the_sps_bytes() {
    assert_eq!(codec_string_from_sps(&SPS).as_deref(), Some("avc1.42e01f"));
    let au = annexb_of(&[&[0x09, 0x10], &[0x67, 0x4d, 0x40, 0x28, 0x95], &PPS, &[0x65]]);
    assert_eq!(codec_string(&au).as_deref(), Some("avc1.4d4028"));
    assert_eq!(codec_string(&annexb_of(&[&[0x41, 0x9a]])), None);
    assert_eq!(codec_string_from_sps(&PPS), None);
}

#[test]
fn nv12_of_flat_colours_is_bt709_limited_range() {
    let px = |r: u8, g: u8, b: u8| -> Vec<u8> {
        let rgb: Vec<u8> = [r, g, b].repeat(4);
        let mut out = Vec::new();
        rgb_to_nv12(&rgb, 2, 2, &mut out);
        out
    };
    assert_eq!(px(255, 255, 255), vec![235, 235, 235, 235, 128, 128]);
    assert_eq!(px(0, 0, 0), vec![16, 16, 16, 16, 128, 128]);
    // Red: Y 63, Cb 102, Cr 240 (BT.709: 62.6 / 102.3 / 240).
    assert_eq!(px(255, 0, 0), vec![63, 63, 63, 63, 102, 240]);
    // Blue: Y 32, Cb 240, Cr 118 (BT.709: 32.2 / 240 / 118.3).
    assert_eq!(px(0, 0, 255), vec![32, 32, 32, 32, 240, 118]);
}

#[test]
fn nv12_layout_is_y_plane_then_interleaved_half_res_chroma() {
    // 4x2: left 2x2 block black, right 2x2 block white.
    let mut rgb = Vec::new();
    for _ in 0..2 {
        rgb.extend([0u8; 6]);
        rgb.extend([255u8; 6]);
    }
    let mut out = Vec::new();
    rgb_to_nv12(&rgb, 4, 2, &mut out);
    assert_eq!(out.len(), 4 * 2 * 3 / 2);
    assert_eq!(&out[..8], &[16, 16, 235, 235, 16, 16, 235, 235]);
    assert_eq!(&out[8..], &[128, 128, 128, 128]);
}

#[test]
fn bgra_respects_stride_and_channel_order() {
    let rgb = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let mut dst = vec![0u8; 2 * 12];
    rgb_to_bgra(&rgb, 2, 2, &mut dst, 12);
    assert_eq!(&dst[..8], &[3, 2, 1, 255, 6, 5, 4, 255]);
    assert_eq!(&dst[8..12], &[0, 0, 0, 0]);
    assert_eq!(&dst[12..20], &[9, 8, 7, 255, 12, 11, 10, 255]);
}

#[test]
fn bitrate_grows_with_quality_and_is_clamped() {
    let lo = bitrate_for(1920, 1080, 20);
    let mid = bitrate_for(1920, 1080, 60);
    let hi = bitrate_for(1920, 1080, 90);
    assert!(lo < mid && mid < hi, "{lo} {mid} {hi}");
    assert!((500_000..800_000).contains(&lo), "{lo}");
    assert!((4_000_000..5_500_000).contains(&hi), "{hi}");
    assert_eq!(bitrate_for(1920, 1080, 5), lo);
    assert_eq!(bitrate_for(64, 64, 20), 200_000);
    assert_eq!(bitrate_for(7680, 4320, 90), 25_000_000);
}

#[test]
fn odd_dimensions_are_refused() {
    assert!(super::Encoder::new(641, 480, 50).is_err());
    assert!(super::Encoder::new(640, 0, 50).is_err());
}

#[cfg(not(any(target_os = "macos", windows)))]
#[test]
fn no_encoder_off_macos_and_windows() {
    assert!(!super::available());
    let e = super::Encoder::new(640, 480, 50).err().unwrap();
    assert_eq!(e, "no OS H.264 encoder on this platform");
}

/// A moving gradient with a sliding bar: changes every frame, like a screen.
#[cfg(any(target_os = "macos", windows))]
fn synthetic(w: u32, h: u32, i: u32) -> image::RgbImage {
    image::RgbImage::from_fn(w, h, |x, y| {
        let bar = (x + 4 * i) % w < 40;
        if bar {
            image::Rgb([255, 255, 255])
        } else {
            image::Rgb([((x + 3 * i) % 256) as u8, ((y + i) % 256) as u8, ((x + y) / 4 % 256) as u8])
        }
    })
}

#[cfg(any(target_os = "macos", windows))]
fn out_path(name: &str) -> String {
    let dir = std::env::var("H264_TEST_OUT").unwrap_or_else(|_| std::env::temp_dir().to_string_lossy().into_owned());
    format!("{}/{name}", dir.trim_end_matches('/'))
}

#[cfg(any(target_os = "macos", windows))]
#[test]
fn synthetic_frames_encode_to_one_annexb_au_each() {
    use std::io::Write;
    let (w, h) = (640u32, 360u32);
    let mut enc = super::Encoder::new(w, h, 60).unwrap();
    let path = out_path("h264-synthetic.h264");
    let mut f = std::fs::File::create(&path).unwrap();
    for i in 0..60 {
        let force = i == 0 || i == 40;
        let au = enc.encode(&synthetic(w, h, i), force).unwrap_or_else(|e| panic!("frame {i}: {e}"));
        assert!(au.starts_with(&[0, 0, 0, 1]) || au.starts_with(&[0, 0, 1]), "frame {i} not Annex-B");
        assert!(!au.is_empty());
        if force {
            assert!(is_idr(&au), "frame {i} forced but not IDR");
            assert!(has_nal(&au, NAL_SPS) && has_nal(&au, NAL_PPS), "frame {i} IDR without SPS/PPS");
            let codec = codec_string(&au).unwrap();
            assert!(codec.starts_with("avc1.42"), "not Baseline: {codec}");
        } else {
            assert!(!is_idr(&au), "frame {i} unexpectedly IDR");
            // No B-frames: Baseline has none, and no slice may be a B slice.
        }
        f.write_all(&au).unwrap();
    }
    eprintln!("wrote {path} with {}", enc.name());
    eprintln!("codec string of the first IDR: {:?}", codec_string(&std::fs::read(&path).unwrap()));
}

#[cfg(any(target_os = "macos", windows))]
#[test]
fn available_is_true_and_cached() {
    let t = std::time::Instant::now();
    assert!(super::available());
    let first = t.elapsed();
    let t = std::time::Instant::now();
    assert!(super::available());
    assert!(t.elapsed() < std::time::Duration::from_millis(1), "second call took {:?} (first {first:?})", t.elapsed());
}

#[cfg(target_os = "macos")]
#[test]
fn string_literals_match_the_newer_videotoolbox_symbols() {
    use super::mac::literal_matches_symbol as m;
    assert_eq!(m("kVTProfileLevel_H264_ConstrainedBaseline_AutoLevel", "H264_ConstrainedBaseline_AutoLevel"), Some(true));
    assert_eq!(m("kVTProfileLevel_H264_Baseline_AutoLevel", "H264_ConstrainedBaseline_AutoLevel"), Some(false));
}

/// RSS (KiB) of this process, via ps.
#[cfg(target_os = "macos")]
fn rss_kib() -> u64 {
    let out = std::process::Command::new("ps").args(["-o", "rss=", "-p", &std::process::id().to_string()]).output().unwrap();
    String::from_utf8_lossy(&out.stdout).trim().parse().unwrap()
}

/// 1000 frames through one encoder plus 50 encoder create/drop cycles; RSS
/// must not keep growing. Run: cargo test -p it-ai-agent h264::tests::no_leak -- --ignored --nocapture
#[cfg(target_os = "macos")]
#[test]
#[ignore]
fn no_leak_over_1000_frames() {
    let (w, h) = (1280u32, 720u32);
    let frames: Vec<_> = (0..20).map(|i| synthetic(w, h, i * 7)).collect();
    let mut enc = super::Encoder::new(w, h, 60).unwrap();
    for i in 0..100 {
        enc.encode(&frames[i % 20], i % 50 == 0).unwrap();
    }
    let after_100 = rss_kib();
    for i in 100..1000 {
        enc.encode(&frames[i % 20], i % 50 == 0).unwrap();
        if i == 550 {
            eprintln!("rss after 550 frames: {} KiB", rss_kib());
        }
    }
    let after_1000 = rss_kib();
    drop(enc);
    for _ in 0..50 {
        let mut e = super::Encoder::new(w, h, 60).unwrap();
        e.encode(&frames[0], true).unwrap();
    }
    let after_cycles = rss_kib();
    eprintln!("rss after 100 frames: {after_100} KiB, after 1000: {after_1000} KiB, after 50 create/drop cycles: {after_cycles} KiB");
    assert!(after_1000 < after_100 + 20 * 1024, "grew {} KiB over 900 frames", after_1000 - after_100);
    assert!(after_cycles < after_1000 + 20 * 1024, "grew {} KiB over 50 encoder cycles", after_cycles - after_1000);
}

/// The real `--h264-selftest` path (needs Screen Recording permission).
#[cfg(any(target_os = "macos", windows))]
#[test]
#[ignore]
fn screen_selftest() {
    let path = out_path("h264-screen.h264");
    println!("{}", super::selftest(&path).unwrap());
}

#[test]
fn encoder_is_send() {
    fn assert_send<T: Send>() {}
    assert_send::<super::Encoder>();
}
