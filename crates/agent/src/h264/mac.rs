// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

// VideoToolbox H.264 encoder (raw FFI; no extra crates).
//
// One VTCompressionSession per Encoder: real-time, no frame reordering,
// Baseline profile. Frames go in as BGRA CVPixelBuffers from the session's
// pool; VTCompressionSessionCompleteFrames after each frame makes encode()
// synchronous, so one frame in -> one access unit out. The output callback
// converts AVCC -> Annex-B and puts SPS+PPS (from the CMFormatDescription) in
// front of every IDR.
//
// Not the low-latency rate controller (EnableLowLatencyRateControl): measured
// here, it drops the frame right after an IDR to stay on budget, and a dropped
// frame leaves the viewer on a stale picture once the screen stops changing.
// The default controller overshoots instead.
//
// Only symbols that exist since macOS 10.9 are linked by name. The newer
// constrained-baseline profile key is created from its string value, so an
// older macOS rejects it at runtime (and we fall back to plain Baseline)
// instead of failing to load the whole agent.

use std::ffi::{c_void, CString};
use std::ptr::null;
use std::sync::Mutex;
use std::time::Instant;

use super::annexb;
use super::convert;

type CFTypeRef = *const c_void;
type CFStringRef = *const c_void;
type CFDictionaryRef = *const c_void;
type CFAllocatorRef = *const c_void;
type OSStatus = i32;
type VTSession = *mut c_void;
type CVPixelBufferRef = *mut c_void;
type CVPixelBufferPoolRef = *mut c_void;
type CMSampleBufferRef = *mut c_void;
type CMFormatDescriptionRef = *mut c_void;
type CMBlockBufferRef = *mut c_void;

#[repr(C)]
#[derive(Clone, Copy)]
struct CMTime {
    value: i64,
    timescale: i32,
    flags: u32,
    epoch: i64,
}

const CMTIME_VALID: u32 = 1;
const CMTIME_INVALID: CMTime = CMTime { value: 0, timescale: 0, flags: 0, epoch: 0 };
const CODEC_AVC1: u32 = u32::from_be_bytes(*b"avc1");
const PIXEL_BGRA: u32 = u32::from_be_bytes(*b"BGRA");
const CF_NUMBER_SINT32: isize = 3;
const CF_STRING_UTF8: u32 = 0x0800_0100;
const VT_ENCODE_INFO_FRAME_DROPPED: u32 = 1 << 1;

type OutputCallback = extern "C" fn(*mut c_void, *mut c_void, OSStatus, u32, CMSampleBufferRef);

#[link(name = "CoreFoundation", kind = "framework")]
extern "C" {
    static kCFBooleanTrue: CFTypeRef;
    static kCFBooleanFalse: CFTypeRef;
    static kCFTypeDictionaryKeyCallBacks: [usize; 6];
    static kCFTypeDictionaryValueCallBacks: [usize; 5];
    fn CFRelease(cf: CFTypeRef);
    fn CFNumberCreate(alloc: CFAllocatorRef, the_type: isize, value: *const c_void) -> CFTypeRef;
    fn CFStringCreateWithCString(alloc: CFAllocatorRef, s: *const i8, encoding: u32) -> CFStringRef;
    fn CFDictionaryCreate(
        alloc: CFAllocatorRef,
        keys: *const CFTypeRef,
        values: *const CFTypeRef,
        n: isize,
        key_cb: *const c_void,
        value_cb: *const c_void,
    ) -> CFDictionaryRef;
}

#[link(name = "CoreVideo", kind = "framework")]
extern "C" {
    static kCVPixelBufferPixelFormatTypeKey: CFStringRef;
    static kCVPixelBufferWidthKey: CFStringRef;
    static kCVPixelBufferHeightKey: CFStringRef;
    static kCVPixelBufferIOSurfacePropertiesKey: CFStringRef;
    static kCVImageBufferColorPrimaries_ITU_R_709_2: CFStringRef;
    static kCVImageBufferTransferFunction_ITU_R_709_2: CFStringRef;
    static kCVImageBufferYCbCrMatrix_ITU_R_709_2: CFStringRef;
    fn CVPixelBufferPoolCreatePixelBuffer(alloc: CFAllocatorRef, pool: CVPixelBufferPoolRef, out: *mut CVPixelBufferRef) -> i32;
    fn CVPixelBufferCreate(alloc: CFAllocatorRef, w: usize, h: usize, fmt: u32, attrs: CFDictionaryRef, out: *mut CVPixelBufferRef) -> i32;
    fn CVPixelBufferLockBaseAddress(pb: CVPixelBufferRef, flags: u64) -> i32;
    fn CVPixelBufferUnlockBaseAddress(pb: CVPixelBufferRef, flags: u64) -> i32;
    fn CVPixelBufferGetBaseAddress(pb: CVPixelBufferRef) -> *mut u8;
    fn CVPixelBufferGetBytesPerRow(pb: CVPixelBufferRef) -> usize;
    fn CVPixelBufferGetWidth(pb: CVPixelBufferRef) -> usize;
    fn CVPixelBufferGetHeight(pb: CVPixelBufferRef) -> usize;
}

#[link(name = "CoreMedia", kind = "framework")]
extern "C" {
    fn CMSampleBufferGetDataBuffer(sb: CMSampleBufferRef) -> CMBlockBufferRef;
    fn CMSampleBufferGetFormatDescription(sb: CMSampleBufferRef) -> CMFormatDescriptionRef;
    fn CMBlockBufferGetDataLength(bb: CMBlockBufferRef) -> usize;
    fn CMBlockBufferCopyDataBytes(bb: CMBlockBufferRef, offset: usize, len: usize, dest: *mut c_void) -> OSStatus;
    fn CMVideoFormatDescriptionGetH264ParameterSetAtIndex(
        fd: CMFormatDescriptionRef,
        index: usize,
        ptr_out: *mut *const u8,
        size_out: *mut usize,
        count_out: *mut usize,
        nal_header_len_out: *mut i32,
    ) -> OSStatus;
}

#[link(name = "VideoToolbox", kind = "framework")]
extern "C" {
    static kVTCompressionPropertyKey_RealTime: CFStringRef;
    static kVTCompressionPropertyKey_AllowFrameReordering: CFStringRef;
    static kVTCompressionPropertyKey_ProfileLevel: CFStringRef;
    static kVTCompressionPropertyKey_AverageBitRate: CFStringRef;
    static kVTCompressionPropertyKey_MaxKeyFrameInterval: CFStringRef;
    static kVTCompressionPropertyKey_ExpectedFrameRate: CFStringRef;
    static kVTCompressionPropertyKey_MaxFrameDelayCount: CFStringRef;
    static kVTCompressionPropertyKey_ColorPrimaries: CFStringRef;
    static kVTCompressionPropertyKey_TransferFunction: CFStringRef;
    static kVTCompressionPropertyKey_YCbCrMatrix: CFStringRef;
    static kVTCompressionPropertyKey_UsingHardwareAcceleratedVideoEncoder: CFStringRef;
    static kVTEncodeFrameOptionKey_ForceKeyFrame: CFStringRef;
    static kVTVideoEncoderSpecification_EnableHardwareAcceleratedVideoEncoder: CFStringRef;
    static kVTProfileLevel_H264_Baseline_AutoLevel: CFStringRef;
    fn VTCompressionSessionCreate(
        alloc: CFAllocatorRef,
        width: i32,
        height: i32,
        codec: u32,
        encoder_spec: CFDictionaryRef,
        source_attrs: CFDictionaryRef,
        compressed_alloc: CFAllocatorRef,
        callback: Option<OutputCallback>,
        refcon: *mut c_void,
        out: *mut VTSession,
    ) -> OSStatus;
    fn VTSessionSetProperty(session: VTSession, key: CFStringRef, value: CFTypeRef) -> OSStatus;
    fn VTSessionCopyProperty(session: VTSession, key: CFStringRef, alloc: CFAllocatorRef, out: *mut CFTypeRef) -> OSStatus;
    fn VTCompressionSessionPrepareToEncodeFrames(session: VTSession) -> OSStatus;
    fn VTCompressionSessionGetPixelBufferPool(session: VTSession) -> CVPixelBufferPoolRef;
    fn VTCompressionSessionEncodeFrame(
        session: VTSession,
        image: CVPixelBufferRef,
        pts: CMTime,
        duration: CMTime,
        frame_props: CFDictionaryRef,
        frame_refcon: *mut c_void,
        info_out: *mut u32,
    ) -> OSStatus;
    fn VTCompressionSessionCompleteFrames(session: VTSession, until: CMTime) -> OSStatus;
    fn VTCompressionSessionInvalidate(session: VTSession);
}

/// An owned CF object, released on drop.
struct Cf(CFTypeRef);

impl Drop for Cf {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CFRelease(self.0) }
        }
    }
}

fn cf_i32(v: i32) -> Cf {
    Cf(unsafe { CFNumberCreate(null(), CF_NUMBER_SINT32, &v as *const i32 as *const c_void) })
}

fn cf_str(s: &str) -> Cf {
    let c = CString::new(s).unwrap_or_default();
    Cf(unsafe { CFStringCreateWithCString(null(), c.as_ptr(), CF_STRING_UTF8) })
}

fn cf_dict(pairs: &[(CFTypeRef, CFTypeRef)]) -> Cf {
    let keys: Vec<CFTypeRef> = pairs.iter().map(|p| p.0).collect();
    let values: Vec<CFTypeRef> = pairs.iter().map(|p| p.1).collect();
    Cf(unsafe {
        CFDictionaryCreate(
            null(),
            keys.as_ptr(),
            values.as_ptr(),
            pairs.len() as isize,
            &kCFTypeDictionaryKeyCallBacks as *const _ as *const c_void,
            &kCFTypeDictionaryValueCallBacks as *const _ as *const c_void,
        )
    })
}

/// Where the output callback leaves each encoded frame.
struct Sink {
    out: Mutex<Vec<Result<Vec<u8>, String>>>,
}

extern "C" fn on_output(refcon: *mut c_void, _frame: *mut c_void, status: OSStatus, flags: u32, sb: CMSampleBufferRef) {
    if refcon.is_null() {
        return;
    }
    let sink = unsafe { &*(refcon as *const Sink) };
    let r = if status != 0 {
        Err(format!("VideoToolbox encode failed (OSStatus {status})"))
    } else if sb.is_null() || flags & VT_ENCODE_INFO_FRAME_DROPPED != 0 {
        Err(format!("VideoToolbox dropped the frame (flags {flags:#x}, sample {})", !sb.is_null()))
    } else {
        unsafe { sample_to_annexb(sb) }
    };
    if let Ok(mut v) = sink.out.lock() {
        v.push(r);
    }
}

/// CMSampleBuffer (AVCC) → one Annex-B access unit, SPS+PPS first on an IDR.
/// Nothing here is retained, so nothing is released: VideoToolbox owns `sb`.
unsafe fn sample_to_annexb(sb: CMSampleBufferRef) -> Result<Vec<u8>, String> {
    let bb = CMSampleBufferGetDataBuffer(sb);
    if bb.is_null() {
        return Err("encoded sample has no data".into());
    }
    let len = CMBlockBufferGetDataLength(bb);
    let mut avcc = vec![0u8; len];
    let st = CMBlockBufferCopyDataBytes(bb, 0, len, avcc.as_mut_ptr() as *mut c_void);
    if st != 0 {
        return Err(format!("CMBlockBufferCopyDataBytes failed ({st})"));
    }
    let fd = CMSampleBufferGetFormatDescription(sb);
    let mut header_len: i32 = 4;
    let mut count: usize = 0;
    let mut params = Vec::new();
    if !fd.is_null() {
        let (mut p, mut sz) = (null(), 0usize);
        if CMVideoFormatDescriptionGetH264ParameterSetAtIndex(fd, 0, &mut p, &mut sz, &mut count, &mut header_len) != 0 {
            count = 0;
            header_len = 4;
        }
        for i in 0..count {
            let (mut p, mut sz) = (null(), 0usize);
            if CMVideoFormatDescriptionGetH264ParameterSetAtIndex(fd, i, &mut p, &mut sz, null::<usize>() as *mut usize, null::<i32>() as *mut i32) == 0
                && !p.is_null()
            {
                params.extend_from_slice(&annexb::START_CODE);
                params.extend_from_slice(std::slice::from_raw_parts(p, sz));
            }
        }
    }
    let mut au = Vec::with_capacity(len + params.len() + 16);
    annexb::avcc_to_annexb(&avcc, header_len as usize, &mut au)?;
    Ok(annexb::with_param_sets(au, &params))
}

pub struct MacEncoder {
    session: VTSession,
    sink: Box<Sink>,
    force_key: Cf,
    w: u32,
    h: u32,
    start: Instant,
    last_pts: i64,
    pub name: String,
}

// The session is only ever driven by one thread at a time (the Encoder sits
// behind a Mutex); VideoToolbox sessions are not tied to the creating thread.
unsafe impl Send for MacEncoder {}

impl MacEncoder {
    pub fn new(w: u32, h: u32, quality: u8) -> Result<MacEncoder, String> {
        let sink = Box::new(Sink { out: Mutex::new(Vec::new()) });
        let refcon = &*sink as *const Sink as *mut c_void;
        let attrs = {
            let (fmt, cw, ch) = (cf_i32(PIXEL_BGRA as i32), cf_i32(w as i32), cf_i32(h as i32));
            let empty = cf_dict(&[]);
            unsafe {
                cf_dict(&[
                    (kCVPixelBufferPixelFormatTypeKey, fmt.0),
                    (kCVPixelBufferWidthKey, cw.0),
                    (kCVPixelBufferHeightKey, ch.0),
                    (kCVPixelBufferIOSurfacePropertiesKey, empty.0),
                ])
            }
        };
        let mut session: VTSession = std::ptr::null_mut();
        let spec = unsafe { cf_dict(&[(kVTVideoEncoderSpecification_EnableHardwareAcceleratedVideoEncoder, kCFBooleanTrue)]) };
        let st = unsafe {
            VTCompressionSessionCreate(null(), w as i32, h as i32, CODEC_AVC1, spec.0, attrs.0, null(), Some(on_output), refcon, &mut session)
        };
        if st != 0 || session.is_null() {
            return Err(format!("VTCompressionSessionCreate failed (OSStatus {st})"));
        }
        let mut enc = MacEncoder {
            session,
            sink,
            force_key: unsafe { cf_dict(&[(kVTEncodeFrameOptionKey_ForceKeyFrame, kCFBooleanTrue)]) },
            w,
            h,
            start: Instant::now(),
            last_pts: -1,
            name: String::new(),
        };
        let set = |k: CFStringRef, v: CFTypeRef| unsafe { VTSessionSetProperty(session, k, v) };
        unsafe {
            set(kVTCompressionPropertyKey_RealTime, kCFBooleanTrue);
            if set(kVTCompressionPropertyKey_AllowFrameReordering, kCFBooleanFalse) != 0 {
                return Err("VideoToolbox refused AllowFrameReordering=false".into());
            }
            // Constrained Baseline (macOS 12+) first, then plain Baseline.
            let cb = cf_str("H264_ConstrainedBaseline_AutoLevel");
            if set(kVTCompressionPropertyKey_ProfileLevel, cb.0) != 0 {
                let st = set(kVTCompressionPropertyKey_ProfileLevel, kVTProfileLevel_H264_Baseline_AutoLevel);
                if st != 0 {
                    return Err(format!("VideoToolbox refused the Baseline profile (OSStatus {st})"));
                }
            }
            let br = cf_i32(convert::bitrate_for(w, h, quality) as i32);
            set(kVTCompressionPropertyKey_AverageBitRate, br.0);
            let gop = cf_i32(super::GOP as i32);
            set(kVTCompressionPropertyKey_MaxKeyFrameInterval, gop.0);
            let fps = cf_i32(convert::NOMINAL_FPS as i32);
            set(kVTCompressionPropertyKey_ExpectedFrameRate, fps.0);
            let zero = cf_i32(0);
            set(kVTCompressionPropertyKey_MaxFrameDelayCount, zero.0);
            set(kVTCompressionPropertyKey_ColorPrimaries, kCVImageBufferColorPrimaries_ITU_R_709_2);
            set(kVTCompressionPropertyKey_TransferFunction, kCVImageBufferTransferFunction_ITU_R_709_2);
            set(kVTCompressionPropertyKey_YCbCrMatrix, kCVImageBufferYCbCrMatrix_ITU_R_709_2);
            let st = VTCompressionSessionPrepareToEncodeFrames(session);
            if st != 0 {
                return Err(format!("VTCompressionSessionPrepareToEncodeFrames failed (OSStatus {st})"));
            }
            let mut hw: CFTypeRef = null();
            let hw_on = VTSessionCopyProperty(session, kVTCompressionPropertyKey_UsingHardwareAcceleratedVideoEncoder, null(), &mut hw) == 0
                && !hw.is_null()
                && hw == kCFBooleanTrue;
            drop(Cf(hw));
            enc.name = format!("VideoToolbox ({})", if hw_on { "hardware" } else { "software" });
        }
        Ok(enc)
    }

    pub fn encode(&mut self, frame: &image::RgbImage, force_key: bool) -> Result<Vec<u8>, String> {
        if frame.width() != self.w || frame.height() != self.h {
            return Err(format!("frame is {}x{}, encoder is {}x{}", frame.width(), frame.height(), self.w, self.h));
        }
        let (w, h) = (self.w as usize, self.h as usize);
        let pb = unsafe { self.pixel_buffer()? };
        let pb_owned = Cf(pb as CFTypeRef);
        unsafe {
            if CVPixelBufferGetWidth(pb) < w || CVPixelBufferGetHeight(pb) < h {
                return Err("pixel buffer smaller than the frame".into());
            }
            if CVPixelBufferLockBaseAddress(pb, 0) != 0 {
                return Err("CVPixelBufferLockBaseAddress failed".into());
            }
            let base = CVPixelBufferGetBaseAddress(pb);
            let stride = CVPixelBufferGetBytesPerRow(pb);
            if base.is_null() || stride < w * 4 {
                CVPixelBufferUnlockBaseAddress(pb, 0);
                return Err("pixel buffer has no usable memory".into());
            }
            let dst = std::slice::from_raw_parts_mut(base, stride * (h - 1) + w * 4);
            convert::rgb_to_bgra(frame.as_raw(), w, h, dst, stride);
            CVPixelBufferUnlockBaseAddress(pb, 0);
        }
        // Timestamps in ms of wall time keep the rate controller honest about
        // the real (variable) frame rate; they must strictly increase.
        let now = self.start.elapsed().as_millis() as i64;
        self.last_pts = now.max(self.last_pts + 1);
        let pts = CMTime { value: self.last_pts, timescale: 1000, flags: CMTIME_VALID, epoch: 0 };
        let props = if force_key { self.force_key.0 } else { null() };
        let mut info = 0u32;
        let st = unsafe {
            VTCompressionSessionEncodeFrame(self.session, pb, pts, CMTIME_INVALID, props, std::ptr::null_mut(), &mut info)
        };
        drop(pb_owned);
        if st != 0 {
            return Err(format!("VTCompressionSessionEncodeFrame failed (OSStatus {st})"));
        }
        let st = unsafe { VTCompressionSessionCompleteFrames(self.session, CMTIME_INVALID) };
        if st != 0 {
            return Err(format!("VTCompressionSessionCompleteFrames failed (OSStatus {st})"));
        }
        let mut outs = std::mem::take(&mut *self.sink.out.lock().map_err(|_| "encoder state poisoned".to_string())?);
        match outs.len() {
            0 => Err("VideoToolbox produced no output for the frame".into()),
            1 => outs.pop().unwrap_or_else(|| Err("no output".into())),
            _ => {
                let mut au = Vec::new();
                for o in outs {
                    au.extend_from_slice(&o?);
                }
                Ok(au)
            }
        }
    }

    /// A BGRA buffer from the session's pool (IOSurface-backed, reused), or a
    /// fresh one if the pool is gone. The caller owns the returned reference.
    unsafe fn pixel_buffer(&self) -> Result<CVPixelBufferRef, String> {
        let mut pb: CVPixelBufferRef = std::ptr::null_mut();
        let pool = VTCompressionSessionGetPixelBufferPool(self.session);
        if !pool.is_null() && CVPixelBufferPoolCreatePixelBuffer(null(), pool, &mut pb) == 0 && !pb.is_null() {
            return Ok(pb);
        }
        let st = CVPixelBufferCreate(null(), self.w as usize, self.h as usize, PIXEL_BGRA, null(), &mut pb);
        if st != 0 || pb.is_null() {
            return Err(format!("CVPixelBufferCreate failed ({st})"));
        }
        Ok(pb)
    }
}

impl Drop for MacEncoder {
    fn drop(&mut self) {
        unsafe {
            VTCompressionSessionCompleteFrames(self.session, CMTIME_INVALID);
            VTCompressionSessionInvalidate(self.session);
            CFRelease(self.session as CFTypeRef);
        }
        // `sink` is dropped after the session is gone, so no callback can
        // reach freed memory.
    }
}

/// Test hook: does the CFString literal we pass for a newer key equal the
/// value of the real exported symbol on this macOS? None if the symbol is absent.
#[cfg(test)]
pub fn literal_matches_symbol(symbol: &str, literal: &str) -> Option<bool> {
    extern "C" {
        fn CFEqual(a: CFTypeRef, b: CFTypeRef) -> u8;
    }
    let name = CString::new(symbol).ok()?;
    let p = unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr()) } as *const CFStringRef;
    if p.is_null() {
        return None;
    }
    let lit = cf_str(literal);
    Some(unsafe { CFEqual(*p, lit.0) } != 0)
}
