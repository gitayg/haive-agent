// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

// Media Foundation H.264 encoder MFT.
//
// Only SYNCHRONOUS encoder MFTs are used (MFT_ENUM_FLAG_SYNCMFT), which in
// practice is Microsoft's own software encoder (CLSID_CMSH264EncoderMFT, also
// the fallback when enumeration finds nothing). Hardware encoder MFTs are all
// asynchronous: they need MF_TRANSFORM_ASYNC_UNLOCK, an IMFMediaEventGenerator
// loop of METransformNeedInput/METransformHaveOutput events, and several of them
// only accept D3D11 surfaces, not system-memory NV12. That path cannot be tested
// here and a wrong guess there means a broken live view, while the software
// encoder is on every Windows 8+ box and keeps one frame in → one access unit
// out with CODECAPI_AVLowLatencyMode. Hardware MFTs are a follow-up once this
// one is proven on a real device.
//
// MFStartup runs once per process; COM is initialised (MTA) on each thread that
// touches the encoder, tolerating a thread that is already STA.

use std::cell::Cell;
use std::mem::ManuallyDrop;
use std::sync::OnceLock;
use std::time::Instant;

use windows::Win32::Media::MediaFoundation::*;
use windows::Win32::System::Com::{CoCreateInstance, CoInitializeEx, CoTaskMemFree, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED};
use windows::Win32::System::Variant::VARIANT;

use super::annexb;
use super::convert;

fn com_init() {
    thread_local! { static DONE: Cell<bool> = const { Cell::new(false) }; }
    DONE.with(|d| {
        if !d.get() {
            // S_OK, S_FALSE (already MTA) and RPC_E_CHANGED_MODE (already STA)
            // all leave COM usable on this thread; the MFT is free-threaded.
            let _ = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
            d.set(true);
        }
    });
}

fn mf_startup() -> Result<(), String> {
    static MF: OnceLock<Result<(), String>> = OnceLock::new();
    MF.get_or_init(|| unsafe { MFStartup(MF_VERSION, MFSTARTUP_FULL) }.map_err(|e| format!("MFStartup failed: {e}")))
        .clone()
}

fn e(what: &str) -> impl Fn(windows::core::Error) -> String + '_ {
    move |err| format!("{what}: {err}")
}

/// First synchronous H.264 encoder MFT that activates, with its friendly name.
unsafe fn create_mft() -> Result<(IMFTransform, String), String> {
    let input = MFT_REGISTER_TYPE_INFO { guidMajorType: MFMediaType_Video, guidSubtype: MFVideoFormat_NV12 };
    let output = MFT_REGISTER_TYPE_INFO { guidMajorType: MFMediaType_Video, guidSubtype: MFVideoFormat_H264 };
    let mut list: *mut Option<IMFActivate> = std::ptr::null_mut();
    let mut n = 0u32;
    let flags = MFT_ENUM_FLAG_SYNCMFT | MFT_ENUM_FLAG_LOCALMFT | MFT_ENUM_FLAG_SORTANDFILTER;
    let mut found = None;
    if MFTEnumEx(MFT_CATEGORY_VIDEO_ENCODER, flags, Some(&input), Some(&output), &mut list, &mut n).is_ok() && !list.is_null() {
        for slot in std::slice::from_raw_parts_mut(list, n as usize) {
            let Some(act) = slot.take() else { continue };
            if found.is_some() {
                continue;
            }
            let name = friendly_name(&act).unwrap_or_else(|| "H.264 encoder MFT".into());
            if let Ok(t) = act.ActivateObject::<IMFTransform>() {
                found = Some((t, name));
            }
        }
        CoTaskMemFree(Some(list as *const _));
    }
    if let Some(f) = found {
        return Ok(f);
    }
    let t: IMFTransform = CoCreateInstance(&CMSH264EncoderMFT, None, CLSCTX_INPROC_SERVER).map_err(e("CoCreateInstance(CLSID_CMSH264EncoderMFT)"))?;
    Ok((t, "Microsoft H264 Video Encoder MFT".into()))
}

unsafe fn friendly_name(act: &IMFActivate) -> Option<String> {
    let mut p = windows::core::PWSTR::null();
    let mut len = 0u32;
    act.GetAllocatedString(&MFT_FRIENDLY_NAME_Attribute, &mut p, &mut len).ok()?;
    let s = p.to_string().ok();
    CoTaskMemFree(Some(p.0 as *const _));
    s
}

fn pack(hi: u32, lo: u32) -> u64 {
    ((hi as u64) << 32) | lo as u64
}

pub struct WinEncoder {
    mft: IMFTransform,
    codec: Option<ICodecAPI>,
    w: u32,
    h: u32,
    nv12: Vec<u8>,
    params: Vec<u8>,
    out_info: MFT_OUTPUT_STREAM_INFO,
    start: Instant,
    last_ts: i64,
    pub name: String,
}

// Used from one thread at a time (behind a Mutex); every thread that touches
// it initialises COM first, and the Microsoft encoder MFT is free-threaded.
unsafe impl Send for WinEncoder {}

impl WinEncoder {
    pub fn new(w: u32, h: u32, quality: u8) -> Result<WinEncoder, String> {
        com_init();
        mf_startup()?;
        unsafe {
            let (mft, name) = create_mft()?;
            let bitrate = convert::bitrate_for(w, h, quality);
            if let Ok(attrs) = mft.GetAttributes() {
                let _ = attrs.SetUINT32(&MF_LOW_LATENCY, 1);
            }
            let codec: Option<ICodecAPI> = windows::core::Interface::cast(&mft).ok();
            if let Some(c) = &codec {
                // Best-effort: an encoder that rejects one of these still works.
                let _ = c.SetValue(&CODECAPI_AVLowLatencyMode, &VARIANT::from(true));
                let _ = c.SetValue(&CODECAPI_AVEncCommonRateControlMode, &VARIANT::from(eAVEncCommonRateControlMode_CBR.0 as u32));
                let _ = c.SetValue(&CODECAPI_AVEncCommonMeanBitRate, &VARIANT::from(bitrate));
                let _ = c.SetValue(&CODECAPI_AVEncMPVGOPSize, &VARIANT::from(super::GOP));
                let _ = c.SetValue(&CODECAPI_AVEncMPVDefaultBPictureCount, &VARIANT::from(0u32));
            }
            // The H.264 encoder wants its output type before its input type.
            let out = MFCreateMediaType().map_err(e("MFCreateMediaType"))?;
            out.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video).map_err(e("output major type"))?;
            out.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_H264).map_err(e("output subtype"))?;
            out.SetUINT32(&MF_MT_AVG_BITRATE, bitrate).map_err(e("output bitrate"))?;
            out.SetUINT64(&MF_MT_FRAME_SIZE, pack(w, h)).map_err(e("output frame size"))?;
            out.SetUINT64(&MF_MT_FRAME_RATE, pack(convert::NOMINAL_FPS, 1)).map_err(e("output frame rate"))?;
            out.SetUINT64(&MF_MT_PIXEL_ASPECT_RATIO, pack(1, 1)).map_err(e("output aspect"))?;
            out.SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32).map_err(e("output interlace"))?;
            out.SetUINT32(&MF_MT_MPEG2_PROFILE, eAVEncH264VProfile_Base.0 as u32).map_err(e("output profile"))?;
            mft.SetOutputType(0, &out, 0).map_err(e("SetOutputType(H.264 Baseline)"))?;

            let inp = MFCreateMediaType().map_err(e("MFCreateMediaType"))?;
            inp.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video).map_err(e("input major type"))?;
            inp.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_NV12).map_err(e("input subtype"))?;
            inp.SetUINT64(&MF_MT_FRAME_SIZE, pack(w, h)).map_err(e("input frame size"))?;
            inp.SetUINT64(&MF_MT_FRAME_RATE, pack(convert::NOMINAL_FPS, 1)).map_err(e("input frame rate"))?;
            inp.SetUINT64(&MF_MT_PIXEL_ASPECT_RATIO, pack(1, 1)).map_err(e("input aspect"))?;
            inp.SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32).map_err(e("input interlace"))?;
            let _ = inp.SetUINT32(&MF_MT_YUV_MATRIX, MFVideoTransferMatrix_BT709.0 as u32);
            let _ = inp.SetUINT32(&MF_MT_VIDEO_NOMINAL_RANGE, MFNominalRange_16_235.0 as u32);
            mft.SetInputType(0, &inp, 0).map_err(e("SetInputType(NV12)"))?;

            let out_info = mft.GetOutputStreamInfo(0).map_err(e("GetOutputStreamInfo"))?;
            let _ = mft.ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0);
            let _ = mft.ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0);
            Ok(WinEncoder {
                mft,
                codec,
                w,
                h,
                nv12: Vec::new(),
                params: Vec::new(),
                out_info,
                start: Instant::now(),
                last_ts: -1,
                name: format!("Media Foundation ({name})"),
            })
        }
    }

    pub fn encode(&mut self, frame: &image::RgbImage, force_key: bool) -> Result<Vec<u8>, String> {
        if frame.width() != self.w || frame.height() != self.h {
            return Err(format!("frame is {}x{}, encoder is {}x{}", frame.width(), frame.height(), self.w, self.h));
        }
        com_init();
        convert::rgb_to_nv12(frame.as_raw(), self.w as usize, self.h as usize, &mut self.nv12);
        // 100 ns units of wall time, strictly increasing.
        let now = (self.start.elapsed().as_nanos() / 100) as i64;
        self.last_ts = now.max(self.last_ts + 1);
        unsafe {
            if force_key {
                if let Some(c) = &self.codec {
                    c.SetValue(&CODECAPI_AVEncVideoForceKeyFrame, &VARIANT::from(1u32)).map_err(e("force key frame"))?;
                }
            }
            let sample = self.input_sample()?;
            if let Err(err) = self.mft.ProcessInput(0, &sample, 0) {
                if err.code() != MF_E_NOTACCEPTING {
                    return Err(format!("ProcessInput: {err}"));
                }
                // Output was pending: collect it, then the input fits.
                let mut au = self.pull()?;
                self.mft.ProcessInput(0, &sample, 0).map_err(e("ProcessInput"))?;
                au.extend(self.pull()?);
                return Ok(self.finish(au));
            }
            let mut au = self.pull()?;
            if au.is_empty() {
                // An encoder that still holds the frame back: drain it.
                self.mft.ProcessMessage(MFT_MESSAGE_COMMAND_DRAIN, 0).map_err(e("drain"))?;
                au = self.pull()?;
            }
            if au.is_empty() {
                return Err("Media Foundation produced no output for the frame".into());
            }
            Ok(self.finish(au))
        }
    }

    unsafe fn input_sample(&self) -> Result<IMFSample, String> {
        let len = self.nv12.len() as u32;
        let buf = MFCreateMemoryBuffer(len).map_err(e("MFCreateMemoryBuffer"))?;
        let mut p: *mut u8 = std::ptr::null_mut();
        buf.Lock(&mut p, None, None).map_err(e("IMFMediaBuffer::Lock"))?;
        std::ptr::copy_nonoverlapping(self.nv12.as_ptr(), p, self.nv12.len());
        buf.Unlock().map_err(e("IMFMediaBuffer::Unlock"))?;
        buf.SetCurrentLength(len).map_err(e("SetCurrentLength"))?;
        let s = MFCreateSample().map_err(e("MFCreateSample"))?;
        s.AddBuffer(&buf).map_err(e("AddBuffer"))?;
        s.SetSampleTime(self.last_ts).map_err(e("SetSampleTime"))?;
        s.SetSampleDuration(10_000_000 / convert::NOMINAL_FPS as i64).map_err(e("SetSampleDuration"))?;
        Ok(s)
    }

    /// Every output sample the MFT has ready, concatenated (already Annex-B).
    unsafe fn pull(&mut self) -> Result<Vec<u8>, String> {
        let mut au = Vec::new();
        loop {
            let provides = self.out_info.dwFlags & (MFT_OUTPUT_STREAM_PROVIDES_SAMPLES.0 as u32) != 0;
            let mine = if provides {
                None
            } else {
                let size = self.out_info.cbSize.max(self.w * self.h * 3 / 2 + 65536);
                let b = MFCreateMemoryBuffer(size).map_err(e("MFCreateMemoryBuffer(out)"))?;
                let s = MFCreateSample().map_err(e("MFCreateSample(out)"))?;
                s.AddBuffer(&b).map_err(e("AddBuffer(out)"))?;
                Some(s)
            };
            let mut db = [MFT_OUTPUT_DATA_BUFFER {
                dwStreamID: 0,
                pSample: ManuallyDrop::new(mine),
                dwStatus: 0,
                pEvents: ManuallyDrop::new(None),
            }];
            let mut status = 0u32;
            let r = self.mft.ProcessOutput(0, &mut db, &mut status);
            let sample = ManuallyDrop::take(&mut db[0].pSample);
            drop(ManuallyDrop::take(&mut db[0].pEvents));
            match r {
                Ok(()) => {
                    if let Some(s) = sample {
                        let b = s.ConvertToContiguousBuffer().map_err(e("ConvertToContiguousBuffer"))?;
                        let mut p: *mut u8 = std::ptr::null_mut();
                        let mut n = 0u32;
                        b.Lock(&mut p, None, Some(&mut n)).map_err(e("Lock(out)"))?;
                        au.extend_from_slice(std::slice::from_raw_parts(p, n as usize));
                        b.Unlock().map_err(e("Unlock(out)"))?;
                    }
                }
                Err(err) if err.code() == MF_E_TRANSFORM_NEED_MORE_INPUT => return Ok(au),
                Err(err) if err.code() == MF_E_TRANSFORM_STREAM_CHANGE => {
                    let t = self.mft.GetOutputAvailableType(0, 0).map_err(e("GetOutputAvailableType"))?;
                    self.mft.SetOutputType(0, &t, 0).map_err(e("SetOutputType(after stream change)"))?;
                    self.out_info = self.mft.GetOutputStreamInfo(0).map_err(e("GetOutputStreamInfo"))?;
                }
                Err(err) => return Err(format!("ProcessOutput: {err}")),
            }
        }
    }

    /// Keep SPS+PPS in front of every IDR: remember them from the stream, or
    /// fall back to MF_MT_MPEG_SEQUENCE_HEADER on the output type.
    unsafe fn finish(&mut self, au: Vec<u8>) -> Vec<u8> {
        let ps = annexb::param_sets(&au);
        if annexb::has_nal(&ps, annexb::NAL_SPS) && annexb::has_nal(&ps, annexb::NAL_PPS) {
            self.params = ps;
        } else if annexb::is_idr(&au) && self.params.is_empty() {
            if let Some(h) = self.sequence_header() {
                self.params = h;
            }
        }
        annexb::with_param_sets(au, &self.params)
    }

    unsafe fn sequence_header(&self) -> Option<Vec<u8>> {
        let t = self.mft.GetOutputCurrentType(0).ok()?;
        let mut p: *mut u8 = std::ptr::null_mut();
        let mut n = 0u32;
        t.GetAllocatedBlob(&MF_MT_MPEG_SEQUENCE_HEADER, &mut p, &mut n).ok()?;
        let blob = std::slice::from_raw_parts(p, n as usize).to_vec();
        CoTaskMemFree(Some(p as *const _));
        let ps = annexb::param_sets(&blob);
        (!ps.is_empty()).then_some(ps)
    }
}

impl Drop for WinEncoder {
    fn drop(&mut self) {
        com_init();
        unsafe {
            let _ = self.mft.ProcessMessage(MFT_MESSAGE_NOTIFY_END_OF_STREAM, 0);
            let _ = self.mft.ProcessMessage(MFT_MESSAGE_NOTIFY_END_STREAMING, 0);
        }
    }
}
