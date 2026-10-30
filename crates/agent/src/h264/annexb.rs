// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

// H.264 bitstream helpers: AVCC (length-prefixed) → Annex-B (start codes),
// NAL scanning, parameter-set handling and the WebCodecs codec string.

// Each OS backend uses a different subset of these.
#![allow(dead_code)]

pub const START_CODE: [u8; 4] = [0, 0, 0, 1];

pub const NAL_IDR: u8 = 5;
pub const NAL_SPS: u8 = 7;
pub const NAL_PPS: u8 = 8;
pub const NAL_AUD: u8 = 9;

pub fn nal_type(nal: &[u8]) -> u8 {
    nal.first().map(|b| b & 0x1f).unwrap_or(0)
}

/// Append each NAL of an AVCC buffer (`len_size`-byte big-endian lengths) to
/// `out` with a 4-byte start code.
pub fn avcc_to_annexb(data: &[u8], len_size: usize, out: &mut Vec<u8>) -> Result<(), String> {
    if !(1..=4).contains(&len_size) {
        return Err(format!("bad AVCC length size {len_size}"));
    }
    let mut i = 0;
    while i < data.len() {
        if i + len_size > data.len() {
            return Err("truncated AVCC length prefix".into());
        }
        let n = data[i..i + len_size].iter().fold(0usize, |a, &b| (a << 8) | b as usize);
        i += len_size;
        if n == 0 || i + n > data.len() {
            return Err(format!("bad AVCC NAL length {n} at offset {}", i - len_size));
        }
        out.extend_from_slice(&START_CODE);
        out.extend_from_slice(&data[i..i + n]);
        i += n;
    }
    Ok(())
}

/// (start_code_offset, payload_start, payload_end) of every NAL in an Annex-B
/// buffer. Accepts 3- and 4-byte start codes.
pub fn nal_spans(au: &[u8]) -> Vec<(usize, usize, usize)> {
    let mut starts = Vec::new();
    let mut i = 0;
    while i + 3 <= au.len() {
        if au[i] == 0 && au[i + 1] == 0 && au[i + 2] == 1 {
            let sc = if i > 0 && au[i - 1] == 0 { i - 1 } else { i };
            starts.push((sc, i + 3));
            i += 3;
        } else {
            i += 1;
        }
    }
    let mut spans = Vec::with_capacity(starts.len());
    for (k, &(sc, p)) in starts.iter().enumerate() {
        let mut end = starts.get(k + 1).map(|s| s.0).unwrap_or(au.len());
        while end > p && au[end - 1] == 0 {
            end -= 1;
        }
        spans.push((sc, p, end));
    }
    spans
}

pub fn nals(au: &[u8]) -> Vec<&[u8]> {
    nal_spans(au).into_iter().map(|(_, s, e)| &au[s..e]).collect()
}

pub fn has_nal(au: &[u8], t: u8) -> bool {
    nals(au).iter().any(|n| nal_type(n) == t)
}

pub fn is_idr(au: &[u8]) -> bool {
    has_nal(au, NAL_IDR)
}

/// All SPS and PPS NALs of `au`, re-emitted as Annex-B. Empty when none.
pub fn param_sets(au: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for n in nals(au) {
        let t = nal_type(n);
        if t == NAL_SPS || t == NAL_PPS {
            out.extend_from_slice(&START_CODE);
            out.extend_from_slice(n);
        }
    }
    out
}

/// An IDR access unit that lacks SPS or PPS gets `params` (Annex-B SPS+PPS)
/// inserted in front of its first NAL that is not an access unit delimiter.
/// Anything else is returned unchanged.
pub fn with_param_sets(au: Vec<u8>, params: &[u8]) -> Vec<u8> {
    if params.is_empty() || !is_idr(&au) || (has_nal(&au, NAL_SPS) && has_nal(&au, NAL_PPS)) {
        return au;
    }
    let spans = nal_spans(&au);
    let at = spans
        .iter()
        .find(|(_, s, e)| nal_type(&au[*s..*e]) != NAL_AUD)
        .map(|(sc, _, _)| *sc)
        .unwrap_or(0);
    let mut out = Vec::with_capacity(au.len() + params.len());
    out.extend_from_slice(&au[..at]);
    out.extend_from_slice(params);
    out.extend_from_slice(&au[at..]);
    out
}

/// `avc1.PPCCLL` from an SPS NAL (header byte included): profile_idc,
/// constraint flags and level_idc are its first three payload bytes. None of
/// them can hold an emulation-prevention byte, since profile_idc is never 0.
pub fn codec_string_from_sps(sps: &[u8]) -> Option<String> {
    if sps.len() < 4 || nal_type(sps) != NAL_SPS {
        return None;
    }
    Some(format!("avc1.{:02x}{:02x}{:02x}", sps[1], sps[2], sps[3]))
}

/// Codec string of the first SPS in an Annex-B access unit.
pub fn codec_string(au: &[u8]) -> Option<String> {
    nals(au).into_iter().find(|n| nal_type(n) == NAL_SPS).and_then(codec_string_from_sps)
}
