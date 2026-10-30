// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

// `/screen` response body: "ITS1" + u32 LE header length + JSON header + payload.
use serde::{Deserialize, Serialize};

pub const MAGIC: &[u8; 4] = b"ITS1";
pub const CONTENT_TYPE: &str = "application/x-itai-screen";

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Rect {
    pub x: u32,
    pub y: u32,
    pub w: u32,
    pub h: u32,
    pub off: usize,
    pub len: usize,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq)]
pub struct Point {
    pub x: i32,
    pub y: i32,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Header {
    pub seq: u64,
    pub key: bool,
    pub codec: String,
    pub w: u32,
    pub h: u32,
    pub rects: Vec<Rect>,
    pub unchanged: bool,
    pub cursor: Option<Point>,
    pub desktop: Option<String>,
    pub enc_ms: u64,
    pub wait_ms: u64,
    pub note: Option<String>,
}

pub fn encode(header: &Header, payload: &[u8]) -> Vec<u8> {
    let json = serde_json::to_vec(header).unwrap_or_default();
    let mut out = Vec::with_capacity(8 + json.len() + payload.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(json.len() as u32).to_le_bytes());
    out.extend_from_slice(&json);
    out.extend_from_slice(payload);
    out
}

/// Parse a body back into (header, payload) — what a viewer does.
#[cfg(test)]
pub fn decode(body: &[u8]) -> Result<(Header, &[u8]), String> {
    if body.len() < 8 || &body[..4] != MAGIC {
        return Err("bad magic".into());
    }
    let n = u32::from_le_bytes([body[4], body[5], body[6], body[7]]) as usize;
    let json = body.get(8..8 + n).ok_or("header length past end")?;
    let header = serde_json::from_slice(json).map_err(|e| e.to_string())?;
    Ok((header, &body[8 + n..]))
}
