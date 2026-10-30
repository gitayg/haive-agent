// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

// Request authentication between the session-0 service and its SYSTEM screen
// helper. The helper listens on 127.0.0.1, but loopback is NOT a trust boundary:
// any local user can connect to it. So every request carries an HMAC-SHA256 over
// (method, path+query, nonce, body hash) keyed by a per-launch random secret, and
// every answer carries an HMAC over (nonce, status) so the service can tell its
// own helper from a process that grabbed the port first. The secret itself never
// crosses the socket — a squatter on the port learns nothing it can replay.
#![cfg_attr(not(windows), allow(dead_code))]

use sha2::{Digest, Sha256};
use std::collections::VecDeque;

pub const KEY_LEN: usize = 32;
/// Nonces are 16 random bytes, hex-encoded.
pub const NONCE_HEX_LEN: usize = 32;

pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let inner = Sha256::new().chain_update(ipad).chain_update(msg).finalize();
    Sha256::new().chain_update(opad).chain_update(inner).finalize().into()
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| s.get(i..i + 2).and_then(|p| u8::from_str_radix(p, 16).ok()))
        .collect()
}

/// Constant-time equality (length is not secret).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The helper's key, as the service hands it over (64 hex chars).
pub fn parse_key(s: &str) -> Option<[u8; KEY_LEN]> {
    unhex(s.trim())?.try_into().ok()
}

fn request_msg(method: &str, path: &str, nonce: &str, body: &[u8]) -> Vec<u8> {
    format!("itai-sh-req\n{method}\n{path}\n{nonce}\n{}", hex(&Sha256::digest(body))).into_bytes()
}

pub fn request_tag(key: &[u8], method: &str, path: &str, nonce: &str, body: &[u8]) -> String {
    hex(&hmac_sha256(key, &request_msg(method, path, nonce, body)))
}

/// Helper side: is this request from the service that launched us?
pub fn verify_request(key: &[u8], method: &str, path: &str, nonce: &str, body: &[u8], tag: &str) -> bool {
    if nonce.len() != NONCE_HEX_LEN || unhex(nonce).is_none() {
        return false;
    }
    let Some(got) = unhex(tag) else { return false };
    ct_eq(&got, &hmac_sha256(key, &request_msg(method, path, nonce, body)))
}

pub fn response_tag(key: &[u8], nonce: &str, status: u16) -> String {
    hex(&hmac_sha256(key, format!("itai-sh-resp\n{nonce}\n{status}").as_bytes()))
}

/// Service side: did OUR helper answer (and not something squatting its port)?
pub fn verify_response(key: &[u8], nonce: &str, status: u16, tag: &str) -> bool {
    let Some(got) = unhex(tag) else { return false };
    ct_eq(&got, &hmac_sha256(key, format!("itai-sh-resp\n{nonce}\n{status}").as_bytes()))
}

/// Rejects a nonce seen recently, so a captured request can't be replayed.
pub struct NonceCache {
    seen: VecDeque<String>,
    cap: usize,
}

impl NonceCache {
    pub fn new(cap: usize) -> Self {
        NonceCache { seen: VecDeque::with_capacity(cap), cap }
    }

    /// True the first time a nonce is presented, false on a replay.
    pub fn claim(&mut self, nonce: &str) -> bool {
        if self.seen.iter().any(|n| n == nonce) {
            return false;
        }
        if self.seen.len() == self.cap {
            self.seen.pop_front();
        }
        self.seen.push_back(nonce.to_string());
        true
    }
}

/// N bytes from the OS CSPRNG. The crate has no `rand` dependency; vpn.rs reads
/// /dev/urandom, so unix does the same, and Windows uses ProcessPrng (the RNG
/// Rust's std itself uses), falling back to RtlGenRandom. Both are resolved from
/// System32 only, never the DLL search path, because this runs as SYSTEM.
pub fn random_bytes<const N: usize>() -> Result<[u8; N], String> {
    let mut b = [0u8; N];
    fill_os(&mut b)?;
    Ok(b)
}

#[cfg(unix)]
fn fill_os(buf: &mut [u8]) -> Result<(), String> {
    use std::io::Read;
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(buf))
        .map_err(|e| format!("/dev/urandom: {e}"))
}

#[cfg(windows)]
fn fill_os(buf: &mut [u8]) -> Result<(), String> {
    use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32};
    let wide = |s: &str| s.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
    unsafe {
        let lib = LoadLibraryExW(wide("bcryptprimitives.dll").as_ptr(), std::ptr::null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32);
        if !lib.is_null() {
            if let Some(f) = GetProcAddress(lib, c"ProcessPrng".as_ptr().cast()) {
                let prng: unsafe extern "system" fn(*mut u8, usize) -> i32 = std::mem::transmute(f);
                if prng(buf.as_mut_ptr(), buf.len()) != 0 {
                    return Ok(());
                }
            }
        }
        let lib = LoadLibraryExW(wide("advapi32.dll").as_ptr(), std::ptr::null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32);
        if !lib.is_null() {
            if let Some(f) = GetProcAddress(lib, c"SystemFunction036".as_ptr().cast()) {
                let gen: unsafe extern "system" fn(*mut u8, u32) -> u8 = std::mem::transmute(f);
                if gen(buf.as_mut_ptr(), buf.len() as u32) != 0 {
                    return Ok(());
                }
            }
        }
    }
    Err("no OS random number generator available".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 4231 test case 2.
    #[test]
    fn hmac_matches_rfc4231() {
        assert_eq!(
            hex(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    // RFC 4231 test case 6: a key longer than the block size is hashed first.
    #[test]
    fn hmac_long_key_matches_rfc4231() {
        assert_eq!(
            hex(&hmac_sha256(&[0xaa; 131], b"Test Using Larger Than Block-Size Key - Hash Key First")),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    fn nonce() -> String {
        hex(&random_bytes::<16>().unwrap())
    }

    #[test]
    fn request_tag_round_trips() {
        let key = random_bytes::<KEY_LEN>().unwrap();
        let n = nonce();
        let tag = request_tag(&key, "POST", "/input", &n, br#"{"type":"move"}"#);
        assert!(verify_request(&key, "POST", "/input", &n, br#"{"type":"move"}"#, &tag));
    }

    #[test]
    fn request_tag_rejects_any_change() {
        let key = random_bytes::<KEY_LEN>().unwrap();
        let other = random_bytes::<KEY_LEN>().unwrap();
        let n = nonce();
        let tag = request_tag(&key, "GET", "/screen?sid=a&ack=0", &n, b"");
        assert!(!verify_request(&other, "GET", "/screen?sid=a&ack=0", &n, b"", &tag), "wrong key");
        assert!(!verify_request(&key, "POST", "/screen?sid=a&ack=0", &n, b"", &tag), "method");
        assert!(!verify_request(&key, "GET", "/screen?sid=b&ack=0", &n, b"", &tag), "query");
        assert!(!verify_request(&key, "GET", "/screen?sid=a&ack=0", &nonce(), b"", &tag), "nonce");
        assert!(!verify_request(&key, "GET", "/screen?sid=a&ack=0", &n, b"x", &tag), "body");
        assert!(!verify_request(&key, "GET", "/screen?sid=a&ack=0", &n, b"", ""), "empty tag");
        assert!(!verify_request(&key, "GET", "/screen?sid=a&ack=0", &n, b"", "zz"), "non-hex tag");
        assert!(!verify_request(&key, "GET", "/screen?sid=a&ack=0", "short", b"", &tag), "bad nonce");
    }

    #[test]
    fn response_tag_binds_nonce_and_status() {
        let key = random_bytes::<KEY_LEN>().unwrap();
        let n = nonce();
        let tag = response_tag(&key, &n, 200);
        assert!(verify_response(&key, &n, 200, &tag));
        assert!(!verify_response(&key, &n, 500, &tag));
        assert!(!verify_response(&key, &nonce(), 200, &tag));
        assert!(!verify_response(&random_bytes::<KEY_LEN>().unwrap(), &n, 200, &tag));
    }

    #[test]
    fn ct_eq_compares_all_bytes() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"xbc", b"abc"));
        assert!(!ct_eq(b"ab", b"abc"));
    }

    #[test]
    fn key_parse_needs_exactly_32_bytes() {
        let k = random_bytes::<KEY_LEN>().unwrap();
        assert_eq!(parse_key(&hex(&k)), Some(k));
        assert_eq!(parse_key(&hex(&k[..31])), None);
        assert_eq!(parse_key("not hex"), None);
    }

    #[test]
    fn nonce_cache_rejects_replay_and_forgets_oldest() {
        let mut c = NonceCache::new(2);
        assert!(c.claim("a"));
        assert!(!c.claim("a"));
        assert!(c.claim("b"));
        assert!(c.claim("c")); // evicts "a"
        assert!(c.claim("a"));
        assert!(!c.claim("c"));
    }

    #[test]
    fn random_bytes_differ() {
        assert_ne!(random_bytes::<32>().unwrap(), random_bytes::<32>().unwrap());
    }
}
