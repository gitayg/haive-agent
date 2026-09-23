// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

//! Hub-issued capability tokens: the shared vocabulary of the LAN-direct path.
//!
//! A controller that reaches an agent over the LAN bypasses the hub's proxy, and
//! with it the authorization, command deny-list and audit trail that proxy runs.
//! A capability token restores them: the controller asks the hub for permission
//! to perform one operation on one device with one argument, the hub runs those
//! controls and signs a 60-second grant, and the agent verifies the grant before
//! serving the request.
//!
//! This crate is the single definition of the two rules both ends must agree on,
//! byte for byte — the **op/argument canonicalization** (`op_for`, `arg_hash`)
//! and the **token format** (`parse_and_verify`). The controller (`it-ai-direct`)
//! uses it to work out what to ask the hub for; the agent (`it-ai-agent`) uses it
//! to work out what it should have been handed. If the two ever disagreed, every
//! direct call would fail closed — which is why they are not allowed to be two
//! separate implementations.
//!
//! The hub, being a separate repository, necessarily carries its own copy of the
//! same rules (`crates/hub/src/capability.rs`); the wire contract below is what
//! keeps them the same, and the hub only ever hashes an argument string the
//! controller supplies, so the *derivation* of that string lives only here.
//!
//! ## Wire contract
//!
//! ```text
//! <base64url-nopad(payload_json)>.<base64url-nopad(ed25519_sig_64)>
//! ```
//!
//! The signature covers the exact `payload_json` bytes before encoding:
//!
//! ```json
//! {"v":1,"dev":"hc-…","op":"exec","arg":"<sha256-hex>","iat":…,"exp":…,"nonce":"<32-hex>"}
//! ```

use base64::Engine;
use sha2::{Digest, Sha256};

/// The request header a capability travels in.
pub const HEADER: &str = "X-IT-AI-Capability";

/// Tolerance for disagreeing clocks between hub and agent. Applied to both ends
/// of the window: a token may be up to this far in the future when it arrives,
/// and stays acceptable this far past its stated expiry.
pub const SKEW_SECS: u64 = 30;

/// Upper bound on the replay cache. See `ReplayCache`.
const REPLAY_MAX: usize = 100_000;

#[derive(Debug, Clone)]
pub struct Payload {
    pub dev: String,
    pub op: String,
    pub arg: String,
    pub iat: u64,
    pub exp: u64,
    pub nonce: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CapError {
    Missing,
    Malformed,
    BadSignature,
    Expired,
    NotYetValid,
    WrongDevice,
    WrongOp,
    WrongArg,
    Replayed,
    CacheFull,
}

impl CapError {
    pub fn as_str(&self) -> &'static str {
        match self {
            CapError::Missing => "capability required for LAN-direct access",
            CapError::Malformed => "malformed capability",
            CapError::BadSignature => "capability signature invalid",
            CapError::Expired => "capability expired",
            CapError::NotYetValid => "capability not yet valid",
            CapError::WrongDevice => "capability issued for a different device",
            CapError::WrongOp => "capability issued for a different operation",
            CapError::WrongArg => "capability issued for a different argument",
            CapError::Replayed => "capability already used",
            CapError::CacheFull => "capability replay cache full",
        }
    }
}

/// The canonicalization rule for a capability's `arg`: lowercase hex SHA-256 over
/// the UTF-8 bytes of the canonical argument string, verbatim — no trimming, no
/// case folding, no Unicode normalization, no JSON re-serialization. An operation
/// with no meaningful argument hashes the empty string.
pub fn arg_hash(arg: &str) -> String {
    let mut h = Sha256::new();
    h.update(arg.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Map an agent endpoint to the capability it requires: `(op, canonical arg)`.
///
/// `path` is the agent's own path with or without its leading slash — the same
/// string `it-ai-direct`'s `Op::path` carries and the same one the agent routes
/// on, which is what makes one rule serve both ends. `body` is the parsed JSON
/// request body where there is one.
///
/// `None` means the endpoint has no capability defined for it. The agent treats
/// that as a refusal on the LAN listener (there is no token that could authorize
/// it), so `/update`, `/dissolve`, `/persist`, `/wol` and `/schedule/*` are
/// reachable over the relay and loopback only — deliberately, since none of them
/// is on the direct path and inventing an op for them would widen the contract
/// past what the hub mints.
pub fn op_for(path: &str, body: Option<&serde_json::Value>) -> Option<(&'static str, String)> {
    let p = path.trim_start_matches('/');
    let str_field = |k: &str| {
        body.and_then(|v| v.get(k)).and_then(|x| x.as_str()).unwrap_or("").to_string()
    };
    match p {
        // The hub's deny-list distinguishes a foreground command from a detached
        // one, so the capability does too — a grant to `exec` does not authorize
        // the same command as a background `launch`.
        "exec" => {
            let detach = body.and_then(|v| v.get("detach")).and_then(|x| x.as_bool()).unwrap_or(false);
            Some((if detach { "launch" } else { "exec" }, str_field("cmd")))
        }
        // Bound to the event kind, which is exactly what `policy::enforce("input", …)`
        // inspects on the hub — so a grant for a pointer move does not also
        // authorize a keystroke.
        "input" => Some(("input", str_field("type"))),
        "frame" | "stream" => Some(("frame", String::new())),
        "camera" | "camstream" => Some(("camera", String::new())),
        // `list` and `file-status` are reads of the same file surface `download`
        // covers, including the reachability probe the controller opens with.
        "download" | "list" | "file-status" => Some(("download", String::new())),
        "upload" | "fetch-file" => Some(("upload", String::new())),
        _ if p.starts_with("shell/") => Some(("shell", String::new())),
        _ => None,
    }
}

/// Split a token, verify its ed25519 signature against `pubkey`, and check every
/// field binds it to this request: the device, the operation, the argument hash
/// and the validity window. `now` is unix seconds.
///
/// Signature first, then the fields: a forged token must not be able to produce a
/// more specific error than "invalid signature", which would otherwise let an
/// attacker probe what the agent expects.
pub fn parse_and_verify(
    token: &str,
    pubkey: &[u8; 32],
    dev: &str,
    op: &str,
    arg: &str,
    now: u64,
) -> Result<Payload, CapError> {
    use ed25519_dalek::{Signature, VerifyingKey};

    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let (p64, s64) = token.split_once('.').ok_or(CapError::Malformed)?;
    let payload_bytes = b64.decode(p64).map_err(|_| CapError::Malformed)?;
    let sig_bytes: [u8; 64] =
        b64.decode(s64).map_err(|_| CapError::Malformed)?.try_into().map_err(|_| CapError::Malformed)?;

    let vk = VerifyingKey::from_bytes(pubkey).map_err(|_| CapError::BadSignature)?;
    // `verify_strict` (not `verify`) — it rejects small-order / torsion-component
    // public keys and signatures, the same hardening the update-signature check
    // uses.
    vk.verify_strict(&payload_bytes, &Signature::from_bytes(&sig_bytes))
        .map_err(|_| CapError::BadSignature)?;

    let v: serde_json::Value = serde_json::from_slice(&payload_bytes).map_err(|_| CapError::Malformed)?;
    if v.get("v").and_then(|x| x.as_u64()) != Some(1) {
        return Err(CapError::Malformed);
    }
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).map(String::from).ok_or(CapError::Malformed);
    let n = |k: &str| v.get(k).and_then(|x| x.as_u64()).ok_or(CapError::Malformed);
    let p = Payload {
        dev: s("dev")?,
        op: s("op")?,
        arg: s("arg")?,
        iat: n("iat")?,
        exp: n("exp")?,
        nonce: s("nonce")?,
    };
    if p.nonce.len() != 32 {
        return Err(CapError::Malformed);
    }
    if now > p.exp.saturating_add(SKEW_SECS) {
        return Err(CapError::Expired);
    }
    if p.iat > now.saturating_add(SKEW_SECS) {
        return Err(CapError::NotYetValid);
    }
    if p.dev != dev {
        return Err(CapError::WrongDevice);
    }
    if p.op != op {
        return Err(CapError::WrongOp);
    }
    if p.arg != arg_hash(arg) {
        return Err(CapError::WrongArg);
    }
    Ok(p)
}

/// Nonces already spent, so a captured token cannot be used twice inside its
/// 60-second window.
///
/// Bounded two ways. Every insert first drops entries whose token has expired,
/// which is what normally keeps it small — a nonce is only interesting for as
/// long as the token it belongs to is valid, so steady-state size is "capabilities
/// minted in the last minute". `REPLAY_MAX` is the backstop for the case that
/// sweep cannot handle: reaching it means ~100k *hub-signed* capabilities arrived
/// inside one TTL, at which point the agent refuses further direct calls rather
/// than evicting live nonces and re-opening the replay window. Refusing is not an
/// outage — the controller falls back to the relay, which the hub authorizes
/// itself.
#[derive(Default)]
pub struct ReplayCache {
    seen: std::collections::HashMap<String, u64>,
}

impl ReplayCache {
    /// Record `nonce` as spent. `Err(Replayed)` if it was already here.
    pub fn claim(&mut self, nonce: &str, exp: u64, now: u64) -> Result<(), CapError> {
        self.seen.retain(|_, e| *e + SKEW_SECS > now);
        if self.seen.contains_key(nonce) {
            return Err(CapError::Replayed);
        }
        if self.seen.len() >= REPLAY_MAX {
            return Err(CapError::CacheFull);
        }
        self.seen.insert(nonce.to_string(), exp);
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

/// Decode the hub's `/relay/cap-key` / `/m/cap-key` response (64 lowercase hex
/// characters) into a raw ed25519 public key.
pub fn pubkey_from_hex(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}
