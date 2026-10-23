// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

// MoorAI approval receipts. Claude Code may add `_moorai: {"receipt": "…"}` to a
// tool's input. The key is removed before the tool runs, and the receipt goes to
// the hub on every hub request the call makes, as three headers:
//
//   X-MoorAI-Receipt  the receipt, verbatim
//   X-MoorAI-Tool     the bare tool name
//   X-MoorAI-Args     base64url (no padding) of the tool input without `_moorai`
//
// The hub decides what a receipt is worth; it-ai-mcp only carries it. A dry run,
// encoded args over 16384 bytes, or a `_moorai` that is not an object with a
// string `receipt` sends no headers, and the call runs as it would without one.
use base64::Engine;
use reqwest::header::{HeaderMap, HeaderValue};
use rmcp::model::JsonObject;
use serde_json::Value;

const KEY: &str = "_moorai";
const MAX_ARGS: usize = 16384;

/// Remove `_moorai` from `args`, and return the headers this call's hub requests
/// carry, if any.
pub fn take(tool: &str, args: &mut Option<JsonObject>) -> Option<HeaderMap> {
    let a = args.as_mut()?;
    let m = a.remove(KEY)?;
    let receipt = m.as_object()?.get("receipt")?.as_str()?;
    if a.get("dry_run") == Some(&Value::Bool(true)) {
        return None;
    }
    let enc = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(a).ok()?);
    if enc.len() > MAX_ARGS {
        return None;
    }
    let mut h = HeaderMap::new();
    h.insert("x-moorai-receipt", secret(receipt)?);
    h.insert("x-moorai-tool", HeaderValue::from_str(tool).ok()?);
    h.insert("x-moorai-args", secret(&enc)?);
    Some(h)
}

/// A header value that `Debug` prints as `Sensitive`.
fn secret(s: &str) -> Option<HeaderValue> {
    let mut v = HeaderValue::from_str(s).ok()?;
    v.set_sensitive(true);
    Some(v)
}

#[cfg(test)]
mod tests;
