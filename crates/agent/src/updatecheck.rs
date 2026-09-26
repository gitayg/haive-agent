// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

//! Deciding whether an update would change anything, before paying for it.
//!
//! Two places used to act without asking. The auto-update loops downloaded the
//! whole ~10 MB binary every 120 s just to compare it with the running one — about
//! 7 GB a day across four agents, all of it through the hub. And `POST /update`
//! installed whatever it downloaded, so a hub that kept pushing (Sept 2026: hub
//! auto-update compared agents to the hub's own version, never equal) made every
//! agent reinstall the identical binary and restart every five minutes.
//!
//! The checksum file consulted here is not signed. That is fine for this use: the
//! worst a lying hub can do by claiming "unchanged" is suppress an update. Anything
//! that actually gets installed still passes the pinned-key signature check.

use sha2::{Digest, Sha256};

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// The hash published for `asset` in a `sha256sum`-format listing
/// (`<hex>  <name>`, or `<hex> *<name>` for binary mode).
pub(crate) fn published_hash(sums: &str, asset: &str) -> Option<String> {
    sums.lines().find_map(|line| {
        let (hash, name) = line.trim().split_once(char::is_whitespace)?;
        let name = name.trim_start().trim_start_matches('*');
        (name == asset && hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()))
            .then(|| hash.to_ascii_lowercase())
    })
}

/// `Some(true)` when the hub's published checksum says `asset` is the binary we
/// already run, `Some(false)` when it says otherwise, and `None` when the hub
/// publishes nothing usable for it (an older hub, or a release without
/// SHA256SUMS) — the caller then falls back to downloading and comparing bytes.
pub(crate) fn is_current(own_hash: &str, sums: Option<&str>, asset: &str) -> Option<bool> {
    published_hash(sums?, asset).map(|h| h == own_hash)
}

/// Whether `bytes` is exactly the executable this process is running from.
pub(crate) fn is_running_binary(bytes: &[u8]) -> bool {
    std::env::current_exe()
        .ok()
        .and_then(|p| std::fs::read(p).ok())
        .is_some_and(|own| own == bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUMS: &str = "\
009bc25bc08f94f90bc0497cae97a6c4da947ae6bc993009ca5cd4dcd2c487c6  it-ai-linux
316fb9095b7c8115a17a620d8cdd2163acc3c2d558a1db35ef961352fcf9ff38  it-ai-linux-arm64
c1144154de7dde53409d81d31fd80374d44e8835c4c6798cc452a4cbf84a9c34 *it-ai-windows.exe
";

    #[test]
    fn finds_the_exact_asset_not_a_prefix_match() {
        assert_eq!(
            published_hash(SUMS, "it-ai-linux").as_deref(),
            Some("009bc25bc08f94f90bc0497cae97a6c4da947ae6bc993009ca5cd4dcd2c487c6")
        );
        // "it-ai-linux" is a prefix of "it-ai-linux-arm64"; the arm64 line must not
        // answer for it, nor the other way round.
        assert_eq!(
            published_hash(SUMS, "it-ai-linux-arm64").as_deref(),
            Some("316fb9095b7c8115a17a620d8cdd2163acc3c2d558a1db35ef961352fcf9ff38")
        );
        assert!(published_hash(SUMS, "it-ai-windows.exe").is_some(), "binary-mode '*' marker");
        assert_eq!(published_hash(SUMS, "it-ai-macos"), None);
    }

    /// The whole point: an unchanged binary must be recognised without a download.
    #[test]
    fn unchanged_binary_skips_the_download() {
        let own = "009bc25bc08f94f90bc0497cae97a6c4da947ae6bc993009ca5cd4dcd2c487c6";
        assert_eq!(is_current(own, Some(SUMS), "it-ai-linux"), Some(true));
    }

    #[test]
    fn changed_binary_is_fetched() {
        let own = "6e23c13d05ce52d19234cee4612277e39778f21d28aedf7574823b108d325d02";
        assert_eq!(is_current(own, Some(SUMS), "it-ai-linux"), Some(false));
    }

    #[test]
    fn no_usable_checksum_falls_back_to_downloading() {
        let own = "009bc25bc08f94f90bc0497cae97a6c4da947ae6bc993009ca5cd4dcd2c487c6";
        assert_eq!(is_current(own, None, "it-ai-linux"), None);
        assert_eq!(is_current(own, Some("not a checksum file"), "it-ai-linux"), None);
        assert_eq!(is_current(own, Some(SUMS), "it-ai-macos"), None);
    }

    #[test]
    fn hashes_like_sha256sum() {
        assert_eq!(sha256_hex(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn recognises_the_running_binary_and_nothing_else() {
        let own = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        assert!(is_running_binary(&own));
        let mut other = own.clone();
        let last = other.len() - 1;
        other[last] ^= 0xff;
        assert!(!is_running_binary(&other));
    }
}
