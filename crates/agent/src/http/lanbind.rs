// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

//! Binding the LAN listener while its port is still taken. After a self-restart the
//! port is held by the image being replaced for a while: ~10 s on macOS while an exec
//! tears down mDNS threads, 0.5-0.7 s on Windows where the old process exits after
//! spawning the new one. One attempt left the agent without its LAN listener for good.

use std::time::{Duration, Instant};

pub(crate) type BindError = Box<dyn std::error::Error + Send + Sync + 'static>;

pub(crate) struct Pace {
    pub fast: Duration,
    pub fast_for: Duration,
    pub slow: Duration,
}

pub(crate) const PACE: Pace = Pace { fast: Duration::from_millis(250), fast_for: Duration::from_secs(30), slow: Duration::from_secs(30) };

fn in_use(e: &BindError) -> bool {
    e.downcast_ref::<std::io::Error>().is_some_and(|e| e.kind() == std::io::ErrorKind::AddrInUse)
}

/// `bind()` until it succeeds, retrying for as long as the port is in use: every
/// `fast` for `fast_for`, then (after one warning) every `slow`. Any other failure
/// is returned at once.
pub(crate) fn until_bound<T>(port: u16, pace: &Pace, mut bind: impl FnMut() -> Result<T, BindError>) -> Result<T, BindError> {
    let t0 = Instant::now();
    let (mut retried, mut warned) = (false, false);
    loop {
        match bind() {
            Ok(s) => {
                if retried {
                    eprintln!("agent: bound port {port} after {} ms (it was in use)", t0.elapsed().as_millis());
                }
                return Ok(s);
            }
            Err(e) if in_use(&e) => retried = true,
            Err(e) => return Err(e),
        }
        if !warned && t0.elapsed() >= pace.fast_for {
            eprintln!(
                "warn: could not bind port {port} (port in use) — continuing with relay + loopback only; retrying every {} s",
                pace.slow.as_secs()
            );
            warned = true;
        }
        std::thread::sleep(if warned { pace.slow } else { pace.fast });
    }
}

#[cfg(test)]
mod tests;
