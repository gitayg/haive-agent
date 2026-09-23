// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

//! Per-device transport decision and its cache.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Which transport a device's calls take.
#[derive(Clone)]
pub enum Route {
    /// The agent answered on its LAN address with a hub-CA-valid cert and
    /// accepted our per-device token. `base` is `https://<ip>:<port>`.
    Direct { base: String, dtok: String },
    /// Everything through the hub's `/m/<action>` proxy.
    Relay,
}

/// How long a decision is trusted before it is re-probed.
///
/// One TTL for both verdicts, deliberately: the failure modes are symmetric.
/// A laptop carried off the LAN turns a stale `Direct` into a per-call timeout
/// (recovered immediately by the demote-on-failure path, so the TTL is not what
/// protects us there), while a laptop carried *onto* the LAN leaves a stale
/// `Relay` with nothing to trigger a re-probe — only the TTL. Two minutes keeps
/// the re-probe cost near zero for a chatty caller like `type_text`, which fires
/// two requests per character, while still picking up a network change quickly.
const TTL: Duration = Duration::from_secs(120);

struct Cached {
    route: Route,
    at: Instant,
}

#[derive(Default)]
pub struct RouteCache {
    map: Mutex<HashMap<String, Cached>>,
}

impl RouteCache {
    pub fn get(&self, target: &str) -> Option<Route> {
        let map = self.map.lock().unwrap();
        let c = map.get(target)?;
        if c.at.elapsed() < TTL {
            Some(c.route.clone())
        } else {
            None
        }
    }

    pub fn put(&self, target: &str, route: Route) {
        self.map
            .lock()
            .unwrap()
            .insert(target.to_string(), Cached { route, at: Instant::now() });
    }

    /// Pin this device to the relay after a direct attempt failed. Deliberately
    /// stores `Relay` rather than clearing the entry: an empty entry would make
    /// the very next call re-probe and re-fail, paying the probe timeout on every
    /// call for as long as the device is off the LAN.
    pub fn demote(&self, target: &str) {
        self.put(target, Route::Relay);
    }
}
