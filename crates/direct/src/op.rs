// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

//! One device operation, described rather than built.
//!
//! An `Op` names an endpoint on the *agent* — the agent's path and body shape are
//! canonical — and carries just enough extra information for the controller to
//! re-express the same call as a hub `/m/<action>` proxy request. Describing the
//! request instead of handing over a built `reqwest::RequestBuilder` is what makes
//! the relay fallback possible: a body that was already streamed into a failed
//! direct attempt cannot be replayed, whereas these owned fields can be rebuilt
//! as many times as needed.

use std::time::Duration;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
}

/// How the *relay* leg names the device. The direct leg never carries a target:
/// the TCP connection is the addressing.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TargetIn {
    /// `?target=…` on the hub URL — frame, camera, download, upload.
    Query,
    /// a `"target"` key merged into the JSON body — exec, input.
    JsonBody,
}

#[derive(Clone)]
pub enum Body {
    Empty,
    Json(serde_json::Value),
    /// `multipart/form-data` with one file part plus optional text fields, held
    /// as owned bytes so the form can be rebuilt for a relay retry.
    Multipart {
        file_name: String,
        bytes: Vec<u8>,
        fields: Vec<(String, String)>,
    },
}

#[derive(Clone)]
pub struct Op {
    pub method: Method,
    /// Path on the agent without the leading slash: `exec`, `frame`, `shell/read`.
    pub path: String,
    /// Hub action when it differs from `path`. Defaults to `path`, which is the
    /// case for every op routed through here today.
    pub hub_action: Option<String>,
    /// Query parameters sent on *both* legs.
    pub query: Vec<(String, String)>,
    pub target_in: TargetIn,
    pub body: Body,
    /// Replaces `body` on the relay leg for the actions where the hub's wrapper
    /// is not the agent's payload. `/input` is the one that needs it: the agent
    /// takes a bare event object, while `/m/input` takes `{"target":…,"ev":…}`,
    /// so merging a `target` key into the agent-shaped body would produce
    /// something neither end understands.
    pub relay_body: Option<Body>,
    /// Whole-request timeout. Connect timeouts are set on the client, not here.
    pub timeout: Duration,
}

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);

impl Op {
    fn new(method: Method, path: &str, body: Body) -> Self {
        Self {
            method,
            path: path.to_string(),
            hub_action: None,
            query: Vec::new(),
            target_in: TargetIn::Query,
            body,
            relay_body: None,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    pub fn get(path: &str) -> Self {
        Self::new(Method::Get, path, Body::Empty)
    }

    pub fn post_json(path: &str, body: serde_json::Value) -> Self {
        Self::new(Method::Post, path, Body::Json(body))
    }

    pub fn post_file(path: &str, file_name: String, bytes: Vec<u8>) -> Self {
        Self::new(
            Method::Post,
            path,
            Body::Multipart { file_name, bytes, fields: Vec::new() },
        )
    }

    pub fn query(mut self, key: &str, value: impl Into<String>) -> Self {
        self.query.push((key.to_string(), value.into()));
        self
    }

    /// Add a multipart text field. No-op on a non-multipart body.
    pub fn field(mut self, key: &str, value: impl Into<String>) -> Self {
        if let Body::Multipart { fields, .. } = &mut self.body {
            fields.push((key.to_string(), value.into()));
        }
        self
    }

    /// The hub expects `target` inside the JSON body for this action.
    pub fn target_in_body(mut self) -> Self {
        self.target_in = TargetIn::JsonBody;
        self
    }

    /// Send a different JSON body on the relay leg, with `target` merged into it.
    pub fn relay_json(mut self, body: serde_json::Value) -> Self {
        self.relay_body = Some(Body::Json(body));
        self.target_in = TargetIn::JsonBody;
        self
    }

    pub fn timeout(mut self, d: Duration) -> Self {
        self.timeout = d;
        self
    }

    pub fn hub_action(mut self, action: &str) -> Self {
        self.hub_action = Some(action.to_string());
        self
    }

    /// The agent-shaped JSON body, when there is one. `it_ai_cap::op_for` reads
    /// the capability's argument out of it — deliberately `self.body` and not
    /// `relay_body`, because the direct leg is the one being authorized and the
    /// agent recomputes the same argument from the body it actually receives.
    pub fn json_body(&self) -> Option<&serde_json::Value> {
        match &self.body {
            Body::Json(v) => Some(v),
            _ => None,
        }
    }
}

pub fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

pub fn encode_query(pairs: &[(String, String)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", urlencode(k), urlencode(v)))
        .collect::<Vec<_>>()
        .join("&")
}
