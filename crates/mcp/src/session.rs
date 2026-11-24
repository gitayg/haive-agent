// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

// Per-session hub tokens (hub 3.30.0). On the first tool call this server trades
// the configured HIVE_MCP_TOKEN for a session token labelled
// `<client> · <host> · pid <pid>`, so the hub's audit log and approvals name this
// one MCP session instead of "shared MCP_TOKEN", and uses it for every later call.
//
// - The mint answers anything but 200 with a token (an older hub's 404, an open
//   hub's 400, …): keep the configured token for good, and say so once on stderr.
// - A 401 with a session token that has worked before: mint a new one, once. A 401
//   with a session token that never worked: fall back to the configured token.
// - A token is never printed: not on stderr, not in an error.
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::Arc;
use std::time::Duration;

use it_ai_direct::op::urlencode;
use it_ai_direct::Controller;

const MINT_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_CLIENT: &str = "it-ai-mcp";

/// The token one tool call runs with, and the hub client bound to it.
#[derive(Clone)]
pub struct Effective {
    pub token: String,
    pub ctl: Arc<Controller>,
    /// true = a session token this server minted.
    pub session: bool,
}

enum Mode {
    Unminted,
    Session { token: String, ctl: Arc<Controller>, proven: bool },
    Configured,
}

struct State {
    mode: Mode,
    label: String,
    logged: bool,
}

pub struct Session {
    hub: String,
    owner: String,
    configured: String,
    client: reqwest::Client,
    base: Arc<Controller>,
    state: tokio::sync::Mutex<State>,
}

/// What a session-token mint answered, minus the token.
#[derive(Debug, PartialEq)]
pub enum Minted {
    Token(String),
    Refused(String),
}

/// Read a `/m/session-token` answer: a token only on 200 with `ok` and a non-empty `token`.
pub fn read_mint(status: u16, body: &[u8]) -> Minted {
    let v: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
    match v["token"].as_str() {
        Some(t) if status == 200 && v["ok"].as_bool() == Some(true) && !t.is_empty() => Minted::Token(t.to_string()),
        _ => Minted::Refused(match v["error"].as_str() {
            Some(e) => format!("HTTP {status}: {}", crate::jobs::redact_token(e)),
            None => format!("HTTP {status}"),
        }),
    }
}

pub fn label(client: Option<&str>, host: &str, pid: u32) -> String {
    let c = client.map(str::trim).filter(|c| !c.is_empty()).unwrap_or(DEFAULT_CLIENT);
    format!("{c} · {host} · pid {pid}")
}

pub fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok()
        .or_else(|| std::process::Command::new("hostname").output().ok().and_then(|o| String::from_utf8(o.stdout).ok()))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown-host".to_string())
}

impl Session {
    pub fn new(hub: String, configured: String, owner: String, client: reqwest::Client) -> Self {
        let base = Arc::new(Controller::new(hub.clone(), configured.clone(), owner.clone(), client.clone()));
        let mode = if configured.is_empty() { Mode::Configured } else { Mode::Unminted };
        Self {
            hub,
            owner,
            configured,
            client,
            base,
            state: tokio::sync::Mutex::new(State { mode, label: String::new(), logged: false }),
        }
    }

    /// The hub client for the configured token.
    pub fn base(&self) -> Arc<Controller> {
        self.base.clone()
    }

    /// The token this call runs with, minting the session token on the first call.
    pub async fn token(&self, client: Option<&str>) -> Effective {
        let mut st = self.state.lock().await;
        if matches!(st.mode, Mode::Unminted) {
            st.label = label(client, &hostname(), std::process::id());
            let m = self.mint(&st.label).await;
            self.adopt(&mut st, m, "is unavailable");
        }
        self.effective(&st)
    }

    /// A 401 came back for `token`. True when the call should be tried again,
    /// because the token it would run with now is a different one.
    pub async fn rejected(&self, token: &str) -> bool {
        let mut st = self.state.lock().await;
        if let Mode::Session { token: t, proven, .. } = &st.mode {
            if t == token {
                if *proven {
                    let label = st.label.clone();
                    let m = self.mint(&label).await;
                    self.adopt(&mut st, m, "was rejected and a new one could not be minted");
                } else {
                    self.adopt(&mut st, Minted::Refused("HTTP 401".into()), "was rejected");
                }
            }
        }
        self.effective(&st).token != token
    }

    /// A hub request with `token` got through.
    pub async fn proven(&self, token: &str) {
        if let Mode::Session { token: t, proven, .. } = &mut self.state.lock().await.mode {
            if t == token {
                *proven = true;
            }
        }
    }

    async fn mint(&self, label: &str) -> Minted {
        let url = self.base.hub_url("session-token", &format!("name={}", urlencode(label)));
        match self.client.post(url).timeout(MINT_TIMEOUT).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                match r.bytes().await {
                    Ok(b) => read_mint(status, &b),
                    Err(e) => Minted::Refused(e.without_url().to_string()),
                }
            }
            Err(e) => Minted::Refused(e.without_url().to_string()),
        }
    }

    fn adopt(&self, st: &mut State, m: Minted, why: &str) {
        st.mode = match m {
            Minted::Token(token) => {
                let ctl = Arc::new(Controller::new(self.hub.clone(), token.clone(), self.owner.clone(), self.client.clone()));
                Mode::Session { token, ctl, proven: false }
            }
            Minted::Refused(reason) => {
                if !st.logged {
                    st.logged = true;
                    eprintln!("it-ai-mcp: a per-session hub token {why} ({reason}); using the configured HIVE_MCP_TOKEN");
                }
                Mode::Configured
            }
        };
    }

    fn effective(&self, st: &State) -> Effective {
        match &st.mode {
            Mode::Session { token, ctl, .. } => Effective { token: token.clone(), ctl: ctl.clone(), session: true },
            _ => Effective { token: self.configured.clone(), ctl: self.base.clone(), session: false },
        }
    }
}

/// What one tool call's hub requests answered: the first status, and whether any
/// was a 401 or got through.
#[derive(Default)]
pub struct Seen {
    first: AtomicU16,
    unauthorized: AtomicBool,
    through: AtomicBool,
}

impl Seen {
    pub fn status(&self, s: u16) {
        let _ = self.first.compare_exchange(0, s, Ordering::SeqCst, Ordering::SeqCst);
        if s == 401 {
            self.unauthorized.store(true, Ordering::SeqCst);
        } else if (200..300).contains(&s) {
            self.through.store(true, Ordering::SeqCst);
        }
    }

    pub fn unauthorized(&self) -> bool {
        self.unauthorized.load(Ordering::SeqCst)
    }

    /// The call's first hub answer was a 401, so nothing it sent has run.
    pub fn first_unauthorized(&self) -> bool {
        self.first.load(Ordering::SeqCst) == 401
    }

    pub fn through(&self) -> bool {
        self.through.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests;
