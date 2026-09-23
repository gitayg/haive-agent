// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

//! LAN-direct hybrid transport, shared by every controller (`itai`, `it-ai-mcp`).
//!
//! Every controller→agent operation used to round-trip through the cloud hub even
//! when the two machines shared a switch. `Controller::call_device` tries the
//! agent's LAN address first and falls back to the hub's `/m/<action>` proxy when
//! that does not work out. The choice is made once per device and cached, so a
//! caller that fires hundreds of small requests (`type_text` sends two per
//! character) pays for the probe once.
//!
//! This is a transport-level shortcut, not a per-feature one: `call_device` takes
//! any `Op`, so once a device is on the direct route every endpoint it describes
//! rides the direct connection.
//!
//! Security model, unchanged by the shortcut: the direct leg validates the
//! agent's hub-signed leaf certificate against the hub CA (fetched once from
//! `/m/ca`), and authorizes with the per-device token the hub hands out at
//! `/m/direct`. The agent applies exactly the same `privileged_path` token gate to
//! a LAN request as to a relayed one.

use std::time::Duration;

use serde::Deserialize;

pub mod op;
pub mod route;

pub use op::{Body, Method, Op, TargetIn};
use op::{encode_query, urlencode};
use route::{Route, RouteCache};

/// TCP+TLS budget for reaching an agent on the LAN. A same-subnet handshake is a
/// few milliseconds; anything slower is not the LAN path we are looking for, and
/// waiting longer would just delay the relay fallback the caller actually needs.
const DIRECT_CONNECT_TIMEOUT: Duration = Duration::from_millis(300);

/// Whole-request budget for the reachability probe (see `probe`). Bounded
/// separately from the connect timeout so a host that completes the handshake and
/// then stalls cannot hold the caller either.
const PROBE_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Deserialize, Clone)]
pub struct AgentInfo {
    pub name: String,
    pub ip: String,
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub scheme: String,
}

impl AgentInfo {
    /// The proxy target the hub understands: `relay://id` for relay devices,
    /// else `scheme://ip:port`.
    pub fn target(&self) -> String {
        if self.scheme == "relay" {
            format!("relay://{}", self.ip)
        } else {
            format!("{}://{}:{}", self.scheme, self.ip, self.port)
        }
    }
}

pub struct Controller {
    hub: String,
    mtok: String,
    owner: String,
    /// Talks to the hub. Carries whatever roots the binary configured (system
    /// roots, or an explicit `HAIVE_CAFILE`).
    client: reqwest::Client,
    /// Optional agent password, applied to the direct leg only — the relay leg is
    /// authorized by `mtok` instead.
    password: Option<String>,
    ca_client: tokio::sync::OnceCell<reqwest::Client>,
    routes: RouteCache,
}

impl Controller {
    pub fn new(hub: String, mtok: String, owner: String, client: reqwest::Client) -> Self {
        Self {
            hub,
            mtok,
            owner,
            client,
            password: None,
            ca_client: tokio::sync::OnceCell::new(),
            routes: RouteCache::default(),
        }
    }

    pub fn with_password(mut self, password: Option<String>) -> Self {
        self.password = password.filter(|p| !p.is_empty());
        self
    }

    pub fn client(&self) -> &reqwest::Client {
        &self.client
    }

    /// Build a hub `/m` URL: `{hub}/m/{action}?mtok=…&owner=…[&extra]`.
    pub fn hub_url(&self, action: &str, extra: &str) -> String {
        let base = self.hub.trim_end_matches('/');
        let mut u = format!("{base}/m/{action}?mtok={}&owner={}", urlencode(&self.mtok), urlencode(&self.owner));
        if !extra.is_empty() {
            u.push('&');
            u.push_str(extra);
        }
        u
    }

    pub async fn agents(&self) -> Result<Vec<AgentInfo>, String> {
        let v: serde_json::Value = self
            .client
            .get(self.hub_url("agents", ""))
            .send()
            .await
            .map_err(|e| e.to_string())?
            .json()
            .await
            .map_err(|e| e.to_string())?;
        Ok(serde_json::from_value(v["agents"].clone()).unwrap_or_default())
    }

    /// Resolve a device name (exact, then substring) to its hub proxy target.
    pub async fn resolve(&self, name: &str) -> Result<String, String> {
        let agents = self.agents().await?;
        let exact: Vec<&AgentInfo> =
            agents.iter().filter(|a| a.name.eq_ignore_ascii_case(name) || a.ip == name).collect();
        let m: Vec<&AgentInfo> = if exact.is_empty() {
            agents.iter().filter(|a| a.name.to_lowercase().contains(&name.to_lowercase())).collect()
        } else {
            exact
        };
        match m.len() {
            0 if agents.is_empty() => Err(format!(
                "no devices visible for this owner ('{}'). Check HIVE_OWNER matches how the device was enrolled (--owner …), or unset it to see all.",
                self.owner
            )),
            0 => Err(format!(
                "no device matching '{name}'. Visible devices: {}",
                agents.iter().map(|a| a.name.clone()).collect::<Vec<_>>().join(", ")
            )),
            1 => Ok(m[0].target()),
            _ => Err(format!("ambiguous device: {}", m.iter().map(|a| a.name.clone()).collect::<Vec<_>>().join(", "))),
        }
    }

    /// Run `op` against `target`, over the LAN when that works and through the hub
    /// relay otherwise.
    ///
    /// The fallback is unconditional by design: a direct attempt that fails for
    /// any reason — no LAN IP known, connect refused, TLS rejected, timeout, or a
    /// token the agent no longer accepts — must not reach the caller as an error
    /// while the relay is still there to try. A direct attempt that *succeeds* at
    /// the transport level and comes back 404 or 500 is not a failed attempt: that
    /// is the agent's own answer, the relay would return the same, and it is
    /// passed through untouched.
    ///
    /// Caveat worth knowing at the call site: a transport failure that happens
    /// after the request was already on the wire cannot be distinguished from one
    /// that happened before, so a non-idempotent op (`/exec`, `/input`, `/upload`)
    /// could in principle run twice — once on the agent that received it and lost
    /// the response, once again over the relay. The window is small because the
    /// route was proved live by a probe or a recent success, but it is real.
    /// Ask the hub to authorize one operation on one device, and return the token
    /// that proves it. The hub runs `may_control`, the command deny-list, the
    /// access record and the audit entry before signing, so this call is where a
    /// direct request picks up every control the proxy would have applied.
    ///
    /// `Ok(None)` means the hub refused to say — it was unreachable, or answered
    /// something unparseable. That is a transport failure and the caller may
    /// relay. `Err` means the hub answered and said NO; that is a decision, and
    /// it must reach the operator unchanged.
    async fn mint_capability(&self, target: &str, op: &str, arg: &str) -> Result<Option<String>, String> {
        let url = self.hub_url("capability", "");
        let body = serde_json::json!({ "target": target, "op": op, "arg": arg });
        let r = match self.client.post(url).json(&body).send().await {
            Ok(r) => r,
            Err(_) => return Ok(None),
        };
        let v: serde_json::Value = match r.json().await {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };
        if v.get("ok").and_then(|x| x.as_bool()) == Some(true) {
            return Ok(v.get("cap").and_then(|x| x.as_str()).map(String::from));
        }
        Err(v
            .get("error")
            .and_then(|x| x.as_str())
            .unwrap_or("the hub refused this operation")
            .to_string())
    }

    pub async fn call_device(&self, target: &str, op: Op) -> Result<reqwest::Response, String> {
        if let Route::Direct { base, dtok } = self.route(target).await {
            // Minted per call, and before the request is built, because the token
            // is bound to this device, this endpoint and this exact argument — one
            // grant cannot cover two commands. A streaming op is the one case where
            // the grant covers a whole session rather than a request, simply
            // because the session IS one request: `/stream` and `/camstream` open
            // once and never return.
            //
            // A refusal ends the call here. Falling back to the relay after a deny
            // would silently re-ask the same question of the same hub and get the
            // same answer, and if it ever did not, a deny would have become a
            // retry loop around the authorization decision.
            //
            // An op with no capability defined, or a hub that could not be asked,
            // takes the relay: the agent would refuse it on the LAN anyway, and
            // the relay is where the hub applies the checks itself.
            let cap = match it_ai_cap::op_for(&op.path, op.json_body()) {
                Some((name, arg)) => self.mint_capability(target, name, &arg).await?,
                None => None,
            };
            if let (Some(cap), Some(c)) = (cap, self.ca_client().await) {
                match self.send_direct(c, &base, &dtok, &op, &cap).await {
                    // 401/403 means the hub handed us a token this agent does not
                    // accept (rotated enrollment, or a different device answering
                    // on a recycled DHCP lease). Drop the route and relay instead.
                    Ok(r) if r.status() == 401 || r.status() == 403 => self.routes.demote(target),
                    Ok(r) => return Ok(r),
                    Err(_) => self.routes.demote(target),
                }
            }
        }
        self.send_relay(target, &op).await
    }

    async fn route(&self, target: &str) -> Route {
        if let Some(r) = self.routes.get(target) {
            return r;
        }
        let r = self.probe(target).await;
        self.routes.put(target, r.clone());
        r
    }

    /// Decide a device's transport by actually talking to it.
    ///
    /// The probe is a real privileged request (`/file-status` with a job id that
    /// does not exist) rather than a bare TCP connect, because reachability alone
    /// proves too little: this one call establishes that the address answers, that
    /// its certificate chains to the hub CA, and that it accepts our token — the
    /// three things the real op needs. It is a pure read with no side effect, and
    /// an unknown job is an ordinary 200 on the agent, so a successful status is
    /// an unambiguous yes.
    async fn probe(&self, target: &str) -> Route {
        let (ips, port, dtok) = match self.direct_info(target).await {
            Some(v) => v,
            None => return Route::Relay,
        };
        let client = match self.ca_client().await {
            Some(c) => c,
            None => return Route::Relay,
        };
        // `/file-status` is privileged, so the probe needs a capability like any
        // other direct call — one `download` grant covers the whole probe, since
        // every address tried is the same device and the same empty argument. No
        // capability means no direct route: the agent would refuse each attempt.
        let (op, arg) = it_ai_cap::op_for("file-status", None).expect("file-status has a capability op");
        let cap = match self.mint_capability(target, op, &arg).await {
            Ok(Some(c)) => c,
            _ => return Route::Relay,
        };
        for ip in ips {
            let base = format!("https://{ip}:{port}");
            let url = format!("{base}/file-status?job=__probe__&dtok={}", urlencode(&dtok));
            let mut rb = client.get(url).timeout(PROBE_TIMEOUT).header(it_ai_cap::HEADER, &cap);
            if let Some(p) = &self.password {
                rb = rb.basic_auth("admin", Some(p));
            }
            if let Ok(r) = rb.send().await {
                if r.status().is_success() {
                    return Route::Direct { base, dtok };
                }
            }
        }
        Route::Relay
    }

    /// Ask the hub for a device's LAN IPs, its direct port, and its per-device
    /// token. Returns None when the hub cannot say — which routes to the relay.
    async fn direct_info(&self, target: &str) -> Option<(Vec<String>, u16, String)> {
        let url = self.hub_url("direct", &format!("target={}", urlencode(target)));
        let v: serde_json::Value = self.client.get(url).send().await.ok()?.json().await.ok()?;
        let ips: Vec<String> = v
            .get("ips")?
            .as_array()?
            .iter()
            .filter_map(|x| x.as_str().map(String::from))
            .collect();
        if ips.is_empty() {
            return None;
        }
        let port = v.get("port").and_then(|p| p.as_u64()).unwrap_or(8765) as u16;
        let token = v.get("token")?.as_str()?.to_string();
        Some((ips, port, token))
    }

    /// A client that trusts the hub CA, built once from `/m/ca`. Separate from
    /// `self.client` because only this one may accept the hub's private CA, and
    /// because it carries the short connect timeout that keeps a dead LAN address
    /// from delaying the relay fallback.
    ///
    /// `get_or_try_init`, not `get_or_init`: a failure must not be cached. The CA
    /// fetch is a network call, and a hub blip during the first device call would
    /// otherwise disable the direct route for the whole life of the process.
    async fn ca_client(&self) -> Option<&reqwest::Client> {
        self.ca_client
            .get_or_try_init(|| async {
                let pem = self.client.get(self.hub_url("ca", "")).send().await.map_err(|_| ())?.bytes().await.map_err(|_| ())?;
                let ca = reqwest::Certificate::from_pem(&pem).map_err(|_| ())?;
                reqwest::Client::builder()
                    .add_root_certificate(ca)
                    .connect_timeout(DIRECT_CONNECT_TIMEOUT)
                    .build()
                    .map_err(|_| ())
            })
            .await
            .ok()
    }

    async fn send_direct(
        &self,
        client: &reqwest::Client,
        base: &str,
        dtok: &str,
        op: &Op,
        cap: &str,
    ) -> Result<reqwest::Response, reqwest::Error> {
        let mut q = op.query.clone();
        q.push(("dtok".to_string(), dtok.to_string()));
        let url = format!("{base}/{}?{}", op.path, encode_query(&q));
        let mut rb = match op.method {
            Method::Get => client.get(url),
            Method::Post => client.post(url),
        };
        // The capability rides a header, not the query string: the agent's
        // `authorized` gate reads `dtok` out of the URL, and a URL is the part of
        // a request most likely to end up in a log on the way past.
        rb = rb.header(it_ai_cap::HEADER, cap);
        if let Some(p) = &self.password {
            rb = rb.basic_auth("admin", Some(p));
        }
        attach_body(rb.timeout(op.timeout), &op.body, None).send().await
    }

    async fn send_relay(&self, target: &str, op: &Op) -> Result<reqwest::Response, String> {
        let action = op.hub_action.as_deref().unwrap_or(&op.path);
        let mut q = op.query.clone();
        if op.target_in == TargetIn::Query {
            q.push(("target".to_string(), target.to_string()));
        }
        let url = self.hub_url(action, &encode_query(&q));
        let rb = match op.method {
            Method::Get => self.client.get(url),
            Method::Post => self.client.post(url),
        };
        let inject = if op.target_in == TargetIn::JsonBody { Some(target) } else { None };
        let body = op.relay_body.as_ref().unwrap_or(&op.body);
        attach_body(rb.timeout(op.timeout), body, inject)
            .send()
            .await
            .map_err(|e| e.to_string())
    }
}

/// Rebuild the request body. `target_in_body` is the hub's JSON convention: the
/// agent addresses itself, so the caller's body is agent-shaped and the device
/// name is merged in only on the relay leg.
fn attach_body(
    rb: reqwest::RequestBuilder,
    body: &Body,
    target_in_body: Option<&str>,
) -> reqwest::RequestBuilder {
    match body {
        Body::Empty => rb,
        Body::Json(v) => match target_in_body {
            Some(t) => {
                let mut v = v.clone();
                if let Some(o) = v.as_object_mut() {
                    o.insert("target".to_string(), serde_json::json!(t));
                }
                rb.json(&v)
            }
            None => rb.json(v),
        },
        Body::Multipart { file_name, bytes, fields } => {
            let part = reqwest::multipart::Part::bytes(bytes.clone()).file_name(file_name.clone());
            let mut form = reqwest::multipart::Form::new().part("file", part);
            for (k, v) in fields {
                form = form.text(k.clone(), v.clone());
            }
            rb.multipart(form)
        }
    }
}
