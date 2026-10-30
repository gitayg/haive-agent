// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

// Every `/relay/*` call goes through here, so a hub that answers with a redirect
// is never taken for a hub that answered. ureq 2 follows a 307/308 only for
// GET/HEAD/OPTIONS/TRACE, hands a POST's 307/308 back as an ordinary `Ok`, and
// turns a POST's 301/302/303 into a bodiless GET. On 2026-10-28 the hub's
// address started answering 308: hellos "succeeded" without reaching it and no
// reply ever arrived, so every device was silently unreachable for 47h.
//
// Here ureq follows nothing. A 307/308 (and, for a GET, a 301/302/303) is
// followed only to https on the same host or a subdomain of it, on the same or
// the default port, re-sending the same method and body, at most MAX_HOPS
// times. Anything else is a failure, logged loudly. The relay token rides in the
// query string (`auth_query`), and a hub's redirect keeps the query (Caddy's
// `{uri}`), so a followed redirect re-sends the token to its target: that is
// acceptable only because the target is https and inside the host the operator
// already gave the token to.
//
// A followed redirect that ends in a 2xx moves the hub base in memory
// (`RelayCred::moved_to`), so later calls go straight there. `relay.cred` and the
// autostart entry keep the `--relay` address.

// The error is ureq's own (callers match `Status(401, _)` on it as before).
#![allow(clippy::result_large_err)]

use std::io::Read;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use url::{Host, Url};

use crate::relaycred::RelayCred;

const MAX_HOPS: usize = 3;

/// While the same redirect persists, log it at most this often.
const QUIET: Duration = Duration::from_secs(600);

/// Which redirect targets may be followed. Production uses `same_family`; tests
/// substitute a rule a plain-http local server can satisfy.
pub(crate) type Rule = fn(&Url, &Url) -> bool;

pub(crate) enum Body<'a> {
    Empty,
    Bytes(Option<&'a str>, &'a [u8]),
    /// Sent once; a redirect after it cannot re-send it.
    Stream(Option<&'a str>, Box<dyn Read + 'a>),
}

fn agent() -> &'static ureq::Agent {
    static A: OnceLock<ureq::Agent> = OnceLock::new();
    A.get_or_init(|| ureq::AgentBuilder::new().redirects(0).build())
}

/// `to` is https, on `from`'s host or a subdomain of it, on `from`'s port or the
/// https default.
pub(crate) fn same_family(from: &Url, to: &Url) -> bool {
    let (Some(f), Some(t)) = (from.host_str(), to.host_str()) else { return false };
    let host = t == f || (matches!(from.host(), Some(Host::Domain(_))) && t.ends_with(&format!(".{f}")));
    let port = to.port().is_none() || to.port() == from.port_or_known_default();
    to.scheme() == "https" && host && port
}

pub(crate) fn get(cred: &RelayCred, url: &str, timeout: Option<Duration>) -> Result<ureq::Response, ureq::Error> {
    send(cred, "GET", url, Body::Empty, timeout, same_family)
}

pub(crate) fn post(cred: &RelayCred, url: &str, body: Body, timeout: Option<Duration>) -> Result<ureq::Response, ureq::Error> {
    send(cred, "POST", url, body, timeout, same_family)
}

/// One relay call. A redirect not followed comes back as `Err(Status(3xx, _))`,
/// so every caller's error path handles it.
pub(crate) fn send(cred: &RelayCred, method: &str, url: &str, body: Body, timeout: Option<Duration>, follow: Rule) -> Result<ureq::Response, ureq::Error> {
    let started = url;
    let (mut url, mut body) = (url.to_string(), Some(body));
    let mut hops = 0;
    loop {
        let mut rq = agent().request(method, &url);
        if let Some(t) = timeout {
            rq = rq.timeout(t);
        }
        let resp = match body.take().unwrap_or(Body::Empty) {
            Body::Empty => {
                body = Some(Body::Empty);
                rq.call()
            }
            Body::Bytes(ct, b) => {
                body = Some(Body::Bytes(ct, b));
                with_type(rq, ct).send_bytes(b)
            }
            Body::Stream(ct, r) => with_type(rq, ct).send(r),
        }?;
        let status = resp.status();
        if !(300..400).contains(&status) {
            if hops > 0 && (200..300).contains(&status) {
                learn(cred, started, &url);
            }
            return Ok(resp);
        }
        let from = Url::parse(&url).ok();
        let to = from.as_ref().and_then(|f| resp.header("Location").and_then(|l| f.join(l).ok()));
        let refused = match (&from, &to) {
            (Some(f), Some(t)) if !follow(f, t) => Some("not https on the same host"),
            (Some(_), Some(_)) if !matches!(status, 307 | 308) && method != "GET" => Some("only a 307/308 keeps the method and body"),
            (Some(_), Some(_)) if body.is_none() && method != "GET" => Some("a streamed body cannot be re-sent"),
            (Some(_), Some(_)) if hops >= MAX_HOPS => Some("too many redirects"),
            (Some(_), Some(_)) => None,
            _ => Some("no usable Location"),
        };
        let (from_s, to_s) = (from.as_ref().map(shown).unwrap_or_default(), to.as_ref().map(shown).unwrap_or_else(|| "nowhere".into()));
        if let Some(why) = refused {
            if due(&LOUD, &key(status, &from, &to), Instant::now()) {
                eprintln!(
                    "relay: hub answered {status} redirect for {method} {from_s} to {to_s} — check-ins are NOT reaching the hub \
                     (not followed: {why}); update --relay to the new address"
                );
            }
            return Err(ureq::Error::Status(status, resp));
        }
        if due(&MOVED, &key(status, &from, &to), Instant::now()) {
            println!("relay: hub moved — {status} from {from_s} to {to_s}; following it for this run, update --relay to the new address");
        }
        url = to.map(String::from).unwrap_or_default();
        hops += 1;
    }
}

fn with_type(rq: ureq::Request, ct: Option<&str>) -> ureq::Request {
    match ct {
        Some(c) => rq.set("Content-Type", c),
        None => rq,
    }
}

/// A followed call ended in a 2xx at `reached`: move the base to wherever the
/// endpoint `started` asked for now lives (the path after the base, e.g.
/// `/relay/hello`). Skipped if `started` was not built on the current base.
fn learn(cred: &RelayCred, started: &str, reached: &str) {
    let (Ok(base), Ok(s), Ok(r)) = (Url::parse(&cred.base()), Url::parse(started), Url::parse(reached)) else { return };
    if s.origin() != base.origin() {
        return;
    }
    let Some(endpoint) = s.path().strip_prefix(base.path().trim_end_matches('/')) else { return };
    let Some(prefix) = r.path().strip_suffix(endpoint) else { return };
    let port = r.port().map(|p| format!(":{p}")).unwrap_or_default();
    cred.moved_to(format!("{}://{}{port}{prefix}", r.scheme(), r.host_str().unwrap_or("")));
}

/// scheme://host[:port]/path — never the query (it carries `tok=`), userinfo or fragment.
pub(crate) fn shown(u: &Url) -> String {
    let port = u.port().map(|p| format!(":{p}")).unwrap_or_default();
    format!("{}://{}{port}{}", u.scheme(), u.host_str().unwrap_or(""), u.path())
}

fn origin(u: &Option<Url>) -> String {
    u.as_ref().map(|u| format!("{}://{}:{}", u.scheme(), u.host_str().unwrap_or(""), u.port_or_known_default().unwrap_or(0))).unwrap_or_default()
}

/// Per hub address pair, not per endpoint: hello, poll and reply hitting the same
/// move are one event.
fn key(status: u16, from: &Option<Url>, to: &Option<Url>) -> String {
    format!("{status} {} {}", origin(from), origin(to))
}

type Slot = Mutex<Option<(String, Instant)>>;
static LOUD: Slot = Mutex::new(None);
static MOVED: Slot = Mutex::new(None);

/// Log on the first occurrence, on change, and then at most once per QUIET.
fn due(slot: &Slot, key: &str, now: Instant) -> bool {
    let mut s = slot.lock().unwrap_or_else(|e| e.into_inner());
    let fire = match &*s {
        Some((k, at)) => k != key || now.duration_since(*at) >= QUIET,
        None => true,
    };
    if fire {
        *s = Some((key.to_string(), now));
    }
    fire
}

/// A local hub for the redirect tests: `/relay/*` answers `status` with
/// `Location: <location>` (`{port}` and `{query}` filled in), and `/moved/relay/*`
/// answers 200 with `reply`. Records `(path, query, body)` of every request.
#[cfg(test)]
pub(crate) mod testhub {
    use std::sync::{Arc, Mutex};

    pub(crate) type Seen = Arc<Mutex<Vec<(String, String, Vec<u8>)>>>;

    pub(crate) fn start(status: u16, location: &'static str, reply: &'static str) -> (String, Seen) {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = server.server_addr().to_ip().unwrap().port();
        let seen: Seen = Arc::default();
        let log = Arc::clone(&seen);
        std::thread::spawn(move || {
            for mut rq in server.incoming_requests() {
                let mut body = Vec::new();
                let _ = std::io::Read::read_to_end(rq.as_reader(), &mut body);
                let (path, query) = rq.url().split_once('?').map(|(p, q)| (p.to_string(), q.to_string())).unwrap_or((rq.url().to_string(), String::new()));
                log.lock().unwrap().push((path.clone(), query.clone(), body));
                let resp = if path.starts_with("/moved/") {
                    tiny_http::Response::from_string(reply)
                } else {
                    let loc = location.replace("{port}", &port.to_string()).replace("{query}", &query).replace("{path}", &path);
                    tiny_http::Response::from_string("").with_status_code(status).with_header(tiny_http::Header::from_bytes("Location", loc).unwrap())
                };
                let _ = rq.respond(resp);
            }
        });
        (format!("http://127.0.0.1:{port}"), seen)
    }

    /// Same host and port, any scheme: lets the plain-http test hub stand in for
    /// an https one. Tests only; production follows `same_family`.
    pub(crate) fn same_host(from: &url::Url, to: &url::Url) -> bool {
        to.host_str() == from.host_str() && to.port_or_known_default() == from.port_or_known_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relaycred::Resolved;

    fn u(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    fn cred(hub: &str, tag: &str) -> RelayCred {
        let file = std::env::temp_dir().join(format!("it-ai-redirect-{tag}-{}", std::process::id())).join("relay.cred");
        RelayCred::new(hub, "hc-1", file, Resolved { token: "hdev_x".into(), is_device: true, supplied_enroll: None })
    }

    #[test]
    fn same_family_allows_https_on_the_host_or_a_subdomain() {
        for (from, to) in [
            ("https://crane.glick.run/haivecontrol-sandbox/relay/hello", "https://haivecontrol-sandbox.crane.glick.run/haivecontrol-sandbox/relay/hello"),
            ("https://crane.glick.run/x", "https://crane.glick.run/y"),
            ("https://CRANE.glick.run/x", "https://a.b.crane.glick.run/y"),
            ("http://crane.glick.run/x", "https://crane.glick.run/x"),
            ("https://hub.example:8443/x", "https://hub.example:8443/y"),
            ("http://hub.example:8080/x", "https://hub.example/y"),
            ("https://hub.example/x", "https://hub.example:443/y"),
            ("https://10.0.0.5/x", "https://10.0.0.5/y"),
        ] {
            assert!(same_family(&u(from), &u(to)), "{from} -> {to} should be followed");
        }
    }

    #[test]
    fn same_family_refuses_everything_else() {
        for (from, to) in [
            ("https://crane.glick.run/x", "https://evil.com/x"),
            ("https://crane.glick.run/x", "https://crane.glick.run.evil.com/x"),
            ("https://crane.glick.run/x", "https://notcrane.glick.run/x"),
            ("https://crane.glick.run/x", "https://glick.run/x"),
            ("https://crane.glick.run/x", "http://crane.glick.run/x"),
            ("https://crane.glick.run/x", "http://haivecontrol-sandbox.crane.glick.run/x"),
            ("https://crane.glick.run/x", "https://crane.glick.run@evil.com/x"),
            ("https://crane.glick.run/x", "https://crane.glick.run:8443/x"),
            ("https://hub.example:8443/x", "https://hub.example:9443/x"),
            ("https://10.0.0.5/x", "https://10.0.0.6/x"),
            ("https://crane.glick.run/x", "ftp://crane.glick.run/x"),
        ] {
            assert!(!same_family(&u(from), &u(to)), "{from} -> {to} must not be followed");
        }
    }

    #[test]
    fn the_incident_move_lands_on_the_new_base() {
        let c = cred("https://crane.glick.run/haivecontrol-sandbox/", "learn");
        let started = "https://crane.glick.run/haivecontrol-sandbox/relay/hello?id=hc-1&tok=hdev_x&ds=1";
        learn(&c, started, "https://haivecontrol-sandbox.crane.glick.run/haivecontrol-sandbox/relay/hello?id=hc-1&tok=hdev_x&ds=1");
        assert_eq!(c.base(), "https://haivecontrol-sandbox.crane.glick.run/haivecontrol-sandbox");
        // A call not built on the current base moves nothing.
        learn(&c, started, "https://other.crane.glick.run/relay/hello");
        assert_eq!(c.base(), "https://haivecontrol-sandbox.crane.glick.run/haivecontrol-sandbox");
    }

    #[test]
    fn shown_drops_the_query_and_userinfo() {
        let s = shown(&u("https://user:pw@hub.example:8443/p/relay/hello?id=hc-1&tok=hdev_secret#f"));
        assert_eq!(s, "https://hub.example:8443/p/relay/hello");
    }

    #[test]
    fn redirect_logs_are_rate_limited_but_a_change_logs_at_once() {
        let slot: Slot = Mutex::new(None);
        let t0 = Instant::now();
        assert!(due(&slot, "308 a b", t0));
        assert!(!due(&slot, "308 a b", t0 + Duration::from_secs(3)));
        assert!(!due(&slot, "308 a b", t0 + QUIET - Duration::from_secs(1)));
        assert!(due(&slot, "308 a c", t0 + Duration::from_secs(4)));
        assert!(due(&slot, "308 a c", t0 + Duration::from_secs(4) + QUIET));
    }

    #[test]
    fn a_post_redirected_off_the_host_family_fails_and_is_not_resent() {
        let (hub, seen) = testhub::start(308, "https://evil.example{path}?{query}", "{}");
        let c = cred(&hub, "evil");
        let url = format!("{hub}/relay/hello?id=hc-1&tok=hdev_x");
        match post(&c, &url, Body::Bytes(None, b"hello"), None) {
            Err(ureq::Error::Status(308, _)) => {}
            other => panic!("expected Err(Status(308)), got {:?}", other.map(|r| r.status())),
        }
        assert_eq!(seen.lock().unwrap().len(), 1);
        assert_eq!(c.base(), hub);
    }

    #[test]
    fn a_post_redirected_within_the_family_is_resent_and_moves_the_base() {
        let (hub, seen) = testhub::start(308, "http://127.0.0.1:{port}/moved{path}?{query}", "ok");
        let c = cred(&hub, "same");
        let url = format!("{hub}/relay/hello?id=hc-1&tok=hdev_x&ds=1");
        let r = send(&c, "POST", &url, Body::Bytes(None, b"payload-1"), None, testhub::same_host).expect("followed");
        assert_eq!(r.status(), 200);
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[1].0, "/moved/relay/hello");
        assert_eq!(seen[1].1, "id=hc-1&tok=hdev_x&ds=1");
        assert_eq!(seen[0].2, b"payload-1");
        assert_eq!(seen[1].2, b"payload-1");
        assert_eq!(c.base(), format!("{hub}/moved"));
    }

    #[test]
    fn the_production_rule_refuses_the_same_host_over_http() {
        let (hub, seen) = testhub::start(308, "http://127.0.0.1:{port}/moved{path}?{query}", "ok");
        let c = cred(&hub, "http");
        assert!(matches!(post(&c, &format!("{hub}/relay/hello?id=hc-1"), Body::Bytes(None, b"x"), None), Err(ureq::Error::Status(308, _))));
        assert_eq!(seen.lock().unwrap().len(), 1);
    }

    #[test]
    fn a_post_301_302_303_is_never_followed() {
        for st in [301, 302, 303] {
            let (hub, seen) = testhub::start(st, "http://127.0.0.1:{port}/moved{path}?{query}", "ok");
            let c = cred(&hub, &format!("s{st}"));
            let r = send(&c, "POST", &format!("{hub}/relay/hello?id=hc-1"), Body::Bytes(None, b"x"), None, testhub::same_host);
            assert!(matches!(r, Err(ureq::Error::Status(s, _)) if s == st), "{st} must fail");
            assert_eq!(seen.lock().unwrap().len(), 1, "{st} must not be followed as a GET");
        }
    }

    #[test]
    fn a_streamed_reply_is_not_resent_on_a_redirect() {
        let (hub, seen) = testhub::start(308, "http://127.0.0.1:{port}/moved{path}?{query}", "ok");
        let c = cred(&hub, "stream");
        let url = format!("{hub}/relay/reply?id=hc-1&req=7&st=200");
        let r = send(&c, "POST", &url, Body::Stream(None, Box::new(&b"frame"[..])), None, testhub::same_host);
        assert!(matches!(r, Err(ureq::Error::Status(308, _))));
        assert_eq!(seen.lock().unwrap().len(), 1);
        assert_eq!(c.base(), hub);
    }

    #[test]
    fn a_redirect_loop_stops() {
        let (hub, seen) = testhub::start(308, "http://127.0.0.1:{port}{path}?{query}", "ok");
        let c = cred(&hub, "loop");
        let r = send(&c, "POST", &format!("{hub}/relay/hello?id=hc-1"), Body::Bytes(None, b"x"), None, testhub::same_host);
        assert!(matches!(r, Err(ureq::Error::Status(308, _))));
        assert_eq!(seen.lock().unwrap().len(), MAX_HOPS + 1);
    }

    #[test]
    fn a_get_follows_within_the_family_too() {
        let (hub, seen) = testhub::start(302, "http://127.0.0.1:{port}/moved{path}?{query}", "cfg");
        let c = cred(&hub, "get");
        let r = send(&c, "GET", &format!("{hub}/relay/config?id=hc-1"), Body::Empty, None, testhub::same_host).expect("followed");
        assert_eq!(r.into_string().unwrap(), "cfg");
        assert_eq!(seen.lock().unwrap().len(), 2);
    }
}
