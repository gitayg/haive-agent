// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

//! The pull behind `/fetch-file` (push_file's stage-and-pull, and fetch_url, agent
//! 3.16.0). Every request names the sha256 of the bytes it wants, so a fetched file
//! is either exactly those bytes at the final path or nothing there at all.
//!
//! ureq follows no redirect here. A 301/302/303/307/308 is followed, at most
//! MAX_HOPS times, only from an https URL to an https URL: a GitHub release asset
//! (https://github.com/… → https://objects.githubusercontent.com/…?<signature>)
//! works, a downgrade to http or any redirect off a plain-http URL does not.
//! A fetch_url request (`"public": true`) is also held to the public-only policy in
//! `public`, on the URL and on every redirect target and resolved address.
//! Errors name a URL by scheme, host and path only: a redirect's query can carry a
//! signature. A hash mismatch does not echo the hash it computed: for a URL the
//! caller cannot read, that would be a content oracle.

use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::time::Duration;

use url::Url;

const MAX_HOPS: usize = 5;
const TIMEOUT: Duration = Duration::from_secs(900);

pub struct FetchReq {
    pub url: String,
    pub sha256: String,
    pub dir: String,
    pub name: String,
    pub job: String,
    /// fetch_url (`"public": true`): the public-only policy in `public`. push_file never sets it.
    pub public: bool,
}

/// 64 hex characters, lowercased; anything else is None.
pub fn valid_sha256(s: &str) -> Option<String> {
    (s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())).then(|| s.to_ascii_lowercase())
}

/// The error carries the status `/fetch-file` answers with (a missing field keeps its old 200).
pub fn parse(body: &str) -> Result<FetchReq, (&'static str, u16)> {
    let v: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
    let field = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
    let (url, name, job) = (field("url"), field("name"), field("job"));
    if url.is_empty() || name.is_empty() || job.is_empty() {
        return Err(("need url, name, job", 200));
    }
    let sha256 = valid_sha256(&field("sha256")).ok_or(("need sha256: 64 hex characters", 400))?;
    let public = v.get("public").and_then(|x| x.as_bool()) == Some(true);
    Ok(FetchReq { url, sha256, dir: field("dir"), name, job, public })
}

/// The destination folder must already exist (as for `/upload`): refuse before any
/// download starts rather than fetch a whole file and fail on writing it.
pub fn dest_dir_ready(dir: &std::path::Path) -> Result<(), String> {
    if dir.is_dir() {
        Ok(())
    } else {
        Err(format!("destination folder does not exist: {}", dir.display()))
    }
}

pub fn redirect_allowed(from: &Url, to: &Url) -> bool {
    from.scheme() == "https" && to.scheme() == "https"
}

/// Whether `open` follows a redirect `from` → `to`; Err says why not.
pub fn hop_allowed(from: &Url, to: &Url, public: bool) -> Result<(), String> {
    let refused = |why: &str| format!("refused redirect {} -> {}: {why}", shown(from), shown(to));
    if !redirect_allowed(from, to) {
        return Err(refused("only https to https is followed"));
    }
    if public {
        public::url_ok(to).map_err(|e| refused(&e))?;
    }
    Ok(())
}

fn shown(u: &Url) -> String {
    let port = u.port().map(|p| format!(":{p}")).unwrap_or_default();
    format!("{}://{}{port}{}", u.scheme(), u.host_str().unwrap_or(""), u.path())
}

/// One GET's outcome: the response to keep, or a 30x and its Location.
pub(crate) enum Step<T> {
    Done(T),
    Redirect(u16, Option<String>),
}

/// The redirect loop, apart from the network: `get` does one request.
pub(crate) fn follow<T>(url: &str, public: bool, mut get: impl FnMut(&Url) -> Result<Step<T>, String>) -> Result<T, String> {
    let mut cur = Url::parse(url).map_err(|e| format!("bad url: {e}"))?;
    if public {
        public::url_ok(&cur).map_err(|e| format!("refused {}: {e}", shown(&cur)))?;
    }
    for _ in 0..=MAX_HOPS {
        let (code, location) = match get(&cur)? {
            Step::Done(r) => return Ok(r),
            Step::Redirect(code, location) => (code, location),
        };
        let next = location
            .and_then(|l| cur.join(&l).ok())
            .ok_or_else(|| format!("GET {}: HTTP {code} with no usable Location", shown(&cur)))?;
        hop_allowed(&cur, &next, public)?;
        cur = next;
    }
    Err(format!("too many redirects (more than {MAX_HOPS})"))
}

type Lookup = fn(&str) -> io::Result<Vec<SocketAddr>>;

/// GET `url`, following only https→https redirects, to a 2xx response. Under
/// `public` the URL and every redirect target must pass `public::url_ok`, and
/// names connect only to their public addresses.
pub fn open(url: &str, public: bool) -> Result<ureq::Response, String> {
    open_with(url, public, public::system)
}

pub(crate) fn open_with(url: &str, public: bool, lookup: Lookup) -> Result<ureq::Response, String> {
    let resolve = move |netloc: &str| if public { public::keep_public(lookup(netloc)?) } else { lookup(netloc) };
    let agent = ureq::AgentBuilder::new().redirects(0).timeout(TIMEOUT).resolver(resolve).build();
    follow(url, public, |cur| {
        let resp = match agent.get(cur.as_str()).call() {
            Ok(r) => r,
            Err(ureq::Error::Status(code, _)) => return Err(format!("GET {} failed: HTTP {code}", shown(cur))),
            Err(ureq::Error::Transport(t)) => {
                let mut why = t.message().map(str::to_string).unwrap_or_else(|| t.kind().to_string());
                if let Some(src) = std::error::Error::source(&t) {
                    why = format!("{why}: {src}");
                }
                return Err(format!("GET {} failed: {why}", shown(cur)));
            }
        };
        let code = resp.status();
        if (200..300).contains(&code) {
            return Ok(Step::Done(resp));
        }
        if !matches!(code, 301 | 302 | 303 | 307 | 308) {
            return Err(format!("GET {} failed: HTTP {code}", shown(cur)));
        }
        Ok(Step::Redirect(code, resp.header("location").map(str::to_string)))
    })
}

/// Pull `url` → `dest`, verifying `sha256` (lowercase hex). The bytes go to
/// `<dest>.part`, renamed over `dest` only when the hash matches; on any failure
/// the part file is removed.
pub fn fetch_to_file(url: &str, dest: &str, sha256: &str, public: bool) -> Result<u64, String> {
    use sha2::{Digest, Sha256};
    let resp = open(url, public)?;
    let tmp = format!("{dest}.part");
    let mut file = std::fs::File::create(&tmp).map_err(|e| format!("create: {e}"))?;
    let copied = (|| {
        let mut reader = resp.into_reader();
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 65536];
        let mut total: u64 = 0;
        loop {
            let n = reader.read(&mut buf).map_err(|e| format!("read: {e}"))?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            file.write_all(&buf[..n]).map_err(|e| format!("write: {e}"))?;
            total += n as u64;
        }
        file.flush().map_err(|e| format!("write: {e}"))?;
        Ok::<_, String>((total, format!("{:x}", hasher.finalize())))
    })();
    drop(file);
    let res = copied.and_then(|(total, got)| {
        if got != sha256 {
            return Err("sha256 mismatch".into());
        }
        std::fs::rename(&tmp, dest).map_err(|e| format!("rename: {e}"))?;
        Ok(total)
    });
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

pub mod public;
#[cfg(test)]
mod tests;
