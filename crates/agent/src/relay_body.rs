// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

// Staged request bodies (hub 3.29.0+, agent 3.15.0+). A request body larger than
// the hub's inline limit is not base64'd into the poll response: the poll carries
// `"bf":1,"bl":<len>` and the agent GETs the bytes from `/relay/body`, streaming
// them straight into the loopback self-call with `Content-Length: <len>`. Neither
// side holds the whole body in memory. The hub only stages a body for an agent
// whose hello carried `"relay_body": 1`.
use std::io::{self, Read};

use crate::relay_redirect;
use crate::relaycred::RelayCred;

pub(crate) fn staged(v: &serde_json::Value) -> bool {
    match v.get("bf") {
        Some(serde_json::Value::Bool(b)) => *b,
        Some(serde_json::Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0),
        _ => false,
    }
}

/// The fetched body, capped at the length the poll announced. Ending before that
/// length is an error (so the self-call is cut off rather than completed short),
/// and `fail` keeps the reason for the 502 reply.
pub(crate) struct Staged {
    reader: Box<dyn Read + Send>,
    want: u64,
    got: u64,
    pub(crate) fail: Option<String>,
}

impl Read for Staged {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let room = (self.want - self.got).min(buf.len() as u64) as usize;
        if room == 0 {
            return Ok(0);
        }
        let why = match self.reader.read(&mut buf[..room]) {
            Ok(n) if n > 0 => {
                self.got += n as u64;
                return Ok(n);
            }
            Ok(_) => format!("short body: got {} of {} bytes", self.got, self.want),
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => format!("short body: got {} of {} bytes", self.got, self.want),
            Err(e) => format!("{e} after {} of {} bytes", self.got, self.want),
        };
        self.fail = Some(why.clone());
        Err(io::Error::other(why))
    }
}

/// GET the staged body. No timeout beyond the agent's connect timeout: a 100 MB
/// body on a slow link must not be cut off mid-stream.
pub(crate) fn fetch(cred: &RelayCred, req_id: u64, want: u64) -> Result<Staged, String> {
    let url = crate::relay::body_url(&cred.base(), cred.relay_id(), &cred.token(), req_id);
    let resp = match relay_redirect::get(cred, &url, None) {
        Ok(r) if r.status() == 200 => r,
        Ok(r) => return Err(format!("hub answered {}", r.status())),
        Err(ureq::Error::Status(s, _)) => return Err(format!("hub answered {s}")),
        Err(ureq::Error::Transport(t)) => return Err(t.message().map(String::from).unwrap_or_else(|| t.kind().to_string())),
    };
    if let Some(n) = resp.header("Content-Length") {
        if n.trim().parse::<u64>().ok() != Some(want) {
            return Err(format!("length mismatch: hub sent {} bytes, expected {want}", n.trim()));
        }
    }
    Ok(Staged { reader: Box::new(resp.into_reader()), want, got: 0, fail: None })
}

/// The loopback self-call with the staged body streamed into it. `Err(reason)`
/// is a body-fetch failure; `Ok` is whatever the self-call itself returned.
pub(crate) fn self_call(cred: &RelayCred, req_id: u64, want: u64, rq: ureq::Request, ct: &str) -> Result<Result<ureq::Response, ureq::Error>, String> {
    let mut body = fetch(cred, req_id, want)?;
    let rq = rq.set("Content-Length", &want.to_string());
    let rq = if ct.is_empty() { rq } else { rq.set("Content-Type", ct) };
    let sent = rq.send(&mut body);
    match body.fail.take() {
        Some(why) => Err(why),
        None => Ok(sent),
    }
}

#[cfg(test)]
mod tests;
