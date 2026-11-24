// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

//! fetch_url's public-only policy (agent 3.16.0), applied when the hub's request
//! carries `"public": true`. push_file pulls from the hub's own URL, which may be
//! http://<LAN address>, so it never sets the flag and none of this applies to it.
//!
//! Two checks, because the hub checks only the first URL and only by name:
//! `url_ok` is the hub's host rule, run on the URL sent and on every redirect
//! target; `resolve` drops every non-public address a name resolves to, at connect
//! time, so a public name pointing at the LAN (or rebinding to it) is refused too.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};

use url::Url;

pub const NON_PUBLIC: &str = "the host resolves only to non-public addresses";

/// The rule crates/hub/src/fetchurl.rs `check` applies to the host: https, a DNS
/// name (no IP literal), not localhost/.localhost/.local/.internal or a single
/// label, no userinfo. A redirect's query is allowed: signed storage URLs carry one.
pub fn url_ok(u: &Url) -> Result<(), String> {
    if u.scheme() != "https" {
        return Err("only https URLs are fetched".into());
    }
    if !u.username().is_empty() || u.password().is_some() {
        return Err("the URL must not carry a username or password".into());
    }
    let host = match u.domain() {
        Some(d) => d.trim_end_matches('.').to_ascii_lowercase(),
        None => return Err("the host must be a DNS name, not an IP address".into()),
    };
    if host == "localhost" || [".localhost", ".local", ".internal"].iter().any(|s| host.ends_with(s)) {
        return Err("the host must be a public DNS name — not localhost, .localhost, .local or .internal".into());
    }
    if !host.contains('.') {
        return Err("the host must be a public DNS name — a single-label name resolves on the local network".into());
    }
    Ok(())
}

pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v4_public(v),
        IpAddr::V6(v) => match embedded_v4(v) {
            Some(v4) => v4_public(v4),
            None => v6_public(v),
        },
    }
}

/// IPv4: everything except the IANA special-purpose ranges that are not globally
/// reachable (RFC 6890 and successors).
fn v4_public(v: Ipv4Addr) -> bool {
    let [a, b, c, _] = v.octets();
    let in_net = |net: [u8; 3], len: u32| {
        let addr = u32::from(v);
        let base = u32::from(Ipv4Addr::new(net[0], net[1], net[2], 0));
        addr >> (32 - len) == base >> (32 - len)
    };
    let special = a == 0                    // 0/8 "this network"
        || a == 10                          // private
        || a == 127                         // loopback
        || (a == 100 && b & 0xc0 == 64)     // 100.64/10 CGNAT
        || (a == 169 && b == 254)           // link-local
        || (a == 172 && b & 0xf0 == 16)     // private
        || (a == 192 && b == 168)           // private
        || in_net([192, 0, 0], 24)          // IETF protocol assignments
        || in_net([192, 0, 2], 24)          // TEST-NET-1
        || (a == 192 && b == 88 && c == 99) // 6to4 relay anycast
        || (a == 198 && b & 0xfe == 18)     // 198.18/15 benchmarking
        || in_net([198, 51, 100], 24)       // TEST-NET-2
        || in_net([203, 0, 113], 24)        // TEST-NET-3
        || a >= 224;                        // multicast 224/4, reserved 240/4, broadcast
    !special
}

/// IPv6: only global unicast 2000::/3, minus the ranges inside it that are not
/// globally reachable or that tunnel to an address we cannot check.
fn v6_public(v: Ipv6Addr) -> bool {
    let s = v.segments();
    let global_unicast = s[0] & 0xe000 == 0x2000;
    let teredo = s[0] == 0x2001 && s[1] == 0;               // 2001::/32
    let ietf = s[0] == 0x2001 && s[1] < 0x0200;              // 2001::/23 protocol assignments
    let documentation = s[0] == 0x2001 && s[1] == 0x0db8;    // 2001:db8::/32
    let six_to_four = s[0] == 0x2002;                         // 2002::/16 (embeds an IPv4)
    let doc_3fff = s[0] == 0x3fff && s[1] < 0x1000;          // 3fff::/20 documentation
    global_unicast && !(teredo || ietf || documentation || six_to_four || doc_3fff)
}

/// An IPv4 address carried in IPv6, judged as that IPv4: mapped (::ffff:a.b.c.d),
/// compatible (::a.b.c.d, which also covers :: and ::1), and NAT64 well-known
/// prefix (64:ff9b::a.b.c.d — an IPv6-only network's DNS64 answer for a v4-only
/// host such as github.com). Local-use NAT64 (64:ff9b:1::/48) is not unwrapped and
/// so is refused by `v6_public` (it is outside 2000::/3).
fn embedded_v4(v: Ipv6Addr) -> Option<Ipv4Addr> {
    let o = v.octets();
    let tail = Ipv4Addr::new(o[12], o[13], o[14], o[15]);
    match v.segments()[..6] {
        [0, 0, 0, 0, 0, 0xffff] | [0, 0, 0, 0, 0, 0] | [0x64, 0xff9b, 0, 0, 0, 0] => Some(tail),
        _ => None,
    }
}

/// Only the public addresses of `addrs`; none left is an error.
pub fn keep_public(addrs: Vec<SocketAddr>) -> io::Result<Vec<SocketAddr>> {
    let kept: Vec<SocketAddr> = addrs.into_iter().filter(|a| is_public(a.ip())).collect();
    if kept.is_empty() {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, NON_PUBLIC));
    }
    Ok(kept)
}

/// The system resolver, what ureq uses by default.
pub fn system(netloc: &str) -> io::Result<Vec<SocketAddr>> {
    netloc.to_socket_addrs().map(Iterator::collect)
}
