// SPDX-License-Identifier: MIT
//! The WireGuard cross-platform UAPI text protocol (`get=1` / `set=1`), as the embedded
//! boringtun device speaks it: requests, response parsing, and the peer changes an apply needs.
//! Keys travel as hex here and as base64 everywhere else in the agent.
// Only the Linux userspace backend talks UAPI; elsewhere this is tests only.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use super::Peer;
use base64::Engine;

pub fn b64_to_hex(k: &str) -> Option<String> {
    let b = base64::engine::general_purpose::STANDARD.decode(k).ok()?;
    (b.len() == 32).then(|| b.iter().map(|x| format!("{x:02x}")).collect())
}

pub fn hex_to_b64(h: &str) -> Option<String> {
    let b = super::hex_decode(h)?;
    (b.len() == 32).then(|| base64::engine::general_purpose::STANDARD.encode(b))
}

/// One peer as `get=1` reports it.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct UPeer {
    pub public_key: String,
    pub preshared_key: Option<String>,
    pub allowed_ips: Vec<String>,
    /// boringtun reports the time SINCE the last handshake here, not a Unix time.
    pub handshake_ago_secs: Option<u64>,
    pub rx: u64,
    pub tx: u64,
}

#[derive(Debug, Default, PartialEq)]
pub struct UDevice {
    pub public_key: Option<String>,
    pub listen_port: u16,
    pub peers: Vec<UPeer>,
}

/// `Ok(body)` for `errno=0`, the errno otherwise. `resp` is everything the device wrote back.
pub fn check(resp: &str) -> Result<&str, String> {
    let (body, tail) = match resp.rfind("errno=") {
        Some(i) => (&resp[..i], &resp[i + "errno=".len()..]),
        None => return Err(format!("no errno in the reply: {resp:?}")),
    };
    match tail.trim().parse::<i32>() {
        Ok(0) => Ok(body),
        Ok(n) => Err(format!("errno={n}")),
        Err(_) => Err(format!("bad errno in the reply: {resp:?}")),
    }
}

pub fn parse_get(body: &str) -> UDevice {
    let mut d = UDevice::default();
    for line in body.lines() {
        let Some((k, v)) = line.split_once('=') else { continue };
        if k == "public_key" {
            d.peers.push(UPeer { public_key: v.into(), ..Default::default() });
            continue;
        }
        match (d.peers.last_mut(), k) {
            (None, "own_public_key") => d.public_key = Some(v.into()),
            (None, "listen_port") => d.listen_port = v.parse().unwrap_or(0),
            (Some(p), "preshared_key") => p.preshared_key = Some(v.into()),
            (Some(p), "allowed_ip") => p.allowed_ips.push(v.into()),
            (Some(p), "last_handshake_time_sec") => p.handshake_ago_secs = v.parse().ok(),
            (Some(p), "rx_bytes") => p.rx = v.parse().unwrap_or(0),
            (Some(p), "tx_bytes") => p.tx = v.parse().unwrap_or(0),
            _ => {}
        }
    }
    d
}

pub const GET: &str = "get=1\n";

pub fn set_device(private_hex: &str, port: u16) -> String {
    format!("set=1\nprivate_key={private_hex}\nlisten_port={port}\n\n")
}

fn add_peer(public_hex: &str, psk_hex: &str, allowed_ip: &str) -> String {
    format!("set=1\npublic_key={public_hex}\npreshared_key={psk_hex}\nallowed_ip={allowed_ip}\n\n")
}

fn remove_peer(public_hex: &str) -> String {
    format!("set=1\npublic_key={public_hex}\nremove=true\n\n")
}

/// The `set=1` requests that turn `current` into `want`, one peer per request. boringtun 0.7
/// panics on a `set` for a peer it already has ("Modifying existing peers is not yet
/// supported"), and carries `remove`/`preshared_key` over from one peer section to the next
/// within a request, so: an unchanged peer gets no request at all, a changed one is removed and
/// added in two requests, and a public key listed twice is applied once (the last, as `wg set`
/// would leave it). Peers whose keys are not valid base64 were refused by `validate` already.
pub fn peer_plan(current: &[UPeer], want: &[Peer]) -> Vec<String> {
    let mut wanted: Vec<(String, String, &str)> = Vec::new();
    for p in want {
        let (Some(pk), Some(psk)) = (b64_to_hex(&p.public_key), b64_to_hex(&p.preshared_key)) else { continue };
        wanted.retain(|(k, _, _)| *k != pk);
        wanted.push((pk, psk, p.allowed_ips.as_str()));
    }
    let mut plan: Vec<String> = current.iter().filter(|c| !wanted.iter().any(|(k, _, _)| *k == c.public_key)).map(|c| remove_peer(&c.public_key)).collect();
    for (pk, psk, ip) in &wanted {
        match current.iter().find(|c| c.public_key == *pk) {
            Some(c) if c.preshared_key.as_deref() == Some(psk.as_str()) && c.allowed_ips == [ip.to_string()] => {}
            Some(_) => {
                plan.push(remove_peer(pk));
                plan.push(add_peer(pk, psk, ip));
            }
            None => plan.push(add_peer(pk, psk, ip)),
        }
    }
    plan
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "A2+2dpchy903HY/kmF70XH8jsgBgj1Vvf4+64neJqwI=";
    const B: &str = "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=";

    fn peer(pk: &str, ip: &str) -> Peer {
        Peer { public_key: pk.into(), preshared_key: B.into(), allowed_ips: ip.into(), expires_at: 0 }
    }

    fn present(pk: &str, ip: &str) -> UPeer {
        UPeer { public_key: b64_to_hex(pk).unwrap(), preshared_key: b64_to_hex(B), allowed_ips: vec![ip.into()], ..Default::default() }
    }

    #[test]
    fn keys_convert_between_base64_and_hex() {
        let h = b64_to_hex(A).unwrap();
        assert_eq!(h, "036fb6769721cbdd371d8fe4985ef45c7f23b200608f556f7f8fbae27789ab02");
        assert_eq!(hex_to_b64(&h).as_deref(), Some(A));
        assert!(b64_to_hex("not-a-key").is_none());
        assert!(hex_to_b64("abcd").is_none(), "not 32 bytes");
    }

    #[test]
    fn get_replies_parse_into_device_and_peers() {
        let resp = "own_public_key=aa\nlisten_port=51820\npublic_key=bb\npreshared_key=cc\nallowed_ip=10.77.0.2/32\nlast_handshake_time_sec=7\nlast_handshake_time_nsec=5\nrx_bytes=148\ntx_bytes=92\npublic_key=dd\nrx_bytes=0\ntx_bytes=0\nerrno=0\n\n";
        let d = parse_get(check(resp).unwrap());
        assert_eq!(d.public_key.as_deref(), Some("aa"));
        assert_eq!(d.listen_port, 51820);
        assert_eq!(d.peers.len(), 2);
        assert_eq!(d.peers[0], UPeer { public_key: "bb".into(), preshared_key: Some("cc".into()), allowed_ips: vec!["10.77.0.2/32".into()], handshake_ago_secs: Some(7), rx: 148, tx: 92 });
        assert_eq!(d.peers[1].handshake_ago_secs, None, "never shook hands");
        assert_eq!(check("errno=22\n\n"), Err("errno=22".into()));
        assert!(check("").is_err());
    }

    #[test]
    fn an_unchanged_peer_gets_no_request() {
        // boringtun 0.7 panics on a set for a peer it already has.
        assert!(peer_plan(&[present(A, "10.77.0.2/32")], &[peer(A, "10.77.0.2/32")]).is_empty());
    }

    #[test]
    fn a_changed_peer_is_removed_then_added() {
        let plan = peer_plan(&[present(A, "10.77.0.2/32")], &[peer(A, "10.77.0.3/32")]);
        let pk = b64_to_hex(A).unwrap();
        assert_eq!(plan.len(), 2, "{plan:#?}");
        assert_eq!(plan[0], format!("set=1\npublic_key={pk}\nremove=true\n\n"));
        assert!(plan[1].contains(&format!("public_key={pk}\n")) && plan[1].contains("allowed_ip=10.77.0.3/32\n") && !plan[1].contains("remove"));
    }

    #[test]
    fn stale_peers_go_and_new_ones_come_one_per_request() {
        let plan = peer_plan(&[present(A, "10.77.0.2/32")], &[peer(B, "10.77.0.4/32")]);
        assert_eq!(plan.len(), 2);
        assert!(plan[0].contains(&b64_to_hex(A).unwrap()) && plan[0].contains("remove=true"));
        assert!(plan[1].contains(&b64_to_hex(B).unwrap()) && !plan[1].contains("remove"));
        assert!(plan.iter().all(|r| r.matches("public_key=").count() == 1), "one peer section per request");
        assert!(plan.iter().all(|r| r.starts_with("set=1\n") && r.ends_with("\n\n")));
    }

    #[test]
    fn a_key_listed_twice_is_applied_once() {
        let plan = peer_plan(&[], &[peer(A, "10.77.0.2/32"), peer(A, "10.77.0.5/32")]);
        assert_eq!(plan.len(), 1, "a second add for the same key would panic boringtun: {plan:#?}");
        assert!(plan[0].contains("allowed_ip=10.77.0.5/32"), "the last one wins, as with wg set");
    }
}
