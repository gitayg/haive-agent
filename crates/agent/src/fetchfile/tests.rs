use super::*;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

const BODY: &[u8] = b"hello from the stage";

fn sha(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}

/// A plain-http server on loopback: `/ok` serves BODY, `/to-ok` redirects to `/ok`,
/// `/to-https` redirects to an https URL carrying a signature in its query.
fn server() -> String {
    let s = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let base = format!("http://{}", s.server_addr().to_ip().unwrap());
    std::thread::spawn(move || {
        for req in s.incoming_requests() {
            let loc = |l: &str| tiny_http::Header::from_bytes("Location", l).unwrap();
            let r = match req.url() {
                "/ok" => tiny_http::Response::from_data(BODY.to_vec()),
                "/to-ok" => tiny_http::Response::from_data(vec![]).with_status_code(302).with_header(loc("/ok")),
                "/to-https" => tiny_http::Response::from_data(vec![])
                    .with_status_code(307)
                    .with_header(loc("https://objects.example.com/x?sig=SECRET")),
                _ => tiny_http::Response::from_data(vec![]).with_status_code(404),
            };
            let _ = req.respond(r);
        }
    });
    base
}

fn dest(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("it-ai-fetch-test-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d.join("file.bin")
}

fn part(p: &std::path::Path) -> PathBuf {
    PathBuf::from(format!("{}.part", p.display()))
}

#[test]
fn fetch_sha256_must_be_64_hex() {
    let good = sha(BODY);
    assert_eq!(valid_sha256(&good).as_deref(), Some(good.as_str()));
    assert_eq!(valid_sha256(&good.to_uppercase()).as_deref(), Some(good.as_str()), "uppercase is normalized");
    for bad in [String::new(), good[..63].to_string(), format!("{good}0"), format!("g{}", &good[1..]), format!(" {}", &good[1..])] {
        assert_eq!(valid_sha256(&bad), None, "{bad:?} accepted");
    }
}

#[test]
fn fetch_request_without_a_valid_sha256_is_refused() {
    let body = |sha: &str| serde_json::json!({"url": "https://example.com/a", "sha256": sha, "name": "a", "job": "j"}).to_string();
    for bad in ["", "abc", &"z".repeat(64)] {
        assert_eq!(parse(&body(bad)).err(), Some(("need sha256: 64 hex characters", 400)), "sha256 {bad:?}");
    }
    let no_sha = serde_json::json!({"url": "https://example.com/a", "name": "a", "job": "j"}).to_string();
    assert_eq!(parse(&no_sha).err(), Some(("need sha256: 64 hex characters", 400)));
    let no_url = serde_json::json!({"sha256": sha(BODY), "name": "a", "job": "j"}).to_string();
    assert_eq!(parse(&no_url).err(), Some(("need url, name, job", 200)));
    let ok = parse(&body(&sha(BODY).to_uppercase())).unwrap();
    assert_eq!((ok.sha256, ok.dir, ok.name, ok.job), (sha(BODY), String::new(), "a".to_string(), "j".to_string()));
}

#[test]
fn fetch_redirects_only_https_to_https() {
    let u = |s: &str| Url::parse(s).unwrap();
    let gh = u("https://github.com/gitayg/haive-agent/releases/download/v3.15.0/it-ai-linux-x86_64");
    let obj = u("https://objects.githubusercontent.com/github-production-release-asset/1?X-Amz-Signature=abc&response-content-disposition=attachment");
    assert!(redirect_allowed(&gh, &obj));
    assert!(!redirect_allowed(&gh, &u("http://objects.githubusercontent.com/x")), "https → http followed");
    assert!(!redirect_allowed(&u("http://hub:8080/files/staged/t"), &u("https://hub/files/staged/t")), "http → https followed");
    assert!(!redirect_allowed(&u("http://hub:8080/a"), &u("http://hub:8080/b")), "http → http followed");
    assert!(!redirect_allowed(&gh, &u("file:///etc/passwd")));
}

#[test]
fn fetch_plain_url_with_matching_hash_lands_at_dest() {
    let base = server();
    let d = dest("ok");
    let n = fetch_to_file(&format!("{base}/ok"), d.to_str().unwrap(), &sha(BODY), false).unwrap();
    assert_eq!(n, BODY.len() as u64);
    assert_eq!(std::fs::read(&d).unwrap(), BODY);
    assert!(!part(&d).exists());
}

#[test]
fn fetch_hash_mismatch_writes_nothing() {
    let base = server();
    let d = dest("mismatch");
    let e = fetch_to_file(&format!("{base}/ok"), d.to_str().unwrap(), &sha(b"other"), false).unwrap_err();
    assert_eq!(e, "sha256 mismatch");
    assert!(!e.contains(&sha(BODY)) && !e.contains(&sha(BODY)[..12]), "the error echoes the computed hash: {e}");
    assert!(!d.exists() && !part(&d).exists(), "a mismatching download was left on disk");
}

#[test]
fn fetch_redirect_off_plain_http_is_refused() {
    let base = server();
    let d = dest("redir");
    for (path, to) in [("/to-ok", "/ok"), ("/to-https", "https://objects.example.com/x")] {
        let e = fetch_to_file(&format!("{base}{path}"), d.to_str().unwrap(), &sha(BODY), false).unwrap_err();
        assert!(e.starts_with("refused redirect") && e.contains(to), "{path}: {e}");
        assert!(!e.contains("SECRET"), "an error echoed a redirect's query: {e}");
        assert!(!d.exists() && !part(&d).exists());
    }
}

#[test]
fn fetch_http_error_is_reported() {
    let base = server();
    let d = dest("404");
    let e = fetch_to_file(&format!("{base}/missing"), d.to_str().unwrap(), &sha(BODY), false).unwrap_err();
    assert!(e.ends_with("HTTP 404"), "{e}");
    assert!(!d.exists() && !part(&d).exists());
}

/// Live: a real GitHub release asset, which answers 302 to a signed
/// objects.githubusercontent.com URL. Run with `--ignored`; set FETCH_LIVE_URL and
/// FETCH_LIVE_SHA256 to the asset and its digest.
#[test]
#[ignore]
fn fetch_live_github_release_asset_follows_https_redirect() {
    let url = std::env::var("FETCH_LIVE_URL").expect("FETCH_LIVE_URL");
    let want = std::env::var("FETCH_LIVE_SHA256").expect("FETCH_LIVE_SHA256");
    let d = dest("live");
    let n = fetch_to_file(&url, d.to_str().unwrap(), &valid_sha256(&want).unwrap(), true).unwrap();
    assert!(n > 0 && d.exists() && !part(&d).exists());
    eprintln!("fetched {n} bytes from {url}");
}

#[test]
fn a_missing_destination_folder_is_refused_before_any_download() {
    let base = std::env::temp_dir().join(format!("it-ai-fetch-dest-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let e = dest_dir_ready(&base.join("missing")).unwrap_err();
    assert!(e.starts_with("destination folder does not exist"), "{e}");
    std::fs::create_dir_all(&base).unwrap();
    assert!(dest_dir_ready(&base).is_ok(), "an existing folder was refused");
    let _ = std::fs::remove_dir_all(&base);
}

/// `follow` with a fake network: the first GET answers 302 to `to`, any later one
/// succeeds. Returns the result and the URLs requested.
fn redirect_to(to: &str, public: bool) -> (Result<(), String>, Vec<String>) {
    let mut asked = vec![];
    let to = to.to_string();
    let r = follow("https://github.com/o/r/releases/download/v1/a.zip", public, |u| {
        asked.push(u.to_string());
        Ok(if asked.len() == 1 { Step::Redirect(302, Some(to.clone())) } else { Step::Done(()) })
    });
    (r, asked)
}

#[test]
fn public_fetch_refuses_a_redirect_to_an_ip_literal() {
    for to in [
        "https://192.168.1.1/admin", "https://10.0.0.1/a", "https://127.0.0.1/a", "https://169.254.169.254/latest/meta-data",
        "https://[::1]/a", "https://[fe80::1]/a", "https://2130706433/a", "https://0x7f000001/a", "https://192.168.1.1:8443/a",
    ] {
        let (r, asked) = redirect_to(to, true);
        let e = r.unwrap_err();
        assert!(e.starts_with("refused redirect") && e.contains("not an IP address"), "{to}: {e}");
        assert_eq!(asked.len(), 1, "{to} was requested: {asked:?}");
        // Control: without `public` (push_file) the same https → https hop is followed.
        let (r, asked) = redirect_to(to, false);
        assert!(r.is_ok() && asked.len() == 2, "{to} without public: {r:?} {asked:?}");
    }
}

#[test]
fn public_fetch_refuses_a_redirect_to_a_local_name() {
    for (to, rule) in [
        ("https://router.local/a", "public DNS name"),
        ("https://Router.Local./a", "public DNS name"),
        ("https://localhost/a", "public DNS name"),
        ("https://localhost./a", "public DNS name"),
        ("https://api.localhost/a", "public DNS name"),
        ("https://metadata.google.internal/a", "public DNS name"),
        ("https://nas/a", "single-label"),
        ("https://user:pw@cdn.example.com/a", "username or password"),
        ("http://cdn.example.com/a", "only https to https"),
    ] {
        let (r, asked) = redirect_to(to, true);
        let e = r.unwrap_err();
        assert!(e.starts_with("refused redirect") && e.contains(rule), "{to}: {e}");
        assert_eq!(asked.len(), 1, "{to} was requested: {asked:?}");
    }
    // Control: a GitHub release's signed storage redirect is followed under public.
    let (r, asked) = redirect_to("https://objects.githubusercontent.com/github-production-release-asset/1?X-Amz-Signature=abc", true);
    assert!(r.is_ok() && asked.len() == 2, "{r:?} {asked:?}");
}

#[test]
fn public_fetch_checks_the_first_url_before_any_request() {
    for (url, rule) in [
        ("https://192.168.1.1/a.zip", "not an IP address"),
        ("https://router.local/a.zip", "public DNS name"),
        ("https://intranet/a.zip", "single-label"),
        ("http://github.com/a.zip", "only https"),
    ] {
        let mut asked = 0;
        let e = follow(url, true, |_| -> Result<Step<()>, String> {
            asked += 1;
            Ok(Step::Done(()))
        })
        .unwrap_err();
        assert!(e.starts_with("refused") && e.contains(rule), "{url}: {e}");
        assert_eq!(asked, 0, "{url} was requested");
    }
}

/// Every name resolves to loopback, on the port asked for.
fn to_loopback(netloc: &str) -> std::io::Result<Vec<std::net::SocketAddr>> {
    let port = netloc.rsplit(':').next().unwrap().parse().unwrap();
    Ok(vec![(std::net::Ipv4Addr::LOCALHOST, port).into()])
}

fn to_private_v6(netloc: &str) -> std::io::Result<Vec<std::net::SocketAddr>> {
    let port: u16 = netloc.rsplit(':').next().unwrap().parse().unwrap();
    Ok(["[::ffff:127.0.0.1]", "[fd00::1]", "[fe80::1]", "[::1]", "[64:ff9b::a00:1]"].iter().map(|h| format!("{h}:{port}").parse().unwrap()).collect())
}

#[test]
fn public_fetch_refuses_a_name_that_resolves_to_a_private_address() {
    for lookup in [to_loopback as fn(&str) -> std::io::Result<Vec<std::net::SocketAddr>>, to_private_v6] {
        let e = open_with("https://files.example.com/a.bin", true, lookup).err().unwrap();
        assert!(e.contains(public::NON_PUBLIC), "{e}");
        assert!(e.starts_with("GET https://files.example.com/a.bin failed"), "{e}");
    }
    // Control: the same resolver without `public` (push_file) reaches the loopback server.
    let port = server().rsplit(':').next().unwrap().to_string();
    let mut body = vec![];
    open_with(&format!("http://files.example.com:{port}/ok"), false, to_loopback).unwrap().into_reader().read_to_end(&mut body).unwrap();
    assert_eq!(body, BODY);
}

#[test]
fn without_public_a_loopback_hub_url_still_works() {
    let base = server();
    let d = dest("pushfile");
    assert_eq!(fetch_to_file(&format!("{base}/ok"), d.to_str().unwrap(), &sha(BODY), false).unwrap(), BODY.len() as u64);
    let _ = std::fs::remove_file(&d);
    let e = fetch_to_file(&format!("{base}/ok"), d.to_str().unwrap(), &sha(BODY), true).unwrap_err();
    assert!(e.starts_with("refused") && e.contains("only https"), "{e}");
    assert!(!d.exists() && !part(&d).exists());
}

#[test]
fn only_public_addresses_survive_resolution() {
    use std::net::IpAddr;
    for ip in [
        "0.0.0.0", "0.1.2.3", "127.0.0.1", "127.9.9.9", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1", "169.254.169.254",
        "100.64.0.1", "100.127.255.255", "224.0.0.1", "239.255.255.250", "255.255.255.255", "198.18.0.1", "198.19.255.255",
        "::", "::1", "fe80::1", "febf::1", "fc00::1", "fd12:3456::1", "ff02::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1",
        "::ffff:192.168.1.1", "::ffff:169.254.169.254", "::10.0.0.1", "::127.0.0.1", "64:ff9b::10.0.0.1", "64:ff9b::7f00:1",
        "192.0.0.8", "192.0.2.1", "192.88.99.1", "198.51.100.7", "203.0.113.5", "240.0.0.1", "250.1.2.3",
        "2002:c0a8:101::1", "2002:808:808::1", "2001::1", "2001:0:4136:e378::1", "2001:db8::1", "2001:10::1",
        "64:ff9b:1::a00:1", "3fff::1", "fec0::1", "4000::1", "100::1",
    ] {
        assert!(!public::is_public(ip.parse::<IpAddr>().unwrap()), "{ip} counted as public");
    }
    for ip in ["8.8.8.8", "140.82.112.3", "100.63.255.255", "100.128.0.1", "172.15.255.255", "172.32.0.1", "198.17.0.1", "198.20.0.1", "2606:4700::1111", "2001:4860:4860::8888", "2a00:1450:4001::1", "::ffff:8.8.8.8", "64:ff9b::808:808", "192.0.1.1", "223.255.255.1"] {
        assert!(public::is_public(ip.parse::<IpAddr>().unwrap()), "{ip} counted as non-public");
    }
    let a = |s: &str| s.parse::<std::net::SocketAddr>().unwrap();
    assert_eq!(public::keep_public(vec![a("10.0.0.1:443"), a("8.8.8.8:443"), a("[::1]:443")]).unwrap(), vec![a("8.8.8.8:443")]);
    assert_eq!(public::keep_public(vec![a("10.0.0.1:443")]).unwrap_err().to_string(), public::NON_PUBLIC);
}

#[test]
fn only_a_true_public_field_turns_the_policy_on() {
    let body = |extra: serde_json::Value| {
        let mut v = serde_json::json!({"url": "https://example.com/a", "sha256": sha(BODY), "name": "a", "job": "j"});
        if let serde_json::Value::Object(m) = extra {
            v.as_object_mut().unwrap().extend(m);
        }
        v.to_string()
    };
    assert!(parse(&body(serde_json::json!({"public": true}))).unwrap().public);
    for off in [serde_json::json!({}), serde_json::json!({"public": false}), serde_json::json!({"public": null})] {
        assert!(!parse(&body(off.clone())).unwrap().public, "{off}");
    }
}
