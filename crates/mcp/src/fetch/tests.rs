use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use it_ai_direct::testhub;
use rmcp::handler::server::wrapper::Parameters;
use serde_json::json;

use super::*;
use crate::testmcp::{hub, out, FAST};

const SHA: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
const URL: &str = "https://github.com/o/r/releases/download/v1.0/squash windows.zip";

fn srv(h: &it_ai_direct::testhub::FakeHub) -> Srv {
    Srv::with(h.url.clone(), "TOK".into(), "me@x.io".into(), FAST)
}

fn started() -> testhub::Resp {
    testhub::json(200, json!({"ok": true, "job": "j1", "status": "fetching", "dest": "C:\\Users\\a\\squash.zip"}))
}

/// `/m/file-status` answers not-done `n` times, then `then`.
fn status_after(n: usize, then: serde_json::Value) -> impl Fn() -> testhub::Resp + Send + Sync {
    let k = Arc::new(AtomicUsize::new(0));
    move || {
        if k.fetch_add(1, Ordering::SeqCst) < n {
            testhub::json(200, json!({"ok": true, "done": false, "success": false, "bytes": 0, "path": "C:\\Users\\a\\squash.zip", "error": ""}))
        } else {
            testhub::json(200, then.clone())
        }
    }
}

fn args(dir: Option<&str>, name: Option<&str>) -> Parameters<FetchArgs> {
    Parameters(FetchArgs::for_test(URL, SHA, dir, name))
}

#[test]
fn the_query_carries_url_sha256_and_only_the_given_options() {
    let a = FetchArgs::for_test("https://h.io/a b?x", &format!(" {SHA}\n"), Some("C:\\tools"), None);
    assert_eq!(
        fetch_query("relay://r1", &a),
        format!("target=relay%3A%2F%2Fr1&url=https%3A%2F%2Fh.io%2Fa%20b%3Fx&sha256={SHA}&dir=C%3A%5Ctools")
    );
    let a = FetchArgs::for_test(URL, SHA, Some(""), Some("s.zip"));
    assert!(fetch_query("relay://r1", &a).ends_with(&format!("sha256={SHA}&name=s.zip")));
}

#[tokio::test]
async fn it_starts_the_download_then_polls_until_the_device_is_done() {
    let st = status_after(2, json!({"ok": true, "done": true, "success": true, "bytes": 1234, "path": "C:\\Users\\a\\squash.zip", "error": ""}));
    let h = hub(move |r| match r.path.as_str() {
        "/m/fetch-url" => Some(started()),
        "/m/file-status" => Some(st()),
        _ => None,
    });
    let r = srv(&h).fetch_url(args(Some("C:\\Users\\a"), Some("squash.zip"))).await.unwrap();
    assert_eq!(out(&r), "fetched 1234 bytes to C:\\Users\\a\\squash.zip (sha256 verified)");
    let f = h.hits("/m/fetch-url");
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].method, "POST");
    let p = |k: &str| f[0].param(k);
    assert_eq!((p("target"), p("url"), p("sha256")), (Some("relay://r1".into()), Some(URL.into()), Some(SHA.into())));
    assert_eq!((p("dir"), p("name"), p("mtok"), p("owner")), (Some("C:\\Users\\a".into()), Some("squash.zip".into()), Some("TOK".into()), Some("me@x.io".into())));
    let polls = h.hits("/m/file-status");
    assert_eq!(polls.len(), 3);
    assert!(polls.iter().all(|q| q.param("job").as_deref() == Some("j1") && q.param("target").as_deref() == Some("relay://r1")));
}

#[tokio::test]
async fn a_hash_mismatch_is_an_error_and_nothing_is_claimed_saved() {
    let st = status_after(0, json!({"ok": true, "done": true, "success": false, "bytes": 0, "path": "C:\\x", "error": "sha256 mismatch"}));
    let h = hub(move |r| match r.path.as_str() {
        "/m/fetch-url" => Some(started()),
        "/m/file-status" => Some(st()),
        _ => None,
    });
    let r = srv(&h).fetch_url(args(None, None)).await.unwrap();
    assert_eq!(out(&r), "[error] fetch failed: sha256 mismatch");
}

#[tokio::test]
async fn a_hub_refusal_is_reported_and_nothing_is_polled() {
    let h = hub(|r| match r.path.as_str() {
        "/m/fetch-url" => Some(testhub::json(400, json!({"ok": false, "error": "url must not carry a query string; use a plain URL"}))),
        _ => None,
    });
    let r = tokio::time::timeout(std::time::Duration::from_secs(5), srv(&h).fetch_url(args(None, None)))
        .await
        .expect("a refusal ends the call, it does not wait for a download")
        .unwrap();
    assert_eq!(out(&r), "[error] url must not carry a query string; use a plain URL");
    assert!(h.hits("/m/file-status").is_empty());
}

#[tokio::test]
async fn an_old_hub_says_which_hub_it_needs() {
    let h = hub(|_| None);
    let r = srv(&h).fetch_url(args(None, None)).await.unwrap();
    assert_eq!(out(&r), "[error] the hub did not start the download (not found); fetch_url needs hub 3.30.0");
}

#[tokio::test]
async fn a_job_the_agent_forgot_ends_the_wait() {
    let st = status_after(1, json!({"ok": false, "done": false, "error": "unknown job"}));
    let h = hub(move |r| match r.path.as_str() {
        "/m/fetch-url" => Some(started()),
        "/m/file-status" => Some(st()),
        _ => None,
    });
    let r = tokio::time::timeout(std::time::Duration::from_secs(5), srv(&h).fetch_url(args(None, None)))
        .await
        .expect("the wait ends at once, not at the 16-minute deadline")
        .unwrap();
    assert!(out(&r).starts_with("[error] the device no longer knows download job j1"), "{}", out(&r));
    assert_eq!(h.hits("/m/file-status").len(), 2);
}

#[tokio::test]
async fn an_approved_fetch_says_who_approved_it_then_waits_for_the_download() {
    let st = status_after(0, json!({"ok": true, "done": true, "success": true, "bytes": 9, "path": "/tmp/a", "error": ""}));
    let h = hub(move |r| match r.path.as_str() {
        "/m/fetch-url" => Some(testhub::json(202, json!({"ok": false, "pending_approval": true, "status": "pending", "approval_id": "apr_7", "action": "upload", "device": "pc1", "poll": "/m/approval?id=apr_7"}))),
        "/m/approval" => Some(testhub::json(200, json!({"ok": true, "id": "apr_7", "status": "executed", "approver": "boss@x.io", "result_status": 200,
                                                        "result": {"ok": true, "job": "j9", "status": "fetching", "dest": "/tmp/a"}}))),
        "/m/file-status" => Some(st()),
        _ => None,
    });
    let r = srv(&h).fetch_url(args(None, None)).await.unwrap();
    assert_eq!(out(&r), "Approved by boss@x.io in the IT-AI dashboard (approval id apr_7); it ran:\nfetched 9 bytes to /tmp/a (sha256 verified)");
    assert_eq!(h.hits("/m/file-status")[0].param("job").as_deref(), Some("j9"));
}
