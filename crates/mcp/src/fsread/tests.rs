use std::time::Duration;

use it_ai_direct::testhub::{self, FakeHub};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::ServiceExt;
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use super::*;
use crate::testmcp::{hub, out, Live, FAST};

const SHA: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
const WIN: &str = "C:\\Program Files\\GitHub CLI\\gh.exe";
const ODD: &str = "/tmp/a&b #1 100%.txt";

fn srv(h: &FakeHub) -> Srv {
    Srv::with(h.url.clone(), "TOK".into(), "me@x.io".into(), FAST)
}

fn listing() -> serde_json::Value {
    json!({"ok": true, "path": "C:\\Program Files", "parent": "C:\\", "entries": [
        {"name": "GitHub CLI", "dir": true, "size": 0, "mtime": 1795000000, "link": false},
        {"name": "current", "dir": true, "size": 0, "mtime": 951782400, "link": true},
        {"name": "readme.txt", "dir": false, "size": 1234, "mtime": 0, "link": false},
    ]})
}

#[test]
fn the_query_url_encodes_windows_paths_and_url_metacharacters() {
    assert_eq!(fs_query("relay://r1", Some(WIN)), "target=relay%3A%2F%2Fr1&path=C%3A%5CProgram%20Files%5CGitHub%20CLI%5Cgh.exe");
    assert_eq!(fs_query("relay://r1", Some(ODD)), "target=relay%3A%2F%2Fr1&path=%2Ftmp%2Fa%26b%20%231%20100%25.txt");
    assert_eq!(fs_query("relay://r1", Some("")), "target=relay%3A%2F%2Fr1");
    assert_eq!(fs_query("relay://r1", None), "target=relay%3A%2F%2Fr1");
}

#[test]
fn unix_seconds_read_as_utc_minutes() {
    assert_eq!(utc(0), "1970-01-01 00:00 UTC");
    assert_eq!(utc(951782400), "2000-02-29 00:00 UTC");
    assert_eq!(utc(1795000000), "2026-11-18 11:06 UTC");
    assert_eq!(utc(4102444799), "2099-12-31 23:59 UTC");
}

#[test]
fn a_listing_is_one_line_per_entry_with_kind_size_time_and_name() {
    assert_eq!(
        fmt_list(&listing()),
        "C:\\Program Files (3 entries)\n\
         d            0 2026-11-18 11:06 UTC GitHub CLI\n\
         l            0 2000-02-29 00:00 UTC current\n\
         f         1234 -                    readme.txt"
    );
    let mut v = listing();
    v["truncated"] = json!(true);
    assert!(fmt_list(&v).ends_with("\n(truncated: the folder has more entries than one listing returns; 3 shown)"), "{}", fmt_list(&v));
    assert_eq!(fmt_list(&json!({"ok": true, "path": "/e", "entries": []})), "/e (0 entries)");
    assert_eq!(fmt_list(&json!({"ok": false, "error": "forbidden"})), "[error] forbidden");
}

#[test]
fn info_is_key_lines_and_a_missing_path_says_so() {
    assert_eq!(
        fmt_info(&json!({"ok": true, "path": WIN, "exists": true, "kind": "file", "size": 12, "mtime": 1795000000, "readonly": true})),
        format!("path: {WIN}\nexists: yes\nkind: file\nsize: 12 bytes\nmodified: 2026-11-18 11:06 UTC\nreadonly: yes")
    );
    assert_eq!(fmt_info(&json!({"ok": true, "path": "/proc/9/environ", "exists": false})), "path: /proc/9/environ\nexists: no");
    assert_eq!(fmt_info(&json!({"ok": false, "error": "path is required"})), "[error] path is required");
}

#[test]
fn a_hash_is_one_sha256sum_style_line() {
    assert_eq!(fmt_hash(&json!({"ok": true, "path": WIN, "size": 7, "sha256": SHA})), format!("{SHA}  {WIN} (7 bytes)"));
    assert_eq!(fmt_hash(&json!({"ok": false, "error": "not a file"})), "[error] not a file");
}

#[tokio::test]
async fn list_dir_asks_the_hub_for_the_folder() {
    let h = hub(|r| (r.path == "/m/list").then(|| testhub::json(200, listing())));
    let r = srv(&h).list_dir(Parameters(ListDirArgs::for_test(Some("C:\\Program Files")))).await.unwrap();
    assert_eq!(out(&r), fmt_list(&listing()));
    let q = &h.hits("/m/list")[0];
    assert_eq!(q.method, "GET");
    let p = |k: &str| q.param(k);
    assert_eq!((p("target"), p("path"), p("mtok"), p("owner")), (Some("relay://r1".into()), Some("C:\\Program Files".into()), Some("TOK".into()), Some("me@x.io".into())));
    srv(&h).list_dir(Parameters(ListDirArgs::for_test(None))).await.unwrap();
    assert_eq!(h.hits("/m/list")[1].param("path"), None, "no path: the agent picks its default folder");
}

#[tokio::test]
async fn file_info_sends_a_windows_path_with_spaces_and_backslashes_intact() {
    let h = hub(|r| (r.path == "/m/stat").then(|| testhub::json(200, json!({"ok": true, "path": WIN, "exists": true, "kind": "file", "size": 12, "mtime": 1795000000, "readonly": false}))));
    let r = srv(&h).file_info(Parameters(FileArgs::for_test(WIN))).await.unwrap();
    assert_eq!(out(&r), format!("path: {WIN}\nexists: yes\nkind: file\nsize: 12 bytes\nmodified: 2026-11-18 11:06 UTC\nreadonly: no"));
    let q = &h.hits("/m/stat")[0];
    assert_eq!(q.method, "GET");
    assert!(q.query.contains("&path=C%3A%5CProgram%20Files%5CGitHub%20CLI%5Cgh.exe"), "{}", q.query);
    assert_eq!(q.param("path").as_deref(), Some(WIN));
}

#[tokio::test]
async fn file_hash_sends_ampersand_hash_and_percent_encoded() {
    let h = hub(|r| (r.path == "/m/hash").then(|| testhub::json(200, json!({"ok": true, "path": ODD, "size": 7, "sha256": SHA}))));
    let r = srv(&h).file_hash(Parameters(FileArgs::for_test(ODD))).await.unwrap();
    assert_eq!(out(&r), format!("{SHA}  {ODD} (7 bytes)"));
    let q = &h.hits("/m/hash")[0];
    assert_eq!(q.method, "GET");
    assert!(q.query.contains("&path=%2Ftmp%2Fa%26b%20%231%20100%25.txt"), "{}", q.query);
    assert_eq!((q.param("path").as_deref(), q.param("target").as_deref()), (Some(ODD), Some("relay://r1")));
}

#[tokio::test]
async fn an_old_agent_is_named_and_a_missing_file_is_an_error_line() {
    let h = hub(|r| match r.path.as_str() {
        "/m/stat" => Some(testhub::json(409, json!({"ok": false, "error": "the device's agent is older than 3.17.0 and has no /stat; update it"}))),
        "/m/hash" => Some(testhub::json(404, json!({"ok": false, "error": "not a file"}))),
        _ => None,
    });
    let r = srv(&h).file_info(Parameters(FileArgs::for_test(WIN))).await.unwrap();
    assert_eq!(out(&r), "[error] the device's agent is older than 3.17.0 and has no /stat; update it");
    let r = srv(&h).file_hash(Parameters(FileArgs::for_test("C:\\Windows"))).await.unwrap();
    assert_eq!(out(&r), "[error] not a file");
}

#[tokio::test]
async fn a_403_is_an_error_line_and_a_blocked_one_still_says_do_not_reroute() {
    let h = hub(|r| match r.path.as_str() {
        "/m/list" => Some(testhub::json(403, json!({"ok": false, "error": "forbidden"}))),
        "/m/hash" => Some(testhub::json(403, json!({"ok": false, "error": "file hash is blocked by policy", "tier": "blocked"}))),
        _ => None,
    });
    let r = srv(&h).list_dir(Parameters(ListDirArgs::for_test(Some("/etc")))).await.unwrap();
    assert_eq!((r.is_error, out(&r)), (Some(true), "[error] forbidden".to_string()));
    let r = srv(&h).file_hash(Parameters(FileArgs::for_test("/etc/hosts"))).await.unwrap();
    assert!(out(&r).starts_with("Blocked by the hub's policy: file hash is blocked by policy."), "{}", out(&r));
}

#[tokio::test]
async fn an_old_hub_says_which_hub_it_needs() {
    let h = hub(|_| None);
    let r = srv(&h).file_hash(Parameters(FileArgs::for_test("/etc/hosts"))).await.unwrap();
    assert_eq!(out(&r), "[error] the hub has no /m/hash (not found); file_hash needs hub 3.31.0");
    let r = srv(&h).list_dir(Parameters(ListDirArgs::for_test(None))).await.unwrap();
    assert_eq!(out(&r), "[error] the hub has no /m/list (not found); list_dir needs hub 3.31.0");
}

#[tokio::test]
async fn an_approved_read_says_who_approved_it_then_shows_the_result() {
    let h = hub(|r| match r.path.as_str() {
        "/m/hash" => Some(testhub::json(202, json!({"ok": false, "pending_approval": true, "status": "pending", "approval_id": "apr_3", "action": "download", "device": "pc1", "poll": "/m/approval?id=apr_3"}))),
        "/m/approval" => Some(testhub::json(200, json!({"ok": true, "id": "apr_3", "status": "executed", "approver": "boss@x.io", "result_status": 200,
                                                        "result": {"ok": true, "path": "/etc/hosts", "size": 7, "sha256": SHA}}))),
        _ => None,
    });
    let r = srv(&h).file_hash(Parameters(FileArgs::for_test("/etc/hosts"))).await.unwrap();
    assert_eq!(out(&r), format!("Approved by boss@x.io in the IT-AI dashboard (approval id apr_3); it ran:\n{SHA}  /etc/hosts (7 bytes)"));
}

#[tokio::test]
async fn every_read_uses_the_session_token_and_no_token_reaches_the_output() {
    let h = hub(|r| match r.path.as_str() {
        "/m/session-token" => Some(testhub::json(200, json!({"ok": true, "token": "SESSION-SECRET", "id": "mt_1", "name": "session: x", "scope": "full", "expires_at": 1790086400}))),
        "/m/list" => Some(testhub::json(200, listing())),
        "/m/stat" => Some(testhub::json(200, json!({"ok": true, "path": WIN, "exists": false}))),
        "/m/hash" => Some(testhub::json(200, json!({"ok": true, "path": ODD, "size": 7, "sha256": SHA}))),
        _ => None,
    });
    let mut s = Live::start(&h, "CONF-SECRET", "claude-code").await;
    let outs = [
        s.call("list_dir", json!({"device": "pc1", "path": "C:\\Program Files"})).await,
        s.call("file_info", json!({"device": "pc1", "path": WIN})).await,
        s.call("file_hash", json!({"device": "pc1", "path": ODD})).await,
    ];
    assert!(outs.iter().all(|o| !o.contains("SECRET")), "{outs:?}");
    assert_eq!(outs, [fmt_list(&listing()), format!("path: {WIN}\nexists: no"), format!("{SHA}  {ODD} (7 bytes)")]);
    assert_eq!(h.hits("/m/session-token")[0].param("mtok").as_deref(), Some("CONF-SECRET"));
    for route in ["/m/list", "/m/stat", "/m/hash"] {
        let hits = h.hits(route);
        assert_eq!(hits.len(), 1, "{route}");
        assert_eq!(hits[0].param("mtok").as_deref(), Some("SESSION-SECRET"), "{route} ran with the minted session token");
    }
}

#[tokio::test]
async fn tools_list_offers_the_three_reads_with_their_arguments() {
    let h = hub(|_| None);
    let (client, server) = tokio::io::duplex(1 << 20);
    let (sr, sw) = tokio::io::split(server);
    let s = srv(&h);
    tokio::spawn(async move {
        let running = s.serve((sr, sw)).await.expect("serve");
        let _ = running.waiting().await;
    });
    let (cr, mut cw) = tokio::io::split(client);
    let mut lines = BufReader::new(cr).lines();
    let send = |v: serde_json::Value| format!("{v}\n");
    cw.write_all(send(json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}})).as_bytes()).await.unwrap();
    let _init = lines.next_line().await.unwrap().unwrap();
    cw.write_all(send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"})).as_bytes()).await.unwrap();
    cw.write_all(send(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})).as_bytes()).await.unwrap();
    let list: serde_json::Value = loop {
        let l = tokio::time::timeout(Duration::from_secs(5), lines.next_line()).await.unwrap().unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_str(&l).unwrap();
        if v["id"] == 2 {
            break v;
        }
    };
    let tools = list["result"]["tools"].as_array().expect("tools");
    for (name, required) in [("list_dir", json!(["device"])), ("file_info", json!(["device", "path"])), ("file_hash", json!(["device", "path"]))] {
        let t = tools.iter().find(|t| t["name"] == name).unwrap_or_else(|| panic!("{name} not listed"));
        let props: Vec<&String> = t["inputSchema"]["properties"].as_object().unwrap().keys().collect();
        assert_eq!(props, ["device", "path"], "{name}");
        assert_eq!(t["inputSchema"]["required"], required, "{name}");
        let d = t["description"].as_str().unwrap();
        assert!(d.contains("without a shell and without an approval; prefer it over run_command"), "{name}: {d}");
        assert!(d.contains("Works the same on Windows, macOS and Linux"), "{name}: {d}");
    }
}
