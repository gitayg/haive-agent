use it_ai_direct::testhub;
use rmcp::handler::server::wrapper::Parameters;
use serde_json::json;

use super::*;
use crate::testmcp::{hub, out, FAST};

fn srv(h: &it_ai_direct::testhub::FakeHub) -> Srv {
    Srv::with(h.url.clone(), "TOK".into(), "me@x.io".into(), FAST)
}

fn a(status: Option<&str>, device: Option<&str>) -> ListApprovalsArgs {
    ListApprovalsArgs::for_test(status, device)
}

#[test]
fn the_query_passes_status_and_device_and_refuses_an_unknown_status() {
    assert_eq!(list_query(&a(None, None)).unwrap(), "");
    assert_eq!(list_query(&a(Some("pending"), Some("pc 1"))).unwrap(), "status=pending&device=pc%201");
    assert_eq!(list_query(&a(Some("all"), Some(""))).unwrap(), "status=all");
    assert_eq!(list_query(&a(Some("open"), None)).unwrap_err(), "[error] status must be one of pending, recent, all, not 'open'");
}

#[test]
fn each_list_the_hub_filled_is_shown_one_approval_per_line() {
    let v = json!({"ok": true,
        "pending": [{"id": "apr_2", "status": "pending", "action": "exec", "device": "pc1", "detail": "rm -rf /tmp/x",
                     "token_name": "session: claude-code · mac1 · pid 7", "expires": 1790003600, "approver": "", "error": "", "exit_code": null}],
        "recent": [{"id": "apr_1", "status": "executed", "action": "job_start", "device": "pc1", "detail": "make",
                    "token_name": "", "approver": "boss@x.io", "error": "", "exit_code": 0},
                   {"id": "apr_0", "status": "denied", "action": "power", "device": "pc2", "detail": "reboot", "approver": "boss@x.io", "error": ""}]});
    assert_eq!(
        fmt_list(&v),
        "Waiting for a human (1):\n\
         - apr_2 [pending] 'exec' on pc1: rm -rf /tmp/x — requested by session: claude-code · mac1 · pid 7, expires 1790003600\n\
         Recently decided (2):\n\
         - apr_1 [executed] 'job_start' on pc1: make, decided by boss@x.io, exit 0\n\
         - apr_0 [denied] 'power' on pc2: reboot, decided by boss@x.io"
    );
    assert_eq!(fmt_list(&json!({"ok": true, "pending": []})), "Waiting for a human (0):");
    assert_eq!(fmt_list(&json!({"ok": true})), "no approvals");
    assert_eq!(fmt_list(&json!({"ok": false, "error": "forbidden"})), "[error] forbidden");
}

#[tokio::test]
async fn it_asks_the_hub_for_this_owners_approvals() {
    let h = hub(|r| match r.path.as_str() {
        "/m/approvals" => Some(testhub::json(200, json!({"ok": true, "pending": [{"id": "apr_2", "status": "pending", "action": "exec", "device": "pc1", "expires": 5}]}))),
        _ => None,
    });
    let r = srv(&h).list_approvals(Parameters(a(Some("pending"), Some("pc1")))).await.unwrap();
    assert_eq!(out(&r), "Waiting for a human (1):\n- apr_2 [pending] 'exec' on pc1, expires 5");
    let q = &h.hits("/m/approvals")[0];
    assert_eq!(q.method, "GET");
    let p = |k: &str| q.param(k);
    assert_eq!((p("status"), p("device"), p("mtok"), p("owner")), (Some("pending".into()), Some("pc1".into()), Some("TOK".into()), Some("me@x.io".into())));
}

#[tokio::test]
async fn an_old_hub_says_which_hub_it_needs() {
    let h = hub(|_| None);
    let r = srv(&h).list_approvals(Parameters(a(None, None))).await.unwrap();
    assert_eq!(out(&r), "[error] the hub has no approval list (not found); list_approvals needs hub 3.30.0");
}
