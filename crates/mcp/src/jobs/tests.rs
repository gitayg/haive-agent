use rmcp::ServerHandler;
use serde_json::json;

use super::*;

fn required(tool: &rmcp::model::Tool) -> Vec<String> {
    let mut r: Vec<String> = tool.input_schema["required"]
        .as_array()
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default();
    r.sort();
    r
}

fn props(tool: &rmcp::model::Tool) -> Vec<String> {
    let mut p: Vec<String> = tool.input_schema["properties"]
        .as_object()
        .map(|o| o.keys().cloned().collect())
        .unwrap_or_default();
    p.sort();
    p
}

#[test]
fn server_lists_the_four_job_tools_with_their_schemas() {
    let srv = Srv::new();
    let names: Vec<String> = srv.tool_router.list_all().iter().map(|t| t.name.to_string()).collect();
    for n in ["job_start", "job_logs", "job_stop", "job_list", "run_command"] {
        assert!(names.iter().any(|x| x == n), "{n} missing from {names:?}");
    }
    // Resolved through the ServerHandler, i.e. what a client's tools/list sees.
    let get = |n: &str| ServerHandler::get_tool(&srv, n).unwrap_or_else(|| panic!("handler has no {n}"));
    let start = get("job_start");
    assert_eq!(props(&start), ["command", "cwd", "device"]);
    assert_eq!(required(&start), ["command", "device"]);
    let logs = get("job_logs");
    assert_eq!(props(&logs), ["device", "id", "offset"]);
    assert_eq!(required(&logs), ["device", "id"]);
    let stop = get("job_stop");
    assert_eq!(props(&stop), ["device", "id"]);
    assert_eq!(required(&stop), ["device", "id"]);
    let list = get("job_list");
    assert_eq!(props(&list), ["device"]);
    assert_eq!(required(&list), ["device"]);
}

fn ctl() -> Controller {
    Controller::new("https://hub.example".into(), "TOK".into(), "me@x.io".into(), reqwest::Client::new())
}

const AUTH: &str = "mtok=TOK&owner=me%40x.io";

#[test]
fn route_urls() {
    let c = ctl();
    let t = "relay://dev 1";
    assert_eq!(start_url(&c, t), format!("https://hub.example/m/job/start?{AUTH}&target=relay%3A%2F%2Fdev%201"));
    assert_eq!(
        logs_url(&c, t, "j17a3f", 0),
        format!("https://hub.example/m/job/logs?{AUTH}&target=relay%3A%2F%2Fdev%201&id=j17a3f&offset=0")
    );
    assert_eq!(
        stop_url(&c, t, "j&x"),
        format!("https://hub.example/m/job/stop?{AUTH}&target=relay%3A%2F%2Fdev%201&id=j%26x")
    );
    assert_eq!(list_url(&c, t), format!("https://hub.example/m/job/list?{AUTH}&target=relay%3A%2F%2Fdev%201"));
}

#[test]
fn start_body_omits_empty_cwd() {
    assert_eq!(start_body("npm run dev -- --port 3000", None), json!({"cmd": "npm run dev -- --port 3000"}));
    assert_eq!(start_body("ls", Some("")), json!({"cmd": "ls"}));
    assert_eq!(start_body("ls", Some("/srv")), json!({"cmd": "ls", "cwd": "/srv"}));
}

#[test]
fn logs_result_carries_offset_running_and_exit_code() {
    let v = json!({"ok":true,"id":"j1","running":false,"exit_code":3,"offset":120,"size":120,"eof":true,"data":"done\n"});
    let blocks = fmt_logs(&v);
    let meta: serde_json::Value = serde_json::from_str(&blocks[0].as_text().unwrap().text).unwrap();
    assert_eq!(meta, json!({"offset":120,"running":false,"exit_code":3,"eof":true,"size":120}));
    assert_eq!(blocks[1].as_text().unwrap().text, "done\n");
}

#[test]
fn refusal_is_reported_like_run_command() {
    let r = refused(&json!({"ok":false,"error":"unknown job"})).expect("refusal");
    assert_eq!(r.content[0].as_text().unwrap().text, "[error] unknown job");
    assert!(refused(&json!({"ok":true})).is_none());
}

#[test]
fn list_formats_running_and_exited() {
    let v = json!({"ok":true,"jobs":[
        {"id":"j1","cmd":"sleep 9","pid":10,"started":1790000000,"running":true,"exit_code":null},
        {"id":"j2","cmd":"make","pid":11,"started":1790000001,"running":false,"exit_code":2}
    ]});
    assert_eq!(
        fmt_list(&v),
        "j1 [running] pid 10 started 1790000000 — sleep 9\nj2 [exit 2] pid 11 started 1790000001 — make"
    );
    assert_eq!(fmt_list(&json!({"ok":true,"jobs":[]})), "no jobs");
}

#[test]
fn redacts_token_in_errors() {
    assert_eq!(
        redact_token("error sending request for url (https://hub/m/agents?mtok=s3cr%2Ft&owner=me)"),
        "error sending request for url (https://hub/m/agents?mtok=***&owner=me)"
    );
}

#[test]
fn shared_error_helper_redacts_token() {
    let e = crate::err("error sending request for url (https://hub/m/exec?mtok=s3cret&owner=me)");
    assert!(!e.message.contains("s3cret"), "{}", e.message);
}
