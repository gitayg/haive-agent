use std::collections::VecDeque;

use clap::Parser;
use serde_json::json;

use super::*;
use crate::{Cli, Cmd};

fn parse(args: &[&str]) -> Result<JobCmd, clap::Error> {
    let mut argv = vec!["itai", "job"];
    argv.extend_from_slice(args);
    match Cli::try_parse_from(argv)?.cmd {
        Cmd::Job { cmd } => Ok(cmd),
        _ => panic!("not a job command"),
    }
}

#[test]
fn start_keeps_everything_after_double_dash() {
    let cmd = parse(&["start", "pc1", "--cwd", "/srv/app", "--", "npm", "run", "dev", "--port", "3000", "-v", "--cwd", "x"]).unwrap();
    match cmd {
        JobCmd::Start { device, cwd, command } => {
            assert_eq!(device, "pc1");
            assert_eq!(cwd.as_deref(), Some("/srv/app"));
            assert_eq!(command, ["npm", "run", "dev", "--port", "3000", "-v", "--cwd", "x"]);
        }
        other => panic!("parsed as {other:?}"),
    }
}

#[test]
fn start_without_cwd_and_single_quoted_command() {
    match parse(&["start", "pc1", "--", "camrelay --preview"]).unwrap() {
        JobCmd::Start { cwd, command, .. } => {
            assert_eq!(cwd, None);
            assert_eq!(command, ["camrelay --preview"]);
            assert_eq!(start_body(&command, None), json!({"cmd": "camrelay --preview"}));
        }
        other => panic!("parsed as {other:?}"),
    }
}

#[test]
fn start_requires_a_command() {
    assert!(parse(&["start", "pc1"]).is_err());
    assert!(parse(&["start", "pc1", "--"]).is_err());
    // The command must come after `--`, so its own flags are never read as itai's.
    assert!(parse(&["start", "pc1", "ls"]).is_err());
}

#[test]
fn start_body_joins_args_and_carries_cwd() {
    let cmd: Vec<String> = ["make", "-j8"].iter().map(|s| s.to_string()).collect();
    assert_eq!(start_body(&cmd, Some("C:\\src")), json!({"cmd": "make -j8", "cwd": "C:\\src"}));
}

#[test]
fn logs_stop_list_parse() {
    match parse(&["logs", "pc1", "j1a2b", "--offset", "42", "--follow"]).unwrap() {
        JobCmd::Logs { device, id, offset, follow } => {
            assert_eq!((device.as_str(), id.as_str(), offset, follow), ("pc1", "j1a2b", 42, true));
        }
        other => panic!("parsed as {other:?}"),
    }
    match parse(&["logs", "pc1", "j1"]).unwrap() {
        JobCmd::Logs { offset, follow, .. } => assert_eq!((offset, follow), (0, false)),
        other => panic!("parsed as {other:?}"),
    }
    assert!(matches!(parse(&["stop", "pc1", "j1"]).unwrap(), JobCmd::Stop { .. }));
    assert_eq!(parse(&["list", "pc1"]).unwrap().device(), "pc1");
}

fn ctl() -> Controller {
    Controller::new("https://hub.example/".into(), "TOK".into(), "me@x.io".into(), reqwest::Client::new())
}

const AUTH: &str = "mtok=TOK&owner=me%40x.io";

#[test]
fn route_urls() {
    let c = ctl();
    let t = "relay://dev 1";
    assert_eq!(start_url(&c, t), format!("https://hub.example/m/job/start?{AUTH}&target=relay%3A%2F%2Fdev%201"));
    assert_eq!(
        logs_url(&c, t, "j17a3f", 65536),
        format!("https://hub.example/m/job/logs?{AUTH}&target=relay%3A%2F%2Fdev%201&id=j17a3f&offset=65536")
    );
    assert_eq!(
        stop_url(&c, t, "j&x"),
        format!("https://hub.example/m/job/stop?{AUTH}&target=relay%3A%2F%2Fdev%201&id=j%26x")
    );
    assert_eq!(list_url(&c, t), format!("https://hub.example/m/job/list?{AUTH}&target=relay%3A%2F%2Fdev%201"));
}

/// Drive `follow` over a scripted response sequence. Fetching past the end of
/// the script panics, so a loop that ignores `eof` fails loudly.
async fn run_follow(start: u64, script: Vec<Result<serde_json::Value, String>>) -> (Result<Option<i64>, String>, Vec<u64>, usize, String) {
    let mut script: VecDeque<_> = script.into();
    let mut asked = Vec::new();
    let mut pauses = 0;
    let mut out = Vec::new();
    let res = follow(
        start,
        |off| {
            asked.push(off);
            std::future::ready(script.pop_front().expect("fetched after eof"))
        },
        || {
            pauses += 1;
            std::future::ready(())
        },
        &mut out,
    )
    .await;
    (res, asked, pauses, String::from_utf8(out).unwrap())
}

#[tokio::test]
async fn follow_polls_from_returned_offset_and_stops_at_eof() {
    let (res, asked, pauses, out) = run_follow(
        10,
        vec![
            Ok(json!({"ok":true,"data":"a","offset":11,"size":11,"running":true,"exit_code":null,"eof":false})),
            Ok(json!({"ok":true,"data":"","offset":11,"size":11,"running":true,"exit_code":null,"eof":false})),
            Ok(json!({"ok":true,"data":"bc","offset":13,"size":13,"running":false,"exit_code":7,"eof":true})),
        ],
    )
    .await;
    assert_eq!(res, Ok(Some(7)));
    assert_eq!(asked, [10, 11, 11]);
    assert_eq!(pauses, 2);
    assert_eq!(out, "abc");
}

#[tokio::test]
async fn follow_catches_up_without_waiting() {
    let (res, asked, pauses, _) = run_follow(
        0,
        vec![
            Ok(json!({"ok":true,"data":"x","offset":1,"size":5,"running":false,"exit_code":0,"eof":false})),
            Ok(json!({"ok":true,"data":"yyyy","offset":5,"size":5,"running":false,"exit_code":0,"eof":true})),
        ],
    )
    .await;
    assert_eq!(res, Ok(Some(0)));
    assert_eq!(asked, [0, 1]);
    assert_eq!(pauses, 0);
}

#[tokio::test]
async fn follow_stops_on_error_and_on_missing_offset() {
    let (res, asked, _, _) = run_follow(0, vec![Err("unknown job".into())]).await;
    assert_eq!(res, Err("unknown job".to_string()));
    assert_eq!(asked, [0]);
    let (res, asked, _, _) = run_follow(0, vec![Ok(json!({"ok":true,"data":"","eof":false}))]).await;
    assert!(res.unwrap_err().contains("no offset"));
    assert_eq!(asked, [0]);
}

#[test]
fn redacts_token_in_errors() {
    let msg = "error sending request for url (https://hub/m/agents?mtok=s3cr%2Ft&owner=me)";
    assert_eq!(redact_token(msg), "error sending request for url (https://hub/m/agents?mtok=***&owner=me)");
    assert_eq!(redact_token("x?mtok=abc)"), "x?mtok=***)");
    assert_eq!(redact_token("no token here"), "no token here");
}
