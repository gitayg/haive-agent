use clap::Parser;
use it_ai_direct::reply::Pending;
use serde_json::json;

use super::*;
use crate::{Cli, Cmd};

fn pending() -> Pending {
    Pending { id: "apr_1".into(), action: "exec".into(), device: "pc1".into(), reason: "needs approval".into(), expires: 0 }
}

#[test]
fn each_settled_state_maps_to_its_exit() {
    let mut err = Vec::new();
    assert_eq!(step(Settled::Done(json!({"ok": true})), &mut err), Step::Run(json!({"ok": true})));
    match step(Settled::Pending(pending()), &mut err) {
        Step::Stop { text, code } => {
            assert_eq!(code, EXIT_PENDING);
            assert!(text.starts_with("Waiting for approval in the IT-AI dashboard (approval id apr_1)"), "{text}");
            assert!(text.ends_with("Check later with: itai approval apr_1"), "{text}");
        }
        other => panic!("{other:?}"),
    }
    let denied = step(Settled::Denied { id: "apr_1".into(), approver: "boss".into() }, &mut err);
    assert!(matches!(&denied, Step::Stop { code: 1, text } if text.starts_with("Denied by boss")), "{denied:?}");
    let expired = step(Settled::Expired { id: "apr_1".into() }, &mut err);
    assert!(matches!(&expired, Step::Stop { code: 1, text } if text.starts_with("Approval apr_1 expired")), "{expired:?}");
    let blocked = step(Settled::Refused { error: "nope".into(), blocked: true }, &mut err);
    assert!(matches!(&blocked, Step::Stop { code: 1, text } if text.starts_with("Blocked by the hub's policy: nope")), "{blocked:?}");
    let dry = step(Settled::DryRun(json!({"dry_run": true, "action": "exec", "tier": "change", "would": "run now and notify the owner"})), &mut err);
    assert!(matches!(&dry, Step::Stop { code: 0, text } if text.starts_with("Dry run, nothing ran: 'exec' is tier change")), "{dry:?}");
    assert!(err.is_empty());
    let ran = step(Settled::Approved { id: "apr_1".into(), approver: "boss".into(), status: 200, result: json!("ok") }, &mut err);
    assert_eq!(ran, Step::Run(json!("ok")));
    assert_eq!(String::from_utf8(err).unwrap(), "Approved by boss in the IT-AI dashboard (approval id apr_1); it ran:\n");
}

#[test]
fn wait_and_dry_run_are_global_flags() {
    let c = Cli::try_parse_from(["itai", "--dry-run", "--wait", "5", "exec", "pc1", "ls"]).unwrap();
    assert!(c.dry_run);
    assert_eq!(c.wait, Some(5));
    let c = Cli::try_parse_from(["itai", "job", "start", "pc1", "--dry-run", "--wait", "0", "--", "make"]).unwrap();
    assert!(c.dry_run);
    assert_eq!(c.wait, Some(0));
    let c = Cli::try_parse_from(["itai", "approval", "apr_7"]).unwrap();
    assert!(matches!(c.cmd, Cmd::Approval { ref id } if id == "apr_7"));
    assert_eq!((c.wait, c.dry_run), (None, false));
}
