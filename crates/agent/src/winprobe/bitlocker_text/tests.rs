use super::{explorer_line, render_explorer, wmi_reason};

// The hub's encryption grader, copied from posture_pass() in
// RemoteScreen/crates/hub/src/main.rs (the "encryption" arm).
fn hub_passes(out: &str) -> bool {
    let n: String = out.to_lowercase().split_whitespace().collect::<Vec<_>>().join(" ");
    n.contains("filevault is on") || n.contains("protection on") || n.contains("percentage encrypted: 100") || n.contains("crypt")
}

const ACCESS_DENIED: i32 = 0x8004_1003_u32 as i32;

#[test]
fn access_denied_says_so() {
    assert_eq!(wmi_reason(Some(ACCESS_DENIED), ""), "access denied, 0x80041003: needs an elevated agent");
    assert_eq!(wmi_reason(Some(0x8007_0005_u32 as i32), ""), "access denied, 0x80070005: needs an elevated agent");
}

#[test]
fn other_hresult_is_shown_in_hex() {
    assert_eq!(wmi_reason(Some(0x8004_100E_u32 as i32), "ignored"), "error 0x8004100E");
}

#[test]
fn foreign_error_text_cannot_pass_the_grader() {
    let r = wmi_reason(None, "missing field `EncryptionMethod`, CRYPT and crypt");
    assert_eq!(r, "missing field `En[c]ryptionMethod`, [C]RYPT and [c]rypt");
    assert!(!hub_passes(&r));
}

#[test]
fn explorer_values_map_to_their_state() {
    assert!(explorer_line(Ok(Some(1))).starts_with("Protection On (from Explorer"));
    assert!(explorer_line(Ok(Some(2))).starts_with("Protection Off"));
    assert!(explorer_line(Ok(Some(3))).starts_with("Protection Unknown (turning on"));
    assert!(explorer_line(Ok(Some(4))).starts_with("Protection Off (turning off"));
    assert!(explorer_line(Ok(Some(5))).starts_with("Protection Off (suspended"));
    assert!(explorer_line(Ok(Some(6))).starts_with("Protection On (locked"));
    assert!(explorer_line(Ok(Some(7))).starts_with("Protection Off (BitLocker cannot"));
    assert!(explorer_line(Ok(Some(8))).starts_with("Protection Off (waiting for activation"));
    assert_eq!(explorer_line(Ok(Some(0))), "Protection Unknown (Explorer value 0)");
    assert_eq!(explorer_line(Ok(Some(9))), "Protection Unknown (Explorer value 9)");
    assert_eq!(explorer_line(Err(ACCESS_DENIED)), "Protection Unknown (Explorer read failed: 0x80041003)");
}

#[test]
fn only_on_and_locked_pass_the_grader() {
    for v in -1..=12 {
        let line = explorer_line(Ok(Some(v)));
        assert_eq!(hub_passes(&line), v == 1 || v == 6, "value {v}: {line}");
        let report = render_explorer(&wmi_reason(Some(ACCESS_DENIED), ""), &[('C', Ok(Some(v)))]);
        assert_eq!(hub_passes(&report), v == 1 || v == 6, "value {v}: {report}");
    }
    assert!(!hub_passes(&explorer_line(Ok(None))));
    assert!(!hub_passes(&explorer_line(Err(ACCESS_DENIED))));
}

#[test]
fn one_protected_volume_passes_a_mixed_machine() {
    let r = render_explorer("x", &[('C', Ok(Some(1))), ('D', Ok(Some(2)))]);
    assert!(hub_passes(&r));
}

#[test]
fn no_volumes_is_unavailable_and_fails() {
    let r = render_explorer(&wmi_reason(Some(ACCESS_DENIED), ""), &[]);
    assert_eq!(r, "BitLocker status: unavailable (WMI: access denied, 0x80041003: needs an elevated agent; Explorer lists no fixed volumes)");
    assert!(!hub_passes(&r));
}

#[test]
fn report_layout() {
    let r = render_explorer(&wmi_reason(Some(ACCESS_DENIED), ""), &[('C', Ok(Some(1))), ('D', Ok(None))]);
    assert_eq!(
        r,
        "BitLocker volume status (WMI: access denied, 0x80041003: needs an elevated agent; read from Explorer instead):\n  \
         C:  Protection On (from Explorer; run the agent elevated for method and progress)\n  \
         D:  Protection Unknown (Explorer has no BitLocker value for this volume)"
    );
}
