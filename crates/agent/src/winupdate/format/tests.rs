use super::*;

fn up(title: &str, size: Option<u128>, msrc: &str, categories: &[&str]) -> Update {
    Update { title: title.into(), size, msrc: msrc.into(), categories: categories.iter().map(|c| c.to_string()).collect() }
}

const PRODUCT: &str = "00000000-0000-0000-0000-00000000a11e";
const DEFINITION: &str = "e0789628-ce08-4437-be74-2495b842f43b";
const UPDATES: &str = "cd5ffd1e-e932-4e3a-bf74-18bf0b1bbd83";
const ROLLUPS: &str = "28bc880e-0592-4cbf-8f95-c79b17911d5f";

fn cumulative(msrc: &str, categories: &[&str]) -> Update {
    up("2026-11 Cumulative Update for Windows 11 Version 24H2 for x64-based Systems (KB5070000)", Some(882_900_000), msrc, categories)
}
fn defender() -> Update {
    up("Security Intelligence Update for Microsoft Defender Antivirus - KB2267602 (Version 1.441.100.0)", Some(103_000_000), "", &[DEFINITION])
}
fn msrt() -> Update {
    up("Windows Malicious Software Removal Tool x64 - v5.137 (KB890830)", Some(73_500_000), "", &[PRODUCT, ROLLUPS])
}

#[test]
fn msrc_severity_alone_makes_a_security_update() {
    assert!(is_security(&cumulative("Important", &[])));
    assert_eq!(row(&cumulative("Important", &[])), "  - 2026-11 Cumulative Update for Windows 11 Version 24H2 for x64-based Systems (KB5070000) (842.0 MB) [security: Important]");
}

#[test]
fn the_security_updates_classification_alone_makes_a_security_update() {
    let u = cumulative("", &[PRODUCT, "0fa1201d-4330-4fa8-8ae9-b877473b6441"]);
    assert!(is_security(&u));
    assert!(row(&u).ends_with(" [security: unrated] [class: Security Updates]"), "{}", row(&u));
}

#[test]
fn critical_updates_definitions_and_rollups_are_not_security() {
    for u in [cumulative("", &[CRITICAL_UPDATES]), defender(), msrt(), cumulative("  ", &[UPDATES])] {
        assert!(!is_security(&u), "{}", row(&u));
        assert!(!row(&u).contains("[security: "), "{}", row(&u));
    }
    assert!(row(&cumulative("", &[CRITICAL_UPDATES])).ends_with(" [class: Critical Updates]"));
}

#[test]
fn a_product_category_is_not_a_classification() {
    assert_eq!(classification(&[PRODUCT.to_string()]), None);
    assert_eq!(classification(&[PRODUCT.to_string(), ROLLUPS.to_string()]), Some("Update Rollups"));
}

#[test]
fn the_summary_counts_every_update_and_the_security_ones_it_could_read() {
    let r = report(3, &[Some(cumulative("Critical", &[])), None, Some(defender())]);
    let lines: Vec<&str> = r.lines().collect();
    assert_eq!(lines.first(), Some(&"3 OS update(s) available (via Windows Update Agent):"));
    assert_eq!(lines.len(), 4, "{r}");
    assert_eq!(lines.last(), Some(&"Summary: 3 update(s), 1 security update(s)."));
    assert_eq!(report(0, &[]), "No OS updates available.");
}

#[test]
fn sizes_and_ages_read_as_people_say_them() {
    assert_eq!(human_size(512), "512 B");
    assert_eq!(human_size(73_500_000), "70.1 MB");
    assert_eq!(row(&up("X", None, "", &[])), "  - X (size unknown)");
    assert_eq!(checked("r", 59), "r\nChecked just now.");
    assert_eq!(checked("r", 12 * 60 + 5), "r\nChecked 12 min ago.");
    assert_eq!(checked("r", 3 * 3600), "r\nChecked 3 h ago.");
    assert_eq!(checking(5), "Windows Update check in progress (started under a minute ago); ask again in a minute.");
    assert_eq!(checking(150), "Windows Update check in progress (started 2 min ago); ask again in a minute.");
}

#[test]
fn errors_name_the_step_and_call_out_elevation() {
    assert_eq!(error(&failure("search", 0x8007_0005u32 as i32)), "OS updates: search: access denied — needs Administrator (run the agent elevated)");
    assert_eq!(error(&failure("search", 0x8024_402Cu32 as i32)), "OS updates: search: unavailable (HRESULT 0x8024402C)");
}

/// An update as WUA hands it back, with any of its reads made to fail.
struct Wua {
    msrc: Option<&'static str>,
    categories: Option<Vec<Option<&'static str>>>,
}

impl Fields for Wua {
    fn title(&self) -> Option<String> {
        Some(cumulative("", &[]).title)
    }
    fn size(&self) -> Option<u128> {
        cumulative("", &[]).size
    }
    fn msrc(&self) -> Option<String> {
        self.msrc.map(String::from)
    }
    fn categories(&self) -> Option<Vec<Option<String>>> {
        self.categories.as_ref().map(|c| c.iter().map(|id| id.map(String::from)).collect())
    }
}

fn wua(msrc: Option<&'static str>, categories: Option<&[Option<&'static str>]>) -> Wua {
    Wua { msrc, categories: categories.map(<[_]>::to_vec) }
}

#[test]
fn an_update_read_in_full_is_a_row() {
    let u = read(&wua(Some(""), Some(&[Some(PRODUCT), Some(UPDATES)]))).expect("every read succeeded");
    assert_eq!(row(&u), row(&cumulative("", &[PRODUCT, UPDATES])));
    let u = read(&wua(Some("Important"), Some(&[]))).expect("every read succeeded");
    assert!(row(&u).ends_with(" [security: Important]"), "{}", row(&u));
}

#[test]
fn an_update_whose_severity_or_a_category_could_not_be_read_is_unreadable() {
    for (what, w) in [
        ("severity", wua(None, Some(&[Some(PRODUCT), Some(UPDATES)]))),
        ("category collection", wua(Some(""), None)),
        ("one category", wua(Some(""), Some(&[Some(UPDATES), None]))),
    ] {
        assert!(read(&w).is_none(), "an update whose {what} read failed was printed as a readable row, so it would count as not a security update");
    }
}

/// Every case the hub grades, as `=== <name>` then the exact output.
fn fixtures() -> String {
    let cases: Vec<(&str, String)> = vec![
        ("none", checked(&report(0, &[]), 12 * 60)),
        ("none-just-now", checked(&report(0, &[]), 0)),
        ("optional", checked(&report(3, &[Some(cumulative("", &[PRODUCT, UPDATES])), Some(msrt()), Some(defender())]), 2 * 3600)),
        ("critical-only", checked(&report(1, &[Some(cumulative("", &[PRODUCT, CRITICAL_UPDATES]))]), 30 * 60)),
        ("security-msrc", checked(&report(2, &[Some(cumulative("Critical", &[PRODUCT, SECURITY_UPDATES])), Some(defender())]), 5 * 60)),
        ("security-class", checked(&report(1, &[Some(cumulative("", &[SECURITY_UPDATES]))]), 0)),
        ("unreadable", checked(&report(3, &[Some(msrt()), None, None]), 0)),
        ("read-failed", checked(&report(2, &[Some(msrt()), read(&wua(None, Some(&[Some(PRODUCT), None])))]), 0)),
        ("denied", error(&failure("search", 0x8007_0005u32 as i32))),
        ("hresult", error(&failure("search", 0x8024_402Cu32 as i32))),
        ("checking", checking(12)),
    ];
    let mut out = String::from(
        "# it-ai:os-updates/check outputs, generated by haive-agent crates/agent/src/winupdate/format/tests.rs.\n\
         # Do not edit. Regenerate: IT_AI_WUA_FIXTURES=<file> cargo test -p it-ai-agent fixture\n\
         # then copy the file to RemoteScreen crates/hub/src/posture/winupdate_fixtures.txt.\n",
    );
    for (name, text) in cases {
        out.push_str(&format!("=== {name}\n{text}\n"));
    }
    out
}

#[test]
fn the_fixture_file_is_this_formatters_output() {
    let now = fixtures();
    if let Ok(path) = std::env::var("IT_AI_WUA_FIXTURES") {
        std::fs::write(&path, &now).unwrap();
    }
    assert_eq!(include_str!("fixtures.txt"), now, "the check's output changed: regenerate the fixture and re-grade it in the hub");
}
