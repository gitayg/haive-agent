use super::noninteractive as n;

const ALL3: &str = "--accept-package-agreements --accept-source-agreements --disable-interactivity";
const SRC2: &str = "--accept-source-agreements --disable-interactivity";

#[test]
fn the_hub_updates_report_stays_a_listing() {
    assert_eq!(n("winget upgrade"), format!("winget upgrade {SRC2}"));
}

#[test]
fn a_listing_upgrade_never_gets_package_agreements() {
    assert_eq!(n("winget update"), format!("winget update {SRC2}"));
    for rest in ["--include-unknown", "-u", "--pinned", "-s winget", "--source msstore", "--accept-source-agreements"] {
        let want = if rest == "--accept-source-agreements" {
            format!("winget upgrade --disable-interactivity {rest}")
        } else {
            format!("winget upgrade {SRC2} {rest}")
        };
        assert_eq!(n(&format!("winget upgrade {rest}")), want, "{rest}");
    }
}

#[test]
fn an_upgrade_that_already_upgrades_gets_package_agreements() {
    for arg in ["--all", "-r", "--recurse", "--id X", "--name X", "--moniker X", "-q X", "--query X", "-m x.yaml", "--manifest x.yaml", "-h", "--silent", "--ALL"] {
        assert_eq!(n(&format!("winget upgrade {arg}")), format!("winget upgrade {ALL3} {arg}"), "{arg}");
    }
}

#[test]
fn the_hub_packages_report_gets_the_source_flags_only() {
    assert_eq!(n("winget list"), format!("winget list {SRC2}"));
}

#[test]
fn the_hub_uninstall_gets_the_source_flags_only() {
    assert_eq!(n("winget uninstall --silent Foo.Bar"), format!("winget uninstall {SRC2} --silent Foo.Bar"));
}

#[test]
fn install_aliases_get_package_agreements() {
    for sub in ["install", "add", "import", "repair", "fix"] {
        assert_eq!(n(&format!("winget {sub} X")), format!("winget {sub} {ALL3} X"), "{sub}");
    }
    for sub in ["upgrade", "update"] {
        assert_eq!(n(&format!("winget {sub} --all")), format!("winget {sub} {ALL3} --all"), "{sub}");
    }
}

#[test]
fn an_upgrade_with_only_a_positional_query_gets_the_source_flags_only() {
    assert_eq!(n("winget upgrade Git.Git"), format!("winget upgrade {SRC2} Git.Git"));
}

#[test]
fn read_only_and_uninstall_aliases_never_get_package_agreements() {
    for sub in ["list", "ls", "uninstall", "remove", "rm", "search", "find", "show", "view", "export", "download"] {
        assert_eq!(n(&format!("winget {sub} X")), format!("winget {sub} {SRC2} X"), "{sub}");
    }
}

#[test]
fn commands_without_these_flags_are_untouched() {
    for line in [
        "winget",
        "winget --version",
        "winget --info",
        "winget -?",
        "winget source list",
        "winget settings",
        "winget pin list",
        "winget hash f.exe",
        "winget configure x.yaml",
        "winget validate m.yaml",
        "winget features",
    ] {
        assert_eq!(n(line), line);
    }
}

#[test]
fn the_hub_install_and_update_all_lines_only_gain_disable_interactivity() {
    assert_eq!(
        n("winget install --silent --accept-package-agreements --accept-source-agreements Foo.Bar"),
        "winget install --disable-interactivity --silent --accept-package-agreements --accept-source-agreements Foo.Bar"
    );
    assert_eq!(
        n("winget upgrade --all --silent --accept-package-agreements --accept-source-agreements"),
        "winget upgrade --disable-interactivity --all --silent --accept-package-agreements --accept-source-agreements"
    );
}

#[test]
fn a_line_already_carrying_every_flag_is_unchanged() {
    let line = format!("winget upgrade --all {ALL3}");
    assert_eq!(n(&line), line);
    let line = format!("winget list {SRC2}");
    assert_eq!(n(&line), line);
}

#[test]
fn flags_already_present_in_another_case_are_not_added_twice() {
    let line = "winget list --Accept-Source-Agreements --DISABLE-INTERACTIVITY";
    assert_eq!(n(line), line);
}

#[test]
fn program_and_subcommand_match_in_any_case() {
    assert_eq!(n("WinGet Upgrade --All"), format!("WinGet Upgrade {ALL3} --All"));
    assert_eq!(n("WinGet Upgrade"), format!("WinGet Upgrade {SRC2}"));
    assert_eq!(n("WinGet Install X"), format!("WinGet Install {ALL3} X"));
    assert_eq!(n("WINGET.EXE LIST"), format!("WINGET.EXE LIST {SRC2}"));
}

#[test]
fn winget_exe_and_winget_by_path_are_rewritten() {
    assert_eq!(n("winget.exe upgrade --all"), format!("winget.exe upgrade {ALL3} --all"));
    let p = r"C:\Users\it\AppData\Local\Microsoft\WindowsApps\winget.exe";
    assert_eq!(n(&format!("{p} list")), format!("{p} list {SRC2}"));
    let q = r#""C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\winget.exe""#;
    assert_eq!(n(&format!("{q} upgrade --all")), format!("{q} upgrade {ALL3} --all"));
    assert_eq!(n("@winget list"), format!("@winget list {SRC2}"));
}

#[test]
fn quoted_arguments_are_kept_byte_for_byte() {
    assert_eq!(
        n(r#"winget install --id "Foo Bar" --override "/S /D=C:\x y""#),
        format!(r#"winget install {ALL3} --id "Foo Bar" --override "/S /D=C:\x y""#)
    );
}

#[test]
fn a_flag_name_inside_a_quoted_value_does_not_count_as_present() {
    assert_eq!(
        n(r#"winget install X --override "/S --disable-interactivity""#),
        format!(r#"winget install {ALL3} X --override "/S --disable-interactivity""#)
    );
}

#[test]
fn programs_that_merely_mention_winget_are_untouched() {
    for line in [
        "echo winget upgrade",
        "wingetx upgrade",
        "notwinget list",
        r"C:\tools\winget-helper.exe upgrade",
        "powershell -Command \"winget upgrade\"",
        "cmd /c winget upgrade",
        "systeminfo",
        "",
        "   ",
    ] {
        assert_eq!(n(line), line);
    }
}

#[test]
fn every_winget_command_in_a_multi_command_line_is_rewritten_and_nothing_else() {
    assert_eq!(n("echo a & winget upgrade"), format!("echo a & winget upgrade {SRC2}"));
    assert_eq!(
        n("winget list && winget upgrade --all || echo failed"),
        format!("winget list {SRC2} && winget upgrade {ALL3} --all || echo failed")
    );
    assert_eq!(n("winget list | findstr Git"), format!("winget list {SRC2} | findstr Git"));
    assert_eq!(n("(winget list)"), format!("(winget list {SRC2})"));
}

#[test]
fn operators_inside_quotes_or_escaped_do_not_start_a_command() {
    let line = r#"echo "x & winget upgrade""#;
    assert_eq!(n(line), line);
    let line = "echo x ^& winget upgrade";
    assert_eq!(n(line), line);
}

#[test]
fn redirections_stay_after_the_inserted_flags() {
    assert_eq!(n("winget list>out.txt"), format!("winget list {SRC2}>out.txt"));
    assert_eq!(n("winget upgrade 2>&1"), format!("winget upgrade {SRC2} 2>&1"));
}
