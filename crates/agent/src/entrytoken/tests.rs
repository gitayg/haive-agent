// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

use super::*;

const EXE: &str = "/usr/local/bin/it-ai";

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

/// The argv an agent older than 3.7.0 persisted: the token rides along.
fn old_args() -> Vec<String> {
    s(&["--relay", "https://hub.example", "--relay-token", "htok_old", "--name", "box", "--owner", "o1"])
}

fn new_args() -> Vec<String> {
    s(&["--relay", "https://hub.example", "--name", "box", "--owner", "o1"])
}

/// `linux_install` (unchanged since before 3.7.0).
fn desktop(args: &[String]) -> String {
    format!("[Desktop Entry]\nType=Application\nName=IT-AI\nExec={EXE} {}\nX-GNOME-Autostart-enabled=true\n", args.join(" "))
}

/// `service_unit` before 3.7.0: no HOME.
fn old_unit(args: &[String]) -> String {
    format!(
        "[Unit]\nDescription=IT-AI agent\nAfter=network.target\n\n[Service]\nExecStart={EXE} {}\nRestart=always\nRestartSec=5\n\n[Install]\nWantedBy=multi-user.target\n",
        args.join(" ")
    )
}

/// Both plists before 3.7.0: no HOME, no log keys.
fn old_plist(args: &[String]) -> String {
    let mut pa = format!("      <string>{EXE}</string>\n");
    for a in args {
        pa.push_str(&format!("      <string>{a}</string>\n"));
    }
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n  <key>Label</key><string>com.itai.agent</string>\n  <key>ProgramArguments</key><array>\n{pa}  </array>\n  <key>RunAtLoad</key><true/>\n  <key>KeepAlive</key><true/>\n</dict></plist>\n"
    )
}

#[test]
fn token_detection_takes_both_forms_and_nothing_else() {
    for (line, has) in [
        ("it-ai --relay h --relay-token htok_a", true),
        ("it-ai --relay h --relay-token=htok_a", true),
        ("it-ai --relay h \"--relay-token\" \"htok_a\"", true),
        ("it-ai --relay h --relay-token", true),
        ("it-ai --relay h", false),
        ("it-ai --relay h --relay-tokens x", false),
        ("it-ai --relay h --name --relay-token-box", false),
        ("it-ai --name \"--relay-token htok_a\"", false),
    ] {
        assert_eq!(strip_cmdline(line, false).is_some(), has, "{line}");
    }
}

#[test]
fn desktop_exec_loses_only_the_token() {
    let old = desktop(&old_args());
    assert_eq!(desktop_strip(&old).as_deref(), Some(desktop(&new_args()).as_str()));
    assert_eq!(desktop_strip(&desktop(&new_args())), None, "no token, nothing to do");
    // The = form, and quoting around other args kept byte for byte.
    let q = "[Desktop Entry]\nExec=\"/opt/IT AI/it-ai\" --relay-token=htok_x --name \"my box\"\r\nName=IT-AI\n";
    assert_eq!(desktop_strip(q).as_deref(), Some("[Desktop Entry]\nExec=\"/opt/IT AI/it-ai\" --name \"my box\"\r\nName=IT-AI\n"));
}

#[test]
fn unit_execstart_loses_only_the_token() {
    assert_eq!(unit_strip(&old_unit(&old_args())).as_deref(), Some(old_unit(&new_args()).as_str()));
    let q = "[Service]\nExecStart=-/opt/it-ai --name 'my box' --relay-token 'htok_x' --owner \"o 1\"\n";
    assert_eq!(unit_strip(q).as_deref(), Some("[Service]\nExecStart=-/opt/it-ai --name 'my box' --owner \"o 1\"\n"));
    assert_eq!(unit_strip("[Service]\nExecStart=/opt/it-ai --relay h\n"), None);
}

#[test]
fn unit_home_resolution() {
    // No HOME, no User=: systemd sets none, so `~/.it-ai` is relative to cwd `/`.
    assert_eq!(unit_home(&old_unit(&old_args())), Ok(EntryHome::Default("/".into())));
    let pinned = crate::persistence::service_unit(Path::new(EXE), &new_args(), Path::new("/root"));
    assert_eq!(unit_home(&pinned), Ok(EntryHome::Pinned("/root".into())));
    let spaced = crate::persistence::service_unit(Path::new(EXE), &new_args(), Path::new("/srv/it ai"));
    assert_eq!(unit_home(&spaced), Ok(EntryHome::Pinned("/srv/it ai".into())));
    assert_eq!(unit_home("[Service]\nWorkingDirectory=/var/lib/x\n"), Ok(EntryHome::Default("/var/lib/x".into())));
    for refused in ["[Service]\nUser=itai\n", "[Service]\nEnvironmentFile=/etc/x\n", "[Service]\nWorkingDirectory=~\n", "[Service]\nEnvironment=HOME=rel\n"] {
        assert!(unit_home(refused).is_err(), "{refused}");
    }
}

#[test]
fn pinning_an_old_unit_gives_exactly_what_service_unit_writes() {
    let stripped = unit_strip(&old_unit(&old_args())).unwrap();
    for home in ["/root", "/srv/it ai"] {
        let pinned = unit_pin_home(&stripped, Path::new(home)).unwrap();
        assert_eq!(pinned, crate::persistence::service_unit(Path::new(EXE), &new_args(), Path::new(home)));
    }
    assert_eq!(unit_pin_home(&stripped, Path::new("/x%h")), None, "a systemd specifier would not read back");
    assert_eq!(unit_pin_home(&stripped, Path::new("rel")), None);
    assert_eq!(unit_pin_home("[Unit]\n", Path::new("/root")), None, "no [Service]");
}

#[test]
fn plist_program_arguments_lose_only_the_token() {
    assert_eq!(plist_strip(&old_plist(&old_args())).as_deref(), Some(old_plist(&new_args()).as_str()));
    // The 3.7.x writers' layout, had a token got in: still exact.
    let mut with = old_args();
    with.push("--relay-token=htok_b".into());
    let home = Path::new("/Users/someone");
    let exe = Path::new(EXE);
    assert_eq!(
        plist_strip(&crate::persistence::agent_plist(exe, &with, home)).as_deref(),
        Some(crate::persistence::agent_plist(exe, &new_args(), home).as_str())
    );
    assert_eq!(plist_strip(&old_plist(&new_args())), None);
    // A token-looking value elsewhere in the plist is not an argument.
    let other = old_plist(&new_args()).replace("<key>RunAtLoad</key>", "<key>X</key><string>--relay-token</string><key>RunAtLoad</key>");
    assert_eq!(plist_strip(&other), None);
}

#[test]
fn plist_label_must_be_ours() {
    assert!(plist_is_ours(&old_plist(&old_args())));
    assert!(!plist_is_ours(&old_plist(&old_args()).replace("com.itai.agent", "com.example.other")));
}

#[test]
fn plist_home_reads_and_pins() {
    let old = plist_strip(&old_plist(&old_args())).unwrap();
    assert_eq!(plist_home(&old), Ok(None));
    let pinned = plist_pin_home(&old, Path::new("/var/root")).unwrap();
    assert_eq!(plist_home(&pinned), Ok(Some("/var/root".into())));
    let cur = crate::persistence::daemon_plist(Path::new(EXE), &new_args(), Path::new("/var/root"));
    assert_eq!(plist_home(&cur), Ok(Some("/var/root".into())));
    // An EnvironmentVariables dict without HOME gets HOME added inside it.
    let env = old.replace("  <key>RunAtLoad</key>", "  <key>EnvironmentVariables</key><dict>\n    <key>LANG</key><string>C</string>\n  </dict>\n  <key>RunAtLoad</key>");
    let p = plist_pin_home(&env, Path::new("/a&b")).unwrap();
    assert_eq!(plist_home(&p), Ok(Some("/a&b".into())));
    assert_eq!(p.matches("<key>EnvironmentVariables</key>").count(), 1);
    assert!(plist_home(&old.replace("</dict></plist>", "<key>EnvironmentVariables</key><dict><key>HOME</key><integer>1</integer></dict></dict></plist>")).is_err());
}

/// Rewritten plists must still be property lists.
#[cfg(target_os = "macos")]
#[test]
fn rewritten_plists_pass_plutil_lint() {
    let d = std::env::temp_dir().join(format!("it-ai-entrytoken-lint-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    let stripped = plist_strip(&old_plist(&old_args())).unwrap();
    let env = stripped.replace("  <key>RunAtLoad</key>", "  <key>EnvironmentVariables</key><dict>\n    <key>LANG</key><string>C</string>\n  </dict>\n  <key>RunAtLoad</key>");
    for (name, body) in [
        ("stripped.plist", stripped.clone()),
        ("pinned.plist", plist_pin_home(&stripped, Path::new("/var/root")).unwrap()),
        ("pinned-env.plist", plist_pin_home(&env, Path::new("/var/root")).unwrap()),
    ] {
        let f = d.join(name);
        std::fs::write(&f, body).unwrap();
        let out = std::process::Command::new("/usr/bin/plutil").arg("-lint").arg(&f).output().unwrap();
        assert!(out.status.success(), "{name}: {}", String::from_utf8_lossy(&out.stdout));
    }
    let _ = std::fs::remove_dir_all(&d);
}

/// `win_install_service` before 3.7.0: `"<exe>" <args...> --background`.
#[test]
fn schtasks_tr_loses_only_the_token() {
    let tr = r#""C:\Program Files\IT-AI\it-ai.exe" --relay https://hub.example --relay-token htok_old --name box --background"#;
    assert_eq!(
        strip_cmdline(tr, false).as_deref(),
        Some(r#""C:\Program Files\IT-AI\it-ai.exe" --relay https://hub.example --name box --background"#)
    );
}

/// `win_install` before 3.7.0: every arg quoted.
#[test]
fn run_value_loses_only_the_token() {
    let v = r#""C:\Users\me\it-ai.exe" "--relay" "https://hub.example" "--relay-token" "htok_old" "--name" "my box" "--background""#;
    assert_eq!(
        strip_cmdline(v, false).as_deref(),
        Some(r#""C:\Users\me\it-ai.exe" "--relay" "https://hub.example" "--name" "my box" "--background""#)
    );
}

const TASK_XML: &str = r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <LogonTrigger><Enabled>true</Enabled><UserId>DESKTOP-X\me</UserId></LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-21-1-2-3-1001</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Actions Context="Author">
    <Exec>
      <Command>"C:\Program Files\IT-AI\it-ai.exe"</Command>
      <Arguments>--relay https://hub.example --relay-token htok_old --name &quot;my box&quot; --background</Arguments>
    </Exec>
  </Actions>
</Task>"#;

#[test]
fn task_xml_parses_and_rebuilds_the_tr() {
    let t = parse_task_xml(TASK_XML).unwrap();
    assert_eq!(t.command, r#""C:\Program Files\IT-AI\it-ai.exe""#);
    assert_eq!(t.arguments, r#"--relay https://hub.example --relay-token htok_old --name "my box" --background"#);
    assert_eq!(t.logon_type.as_deref(), Some("InteractiveToken"));
    assert_eq!(t.user_id.as_deref(), Some("S-1-5-21-1-2-3-1001"), "the principal's, not the trigger's");
    let args = strip_cmdline(&t.arguments, false).unwrap();
    assert_eq!(
        task_tr(&t.command, &args),
        r#""C:\Program Files\IT-AI\it-ai.exe" --relay https://hub.example --name "my box" --background"#
    );
    assert_eq!(task_tr(r"C:\it-ai.exe", ""), r#""C:\it-ai.exe""#);
    let two = TASK_XML.replace("</Exec>", "</Exec><Exec><Command>x</Command></Exec>");
    assert_eq!(parse_task_xml(&two), None, "two actions: not a task we wrote");
}

#[test]
fn tool_output_decodes_utf16_and_utf8() {
    let utf16: Vec<u8> = [0xFF, 0xFE].into_iter().chain("<Task/>".encode_utf16().flat_map(|u| u.to_le_bytes())).collect();
    assert_eq!(decode_output(&utf16), "<Task/>");
    let no_bom: Vec<u8> = "<Task/>".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    assert_eq!(decode_output(&no_bom), "<Task/>");
    assert_eq!(decode_output(b"<Task/>"), "<Task/>");
}

#[test]
fn whoami_and_principal_matching() {
    let (name, sid) = parse_whoami("\"desktop-x\\me\",\"S-1-5-21-1-2-3-1001\"\r\n").unwrap();
    assert_eq!((name.as_str(), sid.as_str()), ("desktop-x\\me", "S-1-5-21-1-2-3-1001"));
    assert!(user_matches("S-1-5-21-1-2-3-1001", &name, &sid));
    assert!(user_matches("DESKTOP-X\\me", &name, &sid));
    assert!(user_matches("me", &name, &sid));
    assert!(!user_matches("S-1-5-18", &name, &sid));
    assert!(!user_matches("OTHER\\me", &name, &sid));
    assert_eq!(parse_whoami("ERROR: nope"), None);
}
