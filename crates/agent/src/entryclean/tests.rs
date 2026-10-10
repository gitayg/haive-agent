// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

use super::*;
#[cfg(unix)]
use super::securefs;
use crate::relaycred::{path_in, save, CredFile};

/// A `pin_to` that accepts any home (the pin rules are tested on their own).
fn any_pin(h: &Path) -> Result<PathBuf, String> {
    Ok(h.to_path_buf())
}

fn eq(a: &Path, b: &Path) -> bool {
    a == b
}

/// Under the build's own target dir, not the system temp dir: Linux's `/tmp` is
/// world-writable, and an entry under it is (rightly) never rewritten.
fn scratch(tag: &str) -> PathBuf {
    let base = std::env::current_exe().unwrap().parent().unwrap().join("entryclean-scratch");
    let d = base.join(format!("{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    std::fs::canonicalize(&d).unwrap()
}

/// A home holding a device secret, as a 3.7.0+ agent leaves it.
fn home_with_secret(root: &Path, name: &str) -> PathBuf {
    let h = root.join(name);
    save(&path_in(&h), &CredFile { hub: "https://hub.example".into(), enroll: None, device: Some("hdev_x".into()) }).unwrap();
    h
}

#[test]
fn cred_home_only_for_a_relay_cred_path() {
    assert_eq!(cred_home(Path::new("/root/.it-ai/relay.cred")), Some("/root".into()));
    assert_eq!(cred_home(Path::new("/.it-ai/relay.cred")), Some("/".into()));
    assert_eq!(cred_home(Path::new("/root/other/relay.cred")), None);
    assert_eq!(cred_home(Path::new("/root/.it-ai/x.cred")), None);
}

#[test]
fn same_path_rewrites_as_is() {
    let loaded = Path::new("/home/u/.it-ai/relay.cred");
    for home in [EntryHome::Default("/home/u".into()), EntryHome::Pinned("/home/u".into())] {
        assert_eq!(decide(&home, loaded, false, &eq), Ok(Plan::Strip), "{home:?}");
        assert_eq!(decide(&home, loaded, true, &eq), Ok(Plan::Strip), "same path never pins: {home:?}");
    }
}

#[test]
fn different_and_pinnable_pins_home_to_the_loaded_one() {
    // An old root unit with no HOME looks in /.it-ai; the secret is in /root/.it-ai.
    let loaded = Path::new("/root/.it-ai/relay.cred");
    assert_eq!(decide(&EntryHome::Default("/".into()), loaded, true, &eq), Ok(Plan::Pin("/root".into())));
    assert_eq!(decide(&EntryHome::Unknown, loaded, true, &eq), Ok(Plan::Pin("/root".into())));
}

#[test]
fn different_and_not_pinnable_is_skipped() {
    let loaded = Path::new("/root/.it-ai/relay.cred");
    assert!(decide(&EntryHome::Default("/".into()), loaded, false, &eq).is_err());
    assert!(decide(&EntryHome::Unknown, loaded, false, &eq).is_err());
    // An entry that pins a different HOME is never overridden.
    assert!(decide(&EntryHome::Pinned("/srv".into()), loaded, true, &eq).is_err());
    // Pinning needs the loaded path to be a `<home>/.it-ai/relay.cred`.
    assert!(decide(&EntryHome::Unknown, Path::new("/root/odd.cred"), true, &eq).is_err());
}

#[test]
fn old_unit_with_a_different_home_is_pinned_and_reads_back() {
    let root = scratch("unit");
    let svc = home_with_secret(&root, "svc");
    let loaded = path_in(&svc);
    let unit = root.join("it-ai.service");
    let old = "[Unit]\nDescription=IT-AI agent\n\n[Service]\nExecStart=/bin/it-ai --relay https://hub.example --relay-token htok_old\nRestart=always\n";
    let (new, pinned) = plan_file(Kind::Unit, old, &unit, &loaded, true, &same_file, &any_pin).unwrap().unwrap();
    assert_eq!(pinned.as_deref(), Some(svc.as_path()));
    // Quoted when the path has a space, as `service_unit` writes it.
    let h = svc.display().to_string();
    let env = if h.contains(' ') { format!("\"HOME={h}\"") } else { format!("HOME={h}") };
    assert_eq!(
        new,
        format!("[Unit]\nDescription=IT-AI agent\n\n[Service]\nEnvironment={env}\nExecStart=/bin/it-ai --relay https://hub.example\nRestart=always\n")
    );
    // Not root: a root unit's HOME is not ours to choose. Left alone.
    let err = plan_file(Kind::Unit, old, &unit, &loaded, false, &same_file, &any_pin).unwrap_err();
    assert!(err.contains("cannot be pinned"), "{err}");
    // Already rewritten: nothing to do (idempotent).
    assert_eq!(plan_file(Kind::Unit, &new, &unit, &loaded, true, &same_file, &any_pin), Ok(None));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn per_user_entries_resolve_from_where_they_live() {
    let root = scratch("user");
    let me = home_with_secret(&root, "me");
    let loaded = path_in(&me);
    let desktop = me.join(".config/autostart/it-ai.desktop");
    let old = "[Desktop Entry]\nExec=/bin/it-ai --relay https://hub.example --relay-token htok_old --name box\n";
    let (new, pinned) = plan_file(Kind::Desktop, old, &desktop, &loaded, false, &same_file, &any_pin).unwrap().unwrap();
    assert_eq!(new, "[Desktop Entry]\nExec=/bin/it-ai --relay https://hub.example --name box\n");
    assert_eq!(pinned, None);
    // The same entry under another user's home would not find this secret, and a
    // .desktop cannot pin HOME: left alone.
    let theirs = home_with_secret(&root, "them").join(".config/autostart/it-ai.desktop");
    assert!(plan_file(Kind::Desktop, old, &theirs, &loaded, true, &same_file, &any_pin).is_err());

    let plist = me.join("Library/LaunchAgents/com.itai.agent.plist");
    let mut args: Vec<String> = ["--relay", "https://hub.example", "--relay-token", "htok_old"].iter().map(|s| s.to_string()).collect();
    let old = crate::persistence::agent_plist(Path::new("/bin/it-ai"), &args, &me);
    args.drain(2..);
    let (new, pinned) = plan_file(Kind::AgentPlist, &old, &plist, &loaded, true, &same_file, &any_pin).unwrap().unwrap();
    assert_eq!(new, crate::persistence::agent_plist(Path::new("/bin/it-ai"), &args, &me));
    assert_eq!(pinned, None);
    // Someone else's label: not ours, never touched.
    assert_eq!(plan_file(Kind::AgentPlist, &old.replace("com.itai.agent", "com.x.y"), &plist, &loaded, true, &same_file, &any_pin), Ok(None));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn old_launchdaemon_gets_home_pinned() {
    let root = scratch("daemon");
    let svc = home_with_secret(&root, "var-root");
    let loaded = path_in(&svc);
    let args: Vec<String> = ["--relay", "https://hub.example", "--relay-token", "htok_old"].iter().map(|s| s.to_string()).collect();
    let old = crate::persistence::daemon_plist(Path::new("/bin/it-ai"), &args, &svc)
        .replace(&format!("  <key>EnvironmentVariables</key><dict>\n    <key>HOME</key><string>{}</string>\n  </dict>\n", svc.display()), "");
    assert_eq!(entry_home(Kind::DaemonPlist, &old, Path::new("/Library/LaunchDaemons/com.itai.agent.plist")), Ok(EntryHome::Unknown));
    let (new, pinned) = plan_file(Kind::DaemonPlist, &old, Path::new("/Library/LaunchDaemons/com.itai.agent.plist"), &loaded, true, &same_file, &any_pin)
        .unwrap()
        .unwrap();
    assert_eq!(pinned.as_deref(), Some(svc.as_path()));
    assert_eq!(et::plist_home(&new), Ok(Some(svc.clone())));
    assert!(!new.contains("htok_old"));
    assert!(plan_file(Kind::DaemonPlist, &old, Path::new("/Library/LaunchDaemons/x.plist"), &loaded, false, &same_file, &any_pin).is_err());
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn windows_entries_rewrite_only_when_the_user_home_finds_the_secret() {
    let root = scratch("win");
    let me = home_with_secret(&root, "me");
    let loaded = path_in(&me);
    let run = r#""C:\it-ai.exe" "--relay" "https://hub.example" "--relay-token" "htok_old" "--background""#;
    assert_eq!(
        plan_cmdline(run, &EntryHome::Default(me.clone()), &loaded, &same_file),
        Ok(Some(r#""C:\it-ai.exe" "--relay" "https://hub.example" "--background""#.to_string()))
    );
    assert!(plan_cmdline(run, &EntryHome::Default(root.join("other")), &loaded, &same_file).is_err());
    assert!(plan_cmdline(run, &EntryHome::Unknown, &loaded, &same_file).is_err());
    assert_eq!(plan_cmdline(r#""C:\it-ai.exe" --background"#, &EntryHome::Default(me), &loaded, &same_file), Ok(None));
    let _ = std::fs::remove_dir_all(&root);
}

#[cfg(unix)]
#[test]
fn replace_keeps_the_mode_and_leaves_no_temp() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let root = scratch("atomic");
    for mode in [0o644, 0o600] {
        let f = root.join("it-ai.service");
        std::fs::write(&f, "old").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(mode)).unwrap();
        let ino = std::fs::metadata(&f).unwrap().ino();
        let e = securefs::open(&f).unwrap().unwrap();
        assert_eq!(e.text, "old");
        e.replace("new").unwrap();
        let m = std::fs::metadata(&f).unwrap();
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "new");
        assert_eq!(m.permissions().mode() & 0o777, mode);
        assert_ne!(m.ino(), ino, "replaced by rename, not rewritten in place");
    }
    let left: Vec<_> = std::fs::read_dir(&root).unwrap().map(|e| e.unwrap().file_name()).collect();
    assert_eq!(left, vec![std::ffi::OsString::from("it-ai.service")]);
    let _ = std::fs::remove_dir_all(&root);
}

#[cfg(unix)]
fn meta(uid: u32, mode: u32) -> securefs::Meta {
    securefs::Meta { uid, gid: 0, mode, nlink: 1, dev: 1, ino: 1 }
}

/// Injected user and group databases: passwd as (uid, name, primary gid), group
/// as (gid, name, supplementary members), and nsswitch.conf (None: unreadable).
#[cfg(unix)]
struct FakeDb {
    passwd: Vec<(u32, &'static str, u32)>,
    group: Vec<(u32, &'static str, Vec<&'static str>)>,
    nss: Option<&'static str>,
    /// `/etc/passwd`, `/etc/group` as (name, text); a name not listed is unreadable.
    etc: Vec<(&'static str, &'static str)>,
}

#[cfg(unix)]
impl securefs::GroupDb for FakeDb {
    fn user(&self, uid: u32) -> Option<(String, u32)> {
        self.passwd.iter().find(|p| p.0 == uid).map(|p| (p.1.to_string(), p.2))
    }
    fn group(&self, gid: u32) -> Option<(String, Vec<String>)> {
        self.group.iter().find(|g| g.0 == gid).map(|g| (g.1.to_string(), g.2.iter().map(|m| m.to_string()).collect()))
    }
    fn primary_users(&self, gid: u32) -> Vec<u32> {
        self.passwd.iter().filter(|p| p.2 == gid).map(|p| p.0).collect()
    }
    fn nsswitch(&self) -> Option<String> {
        self.nss.map(str::to_string)
    }
    fn etc(&self, name: &str) -> Option<String> {
        self.etc.iter().find(|e| e.0 == name).map(|e| e.1.to_string())
    }
}

/// A Debian/Ubuntu-style nsswitch.conf (local sources only; the `hosts:` action
/// brackets are on another database and do not matter).
#[cfg(unix)]
const NSS_LOCAL: &str = "# /etc/nsswitch.conf\npasswd:         files systemd\ngroup:          files systemd\nshadow:         files systemd\nhosts:          files mdns4_minimal [NOTFOUND=return] dns\n";

#[cfg(unix)]
const ETC_LOCAL: [(&str, &str); 2] = [("passwd", "root:x:0:0::/root:/bin/sh\nopswat:x:1000:1000::/home/opswat:/bin/bash\n"), ("group", "root:x:0:\nopswat:x:1000:\n")];

/// The measured Ubuntu box: opswat is uid 1000, group opswat (1000) has no
/// members (`opswat:x:1000:`), and no other user's primary group is 1000. Root's
/// group 0 is root's alone too, but root never gets the exception.
#[cfg(unix)]
fn upg_db() -> FakeDb {
    FakeDb {
        passwd: vec![(0, "root", 0), (1000, "opswat", 1000), (1001, "eve", 1001), (65534, "nobody", 65534)],
        group: vec![(0, "root", vec![]), (1000, "opswat", vec![]), (1001, "eve", vec![]), (27, "sudo", vec!["opswat"]), (65534, "nogroup", vec![])],
        nss: Some(NSS_LOCAL),
        etc: ETC_LOCAL.to_vec(),
    }
}

/// One user `me` (uid) whose private group is `gid`, on local NSS.
#[cfg(unix)]
fn me_db(uid: u32, gid: u32) -> FakeDb {
    FakeDb { passwd: vec![(uid, "me", gid)], group: vec![(gid, "me", vec![])], nss: Some(NSS_LOCAL), etc: ETC_LOCAL.to_vec() }
}

#[cfg(unix)]
fn gmeta(uid: u32, gid: u32, mode: u32) -> securefs::Meta {
    securefs::Meta { gid, ..meta(uid, mode) }
}

/// The user-private-group rule on its own, with injected group data: every
/// condition must be proven, and the refusal names the one that is not.
#[cfg(unix)]
#[test]
fn group_write_is_safe_only_in_the_owners_private_group() {
    use securefs::private_group;
    let db = upg_db();
    let refused = |uid: u32, gid: u32, db: &FakeDb, why: &str| {
        let e = private_group(uid, gid, db).unwrap_err();
        assert!(e.contains(why), "{uid}/{gid}: wanted {why:?}, got {e:?}");
    };
    assert_eq!(private_group(1000, 1000, &db), Ok(()), "opswat:x:1000: with no members, local NSS");
    // Not the owner's primary group.
    refused(1000, 1001, &db, "not uid 1000's primary group");
    refused(1000, 27, &db, "not uid 1000's primary group");
    // The group's name is not the user's name.
    let renamed = FakeDb { group: vec![(1000, "staff", vec![])], ..upg_db() };
    refused(1000, 1000, &renamed, "its name `staff` is not the user name `opswat`");
    // The group lists a supplementary member, even the owner itself.
    refused(1000, 1000, &FakeDb { group: vec![(1000, "opswat", vec!["opswat"])], ..upg_db() }, "lists members opswat");
    refused(1000, 1000, &FakeDb { group: vec![(1000, "opswat", vec!["eve"])], ..upg_db() }, "lists members eve");
    // Another user has it as a primary group.
    let shared = FakeDb { passwd: vec![(1000, "opswat", 1000), (1002, "mallory", 1000)], ..upg_db() };
    refused(1000, 1000, &shared, "uid 1002 also has it as primary group");
    // Unknown user or group: not provably private.
    refused(4242, 4242, &db, "uid 4242 has no passwd entry");
    refused(1000, 1000, &FakeDb { group: vec![], ..upg_db() }, "group 1000 has no group entry");
    // Root never.
    refused(0, 0, &db, "root's paths never");
    // Users or groups from a source that may not be enumerable: refused, even
    // though everything above holds.
    for (nss, why) in [
        ("passwd: files sss\ngroup: files sss\n", "passwd: uses `sss`"),
        ("passwd: files systemd\ngroup: files ldap\n", "group: uses `ldap`"),
        ("passwd: cache files\ngroup: files\n", "passwd: uses `cache`"),
        ("passwd: files winbind\ngroup: files winbind\n", "uses `winbind`"),
        ("passwd: files\n", "has no group: line"),
        ("group: files\n", "has no passwd: line"),
        ("passwd: files\ngroup: files\npasswd: files sss\n", "2 passwd: lines"),
        ("passwd: files [NOTFOUND=return] sss\ngroup: files\n", "action"),
    ] {
        refused(1000, 1000, &FakeDb { nss: Some(nss), ..upg_db() }, why);
    }
    refused(1000, 1000, &FakeDb { nss: None, ..upg_db() }, "/etc/nsswitch.conf cannot be read");
}

/// The nsswitch.conf reading is strict and fails closed: wherever it could
/// disagree with glibc (which then might consult sss or ldap), it refuses.
#[cfg(unix)]
#[test]
fn only_files_and_systemd_count_as_local_nss() {
    use securefs::nss_local;
    let etc = |f: &str| ETC_LOCAL.iter().find(|e| e.0 == f).map(|e| e.1.to_string());
    let ok = |conf: &str| assert_eq!(nss_local(conf, &etc), Ok(()), "{conf:?}");
    let refused = |conf: &str, why: &str| {
        let e = nss_local(conf, &etc).unwrap_err();
        assert!(e.contains(why), "{conf:?}: wanted {why:?}, got {e:?}");
    };
    ok(NSS_LOCAL);
    ok("passwd: files # sss\ngroup: files\n");
    ok("passwd:files\ngroup:files systemd\n");
    ok("  passwd:\tfiles  systemd  \ngroup: files\n");
    ok("#passwd: sss\npasswd: files\ngroup: files\n");
    ok("passwd: files\ngroup: files\npasswd_compat: nis\n");
    // Action brackets on passwd:/group:, in any spacing.
    refused("passwd: files [NOTFOUND=return] systemd\ngroup: files\n", "action");
    refused("passwd: files\ngroup: files [SUCCESS=merge] systemd\n", "action");
    refused("passwd: files [ NOTFOUND = return ] systemd\ngroup: files\n", "action");
    refused("passwd: files [SUCCESS=merge] sss\ngroup: files\n", "action");
    // Exactly one line per database: duplicates, in any case, are refused.
    refused("passwd: files\ngroup: files\npasswd: files sss\n", "2 passwd: lines");
    refused("passwd: files\ngroup: files\npasswd: files\n", "2 passwd: lines");
    refused("passwd: files\ngroup: files\ngroup: files\n", "2 group: lines");
    refused("passwd: files\nPASSWD: files sss\ngroup: files\n", "2 passwd: lines");
    refused("passwd: files\nGroup : ldap\ngroup: files\n", "2 group: lines");
    // A line that is not `database: sources`.
    refused("passwd: files\ngroup: files\npasswd files sss\n", "line 3 is not `database: sources`");
    // Missing database lines or an empty file: glibc's built-in defaults, unknown here.
    refused("", "no passwd: line");
    refused("passwd: files\n", "no group: line");
    refused("group: files\n", "no passwd: line");
    refused("passwd:\ngroup: files\n", "passwd: names no source");
    // Any source outside the allowlist, including case variants and unknown names.
    refused("passwd: files sss\ngroup: files sss\n", "`sss`");
    refused("passwd: files\ngroup: files ldap\n", "`ldap`");
    refused("passwd: Files\ngroup: files\n", "`Files`");
    refused("passwd: files winbind\ngroup: files\n", "`winbind`");
    refused("passwd: cache files\ngroup: files\n", "`cache`");
    refused("passwd: files mymachines\ngroup: files\n", "`mymachines`");
    // compat: only with no passwd_compat/group_compat line and no +/- entries.
    ok("passwd: compat\ngroup: compat\n");
    refused("passwd: compat\ngroup: compat\npasswd_compat: ldap\n", "passwd_compat");
    refused("passwd: compat\ngroup: files\nGROUP_COMPAT: nis\n", "group_compat");
    let nis = |f: &str| match f {
        "passwd" => Some("root:x:0:0::/root:/bin/sh\n+@admins::::::\n".to_string()),
        _ => etc(f),
    };
    assert!(nss_local("passwd: compat\ngroup: compat\n", &nis).unwrap_err().contains("/etc/passwd has NIS"));
    let nis_g = |f: &str| match f {
        "group" => Some("root:x:0:\n-wheel\n".to_string()),
        _ => etc(f),
    };
    assert!(nss_local("passwd: files\ngroup: compat\n", &nis_g).unwrap_err().contains("/etc/group has NIS"));
    assert!(nss_local("passwd: compat\ngroup: files\n", &|_| None).unwrap_err().contains("/etc/passwd cannot be read"));
    // NIS entries do not matter when compat is not used.
    assert_eq!(nss_local("passwd: files\ngroup: files\n", &nis), Ok(()));
}

/// The measured case end to end through the checks: a 0664 file in a 0775
/// directory, both opswat:opswat (a private group), is accepted; the same modes
/// in a shared group, or world-writable, are not.
#[cfg(unix)]
#[test]
fn ubuntu_private_group_664_in_775_is_accepted() {
    use securefs::{check_dir, check_file};
    const REG: u32 = libc::S_IFREG as u32;
    const DIR: u32 = libc::S_IFDIR as u32;
    let db = upg_db();
    let p = Path::new("/home/opswat/.config/autostart");
    assert_eq!(check_file(&gmeta(1000, 1000, REG | 0o664), 1000, &db), Ok(()));
    assert_eq!(check_dir(p, &gmeta(1000, 1000, DIR | 0o775), 1000, true, &db), Ok(()));
    assert_eq!(check_dir(p, &gmeta(1000, 1000, DIR | 0o775), 1000, false, &db), Ok(()));
    // A shared group (one with a member, another user's primary group), a group
    // named for someone else, or users from SSSD: refused.
    for (gid, db) in [
        (27, upg_db()),
        (1001, upg_db()),
        (1000, FakeDb { passwd: vec![(1000, "opswat", 1000), (1002, "mallory", 1000)], ..upg_db() }),
        (1000, FakeDb { group: vec![(1000, "opswat", vec!["eve"])], ..upg_db() }),
        (1000, FakeDb { group: vec![(1000, "staff", vec![])], ..upg_db() }),
        (1000, FakeDb { nss: Some("passwd: files sss\ngroup: files sss\n"), ..upg_db() }),
    ] {
        let e = check_file(&gmeta(1000, gid, REG | 0o664), 1000, &db).unwrap_err();
        assert!(e.contains(&format!("writable by group {gid}")), "{e}");
        assert!(check_dir(p, &gmeta(1000, gid, DIR | 0o775), 1000, true, &db).unwrap_err().contains("writable by group"));
    }
    // World-writable: never, private group or not.
    for mode in [0o666, 0o646, 0o662] {
        let e = check_file(&gmeta(1000, 1000, REG | mode), 1000, &db).unwrap_err();
        assert!(e.contains("world-writable"), "{mode:o}: {e}");
    }
    for mode in [0o777, 0o757, 0o1777] {
        assert!(check_dir(p, &gmeta(1000, 1000, DIR | mode), 1000, true, &db).unwrap_err().contains("world-writable"), "{mode:o}");
    }
    // Root-owned, group-write in root's own group 0: still refused, for a root or user agent.
    assert!(check_dir(p, &gmeta(0, 0, DIR | 0o775), 0, true, &db).unwrap_err().contains("writable by group 0"));
    assert!(check_dir(p, &gmeta(0, 0, DIR | 0o775), 1000, false, &db).is_err());
    // A root agent never rewrites the user's file, private group or not.
    assert!(check_file(&gmeta(1000, 1000, REG | 0o664), 0, &db).unwrap_err().contains("owned by uid 1000"));
}

/// The ownership rules, with injected metadata (no chown needed).
#[cfg(unix)]
#[test]
fn only_our_own_unshared_files_and_dirs_are_rewritten() {
    let db = upg_db();
    let check_dir = |p: &Path, m: &securefs::Meta, e: u32, own: bool| securefs::check_dir(p, m, e, own, &db);
    let check_file = |m: &securefs::Meta, e: u32| securefs::check_file(m, e, &db);
    const REG: u32 = libc::S_IFREG as u32;
    const DIR: u32 = libc::S_IFDIR as u32;
    let p = Path::new("/x");
    // The file: ours, regular, one link, not writable by group/others.
    assert_eq!(check_file(&meta(501, REG | 0o644), 501), Ok(()));
    assert!(check_file(&meta(502, REG | 0o644), 501).unwrap_err().contains("owned by uid 502"));
    assert!(check_file(&meta(0, REG | 0o644), 501).is_err(), "a user agent never rewrites root's file");
    assert!(check_file(&meta(1000, REG | 0o644), 0).is_err(), "a root agent never rewrites a user's file");
    assert!(check_file(&meta(501, REG | 0o664), 501).unwrap_err().contains("writable"));
    assert!(check_file(&meta(501, REG | 0o646), 501).is_err());
    assert!(check_file(&meta(501, libc::S_IFLNK as u32 | 0o777), 501).unwrap_err().contains("symlink"));
    assert!(check_file(&meta(501, libc::S_IFIFO as u32 | 0o644), 501).is_err());
    assert!(check_file(&securefs::Meta { nlink: 2, ..meta(501, REG | 0o644) }, 501).unwrap_err().contains("hard links"));
    // The entry's own directory: ours, not writable by group/others.
    assert_eq!(check_dir(p, &meta(501, DIR | 0o755), 501, true), Ok(()));
    assert!(check_dir(p, &meta(0, DIR | 0o755), 501, true).is_err());
    assert!(check_dir(p, &meta(1000, DIR | 0o700), 0, true).is_err(), "a root agent never writes into a user's dir");
    assert!(check_dir(p, &meta(0, DIR | 0o775), 0, true).unwrap_err().contains("writable"));
    assert!(check_dir(p, &meta(0, DIR | 0o1777), 0, true).is_err(), "sticky does not make /tmp-like dirs safe");
    // Above it: ours or root's, never writable by group/others.
    assert_eq!(check_dir(p, &meta(0, DIR | 0o755), 501, false), Ok(()));
    assert!(check_dir(p, &meta(1000, DIR | 0o755), 0, false).is_err(), "a root agent under a user's dir");
    assert!(check_dir(p, &meta(0, DIR | 0o777), 501, false).is_err());
}

/// A symlink at the entry's path is never read or written, and its target is
/// left exactly as it was.
#[cfg(unix)]
#[test]
fn a_symlinked_entry_is_refused_and_its_target_untouched() {
    let root = scratch("symlink");
    let me = home_with_secret(&root, "me");
    let target = root.join("target");
    let body = "[Desktop Entry]\nExec=/bin/it-ai --relay-token htok_old\n[Service]\nExecStart=/bin/it-ai --relay-token htok_old\n";
    std::fs::write(&target, body).unwrap();
    let entry = me.join("entries/it-ai.desktop");
    std::fs::create_dir_all(entry.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(&target, &entry).unwrap();
    assert!(securefs::open(&entry).unwrap_err().contains("symlink"));
    for kind in [Kind::Desktop, Kind::Unit] {
        assert!(unix::clean(kind, &entry, &path_in(&me), true, true), "reported as not inspected");
    }
    assert_eq!(std::fs::read_to_string(&target).unwrap(), body);
    assert!(std::fs::symlink_metadata(&entry).unwrap().file_type().is_symlink());
    let _ = std::fs::remove_dir_all(&root);
}

/// An entry in a directory others can write (or under one) is left alone.
#[cfg(unix)]
#[test]
fn a_group_or_world_writable_directory_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let root = scratch("gw");
    let me = home_with_secret(&root, "me");
    let entry = me.join(".config/autostart/it-ai.desktop");
    std::fs::create_dir_all(entry.parent().unwrap()).unwrap();
    let old = "[Desktop Entry]\nExec=/bin/it-ai --relay-token htok_old\n";
    // Group-write: refused here only when the scratch dir's group is not this
    // user's private group (macOS staff, root's group 0, a shared group). The
    // private-group case has its own test below.
    use std::os::unix::fs::MetadataExt;
    let gid = std::fs::metadata(entry.parent().unwrap()).unwrap().gid();
    let mut cases = vec![(entry.parent().unwrap().to_path_buf(), 0o757), (me.join(".config"), 0o777)];
    if securefs::private_group(securefs::euid(), gid, &securefs::SysGroups).is_err() {
        cases.push((entry.parent().unwrap().to_path_buf(), 0o775));
    }
    for (dir, mode) in cases {
        std::fs::write(&entry, old).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
        let e = securefs::open(&entry).unwrap().unwrap();
        assert!(e.check(securefs::euid(), &securefs::SysGroups).unwrap_err().contains("writable"), "{} {mode:o}", dir.display());
        assert!(unix::clean(Kind::Desktop, &entry, &path_in(&me), false, true));
        assert_eq!(std::fs::read_to_string(&entry).unwrap(), old, "{} {mode:o}", dir.display());
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    // Back to 0755 all the way: now it is rewritten.
    assert!(!unix::clean(Kind::Desktop, &entry, &path_in(&me), false, true));
    assert!(!std::fs::read_to_string(&entry).unwrap().contains("htok_old"));
    let _ = std::fs::remove_dir_all(&root);
}

/// A real 0664 entry in a 0775 directory, through `Entry::check`: accepted when
/// the group database says the file's group is this user's private group, refused
/// when it says the group is shared. The group the files really have is used, so
/// this needs no chgrp.
#[cfg(unix)]
#[test]
fn a_664_entry_in_a_775_dir_is_checked_against_the_group_database() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let root = scratch("upg");
    let me = securefs::euid();
    let dir = root.join("autostart");
    std::fs::create_dir_all(&dir).unwrap();
    let f = dir.join("it-ai.desktop");
    std::fs::write(&f, "x").unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o775)).unwrap();
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o664)).unwrap();
    let (fg, dg) = (std::fs::metadata(&f).unwrap().gid(), std::fs::metadata(&dir).unwrap().gid());
    let e = securefs::open(&f).unwrap().unwrap();
    if me != 0 && fg == dg {
        assert_eq!(e.check(me, &me_db(me, fg)), Ok(()));
    }
    let mut shared = me_db(me, fg);
    shared.passwd.push((me + 1, "other", fg));
    if dg != fg {
        shared.group.push((dg, "other", vec![]));
    }
    assert!(e.check(me, &shared).unwrap_err().contains("writable by group"));
    let _ = std::fs::remove_dir_all(&root);
}

/// The write goes through the directory fd opened before the checks: if the
/// directory is swapped for another after that, the new one is never written,
/// and the rename lands in the directory that was checked.
#[cfg(unix)]
#[test]
fn a_directory_swapped_after_the_checks_is_not_written() {
    let root = scratch("swapdir");
    let dir = root.join("autostart");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("it-ai.desktop"), "old").unwrap();
    let e = securefs::open(&dir.join("it-ai.desktop")).unwrap().unwrap();
    e.check(securefs::euid(), &securefs::SysGroups).unwrap();
    // The swap: the checked directory moves away, an attacker's takes its place.
    std::fs::rename(&dir, root.join("checked")).unwrap();
    std::fs::create_dir_all(&dir).unwrap();
    e.replace("new").unwrap();
    assert_eq!(std::fs::read_to_string(root.join("checked/it-ai.desktop")).unwrap(), "new");
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0, "the swapped-in directory got nothing");
    let _ = std::fs::remove_dir_all(&root);
}

/// The entry replaced by a symlink after it was read: the rename is refused and
/// the symlink's target is not touched.
#[cfg(unix)]
#[test]
fn an_entry_swapped_for_a_symlink_after_the_read_is_not_written() {
    let root = scratch("swapfile");
    let entry = root.join("it-ai.service");
    let target = root.join("target");
    std::fs::write(&entry, "old").unwrap();
    std::fs::write(&target, "precious").unwrap();
    let e = securefs::open(&entry).unwrap().unwrap();
    std::fs::remove_file(&entry).unwrap();
    std::os::unix::fs::symlink(&target, &entry).unwrap();
    assert!(e.replace("new").unwrap_err().to_string().contains("replaced after it was read"));
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "precious");
    assert!(std::fs::symlink_metadata(&entry).unwrap().file_type().is_symlink());
    let names: Vec<_> = std::fs::read_dir(&root).unwrap().map(|e| e.unwrap().file_name()).collect();
    assert_eq!(names.len(), 2, "no temp file left: {names:?}");
    let _ = std::fs::remove_dir_all(&root);
}

/// The startup path end to end on this OS's real entry kinds, in a throwaway home:
/// not ready (no device secret) leaves the entry, ready rewrites it, and a second
/// run is a no-op.
#[cfg(unix)]
#[test]
fn clean_rewrites_only_when_the_device_secret_is_held() {
    let root = scratch("clean");
    let me = home_with_secret(&root, "me");
    let loaded = path_in(&me);
    #[cfg(target_os = "macos")]
    let (kind, entry, old) = (
        Kind::AgentPlist,
        me.join("Library/LaunchAgents/com.itai.agent.plist"),
        crate::persistence::agent_plist(Path::new("/bin/it-ai"), &["--relay-token".into(), "htok_old".into()], &me),
    );
    #[cfg(not(target_os = "macos"))]
    let (kind, entry, old) = (
        Kind::Desktop,
        me.join(".config/autostart/it-ai.desktop"),
        "[Desktop Entry]\nExec=/bin/it-ai --relay-token htok_old\n".to_string(),
    );
    std::fs::create_dir_all(entry.parent().unwrap()).unwrap();
    std::fs::write(&entry, &old).unwrap();
    assert!(unix::clean(kind, &entry, &loaded, true, false), "not ready: still carries it");
    assert_eq!(std::fs::read_to_string(&entry).unwrap(), old);
    assert!(!unix::clean(kind, &entry, &loaded, true, true));
    let new = std::fs::read_to_string(&entry).unwrap();
    assert!(!new.contains("relay-token") && !new.contains("htok_old"), "{new}");
    assert!(!unix::clean(kind, &entry, &loaded, true, true));
    assert_eq!(std::fs::read_to_string(&entry).unwrap(), new);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn ready_needs_a_device_secret_for_this_hub() {
    let root = scratch("ready");
    let loaded = path_in(&home_with_secret(&root, "me"));
    assert!(holds_device("https://hub.example/", &loaded));
    assert!(!holds_device("https://other.example", &loaded));
    save(&loaded, &CredFile { hub: "https://hub.example".into(), enroll: Some("htok_e".into()), device: None }).unwrap();
    assert!(!holds_device("https://hub.example", &loaded));
    let _ = std::fs::remove_dir_all(&root);
}

/// The read-back guard: an `EnvironmentVariables` written as `<dict/>` is not one
/// the pinner can add to, so it appends a second one, and the rewritten plist would
/// then hold the key twice (which launchd honours is not defined). Reading the new
/// text back finds no HOME it can trust, so the entry is left alone.
#[test]
fn a_rewrite_that_does_not_read_back_is_refused() {
    let root = scratch("readback");
    let svc = home_with_secret(&root, "var-root");
    let loaded = path_in(&svc);
    let args: Vec<String> = ["--relay-token", "htok_old"].iter().map(|s| s.to_string()).collect();
    let old = crate::persistence::daemon_plist(Path::new("/bin/it-ai"), &args, &svc).replace(
        &format!("<dict>\n    <key>HOME</key><string>{}</string>\n  </dict>", svc.display()),
        "<dict/>",
    );
    assert!(old.contains("<key>EnvironmentVariables</key><dict/>"), "{old}");
    let r = plan_file(Kind::DaemonPlist, &old, Path::new("/Library/LaunchDaemons/com.itai.agent.plist"), &loaded, true, &same_file, &any_pin);
    assert!(matches!(&r, Err(e) if e.contains("would not find")), "{r:?}");
    let _ = std::fs::remove_dir_all(&root);
}

/// The HOME pinned into a service must be a directory only root or this agent
/// can change, every component from `/` down, symlinks included.
#[cfg(unix)]
#[test]
fn a_pinned_home_must_be_trusted_from_the_root_down() {
    use std::os::unix::fs::PermissionsExt;
    let set = |p: &Path, m: u32| std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
    let me = securefs::euid();
    let root = scratch("trust");
    let home = home_with_secret(&root, "svc");
    assert_eq!(securefs::check_trusted_dir(&home, me, &securefs::SysGroups), Ok(()));
    assert_eq!(securefs::check_trusted_dir(Path::new("/"), me, &securefs::SysGroups), Ok(()));
    // Owned by someone who is neither root nor this agent.
    if me == 0 {
        std::os::unix::fs::chown(&home, Some(12345), None).unwrap();
        assert!(securefs::check_trusted_dir(&home, 0, &securefs::SysGroups).unwrap_err().contains("owned by uid 12345"));
        std::os::unix::fs::chown(&home, Some(0), None).unwrap();
    } else {
        assert!(securefs::check_trusted_dir(&home, me + 12345, &securefs::SysGroups).unwrap_err().contains("owned by uid"));
    }
    // Writable by others: the dir itself, or any directory above it.
    set(&home, 0o777);
    assert!(securefs::check_trusted_dir(&home, me, &securefs::SysGroups).unwrap_err().contains("writable"));
    set(&home, 0o755);
    set(&root, 0o757);
    assert!(securefs::check_trusted_dir(&home, me, &securefs::SysGroups).unwrap_err().contains("world-writable"));
    // Group-write above it: refused in a shared group, accepted in this user's
    // private group (never for root), with injected group data.
    use std::os::unix::fs::MetadataExt;
    set(&root, 0o775);
    let gid = std::fs::metadata(&root).unwrap().gid();
    let mut shared = me_db(me, gid);
    shared.passwd.push((me + 1, "other", gid));
    assert!(securefs::check_trusted_dir(&home, me, &shared).unwrap_err().contains("writable by group"));
    assert_eq!(securefs::check_trusted_dir(&home, me, &me_db(me, gid)).is_ok(), me != 0);
    let sss = FakeDb { nss: Some("passwd: files sss\ngroup: files sss\n"), ..me_db(me, gid) };
    let why = if me == 0 { "root's paths never" } else { "uses `sss`" };
    assert!(securefs::check_trusted_dir(&home, me, &sss).unwrap_err().contains(why));
    set(&root, 0o755);
    // A symlink in a trusted dir to a trusted dir is fine, and so is the target.
    std::os::unix::fs::symlink(&home, root.join("link")).unwrap();
    assert_eq!(securefs::check_trusted_dir(&root.join("link"), me, &securefs::SysGroups), Ok(()));
    // A symlink in a directory others can write could be repointed later.
    let ww = root.join("ww");
    std::fs::create_dir(&ww).unwrap();
    std::os::unix::fs::symlink(&home, ww.join("link")).unwrap();
    set(&ww, 0o777);
    assert!(securefs::check_trusted_dir(&ww.join("link"), me, &securefs::SysGroups).is_err());
    // A symlink from a trusted dir into an untrusted one.
    std::os::unix::fs::symlink(&ww, root.join("to-ww")).unwrap();
    assert!(securefs::check_trusted_dir(&root.join("to-ww"), me, &securefs::SysGroups).unwrap_err().contains("writable"));
    set(&ww, 0o755);
    #[cfg(target_os = "macos")]
    assert_eq!(securefs::check_trusted_dir(Path::new("/var/root"), 0, &securefs::SysGroups), Ok(()), "/var is root's symlink to /private/var");
    let _ = std::fs::remove_dir_all(&root);
}

/// The service account's home is pinned when the credential is found there; the
/// credential's own home otherwise, and never one others can write.
#[cfg(unix)]
#[test]
fn pin_target_prefers_the_service_home_and_refuses_an_untrusted_one() {
    use std::os::unix::fs::PermissionsExt;
    let me = securefs::euid();
    let root = scratch("pin");
    let home = home_with_secret(&root, "h");
    let loaded = path_in(&home);
    let nowhere = root.join("no-such-service-home");
    assert_eq!(pin_target(&home, &loaded, &nowhere, me, &same_file), Ok(home.clone()));
    // The service home names the same directory (here through a symlink): pin it.
    let svc = root.join("svc");
    std::os::unix::fs::symlink(&home, &svc).unwrap();
    assert_eq!(pin_target(&home, &loaded, &svc, me, &same_file), Ok(svc.clone()));
    // A home, or its .it-ai, that others can write is never pinned.
    for d in [home.clone(), home.join(".it-ai")] {
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(pin_target(&home, &loaded, &nowhere, me, &same_file).unwrap_err().contains("not safe to pin"), "{}", d.display());
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    // Through plan_file: an old unit whose secret lives in a world-writable home is
    // left alone instead of being pinned there.
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o777)).unwrap();
    let old = "[Service]\nExecStart=/bin/it-ai --relay https://hub.example --relay-token htok_old\n";
    let pin_to = |h: &Path| pin_target(h, &loaded, &nowhere, me, &same_file);
    let r = plan_file(Kind::Unit, old, &root.join("it-ai.service"), &loaded, true, &same_file, &pin_to);
    assert!(matches!(&r, Err(e) if e.contains("not safe to pin")), "{r:?}");
    let _ = std::fs::remove_dir_all(&root);
}
