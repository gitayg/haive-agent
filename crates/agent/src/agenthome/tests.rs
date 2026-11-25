use super::*;

fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "it-ai-agenthome-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn never(_: &Path) -> bool {
    false
}

fn root_passwd() -> Option<PathBuf> {
    Some(PathBuf::from("/root"))
}

/// `<home>/.it-ai/relay.cred` holding `bytes`.
fn with_cred(home: &Path, bytes: &[u8]) {
    std::fs::create_dir_all(home.join(".it-ai")).unwrap();
    std::fs::write(crate::relaycred::path_in(home), bytes).unwrap();
}

#[test]
fn a_set_home_is_used_unchanged() {
    let always = |_: &Path| true;
    assert_eq!(pick(Some("/home/u"), Some(Path::new("/")), &always, &root_passwd), PathBuf::from("/home/u"));
    assert_eq!(pick(Some("/home/u/"), None, &never, &|| None), PathBuf::from("/home/u/"));
}

#[test]
fn no_home_takes_the_passwd_home_not_a_relative_path() {
    assert_eq!(pick(None, Some(Path::new("/")), &never, &root_passwd), PathBuf::from("/root"));
    assert_eq!(pick(Some(""), Some(Path::new("/")), &never, &root_passwd), PathBuf::from("/root"));
}

#[cfg(unix)]
#[test]
fn the_passwd_home_comes_from_the_os() {
    let want = if cfg!(target_os = "macos") { "/var/root" } else { "/root" };
    assert_eq!(passwd_home(0), Some(PathBuf::from(want)));
    assert_eq!(os_home().map(|h| h.is_absolute()), Some(true));
}

#[test]
fn the_home_is_never_relative() {
    let rel = pick(Some("rel/home"), None, &never, &|| None);
    assert!(rel.is_absolute() && rel.ends_with("rel/home"), "{}", rel.display());
    for os in [None, Some(PathBuf::from("relative")), Some(PathBuf::new())] {
        let h = pick(None, Some(Path::new("legacy")), &|_| true, &|| os.clone());
        assert!(h.is_absolute(), "{} from os home {os:?}", h.display());
    }
    assert!(Path::new(&crate::persistence::home()).is_absolute());
}

/// glick-run: no HOME, everything in `/.it-ai`, an empty `/root/.it-ai`. The
/// legacy directory stays the home, so the agent loads the very same bytes.
#[cfg(unix)]
#[test]
fn a_legacy_dir_in_use_stays_the_home_with_the_same_credential() {
    let d = scratch("legacy");
    let (legacy, passwd) = (d.join("slash"), d.join("root"));
    let cred = br#"{"hub":"https://hub.example","device":"dsec_KEEP_ME"}"#;
    with_cred(&legacy, cred);
    std::fs::create_dir_all(passwd.join(".it-ai")).unwrap();
    let me = unsafe { libc::geteuid() };
    let h = pick(None, Some(&legacy), &|l| owned_dir(l, me), &|| Some(passwd.clone()));
    assert_eq!(h, legacy);
    assert_eq!(std::fs::read(crate::relaycred::path_in(&h)).unwrap(), cred);
    assert!(!crate::relaycred::path_in(&passwd).exists(), "nothing was moved or copied");
}

/// Even a passwd home with a credential of its own does not take over: with no
/// HOME, the legacy credential is the identity every agent has been using.
#[cfg(unix)]
#[test]
fn a_legacy_dir_in_use_wins_over_a_passwd_home_with_another_credential() {
    let d = scratch("both");
    let (legacy, passwd) = (d.join("slash"), d.join("root"));
    with_cred(&legacy, b"legacy");
    with_cred(&passwd, b"other");
    let me = unsafe { libc::geteuid() };
    let h = pick(None, Some(&legacy), &|l| owned_dir(l, me), &|| Some(passwd.clone()));
    assert_eq!(std::fs::read(crate::relaycred::path_in(&h)).unwrap(), b"legacy");
}

/// An older agent run after a downgrade leaves a `/.it-ai` with a cert and no
/// credential; the device's credential in the passwd home must still be used.
#[cfg(unix)]
#[test]
fn a_legacy_dir_without_a_credential_does_not_take_over_from_one_with_it() {
    let d = scratch("downgraded");
    let (legacy, passwd) = (d.join("slash"), d.join("root"));
    std::fs::create_dir_all(legacy.join(".it-ai")).unwrap();
    std::fs::write(legacy.join(".it-ai").join("cert.pem"), b"cert").unwrap();
    with_cred(&passwd, b"issued");
    let me = unsafe { libc::geteuid() };
    let h = pick(None, Some(&legacy), &|l| owned_dir(l, me), &|| Some(passwd.clone()));
    assert_eq!(std::fs::read(crate::relaycred::path_in(&h)).unwrap(), b"issued");
    // With no credential anywhere, the legacy directory (its cert, schedules) stays.
    std::fs::remove_file(crate::relaycred::path_in(&passwd)).unwrap();
    assert_eq!(pick(None, Some(&legacy), &|l| owned_dir(l, me), &|| Some(passwd.clone())), legacy);
}

#[cfg(unix)]
#[test]
fn no_legacy_dir_means_the_passwd_home() {
    let d = scratch("none");
    let me = unsafe { libc::geteuid() };
    assert_eq!(pick(None, Some(&d), &|l| owned_dir(l, me), &root_passwd), PathBuf::from("/root"));
}

/// Someone else's `.it-ai`, or a link to one, is never adopted.
#[cfg(unix)]
#[test]
fn a_legacy_dir_of_another_user_or_a_link_is_not_adopted() {
    let d = scratch("foreign");
    let me = unsafe { libc::geteuid() };
    let theirs = d.join("theirs");
    with_cred(&theirs, b"planted");
    assert!(owned_dir(&theirs, me));
    assert!(!owned_dir(&theirs, me + 1));
    assert_eq!(pick(None, Some(&theirs), &|l| owned_dir(l, me + 1), &root_passwd), PathBuf::from("/root"));

    let linked = d.join("linked");
    std::fs::create_dir_all(&linked).unwrap();
    std::os::unix::fs::symlink(theirs.join(".it-ai"), linked.join(".it-ai")).unwrap();
    assert!(!owned_dir(&linked, me));
    assert_eq!(pick(None, Some(&linked), &|l| owned_dir(l, me), &root_passwd), PathBuf::from("/root"));
}

#[cfg(unix)]
#[test]
fn a_legacy_file_named_it_ai_is_not_a_home() {
    let d = scratch("file");
    std::fs::write(d.join(".it-ai"), b"x").unwrap();
    let me = unsafe { libc::geteuid() };
    assert!(!owned_dir(&d, me));
}
