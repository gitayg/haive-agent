use super::*;
use std::fs;

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("it-ai-ws-test-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn age(p: &Path, by: Duration) {
    #[cfg(unix)]
    let f = fs::File::open(p).unwrap();
    #[cfg(windows)]
    let f = {
        use std::os::windows::fs::OpenOptionsExt;
        fs::OpenOptions::new().write(true).custom_flags(0x0200_0000).open(p).unwrap() // FILE_FLAG_BACKUP_SEMANTICS
    };
    f.set_modified(SystemTime::now() - by).unwrap();
}

#[test]
fn workspace_create_is_fresh_and_never_reused() {
    let base = scratch("create");
    let root = base.join("workspaces");
    let d = create(&root, "j1").unwrap();
    assert_eq!(d, root.join("j1"));
    assert!(d.is_dir());
    assert!(create(&root, "j1").is_err(), "an existing workspace must not be reused");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&d).unwrap().permissions().mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(&root).unwrap().permissions().mode() & 0o777, 0o700);
    }
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn workspace_remove_takes_read_only_entries() {
    let base = scratch("ro");
    let d = create(&base.join("workspaces"), "j2").unwrap();
    let sub = d.join("cache").join("mod");
    fs::create_dir_all(&sub).unwrap();
    fs::write(sub.join("pack"), b"x").unwrap();
    let mut p = fs::metadata(sub.join("pack")).unwrap().permissions();
    p.set_readonly(true);
    fs::set_permissions(sub.join("pack"), p).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&sub, fs::Permissions::from_mode(0o500)).unwrap();
    }
    assert!(remove(&d), "read-only entries kept the workspace alive");
    assert!(!d.exists());
    assert!(remove(&d), "removing a gone workspace is success");
    let _ = fs::remove_dir_all(&base);
}

#[cfg(unix)]
#[test]
fn workspace_remove_never_follows_a_link_out() {
    use std::os::unix::fs::PermissionsExt;
    let base = scratch("link");
    let outside = base.join("outside");
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("keep"), b"k").unwrap();
    fs::set_permissions(outside.join("keep"), fs::Permissions::from_mode(0o400)).unwrap();
    let d = create(&base.join("workspaces"), "j3").unwrap();
    std::os::unix::fs::symlink(&outside, d.join("dirlink")).unwrap();
    std::os::unix::fs::symlink(outside.join("keep"), d.join("filelink")).unwrap();
    // A file in a read-only dir forces the make-writable pass, which must skip the links.
    fs::create_dir(d.join("ro")).unwrap();
    fs::write(d.join("ro").join("f"), b"x").unwrap();
    fs::set_permissions(d.join("ro"), fs::Permissions::from_mode(0o500)).unwrap();
    assert!(remove(&d));
    assert!(!d.exists());
    assert_eq!(fs::read(outside.join("keep")).unwrap(), b"k");
    assert_eq!(fs::metadata(outside.join("keep")).unwrap().permissions().mode() & 0o777, 0o400, "chmod went through a link");
    let _ = fs::set_permissions(outside.join("keep"), fs::Permissions::from_mode(0o600));
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn workspace_sweep_removes_only_entries_older_than_the_age() {
    let base = scratch("sweep");
    let root = base.join("workspaces");
    let old = create(&root, "jold").unwrap();
    fs::write(old.join("f"), b"x").unwrap();
    let fresh = create(&root, "jfresh").unwrap();
    fs::write(fresh.join("f"), b"x").unwrap();
    fs::write(root.join("stray"), b"x").unwrap();
    age(&old, Duration::from_secs(25 * 3600));
    age(&root.join("stray"), Duration::from_secs(25 * 3600));
    assert_eq!(sweep(&root, SWEEP_AGE), 2);
    assert!(!old.exists() && !root.join("stray").exists());
    assert!(fresh.join("f").exists(), "a workspace younger than 24 h was swept");
    assert_eq!(sweep(&base.join("missing"), SWEEP_AGE), 0);
    let _ = fs::remove_dir_all(&base);
}

#[cfg(unix)]
#[test]
fn workspace_sweep_removes_an_old_link_not_its_target() {
    let base = scratch("sweeplink");
    let root = base.join("workspaces");
    fs::create_dir_all(&root).unwrap();
    let outside = base.join("outside");
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("keep"), b"k").unwrap();
    std::os::unix::fs::symlink(&outside, root.join("jlink")).unwrap();
    let t = SystemTime::now() - Duration::from_secs(25 * 3600);
    let ts = libc::timespec { tv_sec: t.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as libc::time_t, tv_nsec: 0 };
    let c = std::ffi::CString::new(root.join("jlink").as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::utimensat(libc::AT_FDCWD, c.as_ptr(), [ts, ts].as_ptr(), libc::AT_SYMLINK_NOFOLLOW) }, 0);
    assert_eq!(sweep(&root, SWEEP_AGE), 1);
    assert!(root.join("jlink").symlink_metadata().is_err());
    assert_eq!(fs::read(outside.join("keep")).unwrap(), b"k");
    let _ = fs::remove_dir_all(&base);
}
