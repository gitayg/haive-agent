use super::inplace::*;
use super::{requirement, APP_NAME};
use std::collections::BTreeMap;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "itai-inplace-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn write(path: &Path, bytes: &str, mode: u32) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// Every entry under `root`: its kind, contents (or link target) and mode.
fn snapshot(root: &Path) -> BTreeMap<PathBuf, (char, Vec<u8>, u32)> {
    let mut out = BTreeMap::new();
    let mut todo = vec![root.to_path_buf()];
    while let Some(dir) = todo.pop() {
        for e in std::fs::read_dir(&dir).unwrap() {
            let p = e.unwrap().path();
            let m = std::fs::symlink_metadata(&p).unwrap();
            let rel = p.strip_prefix(root).unwrap().to_path_buf();
            let mode = m.permissions().mode() & 0o7777;
            if m.file_type().is_symlink() {
                out.insert(rel, ('l', std::fs::read_link(&p).unwrap().into_os_string().into_encoded_bytes(), 0));
            } else if m.is_dir() {
                out.insert(rel, ('d', Vec::new(), mode));
                todo.push(p);
            } else {
                out.insert(rel, ('f', std::fs::read(&p).unwrap(), mode));
            }
        }
    }
    out
}

/// The installed IT-AI.app this user owns, inside a folder made unwritable (as
/// /Applications is to a standard user), and the new app staged elsewhere.
struct Setup {
    d: PathBuf,
    parent: PathBuf,
    app: PathBuf,
    new_app: PathBuf,
    backup: PathBuf,
}

impl Setup {
    fn new(tag: &str) -> Setup {
        let d = scratch(tag);
        let parent = d.join("Applications");
        let app = parent.join(APP_NAME);
        write(&app.join("Contents/MacOS/it-ai"), "old executable", 0o755);
        write(&app.join("Contents/Info.plist"), "old plist", 0o644);
        // The old layout's top-level CodeResources, which the new app does not have.
        write(&app.join("Contents/CodeResources"), "old seal", 0o644);
        write(&app.join("Contents/Resources/Old.lproj/x.strings"), "old only", 0o644);
        std::os::unix::fs::symlink("MacOS/it-ai", app.join("Contents/link")).unwrap();
        let new_app = d.join("stage/app").join(APP_NAME);
        write(&new_app.join("Contents/MacOS/it-ai"), "new executable", 0o755);
        write(&new_app.join("Contents/Info.plist"), "new plist", 0o644);
        write(&new_app.join("Contents/_CodeSignature/CodeResources"), "new seal", 0o644);
        write(&new_app.join("Contents/Resources/AppIcon.icns"), "icon", 0o600);
        std::os::unix::fs::symlink("Resources/AppIcon.icns", new_app.join("Contents/link")).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o555)).unwrap();
        let backup = d.join("stage/backup").join(APP_NAME);
        Setup { d, parent, app, new_app, backup }
    }
}

impl Drop for Setup {
    fn drop(&mut self) {
        let _ = std::fs::set_permissions(&self.parent, std::fs::Permissions::from_mode(0o755));
        let _ = std::fs::remove_dir_all(&self.d);
    }
}

#[test]
fn an_unwritable_app_folder_falls_back_to_in_place_and_other_errors_do_not() {
    let s = Setup::new("beside");
    let stage = s.parent.join(".IT-AI-update-1");
    // The failure the agent logged 54 times on a standard user's Mac.
    let e = std::fs::create_dir(&stage).unwrap_err();
    assert_eq!(e.raw_os_error(), Some(13), "{e}");
    assert!(matches!(stage_beside(&stage), Ok(Beside::Denied(_))), "a permission error must choose the in-place install");
    // Any other failure keeps today's error.
    let missing = s.d.join("no-such-folder/.IT-AI-update-1");
    let err = stage_beside(&missing).err().expect("a missing folder is not a permission error");
    assert!(err.starts_with("cannot stage the update next to the app:"), "{err}");
    // And a writable folder stages beside the app as before.
    let ok = s.d.join(".IT-AI-update-1");
    assert!(matches!(stage_beside(&ok), Ok(Beside::Staged)));
    assert!(ok.is_dir());
}

#[test]
fn the_in_place_stage_is_owner_only_and_new_each_time() {
    let d = scratch("stage");
    let home = d.join(".it-ai");
    let a = make_stage(&home, "1").unwrap();
    assert_eq!(std::fs::metadata(&a).unwrap().permissions().mode() & 0o777, 0o700);
    assert!(a.file_name().unwrap().to_string_lossy().starts_with(STAGE_PREFIX));
    assert!(make_stage(&home, "1").is_err(), "an attempt never reuses a folder that already exists");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn an_in_place_install_replaces_the_bundle_and_never_writes_the_running_executable() {
    use std::io::Read;
    let s = Setup::new("install");
    let exe = s.app.join("Contents/MacOS/it-ai");
    // The running agent's executable: held open, as the process holds its image.
    let mut running = std::fs::File::open(&exe).unwrap();
    let old_ino = std::fs::metadata(&exe).unwrap().ino();
    let app_ino = std::fs::metadata(&s.app).unwrap().ino();
    let before_parent = snapshot(&s.parent).keys().filter(|k| k.components().count() == 1).cloned().collect::<Vec<_>>();

    backup(&s.app, &s.backup).unwrap();
    put_in_place(&s.app, &s.new_app, &s.backup, |_| Ok(())).unwrap();

    assert_eq!(snapshot(&s.app), snapshot(&s.new_app), "the installed bundle is exactly the new one");
    assert!(!s.app.join("Contents/CodeResources").exists(), "the old bundle's stale CodeResources was left behind");
    assert!(!s.app.join("Contents/Resources/Old.lproj").exists());
    let new_ino = std::fs::metadata(&exe).unwrap().ino();
    assert_ne!(new_ino, old_ino, "the executable's path must point at a new file");
    let mut old_bytes = String::new();
    running.read_to_string(&mut old_bytes).unwrap();
    assert_eq!(old_bytes, "old executable", "the running executable's inode was written");
    assert_eq!(running.metadata().unwrap().ino(), old_ino);
    assert_eq!(running.metadata().unwrap().nlink(), 0, "the old executable is unlinked but still alive for the running process");
    assert_eq!(std::fs::metadata(&s.app).unwrap().ino(), app_ino, "the bundle itself stays where it is");
    let after_parent = snapshot(&s.parent).keys().filter(|k| k.components().count() == 1).cloned().collect::<Vec<_>>();
    assert_eq!(after_parent, before_parent, "nothing was created beside the app");
}

#[test]
fn a_failed_verification_restores_the_current_app_byte_for_byte() {
    let s = Setup::new("verifyfail");
    let before = snapshot(&s.app);
    backup(&s.app, &s.backup).unwrap();
    let seen = std::cell::Cell::new(false);
    let e = put_in_place(&s.app, &s.new_app, &s.backup, |a| {
        // Verification looks at the installed bundle, with the new contents in it.
        seen.set(std::fs::read_to_string(a.join("Contents/MacOS/it-ai")).unwrap() == "new executable");
        Err("not signed".to_string())
    })
    .unwrap_err();
    assert!(seen.get(), "verification did not see the installed new app");
    assert_eq!(e, "the installed app failed verification (not signed); kept the current one");
    assert_eq!(snapshot(&s.app), before, "the current app was not restored exactly");
}

#[test]
fn a_file_and_a_folder_may_trade_places() {
    let d = scratch("kinds");
    let (dst, src) = (d.join("dst"), d.join("src"));
    write(&dst.join("a"), "a file", 0o644);
    write(&dst.join("b/inner"), "in a folder", 0o644);
    write(&src.join("a/inner"), "now a folder", 0o644);
    write(&src.join("b"), "now a file", 0o644);
    replace_contents(&dst, &src).unwrap();
    assert_eq!(snapshot(&dst), snapshot(&src));
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn startup_removes_only_in_place_stages() {
    let d = scratch("cleanup");
    let stage = make_stage(&d, "7").unwrap();
    std::fs::create_dir_all(stage.join("backup/IT-AI.app")).unwrap();
    write(&d.join("agent.log"), "keep", 0o644);
    std::fs::create_dir_all(d.join("jobs")).unwrap();
    cleanup(&d);
    assert!(!stage.exists(), "the stage was left behind");
    assert!(d.join("agent.log").exists() && d.join("jobs").exists(), "cleanup removed the agent's own files");
    let _ = std::fs::remove_dir_all(&d);
}

/// The real `codesign` check, as `install` passes it: an ad hoc signed app with our
/// bundle id is refused after it was put in place, and the current app comes back.
#[test]
fn an_installed_app_that_fails_the_requirement_is_rolled_back() {
    use std::process::Command;
    let s = Setup::new("codesign");
    std::fs::remove_file(s.new_app.join("Contents/_CodeSignature/CodeResources")).unwrap();
    std::fs::remove_file(s.new_app.join("Contents/link")).unwrap();
    std::fs::copy("/usr/bin/true", s.new_app.join("Contents/MacOS/it-ai")).unwrap();
    std::fs::write(
        s.new_app.join("Contents/Info.plist"),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict><key>CFBundleExecutable</key><string>it-ai</string><key>CFBundleIdentifier</key><string>com.itai.agent</string><key>CFBundleShortVersionString</key><string>99.0.0</string></dict></plist>\n",
    )
    .unwrap();
    assert!(Command::new("/usr/bin/codesign").args(["--force", "--sign", "-"]).arg(&s.new_app).status().unwrap().success());
    let before = snapshot(&s.app);
    backup(&s.app, &s.backup).unwrap();
    let e = put_in_place(&s.app, &s.new_app, &s.backup, super::meets_requirement).unwrap_err();
    assert!(e.starts_with("the installed app failed verification ("), "{e}");
    assert!(e.ends_with("; kept the current one"), "{e}");
    assert_eq!(snapshot(&s.app), before);
    // Control: the same bundle passes a requirement it does meet, so the refusal was the requirement's.
    let r = format!("-R={}", "identifier \"com.itai.agent\"");
    assert!(Command::new("/usr/bin/codesign").args(["--verify", "--deep", "--strict", &r]).arg(&s.new_app).status().unwrap().success());
    assert!(requirement().contains("DA4PX65QXV"));
}
