use super::*;
use std::path::Path;

fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "itai-appbundle-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn fake_app(at: &Path, marker: &str) {
    std::fs::create_dir_all(at.join("Contents/MacOS")).unwrap();
    std::fs::write(at.join("Contents/MacOS/it-ai"), marker).unwrap();
}

fn marker(app: &Path) -> String {
    std::fs::read_to_string(app.join("Contents/MacOS/it-ai")).unwrap()
}

#[test]
fn the_bundle_is_found_only_for_an_app_executable() {
    assert_eq!(bundle_of(Path::new("/Applications/IT-AI.app/Contents/MacOS/it-ai")), Some(PathBuf::from("/Applications/IT-AI.app")));
    assert_eq!(bundle_of(Path::new("/Applications/Other.APP/Contents/MacOS/x")), Some(PathBuf::from("/Applications/Other.APP")));
    // The bare binary, as install.sh puts it, is not in a bundle.
    assert_eq!(bundle_of(Path::new("/usr/local/bin/it-ai")), None);
    assert_eq!(bundle_of(Path::new("/opt/it-ai/Contents/MacOS/it-ai")), None, "a Contents/MacOS that is not inside a .app");
    assert_eq!(bundle_of(Path::new("/Applications/IT-AI.app/Contents/Resources/it-ai")), None);
    assert_eq!(bundle_of(Path::new("it-ai")), None);
}

#[test]
fn not_macos_means_no_bundle() {
    if cfg!(not(target_os = "macos")) {
        assert_eq!(running_bundle(), None);
    }
}

#[test]
fn the_zip_sits_beside_the_binary_the_hub_named() {
    assert_eq!(zip_url("https://hub.example/bin/it-ai-macos").as_deref(), Some("https://hub.example/bin/IT-AI-macos.zip"));
    assert_eq!(zip_url("https://hub.example/bin/it-ai-macos?x=1#y").as_deref(), Some("https://hub.example/bin/IT-AI-macos.zip"));
    assert_eq!(zip_url("https://hub.example/sub/bin/it-ai-macos").as_deref(), Some("https://hub.example/sub/bin/IT-AI-macos.zip"));
    assert_eq!(zip_url("it-ai-macos"), None);
    assert_eq!(zip_url("https://hub.example/bin/"), None);
}

#[test]
fn only_a_strictly_newer_version_is_newer() {
    assert!(is_newer("3.14.0", "3.13.1"));
    assert!(is_newer("3.13.10", "3.13.9"), "numeric, not text, comparison");
    assert!(is_newer("v4.0.0", "3.99.99"));
    assert!(!is_newer("3.13.1", "3.13.1"), "the same version is not an update");
    assert!(!is_newer("3.14", "3.14.0"));
    assert!(!is_newer("3.12.0", "3.13.1"), "a downgrade is refused");
    assert!(!is_newer("3.14.0-beta", "3.13.1"), "an unparsable version is not newer");
    assert!(!is_newer("", "3.13.1"));
}

#[test]
fn the_version_is_read_from_the_info_plist() {
    let plist = "<?xml version=\"1.0\"?>\n<plist version=\"1.0\">\n<dict>\n\t<key>CFBundleIdentifier</key>\n\t<string>com.itai.agent</string>\n\t<key>CFBundleShortVersionString</key>\n\t<string> 3.14.0 </string>\n\t<key>CFBundleVersion</key>\n\t<string>42</string>\n</dict>\n</plist>\n";
    assert_eq!(plist_version(plist).as_deref(), Some("3.14.0"));
    assert_eq!(plist_version("<dict><key>CFBundleVersion</key><string>42</string></dict>"), None);
    // The key is followed by something other than its string: not a version.
    assert_eq!(plist_version("<key>CFBundleShortVersionString</key><true/><key>X</key><string>9.9.9</string>"), None);
}

#[test]
fn the_requirement_pins_the_team_the_app_and_developer_id() {
    let r = requirement();
    assert!(r.starts_with("anchor apple generic"));
    assert!(r.contains("identifier \"com.itai.agent\""));
    assert!(r.contains("certificate leaf[subject.OU] = \"DA4PX65QXV\""));
    // Developer ID intermediate and leaf: an Apple Development build of the same team fails.
    assert!(r.contains("certificate 1[field.1.2.840.113635.100.6.2.6] exists"));
    assert!(r.contains("certificate leaf[field.1.2.840.113635.100.6.1.13] exists"));
}

#[test]
fn a_swap_puts_the_new_app_in_place_and_keeps_the_old_one() {
    let d = scratch("swap");
    let (app, new_app, old) = (d.join("IT-AI.app"), d.join("stage/IT-AI.app"), d.join(".IT-AI.app.old-1"));
    fake_app(&app, "old");
    fake_app(&new_app, "new");
    swap(&app, &new_app, &old).unwrap();
    assert_eq!(marker(&app), "new");
    assert_eq!(marker(&old), "old");
    unswap(&app, &new_app, &old).unwrap();
    assert_eq!(marker(&app), "old", "undoing the swap restores the running app");
    assert_eq!(marker(&new_app), "new");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_failed_swap_leaves_the_current_app_in_place() {
    let d = scratch("swapfail");
    let (app, missing, old) = (d.join("IT-AI.app"), d.join("stage/IT-AI.app"), d.join(".IT-AI.app.old-1"));
    fake_app(&app, "old");
    let e = swap(&app, &missing, &old).unwrap_err();
    assert!(e.contains("cannot move the new app in"), "{e}");
    assert_eq!(marker(&app), "old", "the running app was not put back");
    assert!(!old.exists());
    let _ = std::fs::remove_dir_all(&d);
}

/// The real check, macOS only: an app signed ad hoc (no Developer ID) with our
/// bundle id must not meet the requirement `install` verifies against.
#[cfg(target_os = "macos")]
#[test]
fn an_ad_hoc_signed_app_fails_the_requirement() {
    use std::process::Command;
    let d = scratch("codesign");
    let app = d.join("IT-AI.app");
    std::fs::create_dir_all(app.join("Contents/MacOS")).unwrap();
    std::fs::copy("/usr/bin/true", app.join("Contents/MacOS/it-ai")).unwrap();
    std::fs::write(
        app.join("Contents/Info.plist"),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict><key>CFBundleExecutable</key><string>it-ai</string><key>CFBundleIdentifier</key><string>com.itai.agent</string><key>CFBundleShortVersionString</key><string>99.0.0</string></dict></plist>\n",
    )
    .unwrap();
    assert!(Command::new("/usr/bin/codesign").args(["--force", "--sign", "-"]).arg(&app).status().unwrap().success());
    let ok = Command::new("/usr/bin/codesign")
        .args(["--verify", "--deep", "--strict"])
        .arg(format!("-R={}", requirement()))
        .arg(&app)
        .status()
        .unwrap()
        .success();
    assert!(!ok, "an ad hoc signature met the Developer ID requirement");
    // Control: the same app passes a requirement it does meet, so the failure above is the requirement's.
    assert!(Command::new("/usr/bin/codesign").args(["--verify", "--deep", "--strict", "-R=identifier \"com.itai.agent\""]).arg(&app).status().unwrap().success());
    let _ = std::fs::remove_dir_all(&d);
}
