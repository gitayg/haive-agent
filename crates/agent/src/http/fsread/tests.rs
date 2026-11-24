use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use super::*;
use crate::http::{handle, privileged_path, resolve_path};

fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("it-ai-fsread-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn cfg(share: &str, direct_token: &str) -> Config {
    Config {
        password: String::new(),
        port: 0,
        quality: 60,
        max_width: 1600,
        exec_enabled: false,
        tls: false,
        share: share.to_string(),
        grabber: crate::capture::Grabber { index: 0 },
        cert: None,
        direct_token: direct_token.to_string(),
    }
}

/// The real request handler on a loopback port, so routing and the auth gate
/// are exercised exactly as the relay's self-calls hit them.
fn serve(c: Config) -> u16 {
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let port = server.server_addr().to_ip().unwrap().port();
    std::thread::spawn(move || {
        let (tx, _rx) = std::sync::mpsc::channel();
        for req in server.incoming_requests() {
            handle(req, &c, &tx);
        }
    });
    port
}

fn enc(s: &str) -> String {
    s.bytes().map(|b| if b.is_ascii_alphanumeric() { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
}

fn get(port: u16, path_and_query: &str) -> (u16, String) {
    match ureq::get(&format!("http://127.0.0.1:{port}{path_and_query}")).timeout(Duration::from_secs(10)).call() {
        Ok(r) => (r.status(), r.into_string().unwrap()),
        Err(ureq::Error::Status(code, r)) => (code, r.into_string().unwrap()),
        Err(e) => panic!("{path_and_query}: {e}"),
    }
}

fn get_json(port: u16, path_and_query: &str) -> (u16, serde_json::Value) {
    let (code, body) = get(port, path_and_query);
    (code, serde_json::from_str(&body).unwrap_or_else(|_| panic!("{path_and_query}: not JSON: {body}")))
}

fn set_mtime(p: &Path, secs: u64) {
    std::fs::File::options().write(true).open(p).unwrap().set_modified(UNIX_EPOCH + Duration::from_secs(secs)).unwrap();
}

fn entry<'a>(entries: &'a [serde_json::Value], name: &str) -> &'a serde_json::Value {
    entries.iter().find(|e| e["name"] == name).unwrap_or_else(|| panic!("no entry {name} in {entries:?}"))
}

#[test]
fn list_entries_carry_mtime_and_keep_the_old_fields_and_sort() {
    let d = scratch("list-mtime");
    std::fs::write(d.join("b.txt"), b"12345").unwrap();
    set_mtime(&d.join("b.txt"), 1_700_000_000);
    std::fs::create_dir(d.join("Zdir")).unwrap();
    std::fs::write(d.join("A.txt"), b"x").unwrap();
    let (entries, truncated) = list_dir(&d, LIST_CAP);
    assert!(!truncated);
    let names: Vec<&str> = entries.iter().map(|e| e["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["Zdir", "A.txt", "b.txt"]);
    let b = entry(&entries, "b.txt");
    assert_eq!(b["size"], 5);
    assert_eq!(b["dir"], false);
    assert_eq!(b["mtime"], 1_700_000_000u64);
    assert_eq!(b["link"], false);
    assert_eq!(entry(&entries, "Zdir")["dir"], true);
    let _ = std::fs::remove_dir_all(&d);
}

#[cfg(unix)]
#[test]
fn list_marks_symlinks_as_links() {
    let d = scratch("list-link");
    std::fs::write(d.join("target.txt"), b"abc").unwrap();
    std::os::unix::fs::symlink(d.join("target.txt"), d.join("ln")).unwrap();
    let (entries, _) = list_dir(&d, LIST_CAP);
    assert_eq!(entry(&entries, "ln")["link"], true);
    assert_eq!(entry(&entries, "target.txt")["link"], false);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn list_stops_at_the_cap_and_says_so() {
    assert_eq!(LIST_CAP, 2000);
    let d = scratch("list-cap");
    for i in 0..5 {
        std::fs::write(d.join(format!("f{i}")), b"").unwrap();
    }
    let (entries, truncated) = list_dir(&d, 3);
    assert_eq!(entries.len(), 3);
    assert!(truncated);
    assert_eq!(entries[2]["name"], "f2");
    let (entries, truncated) = list_dir(&d, 5);
    assert_eq!(entries.len(), 5);
    assert!(!truncated);
    let port = serve(cfg("", ""));
    let (code, v) = get_json(port, &format!("/list?path={}", enc(&d.to_string_lossy())));
    assert_eq!(code, 200);
    assert_eq!(v["truncated"], false);
    assert_eq!(v["entries"].as_array().unwrap().len(), 5);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn stat_of_a_file() {
    let d = scratch("stat-file");
    let f = d.join("f.bin");
    std::fs::write(&f, vec![7u8; 1234]).unwrap();
    set_mtime(&f, 1_600_000_000);
    let v = stat(&f);
    assert_eq!(v["ok"], true);
    assert_eq!(v["exists"], true);
    assert_eq!(v["kind"], "file");
    assert_eq!(v["size"], 1234);
    assert_eq!(v["mtime"], 1_600_000_000u64);
    assert_eq!(v["readonly"], false);
    assert_eq!(v["path"], f.to_string_lossy().as_ref());
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn stat_of_a_dir() {
    let d = scratch("stat-dir");
    let v = stat(&d);
    assert_eq!(v["exists"], true);
    assert_eq!(v["kind"], "dir");
    let _ = std::fs::remove_dir_all(&d);
}

#[cfg(unix)]
#[test]
fn stat_of_a_symlink_is_a_symlink_with_its_targets_size() {
    let d = scratch("stat-link");
    std::fs::write(d.join("t"), vec![0u8; 4321]).unwrap();
    std::os::unix::fs::symlink(d.join("t"), d.join("ln")).unwrap();
    let v = stat(&d.join("ln"));
    assert_eq!(v["kind"], "symlink");
    assert_eq!(v["size"], 4321);
    std::os::unix::fs::symlink(d.join("gone"), d.join("dangling")).unwrap();
    let v = stat(&d.join("dangling"));
    assert_eq!(v["exists"], true);
    assert_eq!(v["kind"], "symlink");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn stat_of_a_missing_path_says_it_does_not_exist() {
    let d = scratch("stat-missing");
    let v = stat(&d.join("nope"));
    assert_eq!(v, serde_json::json!({"ok": true, "path": d.join("nope").to_string_lossy(), "exists": false}));
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn stat_reports_readonly() {
    let d = scratch("stat-ro");
    let f = d.join("ro");
    std::fs::write(&f, b"x").unwrap();
    let mut p = std::fs::metadata(&f).unwrap().permissions();
    p.set_readonly(true);
    std::fs::set_permissions(&f, p.clone()).unwrap();
    assert_eq!(stat(&f)["readonly"], true);
    #[allow(clippy::permissions_set_readonly_false)]
    p.set_readonly(false);
    std::fs::set_permissions(&f, p).unwrap();
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn hash_of_a_known_file_matches_shasum() {
    let d = scratch("hash-abc");
    std::fs::write(d.join("abc"), b"abc").unwrap();
    let (size, sha) = sha256_file(&d.join("abc")).unwrap().unwrap();
    assert_eq!(size, 3);
    // printf abc | shasum -a 256
    assert_eq!(sha, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn hash_of_a_file_over_64k_crosses_chunks_correctly() {
    let d = scratch("hash-big");
    let f = d.join("big.bin");
    std::fs::write(&f, (0..200_003u32).map(|i| (i % 251) as u8).collect::<Vec<u8>>()).unwrap();
    let port = serve(cfg("", ""));
    let (code, v) = get_json(port, &format!("/hash?path={}", enc(&f.to_string_lossy())));
    assert_eq!(code, 200);
    assert_eq!(v["ok"], true);
    assert_eq!(v["size"], 200_003);
    // shasum -a 256 of the same 200003 bytes (i % 251), computed outside this crate.
    assert_eq!(v["sha256"], "49cbf04ab31e40bccff20650404805fc4a1f508e56d891f406ec592a2176d2e4");
    assert_eq!(v["path"], f.to_string_lossy().as_ref());
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn hash_of_a_dir_or_missing_path_is_404_not_a_file() {
    let d = scratch("hash-dir");
    let port = serve(cfg("", ""));
    for p in [d.clone(), d.join("missing")] {
        let (code, v) = get_json(port, &format!("/hash?path={}", enc(&p.to_string_lossy())));
        assert_eq!((code, v), (404, serde_json::json!({"ok": false, "error": "not a file"})), "{}", p.display());
    }
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn stat_and_hash_without_a_path_are_400() {
    let port = serve(cfg("", ""));
    for q in ["/stat", "/stat?path=", "/hash", "/hash?path=", "/hash?other=1"] {
        let (code, v) = get_json(port, q);
        assert_eq!((code, v), (400, serde_json::json!({"ok": false, "error": "path is required"})), "{q}");
    }
}

#[test]
fn with_a_share_escapes_are_403_and_inside_paths_work() {
    let d = scratch("share");
    std::fs::write(d.join("in.txt"), b"abc").unwrap();
    let port = serve(cfg(&d.to_string_lossy(), ""));
    for bad in ["../etc/passwd", "sub/../../x", "/etc/passwd", "C:\\Windows\\win.ini", "C:/Windows", "\\\\host\\share\\f", "..\\x"] {
        for ep in ["/stat", "/hash", "/list"] {
            let (code, v) = get_json(port, &format!("{ep}?path={}", enc(bad)));
            assert_eq!((code, v), (403, serde_json::json!({"ok": false, "error": "forbidden"})), "{ep} {bad}");
        }
    }
    let (code, v) = get_json(port, "/stat?path=in.txt");
    assert_eq!((code, &v["kind"], &v["size"]), (200, &serde_json::json!("file"), &serde_json::json!(3)));
    let (code, v) = get_json(port, "/hash?path=in.txt");
    assert_eq!((code, &v["sha256"]), (200, &serde_json::json!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")));
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn stat_and_hash_are_privileged_like_download() {
    for p in ["/download", "/list", "/stat", "/hash"] {
        assert!(privileged_path(p), "{p}");
    }
    let d = scratch("auth");
    std::fs::write(d.join("f"), b"abc").unwrap();
    let f = enc(&d.join("f").to_string_lossy());
    let port = serve(cfg("", "dtok-test-123"));
    assert_eq!(get(port, "/").0, 200, "the unprivileged page stays open on loopback");
    for ep in ["/download", "/stat", "/hash"] {
        let (code, body) = get(port, &format!("{ep}?path={f}"));
        assert_eq!((code, body.as_str()), (401, "Authentication required"), "{ep} without the token");
        assert_eq!(get(port, &format!("{ep}?path={f}&dtok=wrong")).0, 401, "{ep} with a wrong token");
        assert_eq!(get(port, &format!("{ep}?path={f}&dtok=dtok-test-123")).0, 200, "{ep} with the token");
    }
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn windows_drive_paths_and_backslashes_pass_through_untouched() {
    let w = "C:\\Program Files\\GitHub CLI\\gh.exe";
    assert_eq!(path_arg(&format!("/stat?path={}", enc(w))), w);
    assert_eq!(path_arg("/hash?path=C%3A%5CUsers%5Cme%5Ca%20b.txt&dtok=x"), "C:\\Users\\me\\a b.txt");
    assert_eq!(resolve_path(&cfg("", ""), w).unwrap().to_string_lossy(), w);
    assert!(resolve_path(&cfg("", ""), "C:\\Users\\..\\Windows").is_none());
    #[cfg(not(windows))]
    {
        let port = serve(cfg("", ""));
        let (code, v) = get_json(port, &format!("/stat?path={}", enc(w)));
        assert_eq!((code, v), (200, serde_json::json!({"ok": true, "path": w, "exists": false})));
    }
}

#[cfg(windows)]
#[test]
fn windows_drive_paths_stat_and_hash() {
    let port = serve(cfg("", ""));
    let (code, v) = get_json(port, &format!("/stat?path={}", enc("C:\\Windows")));
    assert_eq!((code, &v["kind"]), (200, &serde_json::json!("dir")));
    let d = scratch("win");
    std::fs::write(d.join("abc"), b"abc").unwrap();
    let p = format!("{}\\abc", d.to_string_lossy().trim_end_matches('\\'));
    let (code, v) = get_json(port, &format!("/hash?path={}", enc(&p)));
    assert_eq!((code, &v["sha256"]), (200, &serde_json::json!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")));
    let _ = std::fs::remove_dir_all(&d);
}

/// Not a correctness test: hashes `$AFS_HASH_FILE` so `/usr/bin/time -l` can
/// compare this process's peak RSS for a small and a large file.
#[test]
#[ignore]
fn hash_rss_probe() {
    let p = std::env::var("AFS_HASH_FILE").expect("AFS_HASH_FILE");
    let (size, sha) = sha256_file(Path::new(&p)).unwrap().unwrap();
    println!("{sha}  {p} ({size} bytes)");
}
