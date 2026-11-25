use super::*;
use std::fs;
use std::sync::atomic::AtomicU32;
use std::time::SystemTime;

fn scratch(name: &str) -> (PathBuf, PathBuf) {
    let d = std::env::temp_dir().join(format!("it-ai-janitor-test-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    let root = d.join("workspaces");
    (d, root)
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

/// A remove that fails its first `fails` calls (the workspace "still in use"), then removes for real.
fn flaky(fails: u32) -> (Arc<AtomicU32>, impl Fn(&Path) -> bool + Send + Sync + 'static) {
    let calls = Arc::new(AtomicU32::new(0));
    let c = calls.clone();
    (calls, move |p: &Path| c.fetch_add(1, Ordering::SeqCst) >= fails && crate::workspace::remove(p))
}

fn calls(c: &AtomicU32) -> u32 {
    c.load(Ordering::SeqCst)
}

const NOT_BUSY: &dyn Fn(&Path) -> bool = &|_| false;

#[test]
fn janitor_retries_a_left_behind_workspace_until_it_goes() {
    let (base, root) = scratch("retry");
    let (n, remove) = flaky(3);
    let j = Janitor::new(root.clone(), remove);
    let ws = crate::workspace::create(&root, "j1").unwrap();
    fs::write(ws.join("f"), b"x").unwrap();
    j.discard(&ws);
    let t0 = Instant::now();
    assert_eq!(calls(&n), 1);
    assert!(ws.exists() && j.is_pending(&ws), "a workspace that failed to go must be queued");
    assert_eq!(j.retry_due(t0, NOT_BUSY), 0);
    assert_eq!(calls(&n), 1, "retried before its first 30 s were up");
    assert_eq!(j.retry_due(t0 + FIRST_RETRY, NOT_BUSY), 0);
    assert_eq!(calls(&n), 2);
    assert_eq!(j.retry_due(t0 + FIRST_RETRY + Duration::from_secs(59), NOT_BUSY), 0);
    assert_eq!(calls(&n), 2, "the second retry did not back off to 60 s");
    assert_eq!(j.retry_due(t0 + FIRST_RETRY + Duration::from_secs(60), NOT_BUSY), 0);
    assert_eq!(calls(&n), 3);
    assert_eq!(j.retry_due(t0 + Duration::from_secs(30 + 60 + 120), NOT_BUSY), 1);
    assert_eq!(calls(&n), 4);
    assert!(!ws.exists(), "workspace {ws:?} was never removed");
    assert!(!j.is_pending(&ws));
    assert_eq!(j.retry_due(t0 + Duration::from_secs(100_000), NOT_BUSY), 0);
    assert_eq!(calls(&n), 4, "a removed workspace was retried again");
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn janitor_backs_off_to_every_ten_minutes_and_never_gives_up() {
    let (base, root) = scratch("backoff");
    let (n, remove) = flaky(u32::MAX);
    let j = Janitor::new(root.clone(), remove);
    let ws = crate::workspace::create(&root, "j1").unwrap();
    assert!(j.leave(&ws));
    let t0 = Instant::now();
    let mut tries = Vec::new();
    for s in 0..3000u64 {
        let before = calls(&n);
        j.retry_due(t0 + Duration::from_secs(s), NOT_BUSY);
        if calls(&n) != before {
            tries.push(s);
        }
    }
    assert_eq!(tries, [30, 90, 210, 450, 930, 1530, 2130, 2730]);
    assert!(j.is_pending(&ws) && ws.exists());
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn janitor_never_touches_a_running_jobs_workspace() {
    let (base, root) = scratch("busy");
    let (n, remove) = flaky(0);
    let j = Janitor::new(root.clone(), remove);
    let running = crate::workspace::create(&root, "jrun").unwrap();
    fs::write(running.join("f"), b"x").unwrap();
    age(&running, Duration::from_secs(25 * 3600));
    let busy = |p: &Path| p == running;
    assert_eq!(j.sweep(&busy), 0);
    assert!(running.join("f").exists(), "the sweep removed a running job's workspace");
    assert!(j.leave(&running));
    assert_eq!(j.retry_due(Instant::now() + Duration::from_secs(100_000), &busy), 0);
    assert_eq!(calls(&n), 0, "a retry tried to remove a running job's workspace");
    assert!(running.join("f").exists() && j.is_pending(&running));
    assert_eq!(j.retry_due(Instant::now() + Duration::from_secs(200_000), NOT_BUSY), 1);
    assert!(!running.exists(), "once its job ended the workspace was not removed");
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn janitor_never_removes_anything_outside_workspaces() {
    let (base, root) = scratch("outside");
    let (n, remove) = flaky(0);
    let j = Janitor::new(root.clone(), remove);
    fs::create_dir_all(root.join("j1").join("inner")).unwrap();
    let outside = base.join("outside");
    fs::create_dir_all(&outside).unwrap();
    for p in [outside.clone(), root.clone(), base.clone(), root.join("j1").join("inner"), root.join("..").join("outside"), root.join("j1").join("..")] {
        j.discard(&p);
        assert!(!j.leave(&p), "{p:?} was queued");
        assert!(!j.is_pending(&p));
    }
    assert_eq!(j.retry_due(Instant::now() + Duration::from_secs(100_000), NOT_BUSY), 0);
    assert_eq!(calls(&n), 0, "remove was called on a path that is not a workspace");
    assert!(outside.is_dir() && root.join("j1").join("inner").is_dir());
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn janitor_sweeps_leftovers_older_than_a_day_every_hour() {
    let (base, root) = scratch("hourly");
    let (_, remove) = flaky(0);
    let j = Janitor::new(root.clone(), remove);
    let first = crate::workspace::create(&root, "jfirst").unwrap();
    age(&first, Duration::from_secs(25 * 3600));
    let fresh = crate::workspace::create(&root, "jfresh").unwrap();
    let t0 = Instant::now();
    let mut next = t0;
    j.step(t0, &mut next, NOT_BUSY);
    assert!(!first.exists(), "the first pass is the startup sweep");
    let later = crate::workspace::create(&root, "jlater").unwrap();
    age(&later, Duration::from_secs(25 * 3600));
    j.step(t0 + Duration::from_secs(1800), &mut next, NOT_BUSY);
    assert!(later.exists(), "swept again before the hour was up");
    j.step(t0 + SWEEP_EVERY, &mut next, NOT_BUSY);
    assert!(!later.exists(), "a >24 h leftover survived the hourly sweep");
    assert!(fresh.exists(), "a workspace younger than 24 h was swept");
    let _ = fs::remove_dir_all(&base);
}
