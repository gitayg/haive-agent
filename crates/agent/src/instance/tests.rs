use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use super::{claim_at, handoff, try_claim, Claim};

fn scratch() -> std::path::PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    let d = std::env::temp_dir().join(format!(
        "itai-instance-{}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d.join(".it-ai").join("agent.lock")
}

#[test]
fn the_first_agent_takes_the_lock_and_records_its_pid() {
    let p = scratch();
    let Claim::Held(_f) = try_claim(&p) else { panic!("a free lock was not taken") };
    assert_eq!(std::fs::read_to_string(&p).unwrap(), std::process::id().to_string());
}

#[test]
fn a_second_agent_finds_the_lock_taken_and_by_whom() {
    let p = scratch();
    let Claim::Held(first) = try_claim(&p) else { panic!("not taken") };
    match try_claim(&p) {
        Claim::Taken(pid) => assert_eq!(pid, Some(std::process::id()), "the holder's pid"),
        _ => panic!("a held lock was taken a second time"),
    }
    drop(first);
    let t0 = Instant::now();
    while !matches!(try_claim(&p), Claim::Held(_)) {
        assert!(t0.elapsed() < Duration::from_secs(5), "the lock was not free once its holder ended");
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn the_lock_is_never_taken_through_a_link() {
    let p = scratch();
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    let target = p.with_file_name("elsewhere");
    std::fs::write(&target, "keep").unwrap();
    std::os::unix::fs::symlink(&target, &p).unwrap();
    assert!(matches!(try_claim(&p), Claim::Unavailable(_)), "a symlinked lock file was opened");
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep", "the link's target was written");
}

#[test]
fn a_restarted_agent_takes_the_lock_once_its_pre_restart_image_lets_go() {
    let p = scratch();
    let Claim::Held(pre_restart) = try_claim(&p) else { panic!("not taken") };
    let lets_go = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(2));
        drop(pre_restart);
    });
    let t0 = Instant::now();
    let got = claim_at(&p);
    let waited = t0.elapsed();
    lets_go.join().unwrap();
    assert!(got.is_some(), "the lock held under our own pid was given up on after {waited:?}");
    assert!(waited >= Duration::from_millis(1900), "taken after {waited:?}, while the pre-restart image still held it");
    assert_eq!(std::fs::read_to_string(&p).unwrap(), std::process::id().to_string());
}

#[test]
fn a_restart_exec_lets_go_of_the_lock_and_takes_it_back_when_the_exec_fails() {
    let p = scratch();
    let Claim::Held(held) = try_claim(&p) else { panic!("not taken") };
    handoff::remember(&held);
    handoff::let_go();
    let Claim::Held(next) = try_claim(&p) else { panic!("the lock was still held after letting go of it for an exec") };
    next.unlock().unwrap();
    let e = super::exec(std::process::Command::new(p.with_file_name("no-such-agent")));
    assert_eq!(e.kind(), std::io::ErrorKind::NotFound);
    assert!(matches!(try_claim(&p), Claim::Taken(_)), "the lock was not taken back after the exec failed");
}
