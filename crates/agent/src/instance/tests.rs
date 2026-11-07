use super::{try_claim, Claim};

fn scratch() -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "itai-instance-{}-{}",
        std::process::id(),
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
    assert!(matches!(try_claim(&p), Claim::Held(_)), "the lock was not free once its holder ended");
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
