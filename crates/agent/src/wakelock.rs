// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

// Runtime wake lock: while the agent runs, the host must stay reachable, so we
// tell the OS "don't sleep the system." Unlike the powercfg/pmset scheme changes
// in persistence.rs, this needs no elevation, applies on every run (even a plain
// --background enroll), and clears automatically when the process exits — so it
// leaves no lingering system setting behind.

/// Ask the OS to keep the system awake for the lifetime of this process.
/// Call once, early, on the long-lived agent process.
#[cfg(windows)]
pub fn hold() {
    // ES_CONTINUOUS makes the request sticky until this thread resets it or exits;
    // ES_SYSTEM_REQUIRED keeps the system out of idle sleep (the display may still
    // turn off — we don't force the screen on). No admin rights required.
    const ES_CONTINUOUS: u32 = 0x8000_0000;
    const ES_SYSTEM_REQUIRED: u32 = 0x0000_0001;
    extern "system" {
        fn SetThreadExecutionState(es_flags: u32) -> u32;
    }
    unsafe {
        SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED);
    }
}

/// macOS: hold an idle-sleep assertion for as long as the agent runs by keeping a
/// `caffeinate` child alive. `-i` prevents idle sleep, `-s` scopes it to AC power
/// so battery behaviour is untouched. Holding the child's handle does NOT stop it
/// outliving us — on SIGTERM/SIGINT/crash it is reparented to launchd and keeps
/// the Mac awake forever — so `-w <our pid>` makes caffeinate itself exit when we do.
#[cfg(target_os = "macos")]
pub fn hold() {
    use std::sync::OnceLock;
    static CHILD: OnceLock<std::process::Child> = OnceLock::new();
    let me = std::process::id();
    // An auto-update exec()s the new binary in place (http.rs apply_update): same
    // pid, and the previous image's caffeinate child survives the exec, still
    // watching us. Spawning again would stack one more assertion per update.
    if held_by_surviving_child(me) {
        return;
    }
    if let Ok(child) = caffeinate(me) {
        let _ = CHILD.set(child);
    }
}

#[cfg(target_os = "macos")]
fn held_by_surviving_child(pid: u32) -> bool {
    std::process::Command::new("pgrep")
        .args(["-P", &pid.to_string(), "-f", &format!("^caffeinate -i -s -w {pid}$")])
        .stdout(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(target_os = "macos")]
fn caffeinate(watch_pid: u32) -> std::io::Result<std::process::Child> {
    std::process::Command::new("caffeinate")
        .args(["-i", "-s", "-w", &watch_pid.to_string()])
        .spawn()
}

#[cfg(all(unix, not(target_os = "macos")))]
pub fn hold() {
    // Linux idle-sleep is handled at persist time via GNOME gsettings (see
    // persistence.rs); there's no elevation-free, desktop-agnostic runtime knob
    // that's safe to assume here, so this is a no-op.
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use std::time::{Duration, Instant};

    // Stand-in for the agent: a short-lived process. Once it exits, the
    // caffeinate tied to it must exit too instead of lingering as an orphan.
    #[test]
    fn caffeinate_exits_when_watched_pid_exits() {
        let mut owner = std::process::Command::new("sleep").arg("1").spawn().unwrap();
        let mut caf = super::caffeinate(owner.id()).unwrap();
        owner.wait().unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while caf.try_wait().unwrap().is_none() {
            if Instant::now() > deadline {
                let _ = caf.kill();
                let _ = caf.wait();
                panic!("caffeinate outlived the watched pid by >5s");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    const STAGE: &str = "WAKELOCK_TEST_EXEC_STAGE";

    // An auto-update on Unix exec()s the new binary in place (http.rs
    // apply_update): same pid, and the old caffeinate child survives the exec.
    // main() then calls hold() again, so each update must not add another one.
    // Re-runs this test binary as a helper that does hold() + that same exec
    // twice, then reports how many caffeinates are watching its pid.
    #[test]
    fn hold_does_not_stack_across_exec() {
        if let Ok(stage) = std::env::var(STAGE) {
            exec_helper(stage.parse().unwrap());
        }
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["wakelock::tests::hold_does_not_stack_across_exec", "--exact", "--nocapture", "--test-threads=1"])
            .env(STAGE, "0")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        let n: usize = stdout
            .lines()
            .find_map(|l| l.split("CAFFEINATES=").nth(1))
            .unwrap_or_else(|| panic!("helper printed no count: {stdout}"))
            .trim()
            .parse()
            .unwrap();
        assert_eq!(n, 1, "caffeinates watching the agent pid after 2 exec restarts");
    }

    fn exec_helper(stage: u32) -> ! {
        use std::os::unix::process::CommandExt;
        super::hold();
        if stage < 2 {
            let args: Vec<String> = std::env::args().skip(1).collect();
            let e = std::process::Command::new(std::env::current_exe().unwrap())
                .args(&args)
                .env(STAGE, (stage + 1).to_string())
                .exec();
            panic!("exec failed: {e}");
        }
        let me = std::process::id().to_string();
        let ps = std::process::Command::new("ps").args(["-axo", "ppid=,command="]).output().unwrap();
        let n = String::from_utf8_lossy(&ps.stdout)
            .lines()
            .filter(|l| {
                let mut f = l.split_whitespace();
                f.next() == Some(&*me) && f.next() == Some("caffeinate")
            })
            .count();
        println!("CAFFEINATES={n}");
        std::process::exit(0);
    }
}
