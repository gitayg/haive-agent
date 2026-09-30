// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

// Child-process reaping. On Unix an exited child stays in the process table as a
// zombie (`[sh] <defunct>`) until its parent wait()s it, and dropping a
// `std::process::Child` does NOT wait. A long-lived agent that spawns and forgets
// therefore accumulates zombies for as long as it runs — seen on a Linux server
// with three `[sh] <defunct>` children of a 6-day-old agent. On Windows dropping
// the Child just closes its handle, so the reaper thread is harmless there.

use std::io::Read;
use std::process::{Child, Command, Output};
use std::thread::JoinHandle;

/// Spawn `c` fire-and-forget: return its pid at once, and reap it on a background
/// thread when it exits so it never lingers as a zombie. The caller is not blocked.
pub fn spawn_detached(c: &mut Command) -> std::io::Result<u32> {
    let mut child = c.spawn()?;
    let pid = child.id();
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(pid)
}

/// `Child::wait_with_output`, except the child is reaped as soon as it exits rather
/// than after its pipes reach EOF. A background grandchild (`cmd &`, a daemon)
/// inherits the pipes and can hold them open indefinitely; std reads to EOF before
/// waiting, so the already-exited shell stayed a zombie for that grandchild's life.
pub fn wait_with_output(mut child: Child) -> std::io::Result<Output> {
    let out = child.stdout.take().map(drain);
    let err = child.stderr.take().map(drain);
    let status = child.wait()?;
    let stdout = out.map(|h| h.join().unwrap_or_default()).unwrap_or_default();
    let stderr = err.map(|h| h.join().unwrap_or_default()).unwrap_or_default();
    Ok(Output { status, stdout, stderr })
}

fn drain<R: Read + Send + 'static>(mut r: R) -> JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = r.read_to_end(&mut b);
        b
    })
}

#[cfg(all(test, unix))]
mod tests {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    /// `ps` state of `pid` ("Z…" for a zombie), or None once it is fully gone.
    fn ps_stat(pid: u32) -> Option<String> {
        let o = Command::new("ps").args(["-o", "stat=", "-p", &pid.to_string()]).output().unwrap();
        let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
        (!s.is_empty()).then_some(s)
    }

    fn assert_gone_within(pid: u32, limit: Duration) {
        let deadline = Instant::now() + limit;
        while let Some(stat) = ps_stat(pid) {
            if Instant::now() > deadline {
                panic!("child {pid} still in the process table after {limit:?} (stat {stat}) — not reaped");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    #[test]
    fn detached_child_is_reaped_after_exit() {
        let mut c = Command::new("sh");
        c.args(["-c", "true"]).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
        let pid = super::spawn_detached(&mut c).unwrap();
        assert_gone_within(pid, Duration::from_secs(5));
    }

    #[test]
    fn captured_child_is_reaped_while_grandchild_holds_pipe() {
        let mut c = Command::new("sh");
        c.args(["-c", "sleep 3 & echo hi"]).stdout(Stdio::piped()).stderr(Stdio::piped());
        let child = c.spawn().unwrap();
        let pid = child.id();
        let h = std::thread::spawn(move || super::wait_with_output(child));
        // The shell exits at once; the backgrounded sleep keeps stdout open for 3s.
        assert_gone_within(pid, Duration::from_millis(1500));
        let o = h.join().unwrap().unwrap();
        assert!(o.status.success());
        assert_eq!(String::from_utf8_lossy(&o.stdout), "hi\n");
    }
}
