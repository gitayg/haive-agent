// SPDX-License-Identifier: MIT
//! The embedded userspace WireGuard (Cloudflare's boringtun) for kernels without the module.
//!
//! The device is configured over a private socketpair handed to boringtun as its UAPI fd
//! (`DeviceConfig::uapi_fd`), not the `/var/run/wireguard/<iface>.sock` listener: that path
//! also installs SIGINT/SIGTERM handlers on the event loop, which would take the agent's own
//! signals. Closing our end of the pair is boringtun's EOF exit signal; `stop` then joins
//! its worker thread, and dropping the device closes the TUN queue, which removes the
//! interface (it is never made persistent).
//!
//! Watching it (see `health.rs`). boringtun 0.7.1's `DeviceHandle` keeps its workers'
//! `JoinHandle`s private (`threads: Vec<JoinHandle<()>>`) and offers only `wait()`, which joins
//! them with `.unwrap()`; there is no `is_finished()`. Its workers are plain `thread::spawn`s
//! made inside `DeviceHandle::new`. So `new` runs on a thread of ours with a unique name: on
//! Linux a thread starts with its creator's name (comm), so that name marks boringtun's
//! workers in /proc/self/task, both for counting them and for the panic hook.
//!
//! One worker, not two. When boringtun panics while applying a `set=1` (its update_peer
//! panics on a peer it already has), its `Lock::try_writeable` (dev_lock.rs) has set the
//! write-intent flag and never clears it on unwind: every later `Lock::read` waits forever.
//! A second worker would park on it for good, and `DeviceHandle::drop` (which takes a read)
//! would hang. With one worker, a panic leaves no boringtun thread at all, and the device
//! can be released completely without dropping it.

use super::health::Probe;
use super::uapi;
use boringtun::device::{DeviceConfig, DeviceHandle};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::io::{IntoRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{mpsc, Mutex, Once, OnceLock};
use std::time::{Duration, Instant};

/// boringtun worker threads per device.
const WORKERS: usize = 1;
/// The name every device's worker threads carry, followed by a per-device number.
const MARK: &str = "itai-bt";
/// How long an ordinary UAPI request (an apply's peer change) may take.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

pub struct Device {
    handle: DeviceHandle,
    api: Mutex<UnixStream>,
    /// Why a request got no complete answer, once one has not: a late reply would be read as
    /// the answer to the next request, so the channel cannot be trusted again.
    out_of_step: Mutex<Option<String>>,
    /// boringtun's epoll fd, for `leaked_fds` and for releasing a dead device.
    epoll: Option<RawFd>,
    /// The thread name (comm) of this device's workers.
    mark: String,
}

fn fd_target(fd: RawFd) -> String {
    std::fs::read_link(format!("/proc/self/fd/{fd}")).map(|p| p.to_string_lossy().into_owned()).unwrap_or_default()
}

fn open_fds() -> Vec<RawFd> {
    std::fs::read_dir("/proc/self/fd").map(|d| d.filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok()).collect()).unwrap_or_default()
}

/// The fds an epoll instance watches, from its /proc fdinfo (`tfd: <fd> events: …`).
fn watched(epoll: RawFd) -> Vec<RawFd> {
    let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{epoll}")).unwrap_or_default();
    info.lines().filter_map(|l| l.strip_prefix("tfd:")?.split_whitespace().next()?.parse().ok()).collect()
}

/// boringtun 0.7.1's EventPoll closes only its epoll fd when dropped, never the timerfds and
/// eventfds it created and registered (two of each per device): 4 fds lost per enable/disable.
/// They are read off the epoll while the device is still alive and closed once it is gone;
/// no one else holds those numbers, so they cannot have been reused in between. The crate is
/// pinned to =0.7.1 in Cargo.toml, so a release that closes them itself cannot slip in.
fn leaked_fds(epoll: RawFd) -> Vec<RawFd> {
    watched(epoll).into_iter().filter(|fd| matches!(fd_target(*fd).as_str(), "anon_inode:[timerfd]" | "anon_inode:[eventfd]")).collect()
}

/// Every fd a device holds: what its epoll watches (TUN queue, UDP sockets, the UAPI pair's
/// other end, timerfds, eventfds), plus the UDP sockets it keeps itself. Those are the
/// originals of the watched ones (`open_listen_socket` registers `try_clone()`s and stores
/// the sockets as `udp4`/`udp6`), found by their socket inode.
fn device_fds(epoll: RawFd) -> Vec<RawFd> {
    let fds = watched(epoll);
    let sockets: Vec<String> = fds.iter().map(|fd| fd_target(*fd)).filter(|t| t.starts_with("socket:[")).collect();
    let dups = open_fds().into_iter().filter(|fd| !fds.contains(fd) && sockets.contains(&fd_target(*fd)));
    fds.clone().into_iter().chain(dups).collect()
}

/// How many threads of this process carry the name `mark`.
fn alive(mark: &str) -> usize {
    let Ok(tasks) = std::fs::read_dir("/proc/self/task") else { return 0 };
    tasks.filter_map(|t| std::fs::read_to_string(t.ok()?.path().join("comm")).ok()).filter(|c| c.trim_end() == mark).count()
}

fn panics() -> &'static Mutex<HashMap<String, String>> {
    static P: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
    P.get_or_init(Default::default)
}

/// Records the panic message of any boringtun worker (a thread named `MARK…`) for the
/// watchdog, then hands every panic, boringtun's or not, to the hook that was there before,
/// so what gets printed and what happens next stay the same for every thread.
fn install_panic_hook() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let comm = std::fs::read_to_string("/proc/thread-self/comm").unwrap_or_default();
            let comm = comm.trim_end();
            if comm.starts_with(MARK) {
                let msg = info.payload().downcast_ref::<&str>().map(|s| s.to_string()).or_else(|| info.payload().downcast_ref::<String>().cloned()).unwrap_or_else(|| "a non-string panic".into());
                let at = info.location().map(|l| format!(" at {}:{}", l.file(), l.line())).unwrap_or_default();
                if let Ok(mut p) = panics().lock() {
                    p.insert(comm.to_string(), format!("panicked{at}: {msg}"));
                }
            }
            previous(info);
        }));
    });
}

/// One request and its reply up to and including `errno=`, within `timeout` in all.
fn exchange(api: &UnixStream, req: &str, timeout: Duration) -> Result<String, String> {
    let deadline = Instant::now() + timeout;
    let mut api = api;
    api.write_all(req.as_bytes()).map_err(|e| format!("boringtun UAPI write: {e}"))?;
    let mut reader = BufReader::new(api);
    let mut resp = String::new();
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(format!("no answer from boringtun's UAPI within {}s", timeout.as_secs()));
        }
        reader.get_ref().set_read_timeout(Some(left)).map_err(|e| e.to_string())?;
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => return Err("boringtun UAPI closed".into()),
            Ok(_) => {}
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {
                return Err(format!("no answer from boringtun's UAPI within {}s", timeout.as_secs()))
            }
            Err(e) => return Err(format!("boringtun UAPI read: {e}")),
        }
        let last = line.starts_with("errno=");
        resp.push_str(&line);
        if last {
            // The reply ends with a blank line after errno=; take it so the next
            // request starts clean.
            let _ = reader.read_line(&mut String::new());
            return Ok(resp);
        }
    }
}

impl Device {
    pub fn start(name: &str) -> Result<Device, String> {
        // Checked first, for a clear error and so the UAPI fd is never handed over to a
        // device that cannot exist (boringtun opens the TUN before it takes the fd).
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")
            .map_err(|e| format!("/dev/net/tun: {e} (no TUN support here; in a container pass --device /dev/net/tun)"))?;
        install_panic_hook();
        let (ours, theirs) = UnixStream::pair().map_err(|e| format!("socketpair: {e}"))?;
        let config = DeviceConfig { n_threads: WORKERS, use_connected_socket: false, use_multi_queue: false, uapi_fd: theirs.into_raw_fd() };
        static NEXT: AtomicU32 = AtomicU32::new(1);
        let mark = format!("{MARK}{}", NEXT.fetch_add(1, Ordering::Relaxed));
        // Created on a thread named `mark`, so the workers it spawns carry that name too.
        let iface = name.to_string();
        let handle = std::thread::Builder::new()
            .name(mark.clone())
            .spawn(move || DeviceHandle::new(&iface, config).map_err(|e| format!("boringtun: {e}")))
            .map_err(|e| format!("spawning boringtun: {e}"))?
            .join()
            .map_err(|_| "boringtun panicked while starting".to_string())??;
        // Its epoll is the one watching this interface's TUN queue.
        let tun = format!("iff:\t{name}\n");
        let ours_tun = |fd: &RawFd| std::fs::read_to_string(format!("/proc/self/fdinfo/{fd}")).is_ok_and(|i| i.contains(&tun));
        let epoll = open_fds().into_iter().filter(|fd| fd_target(*fd) == "anon_inode:[eventpoll]").find(|ep| watched(*ep).iter().any(ours_tun));
        Ok(Device { handle, api: Mutex::new(ours), out_of_step: Mutex::new(None), epoll, mark })
    }

    fn request_within(&self, req: &str, timeout: Duration) -> Result<String, String> {
        let api = self.api.lock().unwrap_or_else(|e| e.into_inner());
        let mut broken = self.out_of_step.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(e) = broken.as_ref() {
            return Err(format!("an earlier boringtun UAPI request failed ({e}), so its replies are out of step"));
        }
        exchange(&api, req, timeout).inspect_err(|e| *broken = Some(e.clone()))
    }

    /// One UAPI request and its reply, up to and including the `errno=` line.
    pub fn request(&self, req: &str) -> Result<String, String> {
        self.request_within(req, REQUEST_TIMEOUT)
    }

    /// Stops every boringtun thread and removes the interface. Err if that could not be done
    /// cleanly; what the device held is then released anyway (see `release_stuck`).
    pub fn stop(self) -> Result<(), String> {
        let Device { mut handle, api, epoll, mark, .. } = self;
        drop(api);
        if alive(&mark) == 0 {
            release_dead(handle, epoll);
            return Ok(());
        }
        let held = epoll.map(device_fds).unwrap_or_default();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            join_all(&mut handle);
            let leaked = epoll.map(leaked_fds).unwrap_or_default();
            drop(handle);
            for fd in leaked {
                // SAFETY: an fd boringtun created and abandoned; nothing else refers to it.
                unsafe { libc::close(fd) };
            }
            let _ = tx.send(());
        });
        match rx.recv_timeout(Duration::from_secs(10)) {
            Ok(()) => Ok(()),
            Err(_) => {
                release_stuck(&held);
                Err(format!("boringtun did not stop within 10s; its TUN queue and sockets were released and {} thread(s) are left parked", alive(&mark)))
            }
        }
    }

    /// Kills the worker the way boringtun 0.7.1 really dies: a `set=1` for a peer it already
    /// has panics it with "Modifying existing peers is not yet supported". Test-only.
    #[cfg(test)]
    pub fn inject_worker_panic(&self) -> Result<(), String> {
        let dev = uapi::parse_get(uapi::check(&self.request(uapi::GET)?)?);
        let pk = dev.peers.first().ok_or("no peer to re-add")?.public_key.clone();
        // No reply will come: the thread that would answer is the one that dies.
        self.send_unanswered(&format!("set=1\npublic_key={pk}\nallowed_ip=10.77.0.254/32\n\n"))
    }

    /// The name its worker threads carry. Test-only.
    #[cfg(test)]
    pub fn mark(&self) -> &str {
        &self.mark
    }

    /// Writes a request and does not wait for the reply. Test-only.
    #[cfg(test)]
    pub fn send_unanswered(&self, req: &str) -> Result<(), String> {
        let mut api = &*self.api.lock().unwrap_or_else(|e| e.into_inner());
        api.write_all(req.as_bytes()).map_err(|e| e.to_string())
    }
}

/// `DeviceHandle::wait` pops each worker and joins it with `.unwrap()`, so a worker that
/// panicked makes it panic in turn; each retry continues with the workers left.
fn join_all(handle: &mut DeviceHandle) {
    while catch_unwind(AssertUnwindSafe(|| handle.wait())).is_err() {}
}

/// No boringtun thread is left, so nothing can touch the device's fds again. Dropping the
/// handle could block forever (its Drop takes a read on a lock a panicking writer may have
/// left marked, see the module doc), so it is joined, then forgotten, and every fd it held
/// (`device_fds`, then the epoll) is closed by number. What stays is its heap memory.
fn release_dead(mut handle: DeviceHandle, epoll: Option<RawFd>) {
    join_all(&mut handle);
    let fds: Vec<RawFd> = epoll.map(|ep| device_fds(ep).into_iter().chain([ep]).collect()).unwrap_or_default();
    std::mem::forget(handle);
    for fd in fds {
        // SAFETY: the device's own fds; its only threads are gone and its handle is never dropped.
        unsafe { libc::close(fd) };
    }
}

/// A worker is alive but will not stop. It cannot be killed, and it may still use its fd
/// numbers if it ever wakes, so they are not closed: /dev/null is put over each, which frees
/// the TUN queue (the interface goes) and the UDP sockets (the port is free for a new device)
/// while the numbers stay taken.
fn release_stuck(fds: &[RawFd]) {
    let Ok(null) = std::fs::File::open("/dev/null") else { return };
    use std::os::unix::io::AsRawFd;
    for fd in fds {
        // SAFETY: replaces an open fd of the stuck device with /dev/null; the number stays valid.
        unsafe { libc::dup2(null.as_raw_fd(), *fd) };
    }
}

impl uapi::Uapi for Device {
    fn request(&self, req: &str) -> Result<String, String> {
        Device::request(self, req)
    }
}

impl Probe for Device {
    fn workers(&self) -> Result<(), String> {
        let n = alive(&self.mark);
        if n == WORKERS {
            return Ok(());
        }
        let why = panics().lock().ok().and_then(|mut p| p.remove(&self.mark)).map(|m| format!(": {m}")).unwrap_or_default();
        Err(format!("boringtun's worker thread is gone ({n} of {WORKERS} running){why}"))
    }

    fn uapi(&self, timeout: Duration) -> Result<(), String> {
        uapi::check(&self.request_within(uapi::GET, timeout)?).map(|_| ())
    }

    fn iface_exists(&self) -> bool {
        super::iface_up()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workers_are_counted_by_the_name_they_inherit_and_their_panics_recorded() {
        install_panic_hook();
        let mark = "itai-bt-t1".to_string();
        let (go, wait) = mpsc::channel::<()>();
        // Like DeviceHandle::new: an unnamed thread spawned from the named one.
        let worker = std::thread::Builder::new()
            .name(mark.clone())
            .spawn(move || {
                std::thread::spawn(move || {
                    let _ = wait.recv();
                    panic!("Modifying existing peers is not yet supported. Remove and add again instead.");
                })
            })
            .unwrap()
            .join()
            .unwrap();
        assert_eq!(alive(&mark), 1, "the unnamed worker carries its creator's name");
        go.send(()).unwrap();
        assert!(worker.join().is_err());
        assert_eq!(alive(&mark), 0, "a dead worker is no longer counted");
        let msg = panics().lock().unwrap().remove(&mark).expect("the worker's panic was recorded");
        assert!(msg.contains("Modifying existing peers") && msg.contains("userspace.rs:"), "{msg}");

        // Control: a panic on any other thread is not recorded as boringtun's.
        let _ = std::thread::Builder::new().name("not-boringtun".into()).spawn(|| panic!("someone else")).unwrap().join();
        assert!(!panics().lock().unwrap().values().any(|m| m.contains("someone else")));
    }

    #[test]
    fn a_uapi_that_does_not_answer_times_out() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        let t = Instant::now();
        let e = exchange(&ours, uapi::GET, Duration::from_millis(600)).unwrap_err();
        assert!(e.contains("no answer"), "{e}");
        assert!(t.elapsed() < Duration::from_millis(1500), "{:?}", t.elapsed());

        // Control: an answer arrives, split across writes.
        let replier = std::thread::spawn(move || {
            let mut r = BufReader::new(&theirs);
            let mut l = String::new();
            r.read_line(&mut l).unwrap();
            r.read_line(&mut l).unwrap();
            (&theirs).write_all(b"listen_port=51820\n").unwrap();
            std::thread::sleep(Duration::from_millis(100));
            (&theirs).write_all(b"errno=0\n\n").unwrap();
        });
        let got = exchange(&ours, uapi::GET, Duration::from_secs(2)).unwrap();
        assert_eq!(got, "listen_port=51820\nerrno=0\n");
        replier.join().unwrap();
    }
}
