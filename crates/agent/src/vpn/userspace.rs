// SPDX-License-Identifier: MIT
//! The embedded userspace WireGuard (Cloudflare's boringtun) for kernels without the module.
//!
//! The device is configured over a private socketpair handed to boringtun as its UAPI fd
//! (`DeviceConfig::uapi_fd`), not the `/var/run/wireguard/<iface>.sock` listener: that path
//! also installs SIGINT/SIGTERM handlers on the event loop, which would take the agent's own
//! signals. Closing our end of the pair is boringtun's EOF exit signal; `stop` then joins
//! its worker threads, and dropping the device closes the TUN queues, which removes the
//! interface (it is never made persistent).

use boringtun::device::{DeviceConfig, DeviceHandle};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::io::{IntoRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::{mpsc, Mutex};
use std::time::Duration;

pub struct Device {
    handle: DeviceHandle,
    api: Mutex<UnixStream>,
    /// boringtun's epoll fd, for `leaked_fds`.
    epoll: Option<RawFd>,
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

impl Device {
    pub fn start(name: &str) -> Result<Device, String> {
        // Checked first, for a clear error and so the UAPI fd is never handed over to a
        // device that cannot exist (boringtun opens the TUN before it takes the fd).
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")
            .map_err(|e| format!("/dev/net/tun: {e} (no TUN support here; in a container pass --device /dev/net/tun)"))?;
        let (ours, theirs) = UnixStream::pair().map_err(|e| format!("socketpair: {e}"))?;
        ours.set_read_timeout(Some(Duration::from_secs(5))).map_err(|e| e.to_string())?;
        let config = DeviceConfig { n_threads: 2, use_connected_socket: false, use_multi_queue: true, uapi_fd: theirs.into_raw_fd() };
        let handle = DeviceHandle::new(name, config).map_err(|e| format!("boringtun: {e}"))?;
        // Its epoll is the one watching this interface's TUN queue.
        let tun = format!("iff:\t{name}\n");
        let ours_tun = |fd: &RawFd| std::fs::read_to_string(format!("/proc/self/fdinfo/{fd}")).is_ok_and(|i| i.contains(&tun));
        let epoll = open_fds().into_iter().filter(|fd| fd_target(*fd) == "anon_inode:[eventpoll]").find(|ep| watched(*ep).iter().any(ours_tun));
        Ok(Device { handle, api: Mutex::new(ours), epoll })
    }

    /// One UAPI request and its reply, up to and including the `errno=` line.
    pub fn request(&self, req: &str) -> Result<String, String> {
        let mut api = self.api.lock().unwrap_or_else(|e| e.into_inner());
        api.write_all(req.as_bytes()).map_err(|e| format!("boringtun UAPI write: {e}"))?;
        let mut reader = BufReader::new(&*api);
        let mut resp = String::new();
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) => return Err("boringtun UAPI closed".into()),
                Ok(_) => {}
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

    /// Stops every boringtun thread and removes the interface. Err if the threads did not
    /// finish in time; they are then left to finish on their own.
    pub fn stop(self) -> Result<(), String> {
        let Device { mut handle, api, epoll } = self;
        drop(api);
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            handle.wait();
            let leaked = epoll.map(leaked_fds).unwrap_or_default();
            drop(handle);
            for fd in leaked {
                // SAFETY: an fd boringtun created and abandoned; nothing else refers to it.
                unsafe { libc::close(fd) };
            }
            let _ = tx.send(());
        });
        rx.recv_timeout(Duration::from_secs(10)).map_err(|_| "boringtun did not stop within 10s".to_string())
    }
}
