// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

//! `~/.it-ai/agent.log`: where an agent's stdout/stderr land, so "it just
//! vanished" is always answerable. A `--background` relaunch and launchd
//! (`StandardOutPath`) hand the agent the file; on unix an agent started any other
//! way without a terminal (a desktop autostart, `nohup … >/dev/null`) points its
//! own stdout/stderr at it at startup (`adopt_stdio`), unless they go to the
//! journal of a systemd service.
//!
//! Two kinds of writer can hold it open: the `--background` relaunch (our own
//! `O_APPEND` handle) and launchd (`StandardOutPath`/`StandardErrorPath`, which it
//! also opens `O_APPEND` — measured with `F_GETFL` on a scratch job). Appenders
//! interleave whole writes and never clobber each other, so the only thing that
//! has to be careful is trimming: see `cap`.

#[cfg(not(unix))]
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};

/// Past this the log is emptied at the next start, so an agent that restart-loops
/// for months can't fill the disk.
const MAX_LEN: u64 = 1_000_000;

pub(crate) fn path_in(home: &Path) -> PathBuf {
    home.join(".it-ai").join("agent.log")
}

/// Create the log's directory (0700) and the file (0600) before anything opens it.
/// launchd creates a missing `StandardOutPath` itself, but as 0644 inside a 0744
/// directory (measured); a file that already exists keeps its mode when launchd
/// opens it, so the installer makes both first. Also trims an oversized log.
/// On unix nothing is followed: see `open`.
#[cfg_attr(windows, allow(dead_code))]
pub(crate) fn prepare(path: &Path) -> std::io::Result<()> {
    open(path).map(drop).map_err(std::io::Error::other)
}

/// Send a child's stdout and stderr to the log, appending (prepared as above:
/// owner-only, capped), or to null when it cannot be opened safely, saying why on
/// stderr. Used by the `--background` relaunch and by the Windows restart after
/// a self-update.
pub(crate) fn redirect(c: &mut std::process::Command, path: &Path) {
    match open(path).and_then(|f| f.try_clone().map(|g| (f, g)).map_err(|e| e.to_string())) {
        Ok((out, err)) => {
            c.stdout(out).stderr(err);
        }
        Err(why) => {
            eprintln!("log: not writing to {}: {why}", path.display());
            c.stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
        }
    }
}

/// The log, open for appending and trimmed (`MAX_LEN`), created if missing.
pub(crate) fn open(path: &Path) -> Result<std::fs::File, String> {
    open_log(path, true).map(|f| f.expect("created"))
}

/// Unix: never through a link, and only a log no one else can swap. `.it-ai` is
/// created 0700 if missing (`mkdir` does not follow a symlink at that name), then
/// opened `O_DIRECTORY|O_NOFOLLOW` and must be a directory of this euid; the log
/// is opened relative to that fd with `O_NOFOLLOW` (`O_CREAT` 0600 when `create`)
/// and must be a regular file of this euid with one link (`check_log`). A mode
/// left loose by an older agent is tightened through those fds (0700 / 0600), and
/// the trim truncates that fd, never a path. So a root agent whose
/// `~/.it-ai/agent.log`, or `~/.it-ai`, another user made a link to someone
/// else's file never appends to, chmods or truncates it. Ok(None): `create` is
/// false and there is no log.
#[cfg(unix)]
fn open_log(path: &Path, create: bool) -> Result<Option<std::fs::File>, String> {
    use crate::entryclean::securefs::{cstr, cvt, fstat, open_at};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    let (Some(dir), Some(name)) = (path.parent(), path.file_name()) else { return Err("not a file path".into()) };
    let euid = unsafe { libc::geteuid() };
    let nf = |e: &std::io::Error| e.kind() == std::io::ErrorKind::NotFound;
    let cdir = cstr(dir.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
    if create {
        if let Some(home) = dir.parent() {
            std::fs::create_dir_all(home).map_err(|e| format!("{}: {e}", home.display()))?;
        }
        unsafe { libc::mkdir(cdir.as_ptr(), 0o700) };
    }
    let dfd = match cvt(unsafe { libc::open(cdir.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) }) {
        Ok(fd) => unsafe { OwnedFd::from_raw_fd(fd) },
        Err(e) if !create && nf(&e) => return Ok(None),
        Err(e) => return Err(format!("{} cannot be opened as a directory without following a link ({e})", dir.display())),
    };
    let dm = fstat(dfd.as_raw_fd()).map_err(|e| e.to_string())?;
    check_log_dir(&dm, euid).map_err(|why| format!("{} {why}", dir.display()))?;
    if dm.mode & 0o777 != 0o700 {
        cvt(unsafe { libc::fchmod(dfd.as_raw_fd(), 0o700) }).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    let mut flags = libc::O_WRONLY | libc::O_APPEND | libc::O_NOFOLLOW | libc::O_NONBLOCK;
    if create {
        flags |= libc::O_CREAT;
    }
    let fd = match open_at(dfd.as_raw_fd(), &cstr(name.as_bytes()).map_err(|e| e.to_string())?, flags, 0o600) {
        Ok(fd) => fd,
        Err(e) if !create && nf(&e) => return Ok(None),
        Err(e) => return Err(format!("{} cannot be opened without following a link ({e})", path.display())),
    };
    let m = fstat(fd.as_raw_fd()).map_err(|e| e.to_string())?;
    check_log(&m, euid).map_err(|why| format!("{} {why}", path.display()))?;
    // O_NONBLOCK only kept a FIFO planted at the name from blocking the open.
    cvt(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, libc::O_APPEND) }).map_err(|e| e.to_string())?;
    if m.mode & 0o777 != 0o600 {
        cvt(unsafe { libc::fchmod(fd.as_raw_fd(), 0o600) }).map_err(|e| format!("{}: {e}", path.display()))?;
    }
    let f = std::fs::File::from(fd);
    cap_file(&f);
    Ok(Some(f))
}

/// `.it-ai`: a directory of this euid (opened without following a link).
#[cfg(unix)]
pub(crate) fn check_log_dir(m: &crate::entryclean::securefs::Meta, euid: u32) -> Result<(), String> {
    use crate::entryclean::securefs::IFDIR;
    if m.kind() != IFDIR {
        return Err("is not a directory".into());
    }
    if m.uid != euid {
        return Err(format!("is owned by uid {}, not by this agent (uid {euid})", m.uid));
    }
    Ok(())
}

/// `agent.log`: a regular file of this euid with one link (a hard link would let
/// the trim reach the other name's file).
#[cfg(unix)]
pub(crate) fn check_log(m: &crate::entryclean::securefs::Meta, euid: u32) -> Result<(), String> {
    use crate::entryclean::securefs::IFREG;
    if m.kind() != IFREG {
        return Err("is not a regular file".into());
    }
    if m.uid != euid {
        return Err(format!("is owned by uid {}, not by this agent (uid {euid})", m.uid));
    }
    if m.nlink != 1 {
        return Err(format!("has {} hard links", m.nlink));
    }
    Ok(())
}

/// Windows: the path as given (see the README on reparse points).
#[cfg(not(unix))]
fn open_log(path: &Path, create: bool) -> Result<Option<std::fs::File>, String> {
    if create {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
    } else if !path.exists() {
        return Ok(None);
    }
    let f = OpenOptions::new().create(create).append(true).open(path).map_err(|e| e.to_string())?;
    cap_file(&f);
    Ok(Some(f))
}

/// Empty an open log once it passes `MAX_LEN`: through the fd, in place.
fn cap_file(f: &std::fs::File) {
    if f.metadata().map(|m| m.len() > MAX_LEN).unwrap_or(false) {
        let _ = f.set_len(0);
    }
}

/// What `adopt_stdio` looks at in an open stdout/stderr.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Fd {
    pub tty: bool,
    pub regular: bool,
    pub dev: u64,
    pub ino: u64,
}

#[cfg(unix)]
#[allow(clippy::unnecessary_cast)]
fn fd_info(fd: libc::c_int) -> Option<Fd> {
    let mut st = std::mem::MaybeUninit::<libc::stat>::zeroed();
    if unsafe { libc::fstat(fd, st.as_mut_ptr()) } != 0 {
        return None;
    }
    let st = unsafe { st.assume_init() };
    Some(Fd {
        tty: unsafe { libc::isatty(fd) } == 1,
        regular: (st.st_mode as u32 & libc::S_IFMT as u32) == libc::S_IFREG as u32,
        dev: st.st_dev as u64,
        ino: st.st_ino as u64,
    })
}

/// Whether stdout/stderr are the journal stream systemd gave THIS process as a
/// service. systemd.exec(5) on `$JOURNAL_STREAM`: "the device and inode numbers of
/// the file descriptors should be compared with the values set in the environment
/// variable to determine whether the process output is still connected to the
/// journal", because a child inherits the variable along with other output. And
/// `$SYSTEMD_EXEC_PID` (systemd 248+) is the PID of the process the unit started:
/// when it is set and is not us, we are a descendant of some service (a desktop
/// session's autostart, say), not the service. `INVOCATION_ID` alone proves
/// neither, so it is not used.
#[cfg(unix)]
fn is_service_journal(out: Option<Fd>, err: Option<Fd>, journal_stream: Option<&str>, exec_pid: Option<&str>, pid: u32) -> bool {
    let Some((dev, ino)) = journal_stream.and_then(|v| v.trim().split_once(':')).and_then(|(d, i)| Some((d.parse::<u64>().ok()?, i.parse::<u64>().ok()?)))
    else {
        return false;
    };
    let ours = exec_pid.is_none_or(|p| p.trim().parse::<u32>().ok() == Some(pid));
    ours && [out, err].into_iter().flatten().any(|f| f.dev == dev && f.ino == ino)
}

/// Whether to point stdout/stderr at agent.log: not when stdout is a terminal
/// (someone is watching), a regular file (already a log: launchd's
/// `StandardOutPath` agent.log, a `--background` child, a `> file`), or a systemd
/// service's journal. Yes for a pipe, a socket, `/dev/null` or a closed stdout.
#[cfg(unix)]
pub(crate) fn should_adopt(out: Option<Fd>, err: Option<Fd>, journal_stream: Option<&str>, exec_pid: Option<&str>, pid: u32) -> bool {
    match out {
        Some(o) if o.tty || o.regular => false,
        _ => !is_service_journal(out, err, journal_stream, exec_pid, pid),
    }
}

/// Point this process's stdout and stderr at the log (prepared as for `redirect`:
/// 0600, capped, appending) when `should_adopt` says so. Returns whether it did.
/// Before 3.8.3 an agent a desktop autostart started (`Exec=` with no
/// `--background`) wrote to wherever the session sent it, so its `agent.log`
/// stopped at the last `--background` start.
#[cfg(unix)]
pub(crate) fn adopt_stdio(path: &Path) -> bool {
    use std::io::Write;
    use std::os::fd::IntoRawFd;
    let (js, pid) = (std::env::var("JOURNAL_STREAM").ok(), std::env::var("SYSTEMD_EXEC_PID").ok());
    if !should_adopt(fd_info(1), fd_info(2), js.as_deref(), pid.as_deref(), std::process::id()) {
        return false;
    }
    let f = match open(path) {
        Ok(f) => f,
        Err(why) => {
            eprintln!("log: not writing to {}: {why}", path.display());
            return false;
        }
    };
    let _ = std::io::stdout().flush();
    let fd = f.into_raw_fd();
    let ok = unsafe { libc::dup2(fd, 1) == 1 && libc::dup2(fd, 2) == 2 };
    if fd > 2 {
        unsafe { libc::close(fd) };
    }
    ok
}

/// Empty the log IN PLACE once it passes `MAX_LEN`. Truncate, never unlink: a
/// launchd-started agent writes through an fd launchd opened, so removing the path
/// would send that agent's output to an orphaned inode until its next restart, and
/// launchd would then recreate the file 0644. Every writer is `O_APPEND`, so after
/// a truncate each one simply continues at the new end of file. The log is opened
/// as `open` opens it (never through a link) but not created; a log that fails
/// those checks is left alone, with a line on stderr.
pub(crate) fn cap(path: &Path) {
    if let Err(why) = open_log(path, false) {
        eprintln!("log: not trimming {}: {why}", path.display());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("it-ai-logfile-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[cfg(unix)]
    fn mode(p: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    /// The installer makes the dir 0700 and the file 0600, and tightens a log an
    /// older `--background` run left world-readable.
    #[cfg(unix)]
    #[test]
    fn prepare_creates_owner_only_dir_and_file() {
        use std::os::unix::fs::PermissionsExt;
        let home = scratch("perm");
        let log = path_in(&home);
        prepare(&log).unwrap();
        assert!(log.exists());
        assert_eq!(mode(log.parent().unwrap()), 0o700, "log dir");
        assert_eq!(mode(&log), 0o600, "log file");

        std::fs::set_permissions(&log, std::fs::Permissions::from_mode(0o644)).unwrap();
        prepare(&log).unwrap();
        assert_eq!(mode(&log), 0o600, "an existing 0644 log must be tightened");
        let _ = std::fs::remove_dir_all(&home);
    }

    /// Trimming must keep the SAME file: a writer that already holds it open (the
    /// launchd case) has to keep logging into the file at the path, from offset 0,
    /// not into an unlinked inode.
    #[cfg(unix)]
    #[test]
    fn cap_truncates_in_place_so_an_open_writer_keeps_logging() {
        use std::io::Write;
        use std::os::unix::fs::MetadataExt;
        let home = scratch("cap");
        let log = path_in(&home);
        prepare(&log).unwrap();
        // Stand-in for launchd's handle: opened before the trim, O_APPEND.
        let mut held = OpenOptions::new().append(true).open(&log).unwrap();
        held.write_all(&vec![b'x'; MAX_LEN as usize + 1]).unwrap();
        let ino = std::fs::metadata(&log).unwrap().ino();

        cap(&log);

        assert_eq!(std::fs::metadata(&log).unwrap().ino(), ino, "cap must not replace the file");
        held.write_all(b"after\n").unwrap();
        assert_eq!(std::fs::read(&log).unwrap(), b"after\n", "the open writer must continue at the new end");
        let _ = std::fs::remove_dir_all(&home);
    }

    #[cfg(unix)]
    const PIPE: Fd = Fd { tty: false, regular: false, dev: 7, ino: 42 };

    /// The decision, with injected fds and environment.
    #[cfg(unix)]
    #[test]
    fn adopt_only_without_a_terminal_a_file_or_our_own_journal() {
        let tty = Fd { tty: true, ..PIPE };
        let file = Fd { regular: true, ..PIPE };
        assert!(!should_adopt(Some(tty), Some(tty), None, None, 9), "a terminal");
        assert!(!should_adopt(Some(file), Some(file), None, None, 9), "launchd's StandardOutPath, --background");
        assert!(should_adopt(Some(PIPE), Some(PIPE), None, None, 9), "a pipe or socket (desktop session)");
        assert!(should_adopt(Some(Fd { dev: 5, ino: 6, ..PIPE }), None, None, None, 9), "/dev/null");
        assert!(should_adopt(None, None, None, None, 9), "closed");
        // A systemd service: JOURNAL_STREAM names this very stream.
        assert!(!should_adopt(Some(PIPE), Some(PIPE), Some("7:42"), None, 9));
        assert!(!should_adopt(Some(PIPE), Some(PIPE), Some("7:42"), Some("9"), 9), "SYSTEMD_EXEC_PID is us");
        assert!(!should_adopt(Some(Fd { ino: 1, ..PIPE }), Some(PIPE), Some("7:42"), None, 9), "stderr is the journal");
        // Inherited, not ours: another stream, or another process's service.
        assert!(should_adopt(Some(PIPE), Some(PIPE), Some("7:43"), None, 9), "a different stream");
        assert!(should_adopt(Some(PIPE), Some(PIPE), Some("7:42"), Some("1234"), 9), "SYSTEMD_EXEC_PID is an ancestor");
        assert!(should_adopt(Some(PIPE), Some(PIPE), Some("garbage"), None, 9));
        // A terminal or a file stays, journal or not.
        assert!(!should_adopt(Some(file), Some(file), Some("7:43"), Some("1234"), 9));
    }

    const CHILD: &str = "IT_AI_LOGFILE_TEST_CHILD";

    /// The child: adopt, then write one line to each of stdout and stderr.
    #[cfg(unix)]
    fn child_body(log: &str) -> ! {
        let adopted = adopt_stdio(Path::new(log));
        println!("child-out adopted={adopted}");
        eprintln!("child-err");
        std::process::exit(0);
    }

    /// This test binary re-run as a child with the given stdout/stderr and env.
    #[cfg(unix)]
    fn run_child(log: &Path, out: std::process::Stdio, err: std::process::Stdio, env: &[(&str, &str)]) {
        let mut c = std::process::Command::new(std::env::current_exe().unwrap());
        c.args(["logfile::tests::stdout_lands_in_the_log_only_when_nothing_else_keeps_it", "--exact", "--nocapture", "--test-threads=1"])
            .env(CHILD, log)
            .env_remove("JOURNAL_STREAM")
            .env_remove("SYSTEMD_EXEC_PID")
            .stdin(std::process::Stdio::null())
            .stdout(out)
            .stderr(err);
        for (k, v) in env {
            c.env(k, v);
        }
        assert!(c.status().unwrap().success());
    }

    #[cfg(unix)]
    fn read(p: &Path) -> String {
        std::fs::read_to_string(p).unwrap_or_default()
    }

    /// A pipe whose write end goes to the child; returns (read end, write end's dev:ino).
    #[cfg(unix)]
    fn pipe() -> (std::fs::File, std::os::fd::OwnedFd, String) {
        use std::os::fd::FromRawFd;
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let (r, w) = unsafe { (std::fs::File::from_raw_fd(fds[0]), std::os::fd::OwnedFd::from_raw_fd(fds[1])) };
        let f = fd_info(fds[1]).unwrap();
        (r, w, format!("{}:{}", f.dev, f.ino))
    }

    /// Where the agent's own output lands, by what its stdout was at start.
    #[cfg(unix)]
    #[test]
    fn stdout_lands_in_the_log_only_when_nothing_else_keeps_it() {
        use std::io::Read;
        use std::process::Stdio;
        if let Ok(log) = std::env::var(CHILD) {
            child_body(&log);
        }
        let home = scratch("adopt");
        let log = path_in(&home);
        let fresh = || {
            let _ = std::fs::remove_file(&log);
        };

        // /dev/null (a GNOME autostart without a journal, `nohup … >/dev/null`).
        fresh();
        run_child(&log, Stdio::null(), Stdio::null(), &[]);
        let text = read(&log);
        assert!(text.contains("child-out adopted=true\nchild-err\n"), "/dev/null: {text:?}");

        // A pipe (a desktop session's journal stream it opened for the app).
        for env in [vec![], vec![("JOURNAL_STREAM", "1:1")]] {
            fresh();
            let (mut r, w, _) = pipe();
            run_child(&log, Stdio::from(w), Stdio::null(), &env);
            let mut piped = String::new();
            r.read_to_string(&mut piped).unwrap();
            assert!(read(&log).contains("child-out adopted=true\nchild-err\n"), "pipe {env:?}: {:?}", read(&log));
            assert!(!piped.contains("child-out"), "pipe {env:?} still got output: {piped:?}");
        }

        // A systemd service: JOURNAL_STREAM is this very pipe. Kept; no log.
        fresh();
        let (mut r, w, id) = pipe();
        let w2 = w.try_clone().unwrap();
        run_child(&log, Stdio::from(w), Stdio::from(w2), &[("JOURNAL_STREAM", &id)]);
        let mut piped = String::new();
        r.read_to_string(&mut piped).unwrap();
        assert!(piped.contains("child-out adopted=false\nchild-err\n"), "journal: {piped:?}");
        assert!(!log.exists(), "journal: no agent.log written");

        // The same stream, but SYSTEMD_EXEC_PID names another process: inherited
        // from a service up the tree, so adopted.
        fresh();
        let (mut r, w, id) = pipe();
        run_child(&log, Stdio::from(w), Stdio::null(), &[("JOURNAL_STREAM", &id), ("SYSTEMD_EXEC_PID", "1")]);
        let mut piped = String::new();
        r.read_to_string(&mut piped).unwrap();
        assert!(read(&log).contains("child-out adopted=true\nchild-err\n") && !piped.contains("child-out"), "{piped:?}");

        // launchd: stdout and stderr already ARE agent.log, opened O_APPEND. Not
        // redirected again, and each line lands exactly once.
        fresh();
        prepare(&log).unwrap();
        let open = || OpenOptions::new().append(true).open(&log).unwrap();
        run_child(&log, Stdio::from(open()), Stdio::from(open()), &[]);
        let text = read(&log);
        assert_eq!(text.matches("child-out").count(), 1, "{text:?}");
        assert_eq!(text.matches("child-err").count(), 1, "{text:?}");
        assert!(text.contains("child-out adopted=false"), "{text:?}");

        // Another regular file (`> out.txt`): left there, agent.log untouched.
        fresh();
        let other = home.join("out.txt");
        run_child(&log, Stdio::from(std::fs::File::create(&other).unwrap()), Stdio::null(), &[]);
        assert!(read(&other).contains("child-out adopted=false"), "{:?}", read(&other));
        assert!(!log.exists());

        // A terminal.
        fresh();
        // A slave fd stays open here: on macOS the output is dropped once the last one closes.
        let (mut master, slave) = pty();
        let _keep = slave.try_clone().unwrap();
        run_child(&log, Stdio::from(slave), Stdio::null(), &[]);
        assert!(!log.exists(), "tty: no agent.log written");
        unsafe { libc::fcntl(std::os::fd::AsRawFd::as_raw_fd(&master), libc::F_SETFL, libc::O_NONBLOCK) };
        let (mut buf, mut all) = ([0u8; 4096], String::new());
        while let Ok(n @ 1..) = master.read(&mut buf) {
            all.push_str(&String::from_utf8_lossy(&buf[..n]));
        }
        assert!(all.contains("child-out adopted=false"), "tty: {all:?}");

        // agent.log is a symlink to another file: not adopted, the file untouched.
        let _ = std::fs::remove_dir_all(log.parent().unwrap());
        let v = victim(&home, false);
        std::os::unix::fs::symlink(&v, &log).unwrap();
        let other = home.join("err.txt");
        run_child(&log, Stdio::null(), Stdio::from(std::fs::File::create(&other).unwrap()), &[]);
        assert_eq!(read(&v), "precious\n", "adopt_stdio followed the symlink");
        assert!(read(&other).contains("log: not writing to"), "{:?}", read(&other));
        let _ = std::fs::remove_dir_all(&home);
    }

    #[cfg(unix)]
    fn pty() -> (std::fs::File, std::os::fd::OwnedFd) {
        use std::os::fd::FromRawFd;
        let (mut m, mut s) = (0, 0);
        let r = unsafe { libc::openpty(&mut m, &mut s, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut()) };
        assert_eq!(r, 0, "openpty");
        unsafe { (std::fs::File::from_raw_fd(m), std::os::fd::OwnedFd::from_raw_fd(s)) }
    }

    /// A home whose `.it-ai` is a real 0700 dir, and a victim file elsewhere.
    #[cfg(unix)]
    fn victim(home: &Path, big: bool) -> PathBuf {
        let v = home.join("victim");
        std::fs::create_dir_all(home.join(".it-ai")).unwrap();
        std::fs::write(&v, if big { vec![b'v'; MAX_LEN as usize + 10] } else { b"precious\n".to_vec() }).unwrap();
        v
    }

    /// `agent.log` is a symlink: prepare, cap, redirect and adopt_stdio never
    /// follow it, and the file it points at is left exactly as it was.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_log_is_never_followed() {
        let home = scratch("symlog");
        let v = victim(&home, true);
        let log = path_in(&home);
        std::os::unix::fs::symlink(&v, &log).unwrap();
        let before = std::fs::read(&v).unwrap();
        assert!(prepare(&log).is_err(), "prepare must refuse a symlinked log");
        cap(&log);
        let mut c = std::process::Command::new("/bin/sh");
        c.args(["-c", "echo planted"]);
        redirect(&mut c, &log);
        assert!(c.status().unwrap().success());
        let after = std::fs::read(&v).unwrap();
        assert!(after == before, "the symlink's target was written or truncated: {} bytes, was {}", after.len(), before.len());
        assert!(std::fs::symlink_metadata(&log).unwrap().file_type().is_symlink());
        let _ = std::fs::remove_dir_all(&home);
    }

    /// `.it-ai` itself is a symlink to someone else's directory: refused, and
    /// nothing is created or changed in it.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_log_dir_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let home = scratch("symdir");
        let theirs = home.join("theirs");
        std::fs::create_dir_all(&theirs).unwrap();
        std::fs::set_permissions(&theirs, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::create_dir_all(&home).unwrap();
        std::os::unix::fs::symlink(&theirs, home.join(".it-ai")).unwrap();
        let log = path_in(&home);
        assert!(prepare(&log).is_err(), "prepare must refuse a symlinked .it-ai");
        let mut c = std::process::Command::new("/bin/sh");
        c.args(["-c", "echo planted"]);
        redirect(&mut c, &log);
        assert!(c.status().unwrap().success());
        assert_eq!(std::fs::read_dir(&theirs).unwrap().count(), 0, "a file was created through the symlink");
        assert_eq!(std::fs::metadata(&theirs).unwrap().permissions().mode() & 0o777, 0o755, "its mode was changed");
        let _ = std::fs::remove_dir_all(&home);
    }

    /// `agent.log` is a hard link to another file: refused, the other file untouched.
    #[cfg(unix)]
    #[test]
    fn a_hard_linked_log_is_refused() {
        let home = scratch("hardlog");
        let v = victim(&home, true);
        let log = path_in(&home);
        std::fs::hard_link(&v, &log).unwrap();
        let before = std::fs::read(&v).unwrap();
        assert!(prepare(&log).is_err(), "prepare must refuse a log with 2 links");
        cap(&log);
        let mut c = std::process::Command::new("/bin/sh");
        c.args(["-c", "echo planted"]);
        redirect(&mut c, &log);
        assert!(c.status().unwrap().success());
        let after = std::fs::read(&v).unwrap();
        assert!(after == before, "the other link was written or truncated: {} bytes, was {}", after.len(), before.len());
        let _ = std::fs::remove_dir_all(&home);
    }

    /// The fd checks, with injected metadata: a log or `.it-ai` of another uid
    /// (as a root agent would find under a user's HOME) is refused, so is a
    /// hard-linked or non-regular log.
    #[cfg(unix)]
    #[test]
    fn a_log_of_another_uid_or_kind_is_refused() {
        use crate::entryclean::securefs::Meta;
        const REG: u32 = libc::S_IFREG as u32;
        const DIR: u32 = libc::S_IFDIR as u32;
        let m = |uid, mode, nlink| Meta { uid, gid: 0, mode, nlink, dev: 1, ino: 1 };
        assert_eq!(check_log(&m(0, REG | 0o600, 1), 0), Ok(()));
        assert_eq!(check_log(&m(501, REG | 0o644, 1), 501), Ok(()), "a loose mode is tightened, not refused");
        assert!(check_log(&m(1000, REG | 0o600, 1), 0).unwrap_err().contains("owned by uid 1000"));
        assert!(check_log(&m(0, REG | 0o600, 1), 1000).unwrap_err().contains("owned by uid 0"));
        assert!(check_log(&m(0, REG | 0o600, 2), 0).unwrap_err().contains("2 hard links"));
        assert!(check_log(&m(0, libc::S_IFIFO as u32 | 0o600, 1), 0).unwrap_err().contains("not a regular file"));
        assert!(check_log(&m(0, libc::S_IFLNK as u32 | 0o777, 1), 0).is_err());
        assert_eq!(check_log_dir(&m(0, DIR | 0o700, 2), 0), Ok(()));
        assert!(check_log_dir(&m(1000, DIR | 0o700, 2), 0).unwrap_err().contains("owned by uid 1000"));
        assert!(check_log_dir(&m(0, REG | 0o700, 1), 0).unwrap_err().contains("not a directory"));
    }

    /// A FIFO planted at the log's name: refused at once, not a hang.
    #[cfg(unix)]
    #[test]
    fn a_fifo_log_is_refused_without_blocking() {
        let home = scratch("fifo");
        std::fs::create_dir_all(home.join(".it-ai")).unwrap();
        let log = path_in(&home);
        let c = std::ffi::CString::new(log.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        assert!(prepare(&log).is_err());
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn cap_leaves_a_small_log_alone() {
        let home = scratch("small");
        let log = path_in(&home);
        prepare(&log).unwrap();
        std::fs::write(&log, b"keep me\n").unwrap();
        cap(&log);
        assert_eq!(std::fs::read(&log).unwrap(), b"keep me\n");
        let _ = std::fs::remove_dir_all(&home);
    }
}
