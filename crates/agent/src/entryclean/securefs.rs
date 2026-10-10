// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

//! Reading and replacing an entry file without following symlinks, and the rules
//! for when this process may replace one at all. Unix only.
//!
//! The entry's directory is opened once (`O_DIRECTORY|O_NOFOLLOW`) and everything
//! after that is relative to that fd: the entry is `lstat`ed and opened with
//! `O_NOFOLLOW` (and must still be the inode that was `lstat`ed), the temp file is
//! created `O_CREAT|O_EXCL|O_NOFOLLOW` in the same directory, and it is renamed
//! over the entry with `renameat` on that fd, after checking the name still holds
//! the inode that was read. Swapping the directory, or the entry for a symlink,
//! after the checks cannot redirect the write.
//!
//! Who may rewrite: the file and its directory must belong to this process's
//! effective uid, and every directory from there up to `/` to it or to root, and
//! none of them may be writable by group or others (as ssh's `StrictModes`). So
//! a root agent never rewrites a file in a directory a non-root user can change.

use std::ffi::CString;
use std::io::{self, Read, Write};
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/// The parts of a `stat` the rules look at.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Meta {
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub nlink: u64,
    pub dev: u64,
    pub ino: u64,
}

const IFMT: u32 = libc::S_IFMT as u32;
const IFREG: u32 = libc::S_IFREG as u32;
const IFDIR: u32 = libc::S_IFDIR as u32;
const IFLNK: u32 = libc::S_IFLNK as u32;

impl Meta {
    #[allow(clippy::unnecessary_cast)]
    fn from_stat(st: &libc::stat) -> Meta {
        Meta {
            uid: st.st_uid,
            gid: st.st_gid,
            mode: st.st_mode as u32,
            nlink: st.st_nlink as u64,
            dev: st.st_dev as u64,
            ino: st.st_ino as u64,
        }
    }

    fn from_std(m: &std::fs::Metadata) -> Meta {
        use std::os::unix::fs::MetadataExt;
        Meta { uid: m.uid(), gid: m.gid(), mode: m.mode(), nlink: m.nlink(), dev: m.dev(), ino: m.ino() }
    }

    fn kind(&self) -> u32 {
        self.mode & IFMT
    }

    fn same_inode(&self, o: &Meta) -> bool {
        self.dev == o.dev && self.ino == o.ino
    }

    fn others_can_write(&self) -> bool {
        self.mode & 0o022 != 0
    }
}

pub(crate) fn euid() -> u32 {
    unsafe { libc::geteuid() }
}

/// The entry file: a regular file of ours, one link, writable by us alone.
pub(crate) fn check_file(m: &Meta, euid: u32) -> Result<(), String> {
    if m.kind() == IFLNK {
        return Err("it is a symlink".into());
    }
    if m.kind() != IFREG {
        return Err("it is not a regular file".into());
    }
    if m.uid != euid {
        return Err(format!("it is owned by uid {}, not by this agent (uid {euid})", m.uid));
    }
    if m.others_can_write() {
        return Err(format!("it is group- or world-writable ({:04o})", m.mode & 0o7777));
    }
    if m.nlink != 1 {
        return Err(format!("it has {} hard links", m.nlink));
    }
    Ok(())
}

/// A directory on the way to the entry. `own`: the entry's own directory, which
/// must be ours; one above it may also be root's. None may be writable by group
/// or others.
pub(crate) fn check_dir(path: &Path, m: &Meta, euid: u32, own: bool) -> Result<(), String> {
    if m.kind() != IFDIR {
        return Err(format!("{} is not a directory", path.display()));
    }
    if !(m.uid == euid || (!own && m.uid == 0)) {
        return Err(format!("{} is owned by uid {}, not by this agent (uid {euid})", path.display(), m.uid));
    }
    if m.others_can_write() {
        return Err(format!("{} is group- or world-writable ({:04o})", path.display(), m.mode & 0o7777));
    }
    Ok(())
}

/// Whether `path` is a directory only root or `euid` can change: every component
/// from `/` down is checked as `check_dir` checks an ancestor, and a symlink on
/// the way must itself be root's or ours (its directory was checked just before)
/// and its target is checked the same way, from `/`. For a HOME pinned into a
/// service: the agent loads its credential, certs, jobs and schedules from there.
pub(crate) fn check_trusted_dir(path: &Path, euid: u32) -> Result<(), String> {
    trusted(path, euid, 0)
}

fn trusted(path: &Path, euid: u32, depth: u32) -> Result<(), String> {
    use std::path::Component;
    if depth > 16 {
        return Err(format!("{}: too many symlinks", path.display()));
    }
    if !path.is_absolute() {
        return Err(format!("{} is not an absolute path", path.display()));
    }
    let stat = |p: &Path| std::fs::symlink_metadata(p).map(|m| Meta::from_std(&m)).map_err(|e| format!("{}: {e}", p.display()));
    let mut cur = PathBuf::from("/");
    check_dir(&cur, &stat(&cur)?, euid, false)?;
    for c in path.components() {
        match c {
            Component::Normal(n) => cur.push(n),
            Component::ParentDir => {
                cur.pop();
                continue;
            }
            _ => continue,
        }
        let m = stat(&cur)?;
        if m.kind() == IFLNK {
            if !(m.uid == euid || m.uid == 0) {
                return Err(format!("{} is a symlink owned by uid {}", cur.display(), m.uid));
            }
            let target = std::fs::read_link(&cur).map_err(|e| format!("{}: {e}", cur.display()))?;
            let target = if target.is_absolute() { target } else { cur.parent().unwrap_or(Path::new("/")).join(target) };
            trusted(&target, euid, depth + 1)?;
            cur = std::fs::canonicalize(&cur).map_err(|e| format!("{}: {e}", cur.display()))?;
        } else {
            check_dir(&cur, &m, euid, false)?;
        }
    }
    Ok(())
}

fn cvt(r: libc::c_int) -> io::Result<libc::c_int> {
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r)
    }
}

fn cstr(b: &[u8]) -> io::Result<CString> {
    CString::new(b).map_err(io::Error::other)
}

fn fstat(fd: RawFd) -> io::Result<Meta> {
    let mut st = MaybeUninit::<libc::stat>::zeroed();
    cvt(unsafe { libc::fstat(fd, st.as_mut_ptr()) })?;
    Ok(Meta::from_stat(unsafe { &st.assume_init() }))
}

fn lstat_at(dir: RawFd, name: &CString) -> io::Result<Meta> {
    let mut st = MaybeUninit::<libc::stat>::zeroed();
    cvt(unsafe { libc::fstatat(dir, name.as_ptr(), st.as_mut_ptr(), libc::AT_SYMLINK_NOFOLLOW) })?;
    Ok(Meta::from_stat(unsafe { &st.assume_init() }))
}

fn open_at(dir: RawFd, name: &CString, flags: libc::c_int, mode: u32) -> io::Result<OwnedFd> {
    let fd = cvt(unsafe { libc::openat(dir, name.as_ptr(), flags | libc::O_CLOEXEC, mode as libc::c_uint) })?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// An entry file, read through its opened directory.
#[derive(Debug)]
pub(crate) struct Entry {
    dir: OwnedFd,
    dir_path: PathBuf,
    dir_meta: Meta,
    name: CString,
    pub(crate) meta: Meta,
    pub(crate) text: String,
}

fn not_found(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::NotFound
}

/// Open the entry at `path` without following a symlink at it or at its
/// directory. Ok(None): there is no entry there. Err: it cannot be read safely.
pub(crate) fn open(path: &Path) -> Result<Option<Entry>, String> {
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else { return Ok(None) };
    let dir_path = match std::fs::canonicalize(parent) {
        Ok(p) => p,
        Err(e) if not_found(&e) => return Ok(None),
        Err(e) => return Err(format!("its directory cannot be resolved ({e})")),
    };
    let c = cstr(dir_path.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
    let dir = match cvt(unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) }) {
        Ok(fd) => unsafe { OwnedFd::from_raw_fd(fd) },
        Err(e) if not_found(&e) => return Ok(None),
        Err(e) => return Err(format!("its directory cannot be opened ({e})")),
    };
    let dir_meta = fstat(dir.as_raw_fd()).map_err(|e| e.to_string())?;
    let name = cstr(name.as_bytes()).map_err(|e| e.to_string())?;
    let before = match lstat_at(dir.as_raw_fd(), &name) {
        Ok(m) => m,
        Err(e) if not_found(&e) => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    if before.kind() == IFLNK {
        return Err("it is a symlink".into());
    }
    if before.kind() != IFREG {
        return Err("it is not a regular file".into());
    }
    let fd = open_at(dir.as_raw_fd(), &name, libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK, 0).map_err(|e| e.to_string())?;
    let meta = fstat(fd.as_raw_fd()).map_err(|e| e.to_string())?;
    if !meta.same_inode(&before) {
        return Err("it changed while it was being opened".into());
    }
    let mut text = String::new();
    std::fs::File::from(fd).read_to_string(&mut text).map_err(|e| e.to_string())?;
    Ok(Some(Entry { dir, dir_path, dir_meta, name, meta, text }))
}

impl Entry {
    /// May a process running as `euid` replace this entry (see the module doc).
    pub(crate) fn check(&self, euid: u32) -> Result<(), String> {
        check_file(&self.meta, euid)?;
        check_dir(&self.dir_path, &self.dir_meta, euid, true)?;
        let mut up = self.dir_path.parent();
        while let Some(d) = up {
            let m = std::fs::symlink_metadata(d).map_err(|e| format!("{}: {e}", d.display()))?;
            check_dir(d, &Meta::from_std(&m), euid, false)?;
            up = d.parent();
        }
        Ok(())
    }

    /// Replace the entry with `text`, keeping its mode and (as root) its owner. The
    /// temp name does not end in `.plist` / `.service` / `.desktop`, so nothing
    /// loads it.
    pub(crate) fn replace(&self, text: &str) -> io::Result<()> {
        let dir = self.dir.as_raw_fd();
        let tmp = cstr(format!(".{}.it-ai-tmp-{}", self.name.to_string_lossy(), std::process::id()).as_bytes())?;
        // A leftover from an interrupted run; only a name inside the checked directory.
        unsafe { libc::unlinkat(dir, tmp.as_ptr(), 0) };
        let mode = self.meta.mode & 0o777;
        let fd = open_at(dir, &tmp, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW, mode)?;
        let res = (|| {
            let mut f = std::fs::File::from(fd);
            f.write_all(text.as_bytes())?;
            cvt(unsafe { libc::fchmod(f.as_raw_fd(), mode as libc::mode_t) })?;
            if euid() == 0 {
                cvt(unsafe { libc::fchown(f.as_raw_fd(), self.meta.uid, self.meta.gid) })?;
            }
            f.sync_all()?;
            // The name must still be the file that was read and checked.
            let now = lstat_at(dir, &self.name)?;
            if !now.same_inode(&self.meta) || now.kind() != IFREG {
                return Err(io::Error::other("the entry was replaced after it was read"));
            }
            cvt(unsafe { libc::renameat(dir, tmp.as_ptr(), dir, self.name.as_ptr()) })?;
            let _ = unsafe { libc::fsync(dir) };
            Ok(())
        })();
        if res.is_err() {
            unsafe { libc::unlinkat(dir, tmp.as_ptr(), 0) };
        }
        res
    }
}
