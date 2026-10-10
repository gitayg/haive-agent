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
//! none of them may be writable by others, or by a group other than the owner's
//! user-private group (as ssh's `StrictModes`, with Debian's patch for the
//! private group: see `private_group`). So a root agent never rewrites a file in
//! a directory a non-root user can change.

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
pub(crate) const IFREG: u32 = libc::S_IFREG as u32;
pub(crate) const IFDIR: u32 = libc::S_IFDIR as u32;
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

    pub(crate) fn kind(&self) -> u32 {
        self.mode & IFMT
    }

    fn same_inode(&self, o: &Meta) -> bool {
        self.dev == o.dev && self.ino == o.ino
    }

}

/// What the user-private-group rule needs from the user and group databases.
pub(crate) trait GroupDb {
    /// `uid`'s passwd entry: its name and primary gid.
    fn user(&self, uid: u32) -> Option<(String, u32)>;
    /// `gid`'s group entry: its name and supplementary members.
    fn group(&self, gid: u32) -> Option<(String, Vec<String>)>;
    /// The uid of every passwd entry whose primary group is `gid`.
    fn primary_users(&self, gid: u32) -> Vec<u32>;
    /// `/etc/nsswitch.conf`, None when it cannot be read.
    fn nsswitch(&self) -> Option<String>;
    /// `/etc/passwd` or `/etc/group` (`name`), None when it cannot be read.
    fn etc(&self, name: &str) -> Option<String>;
}

/// NSS sources whose users and groups are all on this machine and all
/// enumerable, so "no other user has this primary gid" can be proven by walking
/// them: `files` (/etc/passwd, /etc/group) and `systemd` (nss-systemd: records
/// of this machine only: systemd-homed users, `DynamicUser=` units, userdb
/// drop-ins, the synthesized root/nobody; all returned by getpwent). `compat` is
/// accepted only under the extra conditions in `nss_local`. Everything else is
/// refused: `cache` (libnss-cache: a periodically synced copy of a remote
/// directory, which can lag it), every remote source (`sss`, `ldap`, `winbind`,
/// `nis`, ...), whose users may not be enumerable at all, and any name not
/// listed here, in any case.
const LOCAL_NSS: &[&str] = &["files", "systemd"];

/// Ok only when nsswitch.conf provably makes glibc read users and groups from
/// local sources. Parsed STRICTLY, failing closed wherever this reading could
/// disagree with glibc's (which might then consult sss or ldap behind our back):
/// - every non-comment line must be `database: sources` (text after `#` is a
///   comment); database names are compared case-insensitively, so `PASSWD:` is a
///   `passwd:` line too;
/// - EXACTLY one `passwd:` and EXACTLY one `group:` line: none means glibc's
///   built-in default, two means it is unclear which glibc uses;
/// - no `[...]` action item on either line;
/// - every source is `files` or `systemd`, exactly as written, or `compat`, and
///   `compat` only when there is no `passwd_compat:`/`group_compat:` line and
///   that database's /etc file (`etc("passwd")`, `etc("group")`) is readable and
///   has no `+`/`-` NIS entry.
///
/// A missing /etc/nsswitch.conf (glibc's defaults, or a vendor file such as
/// openSUSE's /usr/etc/nsswitch.conf) is refused by the caller.
pub(crate) fn nss_local(conf: &str, etc: &dyn Fn(&str) -> Option<String>) -> Result<(), String> {
    let mut lines: Vec<(String, &str)> = Vec::new();
    for (n, raw) in conf.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let Some((db, sources)) = line.split_once(':') else {
            return Err(format!("nsswitch.conf line {} is not `database: sources`", n + 1));
        };
        lines.push((db.trim().to_ascii_lowercase(), sources));
    }
    let compat_line = lines.iter().find(|(d, _)| d == "passwd_compat" || d == "group_compat").map(|(d, _)| d.clone());
    for db in ["passwd", "group"] {
        let found: Vec<&str> = lines.iter().filter(|(d, _)| d == db).map(|(_, s)| *s).collect();
        let sources = match found[..] {
            [] => return Err(format!("nsswitch.conf has no {db}: line")),
            [one] => one,
            _ => return Err(format!("nsswitch.conf has {} {db}: lines", found.len())),
        };
        if sources.contains(['[', ']']) {
            return Err(format!("nsswitch.conf {db}: has an action item (`[...]`)"));
        }
        let mut any = false;
        for src in sources.split_whitespace() {
            any = true;
            if LOCAL_NSS.contains(&src) {
                continue;
            }
            if src != "compat" {
                return Err(format!("nsswitch.conf {db}: uses `{src}`, whose users may not all be enumerable here"));
            }
            if let Some(d) = &compat_line {
                return Err(format!("nsswitch.conf {db}: uses `compat`, and there is a {d}: line"));
            }
            let text = etc(db).ok_or_else(|| format!("nsswitch.conf {db}: uses `compat`, and /etc/{db} cannot be read"))?;
            if text.lines().any(|l| l.trim_start().starts_with(['+', '-'])) {
                return Err(format!("nsswitch.conf {db}: uses `compat`, and /etc/{db} has NIS +/- entries"));
            }
        }
        if !any {
            return Err(format!("nsswitch.conf {db}: names no source"));
        }
    }
    Ok(())
}

/// Whether `gid` is the user-private group of `uid`, so that group-write on a
/// file of `uid`'s in that group gives no one else write access. This is the
/// layout Debian and Ubuntu give every user (a group of the user's own, umask
/// 002), where `~/.config/autostart` is 0775 and a file in it 0664. The rule is
/// the one Debian patches into OpenSSH's `StrictModes`
/// (`debian/patches/user-group-modes.patch`, "Allow harmless group-writability",
/// `secure_permissions` in misc.c): a group-writable file is accepted only when
/// its group's one member is the file's owner. It FAILS CLOSED: every condition
/// must be proven, and Err names the first that is not:
/// - not root (root's paths keep the plain rule: no group-write);
/// - users and groups come only from local, enumerable NSS sources (`nss_local`),
///   so the walk below sees every user;
/// - `gid` is `uid`'s primary gid, and the group's name is the user's name (the
///   private-group convention);
/// - the group lists no supplementary members (Debian also accepts the owner as
///   the single listed member; this does not);
/// - no other passwd entry has `gid` as its primary group.
pub(crate) fn private_group(uid: u32, gid: u32, db: &dyn GroupDb) -> Result<(), String> {
    if uid == 0 {
        return Err("root's paths never get the private-group exception".into());
    }
    nss_local(&db.nsswitch().ok_or("/etc/nsswitch.conf cannot be read")?, &|f| db.etc(f))?;
    let (uname, primary) = db.user(uid).ok_or_else(|| format!("uid {uid} has no passwd entry"))?;
    if primary != gid {
        return Err(format!("it is not uid {uid}'s primary group ({primary})"));
    }
    let (gname, members) = db.group(gid).ok_or_else(|| format!("group {gid} has no group entry"))?;
    if gname != uname {
        return Err(format!("its name `{gname}` is not the user name `{uname}`"));
    }
    if !members.is_empty() {
        return Err(format!("it lists members {}", members.join(",")));
    }
    if let Some(other) = db.primary_users(gid).into_iter().find(|&u| u != uid) {
        return Err(format!("uid {other} also has it as primary group"));
    }
    Ok(())
}

/// Why `m` is writable by someone other than its owner, if it is: world-write
/// always counts, group-write unless the group is the owner's private group.
fn others_can_write(m: &Meta, db: &dyn GroupDb) -> Option<String> {
    let mode = m.mode & 0o7777;
    if m.mode & 0o002 != 0 {
        return Some(format!("world-writable ({mode:04o})"));
    }
    if m.mode & 0o020 != 0 {
        if let Err(why) = private_group(m.uid, m.gid, db) {
            return Some(format!("writable by group {} ({mode:04o}), which is not the private group of uid {}: {why}", m.gid, m.uid));
        }
    }
    None
}

/// The system's user and group databases, through NSS (`getpwuid_r`,
/// `getgrgid_r`, `getpwent`), as ssh's check reads them, and nsswitch.conf.
pub(crate) struct SysGroups;

/// Calls `f` with a buffer that grows while it answers ERANGE.
fn with_buf(mut f: impl FnMut(&mut Vec<libc::c_char>) -> libc::c_int) {
    let mut buf = vec![0 as libc::c_char; 4096];
    while f(&mut buf) == libc::ERANGE && buf.len() < 1 << 20 {
        buf.resize(buf.len() * 2, 0);
    }
}

fn owned(p: *const libc::c_char) -> String {
    unsafe { std::ffi::CStr::from_ptr(p) }.to_string_lossy().into_owned()
}

impl GroupDb for SysGroups {
    fn user(&self, uid: u32) -> Option<(String, u32)> {
        let mut pw = MaybeUninit::<libc::passwd>::zeroed();
        let mut res: *mut libc::passwd = std::ptr::null_mut();
        let mut out = None;
        with_buf(|b| {
            let r = unsafe { libc::getpwuid_r(uid as libc::uid_t, pw.as_mut_ptr(), b.as_mut_ptr(), b.len(), &mut res) };
            if r == 0 && !res.is_null() {
                // Copied out while `b` still holds the strings.
                out = Some(unsafe { (owned((*res).pw_name), (*res).pw_gid as u32) });
            }
            r
        });
        out
    }

    fn group(&self, gid: u32) -> Option<(String, Vec<String>)> {
        let mut gr = MaybeUninit::<libc::group>::zeroed();
        let mut res: *mut libc::group = std::ptr::null_mut();
        let mut out = None;
        with_buf(|b| {
            let r = unsafe { libc::getgrgid_r(gid as libc::gid_t, gr.as_mut_ptr(), b.as_mut_ptr(), b.len(), &mut res) };
            if r == 0 && !res.is_null() {
                let mut v = Vec::new();
                let mut p = unsafe { (*res).gr_mem };
                while !p.is_null() && !unsafe { *p }.is_null() {
                    v.push(owned(unsafe { *p }));
                    p = unsafe { p.add(1) };
                }
                out = Some((owned(unsafe { (*res).gr_name }), v));
            }
            r
        });
        out
    }

    fn primary_users(&self, gid: u32) -> Vec<u32> {
        // getpwent walks one process-wide cursor.
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut v = Vec::new();
        unsafe {
            libc::setpwent();
            loop {
                let pw = libc::getpwent();
                if pw.is_null() {
                    break;
                }
                if (*pw).pw_gid as u32 == gid {
                    v.push((*pw).pw_uid as u32);
                }
            }
            libc::endpwent();
        }
        v
    }

    fn nsswitch(&self) -> Option<String> {
        std::fs::read_to_string("/etc/nsswitch.conf").ok()
    }

    fn etc(&self, name: &str) -> Option<String> {
        std::fs::read_to_string(Path::new("/etc").join(name)).ok()
    }
}

pub(crate) fn euid() -> u32 {
    unsafe { libc::geteuid() }
}

/// The entry file: a regular file of ours, one link, writable by us alone (or our
/// private group).
pub(crate) fn check_file(m: &Meta, euid: u32, db: &dyn GroupDb) -> Result<(), String> {
    if m.kind() == IFLNK {
        return Err("it is a symlink".into());
    }
    if m.kind() != IFREG {
        return Err("it is not a regular file".into());
    }
    if m.uid != euid {
        return Err(format!("it is owned by uid {}, not by this agent (uid {euid})", m.uid));
    }
    if let Some(why) = others_can_write(m, db) {
        return Err(format!("it is {why}"));
    }
    if m.nlink != 1 {
        return Err(format!("it has {} hard links", m.nlink));
    }
    Ok(())
}

/// A directory on the way to the entry. `own`: the entry's own directory, which
/// must be ours; one above it may also be root's. None may be writable by others,
/// or by a group other than its owner's private group.
pub(crate) fn check_dir(path: &Path, m: &Meta, euid: u32, own: bool, db: &dyn GroupDb) -> Result<(), String> {
    if m.kind() != IFDIR {
        return Err(format!("{} is not a directory", path.display()));
    }
    if !(m.uid == euid || (!own && m.uid == 0)) {
        return Err(format!("{} is owned by uid {}, not by this agent (uid {euid})", path.display(), m.uid));
    }
    if let Some(why) = others_can_write(m, db) {
        return Err(format!("{} is {why}", path.display()));
    }
    Ok(())
}

/// Whether `path` is a directory only root or `euid` (with its private group) can change: every component
/// from `/` down is checked as `check_dir` checks an ancestor, and a symlink on
/// the way must itself be root's or ours (its directory was checked just before)
/// and its target is checked the same way, from `/`. For a HOME pinned into a
/// service: the agent loads its credential, certs, jobs and schedules from there.
pub(crate) fn check_trusted_dir(path: &Path, euid: u32, db: &dyn GroupDb) -> Result<(), String> {
    trusted(path, euid, 0, db)
}

fn trusted(path: &Path, euid: u32, depth: u32, db: &dyn GroupDb) -> Result<(), String> {
    use std::path::Component;
    if depth > 16 {
        return Err(format!("{}: too many symlinks", path.display()));
    }
    if !path.is_absolute() {
        return Err(format!("{} is not an absolute path", path.display()));
    }
    let stat = |p: &Path| std::fs::symlink_metadata(p).map(|m| Meta::from_std(&m)).map_err(|e| format!("{}: {e}", p.display()));
    let mut cur = PathBuf::from("/");
    check_dir(&cur, &stat(&cur)?, euid, false, db)?;
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
            trusted(&target, euid, depth + 1, db)?;
            cur = std::fs::canonicalize(&cur).map_err(|e| format!("{}: {e}", cur.display()))?;
        } else {
            check_dir(&cur, &m, euid, false, db)?;
        }
    }
    Ok(())
}

pub(crate) fn cvt(r: libc::c_int) -> io::Result<libc::c_int> {
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r)
    }
}

pub(crate) fn cstr(b: &[u8]) -> io::Result<CString> {
    CString::new(b).map_err(io::Error::other)
}

pub(crate) fn fstat(fd: RawFd) -> io::Result<Meta> {
    let mut st = MaybeUninit::<libc::stat>::zeroed();
    cvt(unsafe { libc::fstat(fd, st.as_mut_ptr()) })?;
    Ok(Meta::from_stat(unsafe { &st.assume_init() }))
}

fn lstat_at(dir: RawFd, name: &CString) -> io::Result<Meta> {
    let mut st = MaybeUninit::<libc::stat>::zeroed();
    cvt(unsafe { libc::fstatat(dir, name.as_ptr(), st.as_mut_ptr(), libc::AT_SYMLINK_NOFOLLOW) })?;
    Ok(Meta::from_stat(unsafe { &st.assume_init() }))
}

pub(crate) fn open_at(dir: RawFd, name: &CString, flags: libc::c_int, mode: u32) -> io::Result<OwnedFd> {
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
    pub(crate) fn check(&self, euid: u32, db: &dyn GroupDb) -> Result<(), String> {
        check_file(&self.meta, euid, db)?;
        check_dir(&self.dir_path, &self.dir_meta, euid, true, db)?;
        let mut up = self.dir_path.parent();
        while let Some(d) = up {
            let m = std::fs::symlink_metadata(d).map_err(|e| format!("{}: {e}", d.display()))?;
            check_dir(d, &Meta::from_std(&m), euid, false, db)?;
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
