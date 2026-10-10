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
    /// The uid of every passwd entry that holds `gid` once logged in: its groups
    /// as login computes them (`getgrouplist`, every `initgroups`/`group` source),
    /// primary group included. Err when they cannot be listed.
    fn login_members(&self, gid: u32) -> Result<Vec<u32>, String>;
    /// `/etc/nsswitch.conf`, None when it cannot be read.
    fn nsswitch(&self) -> Option<String>;
    /// `/etc/passwd` or `/etc/group` (`name`), None when it cannot be read.
    fn etc(&self, name: &str) -> Option<String>;
    /// Whether nscd's socket exists: glibc then asks nscd first.
    fn nscd(&self) -> bool;
    /// The first variable set in this process's environment that changes what
    /// nss-systemd returns to it, if any.
    fn systemd_env(&self) -> Option<String>;
}

/// NSS sources whose users and groups are all on this machine: `files`
/// (/etc/passwd, /etc/group) and `systemd` (nss-systemd: userdb drop-ins,
/// systemd-homed users, `DynamicUser=` units, and root/nobody synthesized when
/// /etc lacks them). `compat` is accepted only under the extra conditions in
/// `nss_local`. Everything else is refused: `cache` (libnss-cache: a periodically
/// synced copy of a remote directory, which can lag it), every remote source
/// (`sss`, `ldap`, `winbind`, `nis`, ...), whose users may not be enumerable at
/// all, and any name not listed here, in any case.
///
/// `systemd` is local but NOT fully enumerable, so `private_group` adds
/// conditions when it is listed. Its getpwent leaves out the root/nobody it
/// synthesizes and the foreign-range users (nss-systemd.c `_nss_systemd_setpwent`:
/// `USERDB_DONT_SYNTHESIZE_INTRINSIC | USERDB_DONT_SYNTHESIZE_FOREIGN`), all of them
/// with ids outside 1-60000 (systemd docs/UIDS-GIDS.md). Variables in this
/// process's environment can hide its records from this process alone. And its
/// memberships give a user groups at login (`_nss_systemd_initgroups_dyn`)
/// that `getgrgid` does not show when `files` answers it first.
const LOCAL_NSS: &[&str] = &["files", "systemd"];

/// The databases that decide who holds a group: `passwd` (primary groups),
/// `group` (members, and the groups added at login when there is no
/// `initgroups:` line), `initgroups` (the groups added at login) and `gshadow`
/// (the members `newgrp` admits; glibc defaults it to `group`'s sources).
const NSS_DBS: &[&str] = &["passwd", "group", "initgroups", "gshadow"];

/// The databases `compat` sends `+`/`-` entries to.
const NSS_COMPAT_DBS: &[&str] = &["passwd_compat", "group_compat"];

/// C's `isspace` in the C locale: what glibc splits nsswitch.conf on.
fn c_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\x0b' | '\x0c' | '\r')
}

/// Ok only when nsswitch.conf provably makes glibc read users and groups from
/// local sources; Ok(true) when one of them is `systemd`. The file is read the way
/// glibc reads it, with both parsers the agent can meet: the one in glibc 2.33+
/// (`nss/nss_database.c` `process_line`, `nss/nss_action_parse.c`) and the older
/// one (2.31/2.32 `nss/nsswitch.c` `nss_parse_file`, `nss_getline`; the Linux
/// build's floor is glibc 2.31). It fails closed wherever the two differ, or where
/// this reading might differ from either:
/// - the file must be ASCII with no NUL. A NUL ends glibc's line early, and
///   whether a byte above 0x7f is a space depends on the locale;
/// - it must end in a newline. glibc 2.33+ drops a last line that has none (it
///   checks `feof` before it parses the line), while 2.32 reads it;
/// - a line's database name is the text after any leading space, up to the
///   first space or `:`, compared case-sensitively (`strcmp`), so glibc does not
///   read `PASSWD:` as `passwd:`. A case variant of a name in `NSS_DBS` or
///   `NSS_COMPAT_DBS` is refused, not ignored;
/// - only glibc 2.32 and older treat `#` as a comment (`strchrnul (line, '#')`).
///   glibc 2.33+ has no comments: a line that starts with `#` is skipped only
///   because no database has that name, and in `passwd: files # sss` it reads
///   `#` and `sss` as sources. A `#` anywhere after a name in `NSS_DBS` is refused;
/// - a name in `NSS_DBS` must be followed directly by `:`, with no second `:`
///   before its sources. 2.32 skips one character after the name and reads a
///   further `:` as part of a source name, while 2.33+ skips every space and `:`.
///   There may be no `[...]` action item;
/// - there must be EXACTLY one `passwd:` and one `group:` line, and at most one
///   `initgroups:` and one `gshadow:` line. Without a passwd or group line glibc
///   uses its built-in default (`compat [NOTFOUND=return] files` on a build with
///   --enable-obsolete-nsl, as Ubuntu 20.04's), and of two lines the last wins;
/// - every source is `files` or `systemd`, exactly as written. On `passwd`/`group`
///   it may also be `compat`, but only when there is no
///   `passwd_compat:`/`group_compat:` line and that database's /etc file
///   (`etc("passwd")`, `etc("group")`) is readable and has no `+`/`-` NIS entry.
///
/// Other databases' lines cannot change these, so their sources do not matter.
/// Each still needs a `:`, unless it is blank or starts with `#`.
///
/// A missing /etc/nsswitch.conf (glibc's defaults, or a vendor file such as
/// openSUSE's /usr/etc/nsswitch.conf) is refused by the caller.
pub(crate) fn nss_local(conf: &str, etc: &dyn Fn(&str) -> Option<String>) -> Result<bool, String> {
    if conf.contains('\0') {
        return Err("nsswitch.conf has a NUL byte".into());
    }
    if !conf.is_ascii() {
        return Err("nsswitch.conf has a non-ASCII byte".into());
    }
    let mut lines: Vec<&str> = conf.split('\n').collect();
    // What follows the last newline: only space in a file glibc reads whole.
    if lines.pop().is_some_and(|last| !last.chars().all(c_space)) {
        return Err("nsswitch.conf does not end in a newline (glibc 2.33+ skips such a last line, older glibc reads it)".into());
    }
    let mut found: Vec<(&str, Vec<&str>)> = Vec::new();
    let mut compat_line = None;
    for (n, raw) in lines.iter().enumerate().map(|(i, l)| (i + 1, l)) {
        let line = raw.trim_start_matches(c_space);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, rest) = line.split_at(line.find(|c| c_space(c) || c == ':').unwrap_or(line.len()));
        let Some(&db) = NSS_DBS.iter().chain(NSS_COMPAT_DBS).find(|d| d.eq_ignore_ascii_case(name)) else {
            if !line.contains(':') {
                return Err(format!("nsswitch.conf line {n} is not `database: sources`"));
            }
            continue;
        };
        if name != db {
            return Err(format!("nsswitch.conf line {n} names `{name}`, which glibc does not read as `{db}:` (database names are case-sensitive)"));
        }
        if NSS_COMPAT_DBS.contains(&db) {
            compat_line.get_or_insert(db);
            continue;
        }
        let Some(sources) = rest.strip_prefix(':').filter(|s| !s.trim_start_matches(c_space).starts_with(':')) else {
            return Err(format!("nsswitch.conf line {n} is not `{db}: sources`"));
        };
        if sources.contains('#') {
            return Err(format!("nsswitch.conf line {n} has a `#` after `{db}:` (glibc 2.33+ reads it and what follows as sources, older glibc as a comment)"));
        }
        if sources.contains(['[', ']']) {
            return Err(format!("nsswitch.conf {db}: has an action item (`[...]`)"));
        }
        found.push((db, sources.split(c_space).filter(|s| !s.is_empty()).collect()));
    }
    let mut systemd = false;
    for &db in NSS_DBS {
        let lines: Vec<&Vec<&str>> = found.iter().filter(|(d, _)| *d == db).map(|(_, s)| s).collect();
        let required = matches!(db, "passwd" | "group");
        let sources = match lines[..] {
            [] if required => return Err(format!("nsswitch.conf has no {db}: line")),
            [] => continue,
            [one] => one,
            _ => return Err(format!("nsswitch.conf has {} {db}: lines", lines.len())),
        };
        if sources.is_empty() {
            return Err(format!("nsswitch.conf {db}: names no source"));
        }
        for &src in sources {
            if LOCAL_NSS.contains(&src) {
                systemd |= src == "systemd";
                continue;
            }
            if src != "compat" || !required {
                return Err(format!("nsswitch.conf {db}: uses `{src}`, whose users may not all be enumerable here"));
            }
            if let Some(d) = compat_line {
                return Err(format!("nsswitch.conf {db}: uses `compat`, and there is a {d}: line"));
            }
            let text = etc(db).ok_or_else(|| format!("nsswitch.conf {db}: uses `compat`, and /etc/{db} cannot be read"))?;
            if text.lines().any(|l| l.trim_start().starts_with(['+', '-'])) {
                return Err(format!("nsswitch.conf {db}: uses `compat`, and /etc/{db} has NIS +/- entries"));
            }
        }
    }
    Ok(systemd)
}

/// The highest id of systemd's "regular users" range (docs/UIDS-GIDS.md:
/// 1000…60000, listed in /etc/passwd or a directory service). Every user that
/// nss-systemd returns but getpwent does not list has an id of 0 or above this.
const SYSTEMD_REGULAR_MAX: u32 = 60000;

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
/// - users and groups come only from local NSS sources (`nss_local`), so the
///   walks below see every user;
/// - nscd's socket does not exist (glibc would take lookups from nscd's cache,
///   filled under its own configuration, while getpwent walks NSS itself);
/// - with `systemd` among the sources (see `LOCAL_NSS`), nothing in this
///   process's environment changes what nss-systemd returns, and `gid` is in
///   1-60000, where nss-systemd has no user that getpwent leaves out;
/// - `gid` is `uid`'s primary gid, and the group's name is the user's name (the
///   private-group convention);
/// - the group lists no supplementary members (Debian also accepts the owner as
///   the single listed member; this does not);
/// - no other passwd entry has `gid` as its primary group, or among its groups
///   at login (`login_members`: what an nss-systemd membership or an
///   `initgroups:` source adds, which `getgrgid` may not show).
pub(crate) fn private_group(uid: u32, gid: u32, db: &dyn GroupDb) -> Result<(), String> {
    if uid == 0 {
        return Err("root's paths never get the private-group exception".into());
    }
    let systemd = nss_local(&db.nsswitch().ok_or("/etc/nsswitch.conf cannot be read")?, &|f| db.etc(f))?;
    if db.nscd() {
        return Err("nscd's socket exists (/var/run/nscd/socket), so glibc answers from nscd's cache".into());
    }
    if systemd {
        if let Some(var) = db.systemd_env() {
            return Err(format!("nsswitch.conf uses `systemd`, and {var} is set, which changes what nss-systemd shows this process"));
        }
        if !(1..=SYSTEMD_REGULAR_MAX).contains(&gid) {
            return Err(format!(
                "nsswitch.conf uses `systemd`, which has users getpwent does not list with ids outside 1-{SYSTEMD_REGULAR_MAX}, and this group is {gid}"
            ));
        }
    }
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
    if let Some(other) = db.login_members(gid)?.into_iter().find(|&u| u != uid) {
        return Err(format!("uid {other} gets it at login"));
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
/// `getgrgid_r`, `getpwent`, `getgrouplist`), as ssh's check and login read
/// them, and nsswitch.conf.
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
        passwd_entries().into_iter().filter(|e| e.2 == gid).map(|e| e.0).collect()
    }

    #[cfg(target_os = "linux")]
    fn login_members(&self, gid: u32) -> Result<Vec<u32>, String> {
        let mut v = Vec::new();
        for (uid, name, base) in passwd_entries() {
            let mut groups: Vec<libc::gid_t> = vec![0; 64];
            loop {
                let mut n = groups.len() as libc::c_int;
                if unsafe { libc::getgrouplist(name.as_ptr(), base, groups.as_mut_ptr(), &mut n) } >= 0 {
                    groups.truncate(n as usize);
                    break;
                }
                // Too small: glibc has set `n` to the number it needs.
                if n as usize <= groups.len() || n > 1 << 20 {
                    return Err(format!("the groups of user {} cannot be listed", name.to_string_lossy()));
                }
                groups.resize(n as usize, 0);
            }
            if groups.contains(&gid) {
                v.push(uid);
            }
        }
        Ok(v)
    }

    #[cfg(not(target_os = "linux"))]
    fn login_members(&self, _gid: u32) -> Result<Vec<u32>, String> {
        Err("groups at login are not listed on this OS".into())
    }

    fn nsswitch(&self) -> Option<String> {
        std::fs::read_to_string("/etc/nsswitch.conf").ok()
    }

    fn etc(&self, name: &str) -> Option<String> {
        std::fs::read_to_string(Path::new("/etc").join(name)).ok()
    }

    fn nscd(&self) -> bool {
        // glibc's _PATH_NSCDSOCKET. Anything but "not there" counts as there.
        !matches!(std::fs::symlink_metadata("/var/run/nscd/socket"), Err(e) if e.kind() == io::ErrorKind::NotFound)
    }

    fn systemd_env(&self) -> Option<String> {
        // nss-systemd: SYSTEMD_NSS_BYPASS_SYNTHETIC, SYSTEMD_NSS_DYNAMIC_BYPASS (and
        // SYSTEMD_NSS_BYPASS_BUS before userdb); userdb.c: SYSTEMD_BYPASS_USERDB,
        // SYSTEMD_ONLY_USERDB.
        std::env::vars_os()
            .map(|(k, _)| k.to_string_lossy().into_owned())
            .find(|k| k.starts_with("SYSTEMD_NSS_") || k == "SYSTEMD_BYPASS_USERDB" || k == "SYSTEMD_ONLY_USERDB")
    }
}

/// Every entry getpwent lists: uid, name, primary gid.
fn passwd_entries() -> Vec<(u32, CString, u32)> {
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
            v.push(((*pw).pw_uid as u32, std::ffi::CStr::from_ptr((*pw).pw_name).to_owned(), (*pw).pw_gid as u32));
        }
        libc::endpwent();
    }
    v
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
