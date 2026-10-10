// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

//! Pure text transforms over this agent's own autostart/service entries, for
//! `entryclean`: does an entry carry the enrollment token (`--relay-token`), the
//! same entry without it, which HOME the entry runs with, and the entry with a
//! HOME pinned. No I/O here.
//!
//! Formats, as the writers in `persistence` produce them (and as agents older
//! than 3.7.0 did, with the token): a Linux `.desktop` `Exec=` line, a systemd
//! `ExecStart=` line, a launchd plist `ProgramArguments` array, the command a
//! Windows scheduled task runs (`schtasks /TR`), and the HKCU Run value.

use std::path::{Path, PathBuf};

use crate::relaycred::FLAG;

/// The HOME an entry will run with, as far as the entry itself says.
#[cfg_attr(windows, allow(dead_code))]
#[derive(Debug, PartialEq, Clone)]
pub(crate) enum EntryHome {
    /// The entry sets HOME explicitly.
    Pinned(PathBuf),
    /// The entry sets nothing, and the platform's behaviour gives this.
    Default(PathBuf),
    /// The entry sets nothing, and what the platform gives is not known.
    Unknown,
}

fn is_token_arg(a: &str) -> bool {
    a == FLAG || a.strip_prefix(FLAG).is_some_and(|r| r.starts_with('='))
}

/// Byte spans of the whitespace-separated words of a command line. A double
/// quote groups, a single quote too when `single` (systemd), and a backslash
/// escapes a following quote.
fn words(s: &str, single: bool) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut start = None;
    let mut quote: Option<char> = None;
    let mut it = s.char_indices().peekable();
    while let Some((i, c)) = it.next() {
        if start.is_none() {
            if c.is_whitespace() {
                continue;
            }
            start = Some(i);
        }
        match c {
            '\\' => {
                if let Some(&(_, n)) = it.peek() {
                    if n == '"' || (single && n == '\'') {
                        it.next();
                    }
                }
            }
            '"' | '\'' if quote == Some(c) => quote = None,
            '"' if quote.is_none() => quote = Some('"'),
            '\'' if single && quote.is_none() => quote = Some('\''),
            c if c.is_whitespace() && quote.is_none() => {
                if let Some(st) = start.take() {
                    out.push((st, i));
                }
            }
            _ => {}
        }
    }
    if let Some(st) = start {
        out.push((st, s.len()));
    }
    out
}

/// One word without its quoting.
fn unquote(w: &str, single: bool) -> String {
    let mut out = String::with_capacity(w.len());
    let mut quote: Option<char> = None;
    let mut it = w.chars().peekable();
    while let Some(c) = it.next() {
        match c {
            '\\' if it.peek() == Some(&'"') || (single && it.peek() == Some(&'\'')) => {
                out.push(it.next().unwrap_or_default());
            }
            '"' | '\'' if quote == Some(c) => quote = None,
            '"' if quote.is_none() => quote = Some('"'),
            '\'' if single && quote.is_none() => quote = Some('\''),
            _ => out.push(c),
        }
    }
    out
}

/// Which of `args` to drop: `--relay-token <v>` (both words) and `--relay-token=<v>`,
/// exactly as `relaycred::split_token` reads them.
fn token_drops(args: &[String]) -> Vec<bool> {
    let mut drop = vec![false; args.len()];
    let mut i = 0;
    while i < args.len() {
        if args[i] == FLAG {
            drop[i] = true;
            if i + 1 < args.len() {
                drop[i + 1] = true;
            }
            i += 2;
            continue;
        }
        drop[i] = is_token_arg(&args[i]);
        i += 1;
    }
    drop
}

/// Remove the spans marked in `drop` from `s`, each with the gap before it, and
/// keep every other byte (quoting, separators, the rest) as it was.
fn cut(s: &str, from: usize, spans: &[(usize, usize)], drop: &[bool]) -> String {
    let mut out = String::with_capacity(s.len());
    out.push_str(&s[..from]);
    let mut prev = from;
    for (k, &(_, end)) in spans.iter().enumerate() {
        if !drop[k] {
            out.push_str(&s[prev..end]);
        }
        prev = end;
    }
    out.push_str(&s[prev..]);
    out
}

/// The command line without the token, or None when it carries none.
pub(crate) fn strip_cmdline(s: &str, single: bool) -> Option<String> {
    let spans = words(s, single);
    let args: Vec<String> = spans.iter().map(|&(a, b)| unquote(&s[a..b], single)).collect();
    let drop = token_drops(&args);
    drop.contains(&true).then(|| cut(s, 0, &spans, &drop))
}

/// Rewrite the value of every line starting with `key`; None if none changed.
#[cfg_attr(windows, allow(dead_code))]
fn strip_lines(text: &str, key: &str, single: bool) -> Option<String> {
    let mut changed = false;
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        if let Some(v) = line.strip_prefix(key) {
            let (body, end) = split_eol(v);
            if let Some(nv) = strip_cmdline(body, single) {
                out.push_str(key);
                out.push_str(&nv);
                out.push_str(end);
                changed = true;
                continue;
            }
        }
        out.push_str(line);
    }
    changed.then_some(out)
}

#[cfg_attr(windows, allow(dead_code))]
fn split_eol(l: &str) -> (&str, &str) {
    let body = l.trim_end_matches(['\n', '\r']);
    (body, &l[body.len()..])
}

/// A Linux XDG autostart entry (`Exec=`) without the token.
#[cfg_attr(windows, allow(dead_code))]
pub(crate) fn desktop_strip(text: &str) -> Option<String> {
    strip_lines(text, "Exec=", false)
}

/// A systemd unit (`ExecStart=`) without the token.
#[cfg_attr(windows, allow(dead_code))]
pub(crate) fn unit_strip(text: &str) -> Option<String> {
    strip_lines(text, "ExecStart=", true)
}

/// The HOME a system unit runs with. Ours never set `User=`, and systemd sets no
/// HOME for a system service without one, so the agent's `home()` is empty and
/// its `~/.it-ai` is relative to the working directory: `/` unless the unit says
/// otherwise. Anything that would make HOME depend on more than this file
/// (`User=`, an `EnvironmentFile=`, a `~` working directory) is not resolved.
#[cfg_attr(windows, allow(dead_code))]
pub(crate) fn unit_home(text: &str) -> Result<EntryHome, String> {
    let mut home = None;
    let mut wd = None;
    for line in text.lines() {
        let l = line.trim();
        for k in ["User=", "DynamicUser=", "EnvironmentFile=", "PAMName="] {
            if l.starts_with(k) {
                return Err(format!("the unit sets {}", k.trim_end_matches('=')));
            }
        }
        if let Some(v) = l.strip_prefix("Environment=") {
            for &(a, b) in &words(v, true) {
                if let Some(h) = unquote(&v[a..b], true).strip_prefix("HOME=") {
                    home = Some(h.to_string());
                }
            }
        }
        if let Some(v) = l.strip_prefix("WorkingDirectory=") {
            wd = Some(v.trim().trim_start_matches('-').to_string());
        }
    }
    if let Some(h) = home {
        return if h.starts_with('/') { Ok(EntryHome::Pinned(h.into())) } else { Err(format!("the unit sets HOME={h:?}")) };
    }
    match wd {
        None => Ok(EntryHome::Default(PathBuf::from("/"))),
        Some(w) if w.starts_with('/') => Ok(EntryHome::Default(w.into())),
        Some(w) => Err(format!("the unit sets WorkingDirectory={w}")),
    }
}

/// The unit with `Environment=HOME=<home>` as the first line of `[Service]`,
/// quoted as `persistence::service_unit` quotes it. None if the unit has no
/// `[Service]` or `home` is not an absolute path systemd would read back as is.
#[cfg_attr(windows, allow(dead_code))]
pub(crate) fn unit_pin_home(text: &str, home: &Path) -> Option<String> {
    let h = home.to_str()?;
    if !h.starts_with('/') || h.chars().any(|c| matches!(c, '"' | '\'' | '\\' | '%' | '$' | '\n' | '\r')) {
        return None;
    }
    let env = if h.contains(char::is_whitespace) { format!("\"HOME={h}\"") } else { format!("HOME={h}") };
    let mut out = String::with_capacity(text.len() + env.len() + 13);
    let mut done = false;
    for line in text.split_inclusive('\n') {
        out.push_str(line);
        if !done && line.trim() == "[Service]" {
            if !line.ends_with('\n') {
                out.push('\n');
            }
            out.push_str(&format!("Environment={env}\n"));
            done = true;
        }
    }
    done.then_some(out)
}

#[cfg_attr(windows, allow(dead_code))]
fn compact(s: &str) -> String {
    s.split_whitespace().collect()
}

/// A plist with our label, `com.itai.agent`.
#[cfg_attr(windows, allow(dead_code))]
pub(crate) fn plist_is_ours(text: &str) -> bool {
    compact(text).contains("<key>Label</key><string>com.itai.agent</string>")
}

/// The content of the `<array>` (or `<dict>`) that follows `<key>{key}</key>`.
#[cfg_attr(windows, allow(dead_code))]
fn value_region(text: &str, key: &str, open: &str, close: &str) -> Option<(usize, usize)> {
    let k = text.find(&format!("<key>{key}</key>"))? + key.len() + 11;
    let rest = &text[k..];
    let lead = rest.len() - rest.trim_start().len();
    rest.trim_start().starts_with(open).then_some(())?;
    let a = k + lead + open.len();
    let e = a + text[a..].find(close)?;
    Some((a, e))
}

/// `<string>` elements in `[a, e)`: (element span, unescaped value).
#[cfg_attr(windows, allow(dead_code))]
fn strings_in(text: &str, a: usize, e: usize) -> Vec<((usize, usize), String)> {
    let mut out = Vec::new();
    let mut pos = a;
    while let Some(i) = text[pos..e].find("<string>") {
        let st = pos + i;
        let Some(j) = text[st..e].find("</string>") else { break };
        let end = st + j + "</string>".len();
        out.push(((st, end), xml_unescape(&text[st + 8..st + j])));
        pos = end;
    }
    out
}

fn xml_unescape(s: &str) -> String {
    s.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'").replace("&amp;", "&")
}

#[cfg_attr(windows, allow(dead_code))]
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// A launchd plist without the token in `ProgramArguments`. Each dropped
/// `<string>` goes with the whitespace before it, so the rest stays as written.
#[cfg_attr(windows, allow(dead_code))]
pub(crate) fn plist_strip(text: &str) -> Option<String> {
    let (a, e) = value_region(text, "ProgramArguments", "<array>", "</array>")?;
    let els = strings_in(text, a, e);
    let args: Vec<String> = els.iter().map(|(_, v)| v.clone()).collect();
    let drop = token_drops(&args);
    let spans: Vec<(usize, usize)> = els.iter().map(|(s, _)| *s).collect();
    drop.contains(&true).then(|| cut(text, a, &spans, &drop))
}

/// HOME as the plist's `EnvironmentVariables` pins it: Ok(None) when it pins
/// none, Err when a HOME key is there but not a plain string.
#[cfg_attr(windows, allow(dead_code))]
pub(crate) fn plist_home(text: &str) -> Result<Option<PathBuf>, String> {
    let Some((a, e)) = value_region(text, "EnvironmentVariables", "<dict>", "</dict>") else { return Ok(None) };
    let env = &text[a..e];
    let Some(k) = env.find("<key>HOME</key>") else { return Ok(None) };
    let rest = env[k + 15..].trim_start();
    let v = rest
        .strip_prefix("<string>")
        .and_then(|r| r.find("</string>").map(|j| xml_unescape(&r[..j])))
        .ok_or("the plist's HOME is not a plain string")?;
    if v.starts_with('/') {
        Ok(Some(v.into()))
    } else {
        Err(format!("the plist sets HOME={v:?}"))
    }
}

/// The plist with `HOME` pinned: added to an existing `EnvironmentVariables`
/// dict, or a new one in the layout `persistence::daemon_plist` writes.
#[cfg_attr(windows, allow(dead_code))]
pub(crate) fn plist_pin_home(text: &str, home: &Path) -> Option<String> {
    let h = xml_escape(home.to_str()?);
    if let Some((a, _)) = value_region(text, "EnvironmentVariables", "<dict>", "</dict>") {
        let mut out = text.to_string();
        out.insert_str(a, &format!("\n    <key>HOME</key><string>{h}</string>"));
        return Some(out);
    }
    let close = text.rfind("</dict>")?;
    let mut out = text.to_string();
    out.insert_str(
        close,
        &format!("  <key>EnvironmentVariables</key><dict>\n    <key>HOME</key><string>{h}</string>\n  </dict>\n"),
    );
    Some(out)
}

/// What `schtasks /Query /TN IT-AI /XML` says about the task.
#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Debug, PartialEq)]
pub(crate) struct TaskXml {
    pub command: String,
    pub arguments: String,
    pub logon_type: Option<String>,
    pub user_id: Option<String>,
}

#[cfg_attr(not(windows), allow(dead_code))]
fn xml_text(s: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let a = s.find(&open)? + open.len();
    let e = a + s[a..].find(&format!("</{tag}>"))?;
    Some(xml_unescape(s[a..e].trim()))
}

/// The task's one `Exec` action and its principal. None for a task with no
/// action or more than one, which `persistence` never writes.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn parse_task_xml(xml: &str) -> Option<TaskXml> {
    if xml.matches("<Exec>").count() != 1 {
        return None;
    }
    let exec = &xml[xml.find("<Exec>")?..];
    let principal = xml.find("<Principal ").or_else(|| xml.find("<Principal>")).map(|i| &xml[i..]).unwrap_or("");
    let principal = &principal[..principal.find("</Principal>").unwrap_or(0)];
    Some(TaskXml {
        command: xml_text(exec, "Command")?,
        arguments: xml_text(&exec[..exec.find("</Exec>")?], "Arguments").unwrap_or_default(),
        logon_type: xml_text(principal, "LogonType"),
        user_id: xml_text(principal, "UserId"),
    })
}

/// The `/TR` for `schtasks /Change`: the program quoted, as `win_install_service`
/// writes it, then the arguments.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn task_tr(command: &str, arguments: &str) -> String {
    let c = command.trim();
    let c = if c.starts_with('"') { c.to_string() } else { format!("\"{c}\"") };
    let a = arguments.trim();
    if a.is_empty() {
        c
    } else {
        format!("{c} {a}")
    }
}

/// schtasks and whoami write UTF-16LE to a pipe on some Windows builds and the
/// OEM code page on others; read either.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn decode_output(b: &[u8]) -> String {
    let utf16 = b.starts_with(&[0xFF, 0xFE]) || (b.len() >= 4 && b[1] == 0 && b[3] == 0);
    if utf16 {
        let skip = if b.starts_with(&[0xFF, 0xFE]) { 2 } else { 0 };
        let u: Vec<u16> = b[skip..].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        String::from_utf16_lossy(&u)
    } else {
        String::from_utf8_lossy(b).into_owned()
    }
}

/// `whoami /user /fo csv /nh` → (`DOMAIN\user`, SID).
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn parse_whoami(csv: &str) -> Option<(String, String)> {
    let line = csv.lines().find(|l| !l.trim().is_empty())?;
    let mut f = line.trim().trim_matches('"').split("\",\"");
    let name = f.next()?.to_string();
    let sid = f.next()?.to_string();
    sid.starts_with("S-").then_some((name, sid))
}

/// Whether the task's principal is this user, by SID or name.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn user_matches(user_id: &str, name: &str, sid: &str) -> bool {
    let u = user_id.trim();
    let bare = name.rsplit('\\').next().unwrap_or(name);
    u.eq_ignore_ascii_case(sid) || u.eq_ignore_ascii_case(name) || (!u.contains('\\') && u.eq_ignore_ascii_case(bare))
}

#[cfg(test)]
mod tests;
