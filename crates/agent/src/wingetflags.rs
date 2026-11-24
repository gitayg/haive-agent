// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

//! Make every `winget` invocation the agent runs non-interactive.
//!
//! The agent runs commands with no stdin, so the first time a source such as
//! `msstore` wants its agreements accepted, winget's prompt reads EOF and the
//! command dies with `0x8a150042 : Error reading input in prompt`. The hub sends
//! plain `winget upgrade` / `winget list` / `winget uninstall`, so the agent adds
//! the flags itself, right after the subcommand, and only the ones that
//! subcommand accepts (winget rejects an argument a command does not define).
//! Per the Microsoft Learn page of each command:
//! - install/add, upgrade/update, import, repair/fix: --accept-package-agreements,
//!   --accept-source-agreements, --disable-interactivity (upgrade/update only gets
//!   the package flag when it is already upgrading, see UPGRADE_MODE)
//! - list/ls, uninstall/remove/rm, search/find, show/view, export, download:
//!   --accept-source-agreements, --disable-interactivity
//!
//! The line is read the way cmd.exe splits it: each command after an unquoted
//! `&`, `|`, `(` or `)` (`^` escapes one character) is looked at on its own, and
//! only one whose program is `winget` / `winget.exe` (bare or by path, any case)
//! is touched. Everything else in the line is copied byte for byte.
#![cfg_attr(not(windows), allow(dead_code))]

const PACKAGE: &str = "--accept-package-agreements";
const SOURCE: &str = "--accept-source-agreements";
const NO_PROMPT: &str = "--disable-interactivity";

fn flags_for(sub: &str) -> &'static [&'static str] {
    match sub.to_ascii_lowercase().as_str() {
        "install" | "add" | "upgrade" | "update" | "import" | "repair" | "fix" => &[PACKAGE, SOURCE, NO_PROMPT],
        "list" | "ls" | "uninstall" | "remove" | "rm" | "search" | "find" | "show" | "view" | "export" | "download" => {
            &[SOURCE, NO_PROMPT]
        }
        _ => &[],
    }
}

/// Arguments that already make `winget upgrade` upgrade instead of list. Without
/// one of them a bare `upgrade` LISTS available upgrades, and adding
/// --accept-package-agreements (an InstallerBehavior argument in winget's
/// Argument.cpp) would turn that listing into an upgrade of an empty query
/// (`ShouldListUpgrade` in UpgradeCommand.cpp). Measured on a real device: it
/// exited 0x8A150016 listing every installed package. A positional query is not
/// recognised here, so such a line gets the other two flags only.
const UPGRADE_MODE: &[&str] =
    &["--all", "-r", "--recurse", "--id", "--name", "--moniker", "-q", "--query", "-m", "--manifest", "-h", "--silent"];

fn is_upgrade(sub: &str) -> bool {
    sub.eq_ignore_ascii_case("upgrade") || sub.eq_ignore_ascii_case("update")
}

/// Byte ranges of the commands in a cmd.exe line, split at unquoted operators.
fn segments(line: &str) -> Vec<(usize, usize)> {
    let b = line.as_bytes();
    let (mut out, mut start, mut quoted, mut i) = (Vec::new(), 0, false, 0);
    while i < b.len() {
        match b[i] {
            b'"' => quoted = !quoted,
            b'^' if !quoted => i += 1,
            b'&' | b'|' | b'(' | b')' if !quoted => {
                out.push((start, i));
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    out.push((start, b.len()));
    out
}

/// Tokens of one command as (start, end) byte ranges; quotes group, and an
/// unquoted `<` / `>` ends a token so a redirection is never read as an argument.
fn tokens(line: &str, (from, to): (usize, usize)) -> Vec<(usize, usize)> {
    let b = line.as_bytes();
    let (mut out, mut i) = (Vec::new(), from);
    while i < to {
        while i < to && (b[i].is_ascii_whitespace() || b[i] == b'<' || b[i] == b'>') {
            i += 1;
        }
        let start = i;
        let mut quoted = false;
        while i < to && (quoted || !(b[i].is_ascii_whitespace() || b[i] == b'<' || b[i] == b'>')) {
            match b[i] {
                b'"' => quoted = !quoted,
                b'^' if !quoted => i += 1,
                _ => {}
            }
            i += 1;
        }
        if i > start {
            out.push((start, i.min(to)));
        }
    }
    out
}

fn unquoted(line: &str, (s, e): (usize, usize)) -> String {
    line[s..e].replace('"', "")
}

fn is_winget(program: &str) -> bool {
    let program = program.trim_start_matches('@');
    let name = program.rsplit(['\\', '/']).next().unwrap_or(program).to_ascii_lowercase();
    name == "winget" || name == "winget.exe"
}

/// `line` with the missing non-interactive flags inserted after the subcommand of
/// every winget command in it. A line with no winget command comes back unchanged.
pub(crate) fn noninteractive(line: &str) -> String {
    let mut inserts: Vec<(usize, String)> = Vec::new();
    for seg in segments(line) {
        let toks = tokens(line, seg);
        if toks.len() < 2 || !is_winget(&unquoted(line, toks[0])) {
            continue;
        }
        let sub = unquoted(line, toks[1]);
        let present: Vec<String> = toks[2..].iter().map(|&t| unquoted(line, t).to_ascii_lowercase()).collect();
        let listing = is_upgrade(&sub) && !present.iter().any(|p| UPGRADE_MODE.contains(&p.as_str()));
        let missing: String = flags_for(&sub)
            .iter()
            .filter(|f| !(listing && **f == PACKAGE))
            .filter(|f| !present.iter().any(|p| p == *f))
            .map(|f| format!(" {f}"))
            .collect();
        if !missing.is_empty() {
            inserts.push((toks[1].1, missing));
        }
    }
    let mut out = line.to_string();
    for (at, text) in inserts.into_iter().rev() {
        out.insert_str(at, &text);
    }
    out
}

#[cfg(test)]
mod tests;
