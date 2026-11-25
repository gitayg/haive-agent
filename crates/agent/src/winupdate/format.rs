// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

//! Every line `it-ai:os-updates/check` prints. Pure, so the hub's grader
//! (RemoteScreen crates/hub/src/posture/winupdate.rs) can be tested against the
//! real text: `format/fixtures.txt` is this module's output for each case, and
//! the hub keeps a byte-identical copy that its tests grade.
//!
//! A row is a security update when WUA gives it an MSRC severity
//! (IUpdate.MsrcSeverity: Critical, Important, Moderate, Low) or when one of its
//! categories (IUpdate.Categories, ICategory.CategoryID) is the "Security
//! Updates" classification. Classifications are matched by GUID because
//! ICategory.Name is localized. "Critical Updates" is not security: Microsoft
//! defines a critical update as "a widely released fix for a specific problem
//! that addresses a critical, non-security-related bug" (KB 824684).

/// The WSUS classification GUIDs (learn.microsoft.com, "WSUS Classification GUIDs").
pub const SECURITY_UPDATES: &str = "0FA1201D-4330-4FA8-8AE9-B877473B6441";
pub const CRITICAL_UPDATES: &str = "E6CF1350-C01B-414D-A61F-263D14D133B4";
const CLASSIFICATIONS: [(&str, &str); 12] = [
    ("5C9376AB-8CE6-464A-B136-22113DD69801", "Application"),
    ("434DE588-ED14-48F5-8EED-A15E09A991F6", "Connectors"),
    (CRITICAL_UPDATES, "Critical Updates"),
    ("E0789628-CE08-4437-BE74-2495B842F43B", "Definition Updates"),
    ("E140075D-8433-45C3-AD87-E72345B36078", "Developer Kits"),
    ("B54E7D24-7ADD-428F-8B75-90A396FA584F", "Feature Packs"),
    ("9511D615-35B2-47BB-927F-F73D8E9260BB", "Guidance"),
    (SECURITY_UPDATES, "Security Updates"),
    ("68C5B0A3-D1A6-4553-AE49-01D3A7827828", "Service Packs"),
    ("B4832BD8-E735-4761-8DAF-37F882276DAB", "Tools"),
    ("28BC880E-0592-4CBF-8F95-C79B17911D5F", "Update Rollups"),
    ("CD5FFD1E-E932-4E3A-BF74-18BF0B1BBD83", "Updates"),
];

const E_ACCESSDENIED: i32 = 0x8007_0005u32 as i32;

/// One pending update as WUA reports it.
pub struct Update {
    pub title: String,
    /// MaxDownloadSize in bytes; None when WUA would not say.
    pub size: Option<u128>,
    pub msrc: String,
    /// ICategory.CategoryID of every category the update belongs to.
    pub categories: Vec<String>,
}

/// One update's properties as WUA returned them, None where a read failed.
/// `categories` is None when the collection could not be read, and holds a None
/// for each category whose CategoryID could not be.
pub trait Fields {
    fn title(&self) -> Option<String>;
    fn size(&self) -> Option<u128>;
    fn msrc(&self) -> Option<String>;
    fn categories(&self) -> Option<Vec<Option<String>>>;
}

/// The update as a row, or None (an unreadable row) when its MSRC severity or any
/// of its categories could not be read: either may be what makes it a security
/// update, so a row missing one cannot be ruled a non-security update.
pub fn read(u: &impl Fields) -> Option<Update> {
    let categories = u.categories()?.into_iter().collect::<Option<Vec<String>>>()?;
    Some(Update {
        title: u.title().unwrap_or_else(|| "(untitled update)".to_string()),
        size: u.size(),
        msrc: u.msrc()?,
        categories,
    })
}

/// The classification among an update's categories, by its English name.
pub fn classification(categories: &[String]) -> Option<&'static str> {
    categories
        .iter()
        .find_map(|c| CLASSIFICATIONS.iter().find(|(id, _)| id.eq_ignore_ascii_case(c.trim())).map(|(_, n)| *n))
}

pub fn is_security(u: &Update) -> bool {
    !u.msrc.trim().is_empty() || u.categories.iter().any(|c| c.trim().eq_ignore_ascii_case(SECURITY_UPDATES))
}

pub fn human_size(bytes: u128) -> String {
    const KB: u128 = 1024;
    const MB: u128 = KB * 1024;
    const GB: u128 = MB * 1024;
    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}

/// `  - <title> (<size>)[ [security: <severity>|unrated]][ [class: <classification>]]`
pub fn row(u: &Update) -> String {
    let size = u.size.map(human_size).unwrap_or_else(|| "size unknown".to_string());
    let mut line = format!("  - {} ({size})", u.title);
    if is_security(u) {
        let sev = u.msrc.trim();
        line.push_str(&format!(" [security: {}]", if sev.is_empty() { "unrated" } else { sev }));
    }
    if let Some(class) = classification(&u.categories) {
        line.push_str(&format!(" [class: {class}]"));
    }
    line
}

/// The search result: `total` updates found, `rows[i]` None where WUA could not
/// hand back update i.
pub fn report(total: usize, rows: &[Option<Update>]) -> String {
    if total == 0 {
        return "No OS updates available.".to_string();
    }
    let read: Vec<&Update> = rows.iter().flatten().collect();
    let mut lines = vec![format!("{total} OS update(s) available (via Windows Update Agent):")];
    lines.extend(read.iter().map(|u| row(u)));
    let security = read.iter().filter(|u| is_security(u)).count();
    lines.push(format!("Summary: {total} update(s), {security} security update(s)."));
    lines.join("\n")
}

/// `<ctx>: access denied — …` for E_ACCESSDENIED, else `<ctx>: unavailable (HRESULT 0x…)`.
pub fn failure(ctx: &str, hresult: i32) -> String {
    if hresult == E_ACCESSDENIED {
        format!("{ctx}: access denied — needs Administrator (run the agent elevated)")
    } else {
        format!("{ctx}: unavailable (HRESULT 0x{:08X})", hresult as u32)
    }
}

/// The check's answer when it could not be made.
pub fn error(msg: &str) -> String {
    format!("OS updates: {msg}")
}

fn ago(secs: u64) -> String {
    match secs {
        0..=59 => "just now".to_string(),
        60..=7199 => format!("{} min ago", secs / 60),
        _ => format!("{} h ago", secs / 3600),
    }
}

/// A search result followed by how long ago that search finished.
pub fn checked(report: &str, age_secs: u64) -> String {
    format!("{report}\nChecked {}.", ago(age_secs))
}

/// The answer while the first (or a stale cache's) search is still running.
pub fn checking(running_secs: u64) -> String {
    let started = if running_secs < 60 { "under a minute ago".to_string() } else { ago(running_secs) };
    format!("Windows Update check in progress (started {started}); ask again in a minute.")
}

#[cfg(test)]
#[path = "format/tests.rs"]
mod tests;
