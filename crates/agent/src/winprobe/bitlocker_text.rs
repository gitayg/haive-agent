// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

//! The words the BitLocker probe prints when WMI refuses it and the status comes
//! from Explorer's `System.Volume.BitLockerProtection` instead. Pure, so every
//! string can be checked against the hub's grader, which passes the encryption
//! check when the lowercased output contains "protection on" or "crypt".

const WBEM_E_ACCESS_DENIED: u32 = 0x8004_1003;
const E_ACCESSDENIED: u32 = 0x8007_0005;

/// Why the BitLocker WMI namespace could not be read: the HRESULT when WMI gave
/// one, else its error text.
pub(super) fn wmi_reason(hres: Option<i32>, detail: &str) -> String {
    match hres.map(|h| h as u32) {
        Some(h) if h == WBEM_E_ACCESS_DENIED || h == E_ACCESSDENIED => {
            format!("access denied, 0x{h:08X}: needs an elevated agent")
        }
        Some(h) => format!("error 0x{h:08X}"),
        None => defang(detail),
    }
}

/// Break every "crypt" in text we did not write ("missing field EncryptionMethod")
/// so it cannot pass the grader: "En[c]ryptionMethod".
fn defang(s: &str) -> String {
    let lower = s.to_ascii_lowercase();
    let mut out = String::with_capacity(s.len() + 8);
    let mut i = 0;
    while let Some(off) = lower[i..].find("crypt") {
        let at = i + off;
        out.push_str(&s[i..at]);
        out.push('[');
        out.push_str(&s[at..at + 1]);
        out.push(']');
        out.push_str(&s[at + 1..at + 5]);
        i = at + 5;
    }
    out.push_str(&s[i..]);
    out
}

/// One volume's state from the Explorer value. `Err` is the HRESULT of a failed
/// read, `Ok(None)` a read that came back empty. The value names are the
/// property's own enum (1 On, 2 Off, 3 Encrypting, 4 Decrypting, 5 Suspended,
/// 6 Locked, 7 Not encryptable, 8 Waiting for activation); only On and Locked
/// mean the volume is protected now. Encrypting is not claimed either way: WMI
/// may already report protection on while the conversion runs.
pub(super) fn explorer_line(v: Result<Option<i32>, i32>) -> String {
    match v {
        Ok(Some(1)) => "Protection On (from Explorer; run the agent elevated for method and progress)".into(),
        Ok(Some(2)) => "Protection Off (from Explorer)".into(),
        Ok(Some(3)) => "Protection Unknown (turning on, in progress; from Explorer; run the agent elevated for details)".into(),
        Ok(Some(4)) => "Protection Off (turning off, in progress; from Explorer)".into(),
        Ok(Some(5)) => "Protection Off (suspended; from Explorer)".into(),
        Ok(Some(6)) => "Protection On (locked; from Explorer)".into(),
        Ok(Some(7)) => "Protection Off (BitLocker cannot protect this volume; from Explorer)".into(),
        Ok(Some(8)) => "Protection Off (waiting for activation; from Explorer)".into(),
        Ok(Some(n)) => format!("Protection Unknown (Explorer value {n})"),
        Ok(None) => "Protection Unknown (Explorer has no BitLocker value for this volume)".into(),
        Err(h) => format!("Protection Unknown (Explorer read failed: 0x{:08X})", h as u32),
    }
}

/// The whole fallback report: the WMI reason, then one line per fixed volume.
pub(super) fn render_explorer(reason: &str, vols: &[(char, Result<Option<i32>, i32>)]) -> String {
    if vols.is_empty() {
        return format!("BitLocker status: unavailable (WMI: {reason}; Explorer lists no fixed volumes)");
    }
    let mut out = format!("BitLocker volume status (WMI: {reason}; read from Explorer instead):");
    for (letter, v) in vols {
        out.push_str(&format!("\n  {letter}:  {}", explorer_line(*v)));
    }
    out
}

#[cfg(test)]
mod tests;
