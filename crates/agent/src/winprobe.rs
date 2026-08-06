// IT-AI — LAN remote control & screen sharing with an AI/MCP interface.
// Copyright (C) 2026 The IT-AI Authors.
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Native Windows security-posture probes (no PowerShell, no netsh/manage-bde
// child processes) plus the empty-Recycle-Bin fix. Declared with
// `#[cfg(windows)] mod winprobe;` in main.rs; the inner `#![cfg(windows)]` makes
// the whole file compile to nothing on non-Windows targets, so the wiring in
// analysis.rs / http.rs is what the mac/linux builds exercise.
//
// Every external call is error-tolerant: on any COM/WMI/shell32 failure the
// probe returns a short "<probe>: unavailable" string instead of panicking or
// unwrapping. The five probes share ONE COM/WMI init helper and ONE copy of the
// small formatting helpers (variant_str / pretty_cim_datetime / decode_*).
#![cfg(windows)]

use std::collections::HashMap;

use serde::Deserialize;
use wmi::{COMLibrary, Variant, WMIConnection};

/// Open a WMI connection to `namespace`, or `None` on any COM/WMI failure.
///
/// `COMLibrary::without_security()` skips the process-global CoInitializeSecurity
/// (which can only run once per process), so this is safe to call on any thread —
/// the 5-minute analysis loop thread AND the transient tiny_http /exec workers —
/// without clashing with the tao/wry/tray GUI COM init that runs on a different
/// thread. COM is initialised here and torn down when the returned connection
/// drops, so the apartment is balanced per call and nothing long-lived is held.
fn wmi(namespace: &str) -> Option<WMIConnection> {
    let com = COMLibrary::without_security().ok()?;
    WMIConnection::with_namespace_path(namespace, com).ok()
}

// ── av ───────────────────────────────────────────────────────────────────────

/// Antivirus posture. Matches the retired
/// `Get-MpComputerStatus | Select ... | Format-List` shape the dashboard grades
/// on (`AntivirusEnabled : True`, etc.) and appends a SecurityCenter2 section so
/// third-party AV shows too. Never panics; returns a short "unavailable" note on
/// any failure. The grader lowercases + collapses whitespace, so the single-space
/// `Name : Value` lines below satisfy its `antivirusenabled : true` check.
pub fn av_status() -> String {
    let defender = defender_status();
    let third_party = securitycenter_products();
    match (defender, third_party) {
        (Some(d), Some(tp)) if !tp.is_empty() => {
            format!("{d}\n\nThird-party AV (SecurityCenter2):\n{tp}")
        }
        (Some(d), _) => d,
        (None, Some(tp)) if !tp.is_empty() => {
            format!("Windows Defender : unavailable\n\nThird-party AV (SecurityCenter2):\n{tp}")
        }
        (None, _) => "av: unavailable (WMI query failed)".to_string(),
    }
}

/// root\Microsoft\Windows\Defender :: MSFT_MpComputerStatus. None on any error.
fn defender_status() -> Option<String> {
    let conn = wmi(r"root\Microsoft\Windows\Defender")?;
    let rows: Vec<HashMap<String, Variant>> = conn
        .raw_query(
            "SELECT AntivirusEnabled, RealTimeProtectionEnabled, \
             AntivirusSignatureLastUpdated, AMRunningMode FROM MSFT_MpComputerStatus",
        )
        .ok()?;
    let row = rows.into_iter().next()?;
    Some(format!(
        "AntivirusEnabled : {}\n\
         RealTimeProtectionEnabled : {}\n\
         AntivirusSignatureLastUpdated : {}\n\
         AMRunningMode : {}",
        variant_str(row.get("AntivirusEnabled")),
        variant_str(row.get("RealTimeProtectionEnabled")),
        pretty_cim_datetime(&variant_str(row.get("AntivirusSignatureLastUpdated"))),
        variant_str(row.get("AMRunningMode")),
    ))
}

/// root\SecurityCenter2 :: AntiVirusProduct (client SKUs only; absent on Server →
/// None, silently skipped). Some("") when the namespace exists but lists nothing.
fn securitycenter_products() -> Option<String> {
    #[derive(Deserialize)]
    struct AvProduct {
        #[serde(rename = "displayName")]
        display_name: String,
        #[serde(rename = "productState")]
        product_state: u32,
    }
    let conn = wmi(r"root\SecurityCenter2")?;
    let products: Vec<AvProduct> = conn
        .raw_query("SELECT displayName, productState FROM AntiVirusProduct")
        .ok()?;
    let mut out = String::new();
    for p in products {
        let (enabled, up_to_date) = decode_product_state(p.product_state);
        out.push_str(&format!(
            "  {} — {}, definitions {}\n",
            p.display_name,
            if enabled { "enabled" } else { "disabled" },
            if up_to_date { "up to date" } else { "out of date" },
        ));
    }
    Some(out.trim_end().to_string())
}

/// WSC productState bitfield (community-documented, best-effort): take the low 24
/// bits as 6 hex digits — 2nd byte 0x10/0x11 = on, 3rd byte 0x00 = signatures current.
fn decode_product_state(state: u32) -> (bool, bool) {
    let hex = format!("{:06X}", state & 0x00FF_FFFF); // exactly 6 chars → slices are safe
    let on = &hex[2..4];
    let sig = &hex[4..6];
    (on == "10" || on == "11", sig == "00")
}

/// Only Bool + String matter for these properties; a Debug fallback keeps any
/// unexpected Variant non-panicking. Bool → PowerShell-style "True"/"False"
/// (also what the lowercased grader expects).
fn variant_str(v: Option<&Variant>) -> String {
    match v {
        Some(Variant::Bool(b)) => (if *b { "True" } else { "False" }).to_string(),
        Some(Variant::String(s)) => s.clone(),
        None | Some(Variant::Null) => String::new(),
        Some(other) => format!("{other:?}"),
    }
}

/// CIM_DATETIME `yyyymmddHHMMSS.ffffff±UUU` → `YYYY-MM-DD HH:MM:SS`; anything else
/// (empty / already-formatted) passes through unchanged.
fn pretty_cim_datetime(s: &str) -> String {
    let d: String = s.chars().take(14).collect();
    if d.len() == 14 && d.bytes().all(|b| b.is_ascii_digit()) {
        format!(
            "{}-{}-{} {}:{}:{}",
            &d[0..4], &d[4..6], &d[6..8], &d[8..10], &d[10..12], &d[12..14]
        )
    } else {
        s.to_string()
    }
}

// ── services ─────────────────────────────────────────────────────────────────

/// Running-services table (up to 40, Name + DisplayName), or a short
/// "unavailable" line on any COM/WMI failure. Replaces
/// `Get-Service | ? Status -eq 'Running' | select Name,DisplayName | ft -Auto`.
/// Rows are sorted by Name so identical service state yields no spurious analysis
/// delta (WMI is unordered, unlike a shell pipeline). Never panics.
pub fn services_running() -> String {
    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct Win32Service {
        name: Option<String>,
        display_name: Option<String>,
    }

    let conn = match wmi(r"root\cimv2") {
        Some(c) => c,
        None => return "services: unavailable (WMI connection failed)".to_string(),
    };
    let mut rows: Vec<Win32Service> = match conn
        .raw_query("SELECT Name, DisplayName FROM Win32_Service WHERE State = 'Running'")
    {
        Ok(r) => r,
        Err(e) => return format!("services: unavailable ({e})"),
    };
    rows.sort_by_key(|s| s.name.clone().unwrap_or_default().to_ascii_lowercase());
    rows.truncate(40);

    let items: Vec<(String, String)> = rows
        .into_iter()
        .map(|s| (s.name.unwrap_or_default(), s.display_name.unwrap_or_default()))
        .collect();

    // Auto-size the Name column the way Format-Table -Auto does.
    let name_w = items
        .iter()
        .map(|(n, _)| n.len())
        .max()
        .unwrap_or(0)
        .max("Name".len());
    let disp_w = items
        .iter()
        .map(|(_, d)| d.len())
        .max()
        .unwrap_or(0)
        .max("DisplayName".len());

    let mut out = String::with_capacity(48 + items.len() * (name_w + disp_w + 4));
    out.push_str(&format!("{:<nw$}  {}\n", "Name", "DisplayName", nw = name_w));
    out.push_str(&format!("{}  {}\n", "-".repeat(name_w), "-".repeat(disp_w)));
    for (n, d) in &items {
        out.push_str(&format!("{:<nw$}  {}\n", n, d, nw = name_w));
    }
    out.trim_end().to_string()
}

// ── encryption ───────────────────────────────────────────────────────────────

/// Human-readable BitLocker status for every FIXED volume, replacing
/// `manage-bde -status C:`. The hub renders this verbatim and grades it by
/// substring ("protection on" ⇒ enabled), so ENABLED volumes emit the literal
/// "Protection On" and disabled/unavailable output stays free of the "crypt"
/// token that would false-pass the grader. Never panics.
pub fn encryption_status() -> String {
    use windows_sys::Win32::Storage::FileSystem::GetDriveTypeW;

    // 3 == DRIVE_FIXED (avoids importing the constant).
    const DRIVE_FIXED: u32 = 3;

    #[derive(Deserialize)]
    #[serde(rename = "Win32_EncryptableVolume")]
    #[serde(rename_all = "PascalCase")]
    struct EncVol {
        drive_letter: Option<String>,
        // Property: 0 = off, 1 = on, 2 = unknown.
        protection_status: Option<u32>,
        // ConversionStatus / EncryptionMethod are normally method outputs
        // (GetConversionStatus / GetEncryptionMethod), not queryable columns —
        // deserialised best-effort and simply omitted when absent.
        conversion_status: Option<u32>,
        encryption_method: Option<u32>,
    }

    /// True only for DRIVE_FIXED volumes (excludes removable BitLocker-To-Go, etc.).
    fn is_fixed_volume(drive_letter: &str) -> bool {
        let c = match drive_letter.chars().find(|c| c.is_ascii_alphabetic()) {
            Some(c) => c,
            None => return false,
        };
        let root = format!("{c}:\\");
        let wide: Vec<u16> = root.encode_utf16().chain(std::iter::once(0)).collect();
        // GetDriveTypeW takes a null-terminated wide root path; no fallible path.
        unsafe { GetDriveTypeW(wide.as_ptr()) == DRIVE_FIXED }
    }

    fn method_name(code: u32) -> Option<&'static str> {
        Some(match code {
            0 => return None, // None
            1 => "AES-128 with Diffuser",
            2 => "AES-256 with Diffuser",
            3 => "AES-128",
            4 => "AES-256",
            6 => "XTS-AES-128",
            7 => "XTS-AES-256",
            _ => return None,
        })
    }

    fn conversion_name(code: u32) -> Option<&'static str> {
        Some(match code {
            0 => "Fully Decrypted",
            1 => "Fully Encrypted",
            2 => "Encryption In Progress",
            3 => "Decryption In Progress",
            4 => "Encryption Paused",
            5 => "Decryption Paused",
            _ => return None,
        })
    }

    let conn = match wmi(r"ROOT\CIMV2\Security\MicrosoftVolumeEncryption") {
        Some(c) => c,
        None => return "BitLocker status: unavailable (WMI connection failed)".to_string(),
    };
    let vols: Vec<EncVol> = match conn.query() {
        Ok(v) => v,
        // Non-admin callers typically hit access-denied here.
        Err(e) => return format!("BitLocker status: unavailable ({e})"),
    };

    // Header is deliberately free of the "crypt" substring so a machine with only
    // disabled volumes grades as NOT-encrypted.
    let mut lines: Vec<String> = vec![String::from("BitLocker volume status (probed via WMI):")];
    for v in &vols {
        let letter = match v.drive_letter.as_deref() {
            Some(l) if !l.trim().is_empty() => l.trim().to_string(),
            _ => continue,
        };
        if !is_fixed_volume(&letter) {
            continue;
        }
        let state = match v.protection_status {
            Some(1) => "Protection On",
            Some(0) => "Protection Off",
            _ => "Protection Unknown",
        };
        let mut line = format!("  {letter}  {state}");
        // Only decorate ENABLED volumes with method/conversion detail — keeps
        // "crypt"-bearing words (e.g. "Encrypted") off the disabled lines so the
        // grader's OFF verdict stays correct.
        if v.protection_status == Some(1) {
            if let Some(m) = v.encryption_method.and_then(method_name) {
                line.push_str(", ");
                line.push_str(m);
            }
            if let Some(cs) = v.conversion_status.and_then(conversion_name) {
                line.push_str(", ");
                line.push_str(cs);
            }
        }
        lines.push(line);
    }

    if lines.len() == 1 {
        return String::from("BitLocker: no fixed volumes reported.");
    }
    lines.join("\n")
}

// ── firewall ─────────────────────────────────────────────────────────────────

/// Per-profile firewall state, replacing
/// `netsh advfirewall show allprofiles state`. Primary source: WMI
/// root\StandardCimv2 MSFT_NetFirewallProfile; fallback: the SharedAccess
/// FirewallPolicy registry keys. Output mirrors netsh's per-profile
/// "State ON/OFF" layout so the dashboard render and the hub's posture_pass()
/// heuristic keep working unchanged. Never panics.
pub fn firewall_status() -> String {
    let states = wmi_states().or_else(registry_states);
    match states {
        Some([d, p, u]) => render(&[("Domain", d), ("Private", p), ("Public", u)]),
        None => {
            "firewall: unavailable (WMI query failed and firewall registry keys unreadable)"
                .to_string()
        }
    }
}

fn render(profiles: &[(&str, bool)]) -> String {
    let mut out = String::new();
    for (name, on) in profiles {
        out.push_str(name);
        out.push_str(" Profile Settings:\n");
        out.push_str("----------------------------------------------------------------------\n");
        out.push_str("State                                 ");
        out.push_str(if *on { "ON" } else { "OFF" });
        out.push_str("\n\n");
    }
    // Drop the trailing blank line (all trailing bytes are ASCII whitespace).
    out.truncate(out.trim_end().len());
    out
}

// Query MSFT_NetFirewallProfile. Returns [Domain, Private, Public] enabled flags,
// or None on any COM/WMI error or a missing profile (so we fall back to the
// registry). Every fallible call is `?`/`ok()` → no panic.
fn wmi_states() -> Option<[bool; 3]> {
    let conn = wmi(r"root\StandardCimv2")?;
    let rows: Vec<HashMap<String, Variant>> = conn
        .raw_query("SELECT Name, Enabled FROM MSFT_NetFirewallProfile")
        .ok()?;

    let mut by_name: HashMap<String, bool> = HashMap::new();
    for row in rows {
        let name = match row.get("Name") {
            Some(Variant::String(s)) => s.to_ascii_lowercase(),
            _ => continue,
        };
        // MSFT_NetFirewallProfile.Enabled is the NetSecurity enum uint16
        // (1 = True, 2 = False); some providers surface it as a plain bool.
        // 1/true => ON; anything else => OFF.
        let on = match row.get("Enabled") {
            Some(Variant::Bool(b)) => *b,
            Some(Variant::UI1(n)) => *n == 1,
            Some(Variant::UI2(n)) => *n == 1,
            Some(Variant::UI4(n)) => *n == 1,
            Some(Variant::I2(n)) => *n == 1,
            Some(Variant::I4(n)) => *n == 1,
            _ => continue,
        };
        by_name.insert(name, on);
    }
    Some([
        *by_name.get("domain")?,
        *by_name.get("private")?,
        *by_name.get("public")?,
    ])
}

// Registry fallback: the EnableFirewall DWORD under each profile subkey (note the
// Private profile lives under "StandardProfile"). A value absent within an
// existing key => Windows default is "enabled". Returns None only if NONE of the
// three keys open (registry genuinely unreadable).
fn registry_states() -> Option<[bool; 3]> {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let base = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy";
    let subs = ["DomainProfile", "StandardProfile", "PublicProfile"];
    let mut states = [true; 3];
    let mut any = false;
    for (i, sub) in subs.iter().enumerate() {
        if let Ok(k) = hklm.open_subkey(format!("{base}\\{sub}")) {
            any = true;
            let v: u32 = k.get_value("EnableFirewall").unwrap_or(1);
            states[i] = v == 1;
        }
    }
    if any {
        Some(states)
    } else {
        None
    }
}

// ── cameras (device presence) ─────────────────────────────────────────────────

/// Every camera DEVICE the OS knows about (PNPClass = 'Camera'), paired with its
/// ConfigManagerErrorCode. Unlike the capture-backend query (nokhwa/MediaFoundation,
/// which lists only what it can OPEN), this reports a webcam even when it is turned
/// OFF: a closed privacy shutter / hardware kill-switch surfaces as Code 45 ("not
/// connected"), a disabled device as Code 22. That lets the dashboard show
/// "Integrated Camera — off (…)" instead of a misleading "no camera" for a laptop
/// that plainly has one. Empty on any COM/WMI failure. Never panics.
pub fn camera_devices() -> Vec<(String, u32)> {
    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct PnpCam {
        name: Option<String>,
        config_manager_error_code: Option<u32>,
    }
    let conn = match wmi(r"root\cimv2") {
        Some(c) => c,
        None => return Vec::new(),
    };
    let rows: Vec<PnpCam> = conn
        .raw_query(
            "SELECT Name, ConfigManagerErrorCode FROM Win32_PnPEntity WHERE PNPClass = 'Camera'",
        )
        .unwrap_or_default();
    let mut out: Vec<(String, u32)> = rows
        .into_iter()
        .filter_map(|r| {
            let name = r.name?;
            if name.trim().is_empty() {
                return None;
            }
            Some((name.trim().to_string(), r.config_manager_error_code.unwrap_or(0)))
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Friendly reason for a non-zero Device-Manager ConfigManagerErrorCode.
pub fn cm_error_reason(code: u32) -> &'static str {
    match code {
        22 => "disabled",
        45 => "disconnected — privacy shutter or kill-switch",
        21 => "being removed",
        28 => "driver not installed",
        10 | 43 => "device error",
        _ => "unavailable",
    }
}

// ── empty_recycle_bin (fix action) ───────────────────────────────────────────

/// Empty every drive's Recycle Bin silently (no confirmation dialog, no progress
/// UI, no sound) via SHEmptyRecycleBinW — no PowerShell / child process. Replaces
/// the `Clear-RecycleBin -Force` fix. Never panics.
///
/// hwnd = null      → no owner window (we may run headless / in a service)
/// rootpath = null  → all recycle bins on all drives
/// SHEmptyRecycleBinW self-initializes the shell services it needs, so no
/// explicit CoInitializeEx is required for this call.
pub fn empty_recycle_bin() -> String {
    use windows_sys::Win32::UI::Shell::{
        SHEmptyRecycleBinW, SHERB_NOCONFIRMATION, SHERB_NOPROGRESSUI, SHERB_NOSOUND,
    };

    let flags = SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND;

    // SAFETY: null owner-window and null root-path are the documented "all drives,
    // no UI" invocation; SHEmptyRecycleBinW is a plain FFI call that returns an
    // HRESULT and does not retain the pointers.
    let hr = unsafe { SHEmptyRecycleBinW(std::ptr::null_mut(), std::ptr::null(), flags) };

    match hr {
        // S_OK
        0 => "Recycle Bin emptied.".to_string(),
        // Some Windows builds return E_UNEXPECTED (0x8000FFFF) when the bin is
        // already empty — report that plainly rather than as a failure.
        h if h as u32 == 0x8000_FFFF => "Recycle Bin already empty.".to_string(),
        h => format!("Empty Recycle Bin: unavailable (HRESULT 0x{:08X})", h as u32),
    }
}
