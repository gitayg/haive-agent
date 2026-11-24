// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

//! BitLocker state without admin rights: the shell property
//! `System.Volume.BitLockerProtection` that Explorer's drive padlock reads. The
//! BitLocker WMI namespace admits administrators only, so an agent running as
//! the logged-in user falls back to this. It says on/off/suspended/in progress,
//! not the method or the percentage.

use windows::core::{GUID, HSTRING};
use windows::Win32::Foundation::PROPERTYKEY;
use windows::Win32::System::Com::{CoInitializeEx, CoUninitialize, COINIT_MULTITHREADED};
use windows::Win32::System::Variant::VT_EMPTY;
use windows::Win32::UI::Shell::PropertiesSystem::{IPropertyStore, SHGetPropertyStoreFromParsingName, GPS_DEFAULT};
use windows_sys::Win32::Storage::FileSystem::{GetDriveTypeW, GetLogicalDrives};

use super::bitlocker_text;

/// {2D15A9A1-A556-4189-91AD-027458F11A07}, 1717. Not in the SDK's propkey.h;
/// `PSGetPropertyKeyFromName("System.Volume.BitLockerProtection")` returns it.
pub(super) const PKEY_VOLUME_BITLOCKER_PROTECTION: PROPERTYKEY = PROPERTYKEY {
    fmtid: GUID::from_u128(0x2d15a9a1_a556_4189_91ad_027458f11a07),
    pid: 1717,
};

const DRIVE_FIXED: u32 = 3;

/// The fallback report for every fixed volume, headed by why WMI said no.
pub(super) fn explorer_status(wmi_reason: &str) -> String {
    // WMI already put this thread in the MTA; joining it again keeps COM alive
    // for the shell calls and the matching CoUninitialize balances only ours.
    let com = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
    let vols: Vec<(char, Result<Option<i32>, i32>)> = fixed_volumes().into_iter().map(|l| (l, read(l))).collect();
    if com.is_ok() {
        unsafe { CoUninitialize() };
    }
    bitlocker_text::render_explorer(wmi_reason, &vols)
}

fn fixed_volumes() -> Vec<char> {
    let mask = unsafe { GetLogicalDrives() };
    (0..26u8)
        .filter(|i| mask & (1 << i) != 0)
        .map(|i| (b'A' + i) as char)
        .filter(|l| {
            let root: Vec<u16> = format!("{l}:\\").encode_utf16().chain(std::iter::once(0)).collect();
            unsafe { GetDriveTypeW(root.as_ptr()) == DRIVE_FIXED }
        })
        .collect()
}

/// The property's value for `letter`:\ — `Ok(None)` when the shell has none.
pub(super) fn read(letter: char) -> Result<Option<i32>, i32> {
    let root = HSTRING::from(format!("{letter}:\\"));
    let store: IPropertyStore =
        unsafe { SHGetPropertyStoreFromParsingName(&root, None, GPS_DEFAULT) }.map_err(|e| e.code().0)?;
    let v = unsafe { store.GetValue(&PKEY_VOLUME_BITLOCKER_PROTECTION) }.map_err(|e| e.code().0)?;
    if v.vt() == VT_EMPTY {
        return Ok(None);
    }
    i32::try_from(&v).map(Some).map_err(|e| e.code().0)
}
