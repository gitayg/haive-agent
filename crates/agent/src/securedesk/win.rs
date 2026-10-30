// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

// Windows side of securedesk.rs: follow the input desktop, and SendSAS.

use std::cell::Cell;
use std::sync::OnceLock;

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32};
use windows_sys::Win32::System::StationsAndDesktops::{
    CloseDesktop, GetThreadDesktop, GetUserObjectInformationW, OpenInputDesktop, SetThreadDesktop, DESKTOP_CREATEMENU,
    DESKTOP_CREATEWINDOW, DESKTOP_ENUMERATE, DESKTOP_HOOKCONTROL, DESKTOP_JOURNALPLAYBACK, DESKTOP_JOURNALRECORD,
    DESKTOP_READOBJECTS, DESKTOP_SWITCHDESKTOP, DESKTOP_WRITEOBJECTS, HDESK, UOI_NAME,
};
use windows_sys::Win32::System::Threading::GetCurrentThreadId;

use super::logic::{desktop_label, same_desktop, sas_policy_verdict};

// Rights to read the desktop and inject input into it (SendInput needs the
// journal-playback right). The same set VNC servers use.
const ACCESS: u32 = DESKTOP_READOBJECTS
    | DESKTOP_CREATEWINDOW
    | DESKTOP_CREATEMENU
    | DESKTOP_HOOKCONTROL
    | DESKTOP_JOURNALRECORD
    | DESKTOP_JOURNALPLAYBACK
    | DESKTOP_ENUMERATE
    | DESKTOP_WRITEOBJECTS
    | DESKTOP_SWITCHDESKTOP;

/// The desktop handle this thread was moved onto (one per thread at most), and
/// the thread's original desktop so the handle can be released at thread exit.
struct Owned {
    cur: Cell<isize>,
    orig: Cell<isize>,
}

impl Drop for Owned {
    fn drop(&mut self) {
        let (cur, orig) = (self.cur.get(), self.orig.get());
        // CloseDesktop fails while a thread still uses the handle, so move back to
        // the original desktop first; if that's refused, leak this one handle.
        unsafe {
            if cur != 0 && orig != 0 && SetThreadDesktop(orig as HDESK) != 0 {
                CloseDesktop(cur as HDESK);
            }
        }
    }
}

thread_local! {
    static OWNED: Owned = const { Owned { cur: Cell::new(0), orig: Cell::new(0) } };
}

unsafe fn desktop_name(h: HDESK) -> Option<String> {
    let mut buf = [0u16; 256];
    let mut need = 0u32;
    if GetUserObjectInformationW(h as HANDLE, UOI_NAME, buf.as_mut_ptr().cast(), (buf.len() * 2) as u32, &mut need) == 0 {
        return None;
    }
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    Some(String::from_utf16_lossy(&buf[..len]))
}

/// Microsoft's documented limits this works within
/// (https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setthreaddesktop):
///   "The SetThreadDesktop function will fail if the calling thread has any
///    windows or hooks on its current desktop (unless the hDesktop parameter is a
///    handle to the current desktop)."
/// So only call this on threads that never create windows or hooks (capture and
/// SendInput threads; note a COM single-threaded apartment creates a hidden
/// window — such a thread can't follow). And from
/// https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-closedesktop:
///   "The CloseDesktop function will fail if any thread in the calling process is
///    using the specified desktop handle"
///   and the GetThreadDesktop handle must not be closed ("Do not specify the
///   handle returned by the GetThreadDesktop function").
/// Hence: close the previous OpenInputDesktop handle only AFTER switching away
/// from it, never close the thread's original desktop, and close the freshly
/// opened handle at once when no switch is needed — at most one handle per
/// thread is ever held, nothing accumulates per frame.
pub fn follow_input_desktop() -> Option<String> {
    unsafe {
        let input = OpenInputDesktop(0, 0, ACCESS);
        if input.is_null() {
            // e.g. a user-token process while the Winlogon desktop has input.
            return None;
        }
        let Some(in_name) = desktop_name(input) else {
            CloseDesktop(input);
            return None;
        };
        let cur = GetThreadDesktop(GetCurrentThreadId());
        if !cur.is_null() && desktop_name(cur).is_some_and(|n| same_desktop(&n, &in_name)) {
            CloseDesktop(input);
            return desktop_label(&in_name).map(str::to_string);
        }
        if SetThreadDesktop(input) == 0 {
            CloseDesktop(input);
            return None;
        }
        let switched = OWNED.try_with(|o| {
            if o.orig.get() == 0 {
                o.orig.set(cur as isize);
            }
            o.cur.replace(input as isize)
        });
        match switched {
            Ok(prev) if prev != 0 => {
                CloseDesktop(prev as HDESK);
            }
            Ok(_) => {}
            // Thread is being torn down: nothing will release it, but the thread
            // (and with it the desktop assignment) is going away anyway.
            Err(_) => {}
        }
        desktop_label(&in_name).map(str::to_string)
    }
}

type SendSasFn = unsafe extern "system" fn(i32);

fn send_sas_fn() -> Option<SendSasFn> {
    static F: OnceLock<Option<usize>> = OnceLock::new();
    let addr = *F.get_or_init(|| unsafe {
        let name: Vec<u16> = "sas.dll".encode_utf16().chain(std::iter::once(0)).collect();
        // System32 only: this runs as SYSTEM, so never resolve sas.dll from the
        // DLL search path (planting).
        let lib = LoadLibraryExW(name.as_ptr(), std::ptr::null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32);
        if lib.is_null() {
            return None;
        }
        GetProcAddress(lib, c"SendSAS".as_ptr().cast()).map(|f| f as usize)
    });
    addr.map(|a| unsafe { std::mem::transmute::<usize, SendSasFn>(a) })
}

pub fn sas_available() -> bool {
    crate::winsession::is_session0() && send_sas_fn().is_some()
}

fn sas_policy() -> Option<u32> {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    winreg::RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")
        .and_then(|k| k.get_value::<u32, _>("SoftwareSASGeneration"))
        .ok()
}

/// https://learn.microsoft.com/en-us/windows/win32/api/sas/nf-sas-sendsas:
///   "To successfully call the SendSAS function, an application must either be
///    running as a service or have the uiAccess attribute ... set to "true""
///   "The local security policy of a computer must be configured to allow
///    services and applications to simulate a SAS."
/// and the policy (https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-winlogon,
/// SoftwareSASGeneration): "If you disable or don't configure this setting, only
/// Ease of Access applications running on the secure desktop can simulate the SAS."
/// SendSAS returns VOID, so we check the policy up front and report it; we never
/// write it (that is the administrator's call).
pub fn sas() -> Result<(), String> {
    if !crate::winsession::is_session0() {
        return Err("Ctrl+Alt+Del needs the agent to run as LocalSystem (a service); this agent runs as a normal user".into());
    }
    sas_policy_verdict(sas_policy())?;
    let f = send_sas_fn().ok_or("this Windows has no SendSAS in sas.dll")?;
    // AsUser = FALSE: "TRUE if the caller is running as the current user; otherwise, FALSE."
    unsafe { f(0) };
    Ok(())
}
