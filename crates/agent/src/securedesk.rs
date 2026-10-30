// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

// Windows secure desktop: follow the desktop that has input (UAC prompt, lock
// screen, Ctrl+Alt+Del screen) and generate Ctrl+Alt+Del. No-ops elsewhere.
// The pure pieces (desktop names, helper SPEC, request auth, restart policy) live
// in submodules that build and are tested on every OS.

pub(crate) mod auth;
pub(crate) mod logic;
pub(crate) mod spec;
#[cfg(windows)]
mod win;

/// Attach the calling thread to the desktop currently receiving input. Returns
/// "default", "winlogon" or "screensaver", or None off Windows / when it can't.
pub fn follow_input_desktop() -> Option<String> {
    #[cfg(windows)]
    return win::follow_input_desktop();
    #[cfg(not(windows))]
    None
}

/// True when `sas()` can work on this device (Windows, running as LocalSystem,
/// sas.dll exports SendSAS). The machine policy is checked by `sas()` itself so
/// its refusal can name the setting.
pub fn sas_available() -> bool {
    #[cfg(windows)]
    return win::sas_available();
    #[cfg(not(windows))]
    false
}

/// Generate Ctrl+Alt+Del through SendSAS.
pub fn sas() -> Result<(), String> {
    #[cfg(windows)]
    return win::sas();
    #[cfg(not(windows))]
    Err("Ctrl+Alt+Del is only available on Windows when the agent runs as a service".into())
}
