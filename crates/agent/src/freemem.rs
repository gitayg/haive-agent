// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

//! Free RAM as the hub shows and alerts on it (`free_gb`).
//!
//! sysinfo's `available_memory()` reads 0 on macOS 27 (a 48 GB Mac reported 0.00
//! while `memory_pressure` said 45% free), which made every Mac look out of memory.
//! On macOS the figure is the share macOS itself uses for memory pressure,
//! `kern.memorystatus_level` (percent free) of total RAM; elsewhere, and when that
//! sysctl cannot be read, it stays sysinfo's available memory.

/// Free bytes: `level` percent of `total` when macOS gave a level, else `available`.
pub(crate) fn free_bytes(total: u64, available: u64, level: Option<u32>) -> u64 {
    match level {
        Some(l) => total * l as u64 / 100,
        None => available,
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn memorystatus_level() -> Option<u32> {
    let mut v: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>();
    let rc = unsafe {
        libc::sysctlbyname(
            c"kern.memorystatus_level".as_ptr(),
            &mut v as *mut libc::c_int as *mut libc::c_void,
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    (rc == 0 && len == std::mem::size_of::<libc::c_int>() && v >= 0).then_some(v as u32)
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn memorystatus_level() -> Option<u32> {
    None
}

#[cfg(test)]
mod tests;
