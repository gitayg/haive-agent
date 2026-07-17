// Runtime wake lock: while the agent runs, the host must stay reachable, so we
// tell the OS "don't sleep the system." Unlike the powercfg/pmset scheme changes
// in persistence.rs, this needs no elevation, applies on every run (even a plain
// --background enroll), and clears automatically when the process exits — so it
// leaves no lingering system setting behind.

/// Ask the OS to keep the system awake for the lifetime of this process.
/// Call once, early, on the long-lived agent process.
#[cfg(windows)]
pub fn hold() {
    // ES_CONTINUOUS makes the request sticky until this thread resets it or exits;
    // ES_SYSTEM_REQUIRED keeps the system out of idle sleep (the display may still
    // turn off — we don't force the screen on). No admin rights required.
    const ES_CONTINUOUS: u32 = 0x8000_0000;
    const ES_SYSTEM_REQUIRED: u32 = 0x0000_0001;
    extern "system" {
        fn SetThreadExecutionState(es_flags: u32) -> u32;
    }
    unsafe {
        SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED);
    }
}

/// macOS: hold an idle-sleep assertion for as long as the agent runs by keeping a
/// `caffeinate` child alive (it exits with us because we hold its handle). `-i`
/// prevents idle sleep, `-s` scopes it to AC power so battery behaviour is untouched.
#[cfg(target_os = "macos")]
pub fn hold() {
    use std::sync::OnceLock;
    static CHILD: OnceLock<std::process::Child> = OnceLock::new();
    if let Ok(child) = std::process::Command::new("caffeinate").args(["-i", "-s"]).spawn() {
        let _ = CHILD.set(child);
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
pub fn hold() {
    // Linux idle-sleep is handled at persist time via GNOME gsettings (see
    // persistence.rs); there's no elevation-free, desktop-agnostic runtime knob
    // that's safe to assume here, so this is a no-op.
}
