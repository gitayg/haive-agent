// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

// Platform-independent decisions behind the secure-desktop support, kept here so
// they are unit-tested on every OS: desktop-name mapping, when the session-0
// service (re)spawns its screen helper, and what the SendSAS policy allows.
#![cfg_attr(not(windows), allow(dead_code))]

use std::time::Duration;

use super::spec::EXIT_IDLE;

/// A Windows desktop name → the protocol's `desktop` value (docs/SCREEN-PROTOCOL.md).
/// Any other desktop (a third-party one) maps to None rather than inventing a value.
pub fn desktop_label(name: &str) -> Option<&'static str> {
    match name.to_ascii_lowercase().as_str() {
        "default" => Some("default"),
        "winlogon" => Some("winlogon"),
        "screen-saver" | "screensaver" => Some("screensaver"),
        _ => None,
    }
}

/// Desktop names are case-insensitive.
pub fn same_desktop(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    /// The running helper serves the current console session.
    Reuse,
    /// A helper is running but for another session (user switch): stop it, start anew.
    Replace,
    /// No helper: start one.
    Spawn,
    /// Starting failed recently; wait this long before trying again.
    Backoff(Duration),
    /// No console session right now (session transition).
    NoSession,
}

/// `running` = the console session the live helper was started for (None when
/// there is no live helper — the caller reaps a dead one first).
pub fn decide(running: Option<u32>, console: Option<u32>, fails: u32, since_fail: Option<Duration>) -> Decision {
    let Some(console) = console else { return Decision::NoSession };
    match running {
        Some(s) if s == console => Decision::Reuse,
        Some(_) => Decision::Replace,
        None => match since_fail {
            Some(age) if fails > 0 && age < backoff(fails) => Decision::Backoff(backoff(fails) - age),
            _ => Decision::Spawn,
        },
    }
}

/// 30 s after the first failure, doubling, capped at 10 min — so a box where the
/// helper can't start pays the start-up wait rarely, not on every frame.
pub fn backoff(fails: u32) -> Duration {
    let n = fails.clamp(1, 6) - 1;
    Duration::from_secs((30u64 << n).min(600))
}

/// A helper that exited because it was idle is not a failure; anything else is.
pub fn counts_as_failure(exit_code: u32) -> bool {
    exit_code != EXIT_IDLE
}

pub const SAS_POLICY_KEY: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";

/// Whether the machine's SoftwareSASGeneration policy lets a service simulate
/// Ctrl+Alt+Del. SendSAS returns nothing, so a blocked call is silent — hence we
/// read the policy first and explain it instead. We never change it ourselves.
pub fn sas_policy_verdict(value: Option<u32>) -> Result<(), String> {
    let how = format!(
        "An administrator can allow it with: reg add \"{SAS_POLICY_KEY}\" /v SoftwareSASGeneration /t REG_DWORD /d 1 /f \
         (or Group Policy: Computer Configuration > Administrative Templates > Windows Components > Windows Logon Options > \
         Disable or enable software Secure Attention Sequence = Services)."
    );
    let state = match value {
        Some(1) | Some(3) => return Ok(()),
        None => "is not configured, so only Ease of Access applications on the secure desktop may send it".to_string(),
        Some(0) => "is set to None (0)".to_string(),
        Some(2) => "allows Ease of Access applications only (2)".to_string(),
        Some(v) => format!("has an unrecognized value ({v})"),
    };
    Err(format!(
        "Windows blocks software Ctrl+Alt+Del from services: the policy SoftwareSASGeneration under {SAS_POLICY_KEY} {state}. {how}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desktop_names_map_to_protocol_values() {
        assert_eq!(desktop_label("Default"), Some("default"));
        assert_eq!(desktop_label("Winlogon"), Some("winlogon"));
        assert_eq!(desktop_label("WINLOGON"), Some("winlogon"));
        assert_eq!(desktop_label("Screen-saver"), Some("screensaver"));
        assert_eq!(desktop_label("Disconnect"), None);
        assert_eq!(desktop_label(""), None);
        assert!(same_desktop("Winlogon", "winlogon"));
        assert!(!same_desktop("Default", "Winlogon"));
    }

    const S: Option<Duration> = None;

    #[test]
    fn reuses_a_live_helper_for_the_same_session() {
        assert_eq!(decide(Some(1), Some(1), 0, S), Decision::Reuse);
    }

    #[test]
    fn replaces_the_helper_when_the_console_session_changes() {
        assert_eq!(decide(Some(1), Some(2), 0, S), Decision::Replace);
    }

    #[test]
    fn spawns_when_absent_and_backs_off_after_failures() {
        assert_eq!(decide(None, Some(1), 0, S), Decision::Spawn);
        assert_eq!(decide(None, Some(1), 1, Some(Duration::from_secs(10))), Decision::Backoff(Duration::from_secs(20)));
        assert_eq!(decide(None, Some(1), 1, Some(Duration::from_secs(30))), Decision::Spawn);
        assert_eq!(decide(None, Some(1), 3, Some(Duration::from_secs(60))), Decision::Backoff(Duration::from_secs(60)));
        assert_eq!(decide(None, None, 0, S), Decision::NoSession);
        assert_eq!(decide(Some(1), None, 0, S), Decision::NoSession);
    }

    #[test]
    fn backoff_doubles_and_caps() {
        assert_eq!(backoff(1), Duration::from_secs(30));
        assert_eq!(backoff(2), Duration::from_secs(60));
        assert_eq!(backoff(5), Duration::from_secs(480));
        assert_eq!(backoff(6), Duration::from_secs(600));
        assert_eq!(backoff(50), Duration::from_secs(600));
        assert_eq!(backoff(0), Duration::from_secs(30));
    }

    #[test]
    fn idle_exit_is_not_a_failure() {
        assert!(!counts_as_failure(EXIT_IDLE));
        assert!(counts_as_failure(super::super::spec::EXIT_BIND));
        assert!(counts_as_failure(1));
    }

    #[test]
    fn sas_policy_allows_services_only_for_1_and_3() {
        assert!(sas_policy_verdict(Some(1)).is_ok());
        assert!(sas_policy_verdict(Some(3)).is_ok());
        for v in [None, Some(0), Some(2), Some(7)] {
            let e = sas_policy_verdict(v).unwrap_err();
            assert!(e.contains("SoftwareSASGeneration"), "{e}");
            assert!(e.contains(SAS_POLICY_KEY), "{e}");
            assert!(e.contains("/d 1"), "{e}");
        }
    }
}
