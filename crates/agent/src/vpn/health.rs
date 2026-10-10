// SPDX-License-Identifier: MIT
//! The userspace backend's watchdog: what counts as healthy, when to rebuild, when to give up.
//! Decisions only; the device is behind `Userspace`, so recovery is testable without a TUN.
//!
//! boringtun runs the device on its own worker thread. If that thread panics, only it dies:
//! the agent stays up and `/vpn/status` still looks fine while nothing is forwarded. The
//! kernel backend has no threads of ours, so it is not watched.
// Only the Linux userspace backend has a probe; elsewhere part of this is tests only.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use super::Desired;
use std::collections::VecDeque;
use std::time::Duration;

/// How often a healthy device is checked. Every apply is also checked right away.
pub const CHECK_EVERY: Duration = Duration::from_secs(10);
/// A `get=1` that has not answered by then counts as a hung device.
pub const UAPI_TIMEOUT: Duration = Duration::from_secs(2);
/// This many failures within `WINDOW_SECS` and the watchdog stops rebuilding.
pub const GIVE_UP_AFTER: usize = 5;
pub const WINDOW_SECS: u64 = 600;
const BACKOFF_CAP_SECS: u64 = 60;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Health {
    #[default]
    Ok,
    Recovering,
    Failed,
}

impl Health {
    pub fn name(self) -> &'static str {
        match self {
            Health::Ok => "ok",
            Health::Recovering => "recovering",
            Health::Failed => "failed",
        }
    }
}

/// What the watchdog checks on a running userspace device.
pub trait Probe {
    /// Err when a boringtun worker thread is gone; the reason carries its panic message.
    fn workers(&self) -> Result<(), String>;
    /// Err unless a `get=1` answers errno=0 within `timeout`.
    fn uapi(&self, timeout: Duration) -> Result<(), String>;
    fn iface_exists(&self) -> bool;
}

/// The health check: worker threads, the interface, then a UAPI round trip.
pub fn check(p: &impl Probe) -> Result<(), String> {
    p.workers()?;
    if !p.iface_exists() {
        return Err(format!("the {} interface is gone", super::IFACE));
    }
    p.uapi(UAPI_TIMEOUT)
}

/// The wait before rebuild number `attempt` (0-based) of one recovery: 1s, 2s, 4s… up to 60s.
pub fn backoff(attempt: u32) -> Duration {
    Duration::from_secs(1u64.checked_shl(attempt).unwrap_or(u64::MAX).min(BACKOFF_CAP_SECS))
}

/// The side effects recovery needs, so `step` can run against a fake.
pub trait Userspace {
    /// None when no userspace device is up (the kernel backend, or nothing): not watched.
    fn check(&mut self) -> Option<Result<(), String>>;
    /// Stops the device and removes the interface, whatever state it is in.
    fn teardown(&mut self);
    /// Brings the device up again with the exit's key and port, and `d`'s peers.
    fn rebuild(&mut self, d: &Desired) -> Result<(), String>;
}

/// The watchdog's record, reported in `/vpn/status`.
#[derive(Clone, Debug, Default)]
pub struct Watch {
    pub health: Health,
    /// Teardown-and-rebuilds done since the exit was enabled.
    pub restarts: u64,
    /// Unix seconds and reason of the last failed check.
    pub last_failure: Option<(u64, String)>,
    /// When the failures inside the window happened.
    failures: VecDeque<u64>,
    /// Failures since the device was last healthy; picks the backoff.
    streak: u32,
    /// The state generation a recovery started under. A hub apply or disable since
    /// then ends that recovery: it must not rebuild over (or resurrect) the hub's change.
    episode: Option<u64>,
}

/// What a `step` did, for the caller's log and `last_error`.
#[derive(Debug, PartialEq)]
pub enum Outcome {
    /// Healthy, not watched, given up already, or disabled: check again in `CHECK_EVERY`.
    Idle,
    /// Unhealthy: the next step, after this wait, rebuilds the device.
    Retry(Duration),
    /// A rebuild brought the device back.
    Recovered,
    /// Too many failures: the device was torn down and is left down until the hub applies.
    GaveUp(String),
}

impl Watch {
    /// A hub apply (or the boot resume) succeeded: start from a clean slate. `restarts` and
    /// `last_failure` are history and stay.
    pub fn fresh_apply(&mut self) {
        self.health = Health::Ok;
        self.failures.clear();
        self.streak = 0;
        self.episode = None;
    }

    /// Records a failed check at `now` under `generation`. Returns what to do next.
    pub fn failed(&mut self, now: u64, generation: u64, reason: String) -> Outcome {
        self.failures.retain(|t| now.saturating_sub(*t) < WINDOW_SECS);
        self.failures.push_back(now);
        self.last_failure = Some((now, reason.clone()));
        self.streak += 1;
        if self.failures.len() >= GIVE_UP_AFTER {
            self.health = Health::Failed;
            self.episode = None;
            return Outcome::GaveUp(reason);
        }
        self.health = Health::Recovering;
        self.episode = Some(generation);
        Outcome::Retry(backoff(self.streak - 1))
    }

    fn recovered(&mut self) {
        // The failure window stays, so a device that dies again and again still adds up.
        self.health = Health::Ok;
        self.streak = 0;
        self.episode = None;
    }
}

/// One watchdog round, run under the exit's `op()` lock with the state as it is now:
/// `generation` and `desired` (None = disabled). A recovery that started under an older
/// generation is dropped without touching the device.
pub fn step(w: &mut Watch, generation: u64, desired: Option<&Desired>, dev: &mut impl Userspace, now: u64) -> Outcome {
    let Some(d) = desired else {
        // Disabled: nothing to watch, and nothing to bring back.
        return Outcome::Idle;
    };
    if w.episode.is_some_and(|g| g != generation) {
        // The hub applied since this recovery began; that apply rebuilt what it needed.
        w.episode = None;
        w.streak = 0;
        if w.health == Health::Recovering {
            w.health = Health::Ok;
        }
    }
    if w.health == Health::Failed {
        return Outcome::Idle;
    }
    let result = if w.episode.is_none() {
        match dev.check() {
            None | Some(Ok(())) => return Outcome::Idle,
            Some(Err(e)) => Err(e),
        }
    } else {
        dev.teardown();
        w.restarts += 1;
        dev.rebuild(d).and_then(|()| dev.check().unwrap_or(Ok(())))
    };
    match result {
        Ok(()) => {
            w.recovered();
            Outcome::Recovered
        }
        Err(e) => match w.failed(now, generation, e) {
            Outcome::GaveUp(e) => {
                dev.teardown();
                Outcome::GaveUp(e)
            }
            o => o,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vpn::Peer;

    fn desired(ips: &[&str]) -> Desired {
        let key = "A2+2dpchy903HY/kmF70XH8jsgBgj1Vvf4+64neJqwI=";
        let peers = ips.iter().map(|ip| Peer { public_key: key.into(), preshared_key: key.into(), allowed_ips: (*ip).into(), expires_at: u64::MAX }).collect();
        Desired { relay: "relay.example:31820".into(), secret: "ab".repeat(16), peers }
    }

    /// A device that is healthy until `dies`, and whose rebuilds work after `fix_after` of them.
    #[derive(Default)]
    struct Fake {
        dead: Option<String>,
        rebuilds_fail: usize,
        log: Vec<String>,
        rebuilt_with: Vec<Vec<String>>,
    }

    impl Userspace for Fake {
        fn check(&mut self) -> Option<Result<(), String>> {
            self.log.push("check".into());
            Some(self.dead.clone().map_or(Ok(()), Err))
        }
        fn teardown(&mut self) {
            self.log.push("teardown".into());
        }
        fn rebuild(&mut self, d: &Desired) -> Result<(), String> {
            self.log.push("rebuild".into());
            self.rebuilt_with.push(d.peers.iter().map(|p| p.allowed_ips.clone()).collect());
            if self.rebuilds_fail > 0 {
                self.rebuilds_fail -= 1;
                return Err("boringtun: /dev/net/tun: Device or resource busy".into());
            }
            self.dead = None;
            Ok(())
        }
    }

    struct P {
        workers: Result<(), String>,
        iface: bool,
        uapi: Result<(), String>,
    }

    impl Probe for P {
        fn workers(&self) -> Result<(), String> {
            self.workers.clone()
        }
        fn uapi(&self, timeout: Duration) -> Result<(), String> {
            assert_eq!(timeout, UAPI_TIMEOUT);
            self.uapi.clone()
        }
        fn iface_exists(&self) -> bool {
            self.iface
        }
    }

    #[test]
    fn the_check_fails_on_a_dead_worker_a_missing_interface_or_a_hung_uapi() {
        let ok = || P { workers: Ok(()), iface: true, uapi: Ok(()) };
        assert_eq!(check(&ok()), Ok(()));
        let dead = P { workers: Err("boringtun's worker thread is gone: panicked at x".into()), ..ok() };
        assert!(check(&dead).unwrap_err().contains("panicked at x"));
        assert!(check(&P { iface: false, ..ok() }).unwrap_err().contains("itai-wg"));
        let hung = P { uapi: Err("no answer to get=1 within 2s".into()), ..ok() };
        assert!(check(&hung).unwrap_err().contains("within 2s"));
    }

    #[test]
    fn backoff_doubles_from_one_second_up_to_a_minute() {
        let secs: Vec<u64> = (0..9).map(|a| backoff(a).as_secs()).collect();
        assert_eq!(secs, [1, 2, 4, 8, 16, 32, 60, 60, 60]);
        assert_eq!(backoff(200), Duration::from_secs(60), "no overflow");
    }

    #[test]
    fn a_dead_device_is_rebuilt_with_the_same_peers() {
        let d = desired(&["10.77.0.2/32", "10.77.0.3/32"]);
        let mut f = Fake::default();
        let mut w = Watch::default();
        assert_eq!(step(&mut w, 7, Some(&d), &mut f, 1000), Outcome::Idle, "healthy");
        assert!(f.rebuilt_with.is_empty());

        f.dead = Some("boringtun's worker thread is gone: panicked at …: Modifying existing peers".into());
        assert_eq!(step(&mut w, 7, Some(&d), &mut f, 1010), Outcome::Retry(Duration::from_secs(1)));
        assert_eq!(w.health, Health::Recovering);
        assert!(w.last_failure.as_ref().unwrap().1.contains("Modifying existing peers"));

        assert_eq!(step(&mut w, 7, Some(&d), &mut f, 1011), Outcome::Recovered);
        assert_eq!(f.rebuilt_with, [vec!["10.77.0.2/32".to_string(), "10.77.0.3/32".into()]], "the current desired peers");
        assert_eq!(f.log, ["check", "check", "teardown", "rebuild", "check"], "torn down before the rebuild, checked after it");
        assert_eq!((w.health, w.restarts), (Health::Ok, 1));
        assert_eq!(step(&mut w, 7, Some(&d), &mut f, 1021), Outcome::Idle);
    }

    #[test]
    fn failed_rebuilds_back_off_then_give_up_after_five() {
        let d = desired(&["10.77.0.2/32"]);
        let mut f = Fake { dead: Some("no answer to get=1 within 2s".into()), rebuilds_fail: usize::MAX, ..Default::default() };
        let mut w = Watch::default();
        let mut now = 5000;
        let mut waits = vec![];
        loop {
            match step(&mut w, 1, Some(&d), &mut f, now) {
                Outcome::Retry(t) => {
                    waits.push(t.as_secs());
                    now += t.as_secs();
                }
                Outcome::GaveUp(e) => {
                    assert!(e.contains("Device or resource busy"), "{e}");
                    break;
                }
                o => panic!("{o:?}"),
            }
        }
        assert_eq!(waits, [1, 2, 4, 8], "the detection plus four failed rebuilds = five failures");
        assert_eq!((w.health, w.restarts), (Health::Failed, 4));
        assert_eq!(f.log.last().map(String::as_str), Some("teardown"), "a device that cannot be fixed is left down");
        let n = f.log.len();
        assert_eq!(step(&mut w, 1, Some(&d), &mut f, now + 60), Outcome::Idle);
        assert_eq!(f.log.len(), n, "nothing more is tried until the hub applies");

        w.fresh_apply();
        f.rebuilds_fail = 0;
        assert_eq!(step(&mut w, 2, Some(&d), &mut f, now + 70), Outcome::Retry(Duration::from_secs(1)), "a hub apply gives it a new budget");
    }

    #[test]
    fn a_device_that_keeps_dying_gives_up_even_though_each_rebuild_works() {
        let d = desired(&["10.77.0.2/32"]);
        let mut f = Fake::default();
        let mut w = Watch::default();
        let mut now = 0;
        for round in 1..=5 {
            f.dead = Some(format!("panic #{round}"));
            now += 10;
            let o = step(&mut w, 1, Some(&d), &mut f, now);
            if round == 5 {
                assert_eq!(o, Outcome::GaveUp("panic #5".into()));
                break;
            }
            assert_eq!(o, Outcome::Retry(Duration::from_secs(1)), "round {round}");
            assert_eq!(step(&mut w, 1, Some(&d), &mut f, now + 1), Outcome::Recovered);
        }
        assert_eq!((w.health, w.restarts), (Health::Failed, 4));

        // Spread over more than ten minutes, the same five failures never add up.
        let (mut f, mut w) = (Fake::default(), Watch::default());
        for round in 0..10 {
            f.dead = Some("panic".into());
            let now = round * 200;
            assert!(matches!(step(&mut w, 1, Some(&d), &mut f, now), Outcome::Retry(_)));
            assert_eq!(step(&mut w, 1, Some(&d), &mut f, now + 1), Outcome::Recovered);
        }
    }

    #[test]
    fn a_disable_during_the_backoff_is_not_undone() {
        let d = desired(&["10.77.0.2/32"]);
        let mut f = Fake { dead: Some("boringtun's worker thread is gone".into()), ..Default::default() };
        let mut w = Watch::default();
        assert!(matches!(step(&mut w, 3, Some(&d), &mut f, 100), Outcome::Retry(_)));
        // The hub disables while the watchdog sleeps: generation 4, nothing desired.
        assert_eq!(step(&mut w, 4, None, &mut f, 101), Outcome::Idle);
        assert_eq!(f.log, ["check"], "no teardown, no rebuild: the disable stands");

        // A hub apply instead (generation 4, new peers) ends the old recovery too: the apply
        // rebuilt the device itself, so the next step only checks it.
        let mut f = Fake { dead: Some("dead".into()), ..Default::default() };
        let mut w = Watch::default();
        assert!(matches!(step(&mut w, 3, Some(&d), &mut f, 100), Outcome::Retry(_)));
        f.dead = None;
        assert_eq!(step(&mut w, 4, Some(&desired(&["10.77.0.9/32"])), &mut f, 101), Outcome::Idle);
        assert_eq!(f.log, ["check", "check"]);
        assert!(f.rebuilt_with.is_empty(), "the stale recovery never rebuilt with the old peers");
        assert_eq!(w.health, Health::Ok);
    }
}
