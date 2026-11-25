// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

//! The last Windows Update search and the one running now. A WUA search takes
//! about 30 s (32.5 s measured on DESKTOP-JOL2MB8), so `it-ai:os-updates/check`
//! answers from the last good result while it is FRESH, starts a refresh behind
//! that answer once it is older than REFRESH, and otherwise starts a search and
//! waits a bounded time for it. Only one search runs at a time. A failed search
//! is answered to whoever waited for it but never cached, so the next check
//! tries again.
//!
//! Every search belongs to the generation it started in. An install bumps the
//! generation (`invalidate`): a search that was already running reported the
//! machine before the install, so its result is dropped and a new search starts
//! when it ends. A search running longer than HUNG is abandoned (WUA's Search
//! cannot be cancelled): the next check starts a new one in a new generation and
//! the old one's result, if it ever comes, is dropped. While an abandoned search
//! is still running no second one is abandoned, so at most two search threads
//! ever exist.
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::Duration;

/// A result older than this is not answered: the check waits for a new one.
pub const FRESH: u64 = 6 * 3600;
/// A result older than this is still answered, and a new search starts behind it.
pub const REFRESH: u64 = 3600;
/// A search running longer than this is given up on and a new one started.
pub const HUNG: u64 = 30 * 60;

/// Seconds on some monotonic clock.
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;
/// One search: the report, or the full error line.
pub type Search = Arc<dyn Fn() -> Result<String, String> + Send + Sync>;

#[derive(Debug, PartialEq)]
pub enum Answer {
    /// A successful search that finished `age` seconds ago.
    Report { text: String, age: u64 },
    /// The search that was waited for failed.
    Failed(String),
    /// A search has been running `secs` seconds and has not finished.
    Checking { secs: u64 },
}

#[derive(Debug)]
struct Run {
    started: u64,
    generation: u64,
}

#[derive(Default)]
struct State {
    good: Option<(String, u64)>,
    running: Option<Run>,
    generation: u64,
    abandoned: usize,
    finished: u64,
    last: Option<Result<String, String>>,
}

pub struct Cache {
    shared: Arc<(Mutex<State>, Condvar)>,
    clock: Clock,
    search: Search,
}

impl Cache {
    pub fn new(clock: Clock, search: Search) -> Cache {
        Cache { shared: Arc::new((Mutex::new(State::default()), Condvar::new())), clock, search }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.shared.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The answer to one check, waiting at most `wait` for a search to finish.
    pub fn answer(&self, wait: Duration) -> Answer {
        let now = (self.clock)();
        let mut st = self.state();
        if let Some((text, at)) = st.good.clone() {
            let age = now.saturating_sub(at);
            if age <= FRESH {
                if age > REFRESH {
                    self.start(&mut st, now);
                }
                return Answer::Report { text, age };
            }
        }
        let seen = st.finished;
        self.start(&mut st, now);
        let (st, _) = self
            .shared
            .1
            .wait_timeout_while(st, wait, |s| s.finished == seen)
            .unwrap_or_else(|e| e.into_inner());
        let now = (self.clock)();
        if st.finished == seen {
            return Answer::Checking { secs: now.saturating_sub(st.running.as_ref().map_or(now, |r| r.started)) };
        }
        match st.last.clone() {
            Some(Ok(text)) => Answer::Report { text, age: now.saturating_sub(st.good.as_ref().map_or(now, |g| g.1)) },
            Some(Err(e)) => Answer::Failed(e),
            None => Answer::Checking { secs: 0 },
        }
    }

    /// Forget the last result and any search already running, so the next check searches again.
    pub fn invalidate(&self) {
        let mut st = self.state();
        st.good = None;
        st.generation += 1;
    }

    fn start(&self, st: &mut State, now: u64) {
        spawn(&self.shared, &self.clock, &self.search, st, now);
    }
}

fn spawn(shared: &Arc<(Mutex<State>, Condvar)>, clock: &Clock, search: &Search, st: &mut State, now: u64) {
    if let Some(run) = &st.running {
        let secs = now.saturating_sub(run.started);
        if secs <= HUNG || st.abandoned > 0 {
            return;
        }
        eprintln!("Windows Update search has run {} min without an answer; starting a new one and ignoring the old one's result", secs / 60);
        st.abandoned += 1;
        st.generation += 1;
    }
    let generation = st.generation;
    st.running = Some(Run { started: now, generation });
    let (shared, clock, search) = (shared.clone(), clock.clone(), search.clone());
    std::thread::spawn(move || {
        let r = search();
        let mut st = shared.0.lock().unwrap_or_else(|e| e.into_inner());
        if st.running.as_ref().is_none_or(|run| run.generation != generation) {
            st.abandoned -= 1;
            return;
        }
        st.running = None;
        if generation != st.generation {
            let now = clock();
            spawn(&shared, &clock, &search, &mut st, now);
            return;
        }
        if let Ok(text) = &r {
            st.good = Some((text.clone(), clock()));
        }
        st.last = Some(r);
        st.finished += 1;
        shared.1.notify_all();
    });
}

#[cfg(test)]
#[path = "cache/tests.rs"]
mod tests;
