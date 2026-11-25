// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Itay Glick

//! The one agent-wide worker that finishes off job workspaces (agent 3.18.0). A
//! workspace that cannot be removed when its job ends (Windows: a grandchild the job
//! left running still has it as its working directory or holds a file in it) is queued
//! here and retried, 30 s after the job ended and then backing off to every 10 min,
//! until it goes or the agent exits. The same worker runs the 24 h sweep at start and
//! every hour. Neither ever touches anything but a direct child of `workspaces/`, nor
//! the workspace of a job that is still running.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

pub const FIRST_RETRY: Duration = Duration::from_secs(30);
pub const MAX_RETRY: Duration = Duration::from_secs(600);
pub const SWEEP_EVERY: Duration = Duration::from_secs(3600);

struct Due {
    at: Instant,
    delay: Duration,
}

pub struct Janitor {
    root: PathBuf,
    remove: Box<dyn Fn(&Path) -> bool + Send + Sync>,
    pending: Mutex<BTreeMap<PathBuf, Due>>,
    wake: Condvar,
    started: AtomicBool,
}

impl Janitor {
    pub fn new(root: PathBuf, remove: impl Fn(&Path) -> bool + Send + Sync + 'static) -> Self {
        Janitor { root, remove: Box::new(remove), pending: Mutex::new(BTreeMap::new()), wake: Condvar::new(), started: AtomicBool::new(false) }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn owns(&self, dir: &Path) -> bool {
        dir.file_name().is_some() && dir.parent() == Some(self.root.as_path())
    }

    /// Remove the workspace of a job that has ended, or queue it for retries when it is still in use.
    pub fn discard(&self, dir: &Path) {
        if self.owns(dir) && !(self.remove)(dir) {
            self.leave(dir);
        }
    }

    /// Queue `dir` for retried removal. False (and nothing queued) when it is not a workspace under root.
    pub fn leave(&self, dir: &Path) -> bool {
        if !self.owns(dir) {
            return false;
        }
        let mut p = self.pending.lock().unwrap();
        if !p.contains_key(dir) {
            p.insert(dir.to_path_buf(), Due { at: Instant::now() + FIRST_RETRY, delay: FIRST_RETRY });
            eprintln!("workspace {} is still in use; retrying its removal in the background", dir.display());
        }
        self.wake.notify_all();
        true
    }

    pub fn is_pending(&self, dir: &Path) -> bool {
        self.pending.lock().unwrap().contains_key(dir)
    }

    /// Try every queued workspace due by `now` that is not `busy`; the ones still in use back off.
    pub fn retry_due(&self, now: Instant, busy: &dyn Fn(&Path) -> bool) -> usize {
        let due: Vec<PathBuf> = self.pending.lock().unwrap().iter().filter(|(_, d)| d.at <= now).map(|(p, _)| p.clone()).collect();
        let mut n = 0;
        for dir in due {
            let gone = !busy(&dir) && (self.remove)(&dir);
            let mut p = self.pending.lock().unwrap();
            if gone {
                p.remove(&dir);
                eprintln!("workspace {} finally removed", dir.display());
                n += 1;
            } else if let Some(d) = p.get_mut(&dir) {
                d.delay = (d.delay * 2).min(MAX_RETRY);
                d.at = now + d.delay;
            }
        }
        n
    }

    /// The 24 h sweep of `root`, skipping running jobs' workspaces and the ones already queued.
    pub fn sweep(&self, busy: &dyn Fn(&Path) -> bool) -> usize {
        let n = super::sweep(&self.root, super::SWEEP_AGE, &|p| busy(p) || self.is_pending(p));
        if n > 0 {
            eprintln!("removed {n} job workspace(s) older than 24 h");
        }
        n
    }

    /// One pass of the worker: the sweep when `next_sweep` has come, then the due retries.
    pub fn step(&self, now: Instant, next_sweep: &mut Instant, busy: &dyn Fn(&Path) -> bool) {
        if now >= *next_sweep {
            self.sweep(busy);
            *next_sweep = now + SWEEP_EVERY;
        }
        self.retry_due(now, busy);
    }

    /// Start this janitor's worker thread; later calls do nothing. It sweeps at once.
    pub fn spawn(self: &Arc<Self>, busy: impl Fn(&Path) -> bool + Send + 'static) {
        if self.started.swap(true, Ordering::SeqCst) {
            return;
        }
        let j = self.clone();
        std::thread::spawn(move || {
            let mut next_sweep = Instant::now();
            loop {
                j.step(Instant::now(), &mut next_sweep, &busy);
                let p = j.pending.lock().unwrap();
                let wake = p.values().map(|d| d.at).min().map_or(next_sweep, |a| a.min(next_sweep));
                let _ = j.wake.wait_timeout(p, wake.saturating_duration_since(Instant::now())).unwrap();
            }
        });
    }
}

#[cfg(test)]
mod tests;
