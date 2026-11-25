use super::*;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

/// A cache over a fake clock and a fake search that can be held running (all
/// searches, or only search number `stuck`) and told to fail; `searches` counts
/// the searches started.
struct Rig {
    cache: Cache,
    now: Arc<AtomicU64>,
    searches: Arc<AtomicUsize>,
    hold: Arc<AtomicBool>,
    stuck: Arc<AtomicUsize>,
    fail: Arc<AtomicBool>,
}

fn rig() -> Rig {
    let (now, searches) = (Arc::new(AtomicU64::new(1_000_000)), Arc::new(AtomicUsize::new(0)));
    let (hold, fail) = (Arc::new(AtomicBool::new(false)), Arc::new(AtomicBool::new(false)));
    let stuck = Arc::new(AtomicUsize::new(0));
    let clock = {
        let now = now.clone();
        Arc::new(move || now.load(Ordering::SeqCst))
    };
    let search = {
        let (searches, hold, stuck, fail) = (searches.clone(), hold.clone(), stuck.clone(), fail.clone());
        Arc::new(move || {
            let n = searches.fetch_add(1, Ordering::SeqCst) + 1;
            while hold.load(Ordering::SeqCst) || stuck.load(Ordering::SeqCst) == n {
                std::thread::sleep(Duration::from_millis(2));
            }
            if fail.load(Ordering::SeqCst) {
                Err(format!("OS updates: search {n} failed"))
            } else {
                Ok(format!("report {n}"))
            }
        })
    };
    Rig { cache: Cache::new(clock, search), now, searches, hold, stuck, fail }
}

const LONG: Duration = Duration::from_secs(5);

impl Rig {
    fn later(&self, secs: u64) {
        self.now.fetch_add(secs, Ordering::SeqCst);
    }
    fn searches_reach(&self, n: usize) {
        for _ in 0..500 {
            if self.searches.load(Ordering::SeqCst) >= n {
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(self.searches.load(Ordering::SeqCst), n);
    }
    fn searches_settle_at(&self, n: usize) {
        for _ in 0..500 {
            let idle = {
                let st = self.cache.state();
                st.running.is_none() && st.abandoned == 0
            };
            if self.searches.load(Ordering::SeqCst) == n && idle {
                return;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        panic!("searches = {}, running = {:?}", self.searches.load(Ordering::SeqCst), self.cache.state().running);
    }
}

#[test]
fn the_first_check_waits_for_the_search_and_answers_it() {
    let r = rig();
    assert_eq!(r.cache.answer(LONG), Answer::Report { text: "report 1".into(), age: 0 });
    assert_eq!(r.searches.load(Ordering::SeqCst), 1);
}

#[test]
fn a_fresh_result_is_answered_with_its_age_and_no_new_search() {
    let r = rig();
    r.cache.answer(LONG);
    r.later(REFRESH);
    assert_eq!(r.cache.answer(LONG), Answer::Report { text: "report 1".into(), age: REFRESH });
    r.searches_settle_at(1);
}

#[test]
fn an_aging_result_is_answered_while_a_new_search_runs_behind_it() {
    let r = rig();
    r.cache.answer(LONG);
    r.later(REFRESH + 1);
    assert_eq!(r.cache.answer(Duration::ZERO), Answer::Report { text: "report 1".into(), age: REFRESH + 1 });
    r.searches_settle_at(2);
    assert_eq!(r.cache.answer(Duration::ZERO), Answer::Report { text: "report 2".into(), age: 0 });
}

#[test]
fn a_stale_result_is_never_answered() {
    let r = rig();
    r.cache.answer(LONG);
    r.later(FRESH + 1);
    assert_eq!(r.cache.answer(LONG), Answer::Report { text: "report 2".into(), age: 0 });
    r.hold.store(true, Ordering::SeqCst);
    r.later(FRESH + 1);
    assert_eq!(r.cache.answer(Duration::from_millis(30)), Answer::Checking { secs: 0 });
    r.hold.store(false, Ordering::SeqCst);
}

#[test]
fn a_slow_search_is_answered_as_in_progress_and_never_started_twice() {
    let r = rig();
    r.hold.store(true, Ordering::SeqCst);
    assert_eq!(r.cache.answer(Duration::from_millis(30)), Answer::Checking { secs: 0 });
    r.later(40);
    assert_eq!(r.cache.answer(Duration::from_millis(30)), Answer::Checking { secs: 40 });
    assert_eq!(r.cache.answer(Duration::ZERO), Answer::Checking { secs: 40 });
    r.hold.store(false, Ordering::SeqCst);
    r.searches_settle_at(1);
    assert_eq!(r.cache.answer(Duration::ZERO), Answer::Report { text: "report 1".into(), age: 0 });
}

#[test]
fn a_failed_search_is_answered_once_and_not_kept() {
    let r = rig();
    r.fail.store(true, Ordering::SeqCst);
    assert_eq!(r.cache.answer(LONG), Answer::Failed("OS updates: search 1 failed".into()));
    r.fail.store(false, Ordering::SeqCst);
    assert_eq!(r.cache.answer(LONG), Answer::Report { text: "report 2".into(), age: 0 });
    r.fail.store(true, Ordering::SeqCst);
    r.later(REFRESH + 1);
    r.cache.answer(Duration::ZERO);
    r.searches_settle_at(3);
    assert_eq!(r.cache.answer(Duration::ZERO), Answer::Report { text: "report 2".into(), age: REFRESH + 1 }, "a failed refresh keeps the last good result");
}

#[test]
fn an_invalidated_result_is_searched_again() {
    let r = rig();
    r.cache.answer(LONG);
    r.cache.invalidate();
    assert_eq!(r.cache.answer(LONG), Answer::Report { text: "report 2".into(), age: 0 });
}

#[test]
fn a_search_running_when_updates_are_installed_is_not_answered() {
    let r = rig();
    r.cache.answer(LONG);
    r.later(REFRESH + 1);
    r.hold.store(true, Ordering::SeqCst);
    assert_eq!(r.cache.answer(Duration::ZERO), Answer::Report { text: "report 1".into(), age: REFRESH + 1 });
    r.cache.invalidate();
    r.hold.store(false, Ordering::SeqCst);
    assert_eq!(r.cache.answer(LONG), Answer::Report { text: "report 3".into(), age: 0 }, "the refresh that began before the install reported the machine before it");
    r.searches_settle_at(3);
}

#[test]
fn a_hung_search_is_abandoned_and_its_late_result_dropped() {
    let r = rig();
    r.stuck.store(1, Ordering::SeqCst);
    assert_eq!(r.cache.answer(Duration::from_millis(30)), Answer::Checking { secs: 0 });
    r.searches_reach(1);
    r.later(HUNG);
    assert_eq!(r.cache.answer(Duration::from_millis(30)), Answer::Checking { secs: HUNG }, "not hung yet");
    r.later(1);
    assert_eq!(r.cache.answer(LONG), Answer::Report { text: "report 2".into(), age: 0 });
    r.later(60);
    r.stuck.store(0, Ordering::SeqCst);
    r.searches_settle_at(2);
    assert_eq!(r.cache.answer(Duration::ZERO), Answer::Report { text: "report 2".into(), age: 60 }, "the abandoned search's result came in late and was kept");
}

#[test]
fn only_one_hung_search_is_ever_abandoned() {
    let r = rig();
    r.hold.store(true, Ordering::SeqCst);
    r.cache.answer(Duration::ZERO);
    r.searches_reach(1);
    r.later(HUNG + 1);
    assert_eq!(r.cache.answer(Duration::from_millis(30)), Answer::Checking { secs: 0 });
    r.searches_reach(2);
    r.later(HUNG + 1);
    assert_eq!(r.cache.answer(Duration::from_millis(30)), Answer::Checking { secs: HUNG + 1 });
    assert_eq!(r.searches.load(Ordering::SeqCst), 2, "a second hung search started a third thread");
    r.hold.store(false, Ordering::SeqCst);
    r.searches_settle_at(2);
    assert_eq!(r.cache.answer(Duration::ZERO), Answer::Report { text: "report 2".into(), age: 0 });
}
