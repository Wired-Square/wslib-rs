//! The slow tick that bounds what would otherwise grow until the card fills:
//! the audit log, which every appliance has, and whatever the product keeps.
//!
//! When this box last swept, and the anchor its sweep time is bounded by, are
//! this box's own state, so they never travel in a backup and go with a
//! factory reset.

use std::future::Future;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use wslib_appliance_store::{Store, parse_stamp, stamp};
use wslib_appliance_types::host::{ClockView, Ntp};

const LAST_SWEEP: &str = "retention.last_sweep";
const ANCHOR: &str = "retention.anchor";

/// How far the clock may run ahead of the sweep time before it is logged.
const AHEAD: chrono::TimeDelta = chrono::TimeDelta::minutes(1);

/// How long after boot a round waits for NTP to synchronise the clock.
const SYNC_GRACE: Duration = Duration::from_secs(60 * 60);
const RECHECK: Duration = Duration::from_secs(60);
const CLOCK_WAIT: Duration = Duration::from_secs(10);

/// The clock's state, asked before each sweep, as systemd-timedated reports
/// it; `()` answers that it cannot be read.
pub trait Clock: Send + Sync + 'static {
    /// A read that does not answer within ten seconds counts as unreadable,
    /// and the round goes ahead.
    fn clock(&self) -> impl Future<Output = ClockView> + Send;
}

impl Clock for () {
    async fn clock(&self) -> ClockView {
        ClockView::Unsupported {
            because: "this product does not read the clock".to_string(),
        }
    }
}

/// Every `every`, which must not be zero, delete audit rows older than
/// `keep_audit` and then await `sweeps` with the store and the sweep time,
/// until `stop` fires between rounds.
///
/// The sweep time is the clock when `clock` says NTP has synchronised it, which
/// `()` never does; otherwise the clock, but no later than the highest sweep
/// time since the last synchronised round plus the uptime since it, or this
/// boot's whole uptime if it was in an earlier boot, so a clock set years ahead
/// deletes nothing early. `sweeps` must date what it deletes by it, never by
/// `Utc::now()`. A round that cannot read the stored bound on its sweep time
/// is skipped.
///
/// The first round is a period after the last one this box recorded, or a
/// period from now if it has none, so a restart does not sweep early. A
/// `keep_audit` too long to subtract from the clock keeps the whole audit log.
///
/// A round is held while `clock` says NTP is on and has not synchronised,
/// rechecking every minute, until it synchronises or the box has been up an
/// hour; then it runs late, and the next is a period after it.
pub fn spawn_sweeper<C, S, Fut>(
    store: Store,
    clock: C,
    every: Duration,
    keep_audit: Duration,
    stop: CancellationToken,
    sweeps: S,
) -> JoinHandle<()>
where
    C: Clock,
    S: FnMut(Store, DateTime<Utc>) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send,
{
    let trust = Trust {
        clock,
        up: wslib_host::uptime,
        boot: wslib_host::boot_id,
        recheck: RECHECK,
        said_unsynced: false,
    };
    sweeper(store, trust, every, keep_audit, stop, sweeps)
}

fn sweeper<C, S, Fut>(
    store: Store,
    mut trust: Trust<C>,
    every: Duration,
    keep_audit: Duration,
    stop: CancellationToken,
    mut sweeps: S,
) -> JoinHandle<()>
where
    C: Clock,
    S: FnMut(Store, DateTime<Utc>) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send,
{
    tokio::spawn(async move {
        let window = chrono::Duration::from_std(keep_audit).ok();
        if audit_cutoff(window, Utc::now()).is_none() {
            tracing::warn!(
                ?keep_audit,
                "the audit retention window is too long; keeping the whole audit log"
            );
        }

        let due = until_due(last_sweep(&store).await, every, Utc::now());
        let mut ticks = tokio::time::interval_at(Instant::now() + due, every);
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        let mut said_ahead = false;
        while stop.run_until_cancelled(ticks.tick()).await.is_some() {
            let Some(waited) = trust.wait(&stop).await else {
                break;
            };
            if waited.held {
                ticks.reset();
            }
            let anchor = match store.box_state_doc(ANCHOR).await {
                Ok(anchor) => anchor,
                Err(e) => {
                    tracing::warn!(error = %e, "could not read the sweep anchor; skipping this sweep");
                    continue;
                }
            };
            let wall = wslib_appliance_store::now();
            let (at, anchor) = sweep_time(wall, waited.synced, anchor, trust.uptime());
            if let Some(anchor) = anchor
                && let Err(e) = store.set_box_state_doc(ANCHOR, &anchor).await
            {
                tracing::warn!(error = %e, "could not record the sweep anchor");
            }
            if wall - at > AHEAD && !std::mem::replace(&mut said_ahead, true) {
                tracing::info!(
                    ahead_secs = (wall - at).num_seconds(),
                    "the clock is ahead of the time this box's uptime vouches for; \
                     sweeping by that time instead"
                );
            }
            if let Some(before) = audit_cutoff(window, at) {
                match store.sweep_audit(before).await {
                    Ok(swept) => tracing::debug!(swept, "swept the audit log"),
                    Err(e) => tracing::warn!(error = %e, "could not sweep the audit log"),
                }
            }
            sweeps(store.clone(), at).await;
            if let Err(e) = store.set_box_state(LAST_SWEEP, &stamp(wall)).await {
                tracing::warn!(error = %e, "could not record the sweep");
            }
        }
    })
}

struct Trust<C> {
    clock: C,
    up: fn() -> Option<Duration>,
    boot: fn() -> Option<String>,
    recheck: Duration,
    said_unsynced: bool,
}

struct Waited {
    held: bool,
    synced: bool,
}

impl<C: Clock> Trust<C> {
    fn uptime(&self) -> Option<Uptime> {
        Some(Uptime {
            boot: (self.boot)()?,
            up: (self.up)()?,
        })
    }

    /// Until the clock may date a round; `None` when `stop` fired first.
    async fn wait(&mut self, stop: &CancellationToken) -> Option<Waited> {
        let mut held = false;
        loop {
            let read = tokio::time::timeout(CLOCK_WAIT, self.clock.clock());
            let view = stop.run_until_cancelled(read).await?.ok();
            let synced = matches!(view, Some(ClockView::Ready { synced: true, .. }));
            match view.map_or(Verdict::Sweep, |view| verdict(&view, (self.up)())) {
                Verdict::Sweep => return Some(Waited { held, synced }),
                Verdict::SweepUnsynced => {
                    if !std::mem::replace(&mut self.said_unsynced, true) {
                        tracing::warn!(
                            "the clock has not synchronised and the wait for it is over; \
                             sweeping without it"
                        );
                    }
                    return Some(Waited { held, synced });
                }
                Verdict::Hold => {
                    if !std::mem::replace(&mut held, true) {
                        tracing::info!("holding a sweep until the clock synchronises");
                    }
                    stop.run_until_cancelled(tokio::time::sleep(self.recheck))
                        .await?;
                }
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    Sweep,
    Hold,
    SweepUnsynced,
}

/// An unknown uptime is past the grace.
fn verdict(clock: &ClockView, up: Option<Duration>) -> Verdict {
    let expecting_sync = matches!(
        clock,
        ClockView::Ready {
            ntp: Ntp::On,
            synced: false,
            ..
        }
    );
    match (expecting_sync, up.is_some_and(|up| up < SYNC_GRACE)) {
        (false, _) => Verdict::Sweep,
        (true, true) => Verdict::Hold,
        (true, false) => Verdict::SweepUnsynced,
    }
}

fn audit_cutoff(window: Option<chrono::Duration>, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
    now.checked_sub_signed(window?)
}

/// Where a moment falls on `CLOCK_BOOTTIME`, and in which boot.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct Uptime {
    boot: String,
    up: Duration,
}

/// At least how long passed between two moments; a later boot came after the
/// earlier moment, so its whole uptime counts. Zero when either is unknown.
fn elapsed(earlier: Option<&Uptime>, later: Option<&Uptime>) -> Duration {
    match (earlier, later) {
        (Some(earlier), Some(later)) if earlier.boot == later.boot => {
            later.up.saturating_sub(earlier.up)
        }
        (Some(_), Some(later)) => later.up,
        _ => Duration::ZERO,
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct Anchor {
    at: DateTime<Utc>,
    uptime: Option<Uptime>,
}

/// The time a round sweeps by, and the anchor to record; `None` when a clock
/// NTP has not synchronised is behind the anchor, which is then kept.
fn sweep_time(
    wall: DateTime<Utc>,
    synced: bool,
    anchor: Option<Anchor>,
    here: Option<Uptime>,
) -> (DateTime<Utc>, Option<Anchor>) {
    let at = match anchor {
        Some(anchor) if !synced => {
            let at = chrono::Duration::from_std(elapsed(anchor.uptime.as_ref(), here.as_ref()))
                .ok()
                .and_then(|elapsed| anchor.at.checked_add_signed(elapsed))
                .map_or(wall, |bound| bound.min(wall));
            if at < anchor.at {
                return (at, None);
            }
            at
        }
        _ => wall,
    };
    (at, Some(Anchor { at, uptime: here }))
}

/// A record this build cannot read, or cannot reach, reads as none.
async fn last_sweep(store: &Store) -> Option<DateTime<Utc>> {
    let read = store.box_state(LAST_SWEEP).await.and_then(|raw| {
        raw.map(|raw| parse_stamp("settings", LAST_SWEEP, &raw))
            .transpose()
    });
    read.unwrap_or_else(|e| {
        tracing::warn!(error = %e, "could not read when this box last swept");
        None
    })
}

/// A clock that has gone backwards since the last sweep reads as a full period.
fn until_due(last: Option<DateTime<Utc>>, every: Duration, now: DateTime<Utc>) -> Duration {
    last.map_or(every, |last| {
        every.saturating_sub((now - last).to_std().unwrap_or_default())
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use wslib_appliance_types::AuditRecord;

    use super::*;

    fn ready(ntp: Ntp, synced: bool) -> ClockView {
        ClockView::Ready {
            via: "systemd-timedated".to_string(),
            timezone: None,
            ntp,
            synced,
            server: None,
        }
    }

    #[test]
    fn a_round_waits_only_for_a_clock_ntp_has_yet_to_synchronise_and_only_for_an_hour() {
        let early = Some(Duration::from_secs(60));
        let late = Some(SYNC_GRACE);
        for ntp in [Ntp::On, Ntp::Off, Ntp::Absent] {
            assert_eq!(verdict(&ready(ntp, true), early), Verdict::Sweep, "{ntp:?}");
        }
        for ntp in [Ntp::Off, Ntp::Absent] {
            assert_eq!(
                verdict(&ready(ntp, false), early),
                Verdict::Sweep,
                "{ntp:?}: nothing is coming to set it"
            );
        }
        let unreadable = ClockView::Unsupported {
            because: String::new(),
        };
        assert_eq!(verdict(&unreadable, early), Verdict::Sweep);

        assert_eq!(verdict(&ready(Ntp::On, false), early), Verdict::Hold);
        assert_eq!(
            verdict(&ready(Ntp::On, false), late),
            Verdict::SweepUnsynced,
            "a box with no time server to reach still sweeps"
        );
        assert_eq!(
            verdict(&ready(Ntp::On, false), None),
            Verdict::SweepUnsynced
        );
    }

    #[derive(Clone, Default)]
    struct Syncing(Arc<AtomicBool>);

    impl Clock for Syncing {
        async fn clock(&self) -> ClockView {
            ready(Ntp::On, self.0.load(Ordering::SeqCst))
        }
    }

    /// A sweeper due every 50 ms, on a box just booted whose clock NTP has not set.
    fn held(clock: Syncing, store: Store) -> (Arc<AtomicUsize>, CancellationToken, JoinHandle<()>) {
        let (rounds, sweeps) = counting();
        let stop = CancellationToken::new();
        let trust = Trust {
            clock,
            up: || Some(Duration::ZERO),
            boot: || None,
            recheck: Duration::from_millis(20),
            said_unsynced: false,
        };
        let task = sweeper(
            store,
            trust,
            Duration::from_millis(50),
            Duration::from_secs(3600),
            stop.clone(),
            sweeps,
        );
        (rounds, stop, task)
    }

    #[tokio::test]
    async fn a_held_round_runs_once_the_clock_synchronises_and_anchors_to_it() {
        let store = store().await;
        store
            .set_box_state_doc(ANCHOR, &anchor("an earlier boot", 1000))
            .await
            .unwrap();
        let clock = Syncing::default();
        let (rounds, stop, task) = held(clock.clone(), store.clone());

        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(rounds.load(Ordering::SeqCst), 0, "swept on an unset clock");
        clock.0.store(true, Ordering::SeqCst);
        let ran = tokio::time::timeout(Duration::from_secs(5), async {
            while rounds.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        assert!(ran.is_ok(), "and runs, late, once it has");
        stop.cancel();
        task.await.unwrap();
        assert!(stored(&store).await.is_some_and(|v| v.at > anchor_time()));
    }

    #[tokio::test]
    async fn a_held_round_ends_on_stop() {
        let (rounds, stop, task) = held(Syncing::default(), store().await);
        tokio::time::sleep(Duration::from_millis(50)).await;
        stop.cancel();
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("the sweeper ends on stop")
            .expect("no panic");
        assert_eq!(rounds.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_sweep_is_due_a_period_after_the_last_one_and_now_if_that_has_passed() {
        let every = Duration::from_secs(3600);
        let now = DateTime::from_timestamp(1_757_000_000, 0).unwrap();

        assert_eq!(
            until_due(None, every, now),
            every,
            "never swept waits a period"
        );
        assert_eq!(
            until_due(Some(now - chrono::Duration::seconds(600)), every, now),
            Duration::from_secs(3000)
        );
        assert_eq!(
            until_due(Some(now - chrono::Duration::days(7)), every, now),
            Duration::ZERO,
            "a box that was off for a week sweeps as soon as it is up"
        );
        assert_eq!(
            until_due(Some(now + chrono::Duration::hours(2)), every, now),
            every,
            "a clock that went backwards is a full period, not a panic"
        );
    }

    #[test]
    fn a_window_past_the_earliest_instant_sweeps_nothing() {
        let now = Utc::now();
        assert_eq!(audit_cutoff(None, now), None);
        assert_eq!(audit_cutoff(Some(chrono::Duration::MAX), now), None);
        assert_eq!(
            audit_cutoff(Some(chrono::Duration::days(1)), now),
            Some(now - chrono::Duration::days(1))
        );
    }

    const HOUR: chrono::TimeDelta = chrono::TimeDelta::hours(1);
    const YEAR: chrono::TimeDelta = chrono::TimeDelta::days(365);

    fn anchor_time() -> DateTime<Utc> {
        DateTime::from_timestamp(1_757_000_000, 0).unwrap()
    }

    fn uptime(boot: &str, secs: u64) -> Option<Uptime> {
        Some(Uptime {
            boot: boot.to_string(),
            up: Duration::from_secs(secs),
        })
    }

    fn anchor(boot: &str, secs: u64) -> Anchor {
        Anchor {
            at: anchor_time(),
            uptime: uptime(boot, secs),
        }
    }

    #[test]
    fn a_clock_jumped_years_ahead_within_a_boot_sweeps_by_the_uptime_since_the_anchor() {
        let here = uptime("this", 1000 + 3600);
        let (at, anchored) = sweep_time(
            anchor_time() + YEAR * 10,
            false,
            Some(anchor("this", 1000)),
            here.clone(),
        );
        assert_eq!(at, anchor_time() + HOUR);
        assert_eq!(anchored, Some(Anchor { at, uptime: here }));
    }

    #[test]
    fn a_synchronised_clock_is_trusted_and_re_anchors() {
        for wall in [anchor_time() + YEAR * 10, anchor_time() - YEAR] {
            let here = uptime("this", 1060);
            assert_eq!(
                sweep_time(wall, true, Some(anchor("this", 1000)), here.clone()),
                (
                    wall,
                    Some(Anchor {
                        at: wall,
                        uptime: here
                    })
                ),
                "{wall}"
            );
        }
    }

    #[test]
    fn a_clock_set_back_sweeps_by_itself_and_leaves_the_anchor_for_when_it_is_corrected() {
        let back = anchor_time() - YEAR;
        assert_eq!(
            sweep_time(
                back,
                false,
                Some(anchor("this", 1000)),
                uptime("this", 1060)
            ),
            (back, None)
        );
        let (at, _) = sweep_time(
            anchor_time() + HOUR * 2,
            false,
            Some(anchor("this", 1000)),
            uptime("this", 1000 + 3600),
        );
        assert_eq!(at, anchor_time() + HOUR);
    }

    #[test]
    fn across_a_reboot_this_boots_uptime_is_counted_and_the_anchor_reforms_once_the_clock_reaches_it()
     {
        let before = anchor("before", 5000);
        assert_eq!(
            sweep_time(
                DateTime::UNIX_EPOCH,
                false,
                Some(before.clone()),
                uptime("after", 30)
            ),
            (DateTime::UNIX_EPOCH, None),
            "a clock that starts at the epoch"
        );
        let here = uptime("after", 90);
        let (at, reformed) = sweep_time(anchor_time() + YEAR, false, Some(before), here.clone());
        let booted = anchor_time() + chrono::TimeDelta::seconds(90);
        assert_eq!(at, booted);
        assert_eq!(reformed, Some(Anchor { at, uptime: here }));

        let (at, _) = sweep_time(
            anchor_time() + YEAR,
            false,
            reformed,
            uptime("after", 90 + 3600),
        );
        assert_eq!(at, booted + HOUR);
    }

    #[test]
    fn an_anchor_with_no_uptime_counts_none_of_this_boots() {
        let unknown = Anchor {
            at: anchor_time(),
            uptime: None,
        };
        let (at, _) = sweep_time(
            anchor_time() + YEAR,
            false,
            Some(unknown),
            uptime("this", 3600),
        );
        assert_eq!(at, anchor_time(), "it may be this boot, already counted");
    }

    #[test]
    fn a_clock_behind_the_uptime_since_the_anchor_is_taken_as_it_stands() {
        let wall = anchor_time() + HOUR / 2;
        let here = uptime("this", 1000 + 3600);
        assert_eq!(
            sweep_time(wall, false, Some(anchor("this", 1000)), here.clone()),
            (
                wall,
                Some(Anchor {
                    at: wall,
                    uptime: here
                })
            )
        );
    }

    #[test]
    fn an_unreadable_boot_or_uptime_on_either_side_counts_nothing() {
        let this = uptime("this", 1000);
        assert_eq!(
            elapsed(this.as_ref(), uptime("this", 4600).as_ref()),
            Duration::from_secs(3600)
        );
        assert_eq!(
            elapsed(this.as_ref(), uptime("next", 60).as_ref()),
            Duration::from_secs(60)
        );
        assert_eq!(elapsed(this.as_ref(), None), Duration::ZERO);
        assert_eq!(elapsed(None, this.as_ref()), Duration::ZERO);
        assert_eq!(elapsed(None, None), Duration::ZERO);
    }

    #[test]
    fn with_no_anchor_the_clock_is_taken_and_anchors() {
        let wall = anchor_time() + YEAR * 10;
        let here = uptime("this", 60);
        assert_eq!(
            sweep_time(wall, false, None, here.clone()),
            (
                wall,
                Some(Anchor {
                    at: wall,
                    uptime: here
                })
            )
        );
    }

    #[tokio::test]
    async fn an_anchor_read_back_within_its_boot_keeps_counting_uptime() {
        let store = store().await;
        store
            .set_box_state_doc(ANCHOR, &anchor("this", 1000))
            .await
            .unwrap();
        let (at, _) = sweep_time(
            anchor_time() + YEAR,
            false,
            stored(&store).await,
            uptime("this", 1000 + 3600),
        );
        assert_eq!(at, anchor_time() + HOUR);
    }

    #[tokio::test]
    async fn a_round_on_a_clock_far_ahead_of_its_anchor_sweeps_and_hands_on_the_bounded_time() {
        let store = store().await;
        let now = wslib_appliance_store::now();
        let anchored = now - chrono::TimeDelta::days(30);
        audited(
            &store,
            anchored - chrono::TimeDelta::days(2),
            "old by the anchor",
        )
        .await;
        audited(&store, now - chrono::TimeDelta::days(2), "old by the clock").await;
        store
            .set_box_state_doc(
                ANCHOR,
                &Anchor {
                    at: anchored,
                    uptime: uptime("an earlier boot", 1),
                },
            )
            .await
            .unwrap();
        store
            .set_box_state(LAST_SWEEP, &stamp(now - chrono::TimeDelta::days(1)))
            .await
            .unwrap();
        let given = Arc::new(std::sync::Mutex::new(None));
        let handed = given.clone();
        let stop = CancellationToken::new();
        let trust = Trust {
            clock: (),
            up: || Some(Duration::from_secs(3600)),
            boot: || Some("this boot".to_string()),
            recheck: RECHECK,
            said_unsynced: false,
        };
        let task = sweeper(
            store.clone(),
            trust,
            Duration::from_secs(3600),
            Duration::from_secs(24 * 3600),
            stop.clone(),
            move |_, at| {
                *handed.lock().unwrap() = Some(at);
                std::future::ready(())
            },
        );

        let ran = tokio::time::timeout(Duration::from_secs(5), async {
            while given.lock().unwrap().is_none() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        assert!(ran.is_ok(), "an overdue sweep runs at start");
        stop.cancel();
        task.await.unwrap();

        let bound = anchored + HOUR;
        assert_eq!(*given.lock().unwrap(), Some(bound));
        let left: Vec<_> = store.audit(10, None).await.unwrap().items;
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].message, "old by the clock");
        assert_eq!(
            stored(&store).await,
            Some(Anchor {
                at: bound,
                uptime: uptime("this boot", 3600),
            })
        );
    }

    #[tokio::test]
    async fn a_round_that_cannot_read_its_anchor_sweeps_nothing() {
        let store = store().await;
        store.close().await;
        let (rounds, sweeps) = counting();
        let stop = CancellationToken::new();
        let task = spawn_sweeper(
            store,
            (),
            Duration::from_millis(20),
            Duration::from_secs(3600),
            stop.clone(),
            sweeps,
        );
        tokio::time::sleep(Duration::from_millis(150)).await;
        stop.cancel();
        task.await.unwrap();
        assert_eq!(rounds.load(Ordering::SeqCst), 0);
    }

    async fn stored(store: &Store) -> Option<Anchor> {
        store.box_state_doc(ANCHOR).await.expect("read")
    }

    async fn store() -> Store {
        Store::open_in_memory(None).await.expect("in-memory store")
    }

    async fn audited(store: &Store, at: DateTime<Utc>, message: &str) {
        let record = AuditRecord {
            at,
            level: "INFO".to_string(),
            actor: "admin".to_string(),
            actor_id: None,
            target: module_path!().to_string(),
            message: message.to_string(),
            fields: Vec::new(),
        };
        store.record_audit(&record).await.expect("audit");
    }

    fn counting() -> (
        Arc<AtomicUsize>,
        impl FnMut(Store, DateTime<Utc>) -> std::future::Ready<()> + Send,
    ) {
        let rounds = Arc::new(AtomicUsize::new(0));
        let counter = rounds.clone();
        (rounds, move |_, _| {
            counter.fetch_add(1, Ordering::SeqCst);
            std::future::ready(())
        })
    }

    #[tokio::test]
    async fn a_round_sweeps_the_audit_log_runs_the_products_sweeps_and_records_itself() {
        let store = store().await;
        let now = wslib_appliance_store::now();
        audited(&store, now - chrono::Duration::days(2), "old").await;
        audited(&store, now, "new").await;
        store
            .set_box_state(LAST_SWEEP, &stamp(now - chrono::Duration::days(1)))
            .await
            .unwrap();
        let (rounds, sweeps) = counting();
        let stop = CancellationToken::new();
        let task = spawn_sweeper(
            store.clone(),
            (),
            Duration::from_secs(3600),
            Duration::from_secs(24 * 3600),
            stop.clone(),
            sweeps,
        );

        let ran = tokio::time::timeout(Duration::from_secs(5), async {
            while rounds.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        assert!(ran.is_ok(), "a sweep overdue since yesterday runs at start");
        stop.cancel();
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("the sweeper ends on stop")
            .expect("no panic");

        let left: Vec<_> = store.audit(10, None).await.unwrap().items;
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].message, "new");
        assert!(last_sweep(&store).await.is_some_and(|at| at >= now));
    }

    #[tokio::test]
    async fn a_restart_does_not_sweep_before_a_period_has_passed() {
        let store = store().await;
        store
            .set_box_state(LAST_SWEEP, &stamp(wslib_appliance_store::now()))
            .await
            .unwrap();
        let (rounds, sweeps) = counting();
        let stop = CancellationToken::new();
        let task = spawn_sweeper(
            store,
            (),
            Duration::from_millis(400),
            Duration::from_secs(3600),
            stop.clone(),
            sweeps,
        );

        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(rounds.load(Ordering::SeqCst), 0, "swept early");
        let ran = tokio::time::timeout(Duration::from_secs(5), async {
            while rounds.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        assert!(ran.is_ok(), "and does sweep once it has");
        stop.cancel();
        task.await.unwrap();
    }

    #[tokio::test]
    async fn the_last_sweep_and_its_anchor_are_this_boxs_own_and_never_a_bundles() {
        let store = store().await;
        let at = wslib_appliance_store::now();
        store.set_box_state(LAST_SWEEP, &stamp(at)).await.unwrap();
        store
            .set_box_state_doc(ANCHOR, &anchor("this", 1000))
            .await
            .unwrap();

        assert_eq!(last_sweep(&store).await, Some(at));
        assert_eq!(stored(&store).await, Some(anchor("this", 1000)));
        assert!(
            store
                .exportable_settings()
                .await
                .expect("export")
                .keys()
                .all(|key| !key.contains(LAST_SWEEP) && !key.contains(ANCHOR)),
            "a replacement card must not inherit a sweep it never made"
        );
    }

    #[tokio::test]
    async fn an_anchor_this_build_cannot_read_is_none() {
        let store = store().await;
        store.set_box_state(ANCHOR, "not an anchor").await.unwrap();
        assert_eq!(stored(&store).await, None);
    }
}
