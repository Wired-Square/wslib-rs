//! A service's long-lived tasks — one per device, say — kept in step
//! with the rows that say which should run.
//!
//! The table is told only that something changed and re-reads the whole
//! desired set, so no caller has to name what it changed.

use std::collections::HashMap;
use std::fmt::Display;
use std::future::Future;
use std::hash::Hash;
use std::time::Duration;

use tokio::sync::{Mutex, Notify};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// For a write [`TaskTable::run`] was not notified of, such as one from another
/// process.
const RESYNC: Duration = Duration::from_secs(60);

/// What one pass did. All zeros is the steady state.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Reconciled {
    pub started: usize,
    /// Tasks ended and not replaced.
    pub stopped: usize,
    /// Rows whose value changed, or whose task had ended: stopped, then started.
    pub restarted: usize,
}

struct Running<T> {
    config: T,
    cancel: CancellationToken,
    handle: JoinHandle<()>,
}

/// One task per row of a desired set, keyed by `K` and restarted when its `T`
/// changes.
///
/// A row's task has finished before its replacement starts, so two tasks never
/// hold one row's resource, and a pass waits for every task it stops: a task
/// must end promptly when its token is cancelled.
pub struct TaskTable<K, T> {
    name: &'static str,
    running: Mutex<HashMap<K, Running<T>>>,
    wake: Notify,
    root: CancellationToken,
}

impl<K, T> TaskTable<K, T> {
    /// A table whose log lines carry `name` as their `table` field, to tell it
    /// from a service's other tables. `Default` names it `unnamed`.
    pub fn named(name: &'static str) -> Self {
        Self {
            name,
            running: Mutex::default(),
            wake: Notify::new(),
            root: CancellationToken::new(),
        }
    }
}

impl<K, T> Default for TaskTable<K, T> {
    fn default() -> Self {
        Self::named("unnamed")
    }
}

impl<K: Clone + Eq + Hash, T: PartialEq> TaskTable<K, T> {
    /// Ask [`run`](Self::run) for a pass soon, without waiting for it.
    pub fn notify(&self) {
        self.wake.notify_one();
    }

    /// Start a task for each new row, stop each departed one, and stop then
    /// restart each changed one or one whose task has ended.
    ///
    /// `start` returns `None` for a row that cannot run now; it is tried again
    /// next pass. Once [`run`](Self::run) has stopped, this does nothing.
    pub async fn reconcile<F>(
        &self,
        desired: impl IntoIterator<Item = (K, T)>,
        mut start: impl FnMut(&K, &T, CancellationToken) -> Option<F>,
    ) -> Reconciled
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let mut want: HashMap<K, T> = desired.into_iter().collect();
        let mut counts = Reconciled::default();
        let mut running = self.running.lock().await;
        if self.root.is_cancelled() {
            return counts;
        }

        // Cancelled in place and awaited before removal, so a pass dropped
        // part-way leaves each task in the table for the next pass to wait for.
        let mut ending = Vec::new();
        for (id, task) in running.iter() {
            let live = !task.handle.is_finished() && !task.cancel.is_cancelled();
            if !(live && want.get(id) == Some(&task.config)) {
                task.cancel.cancel();
                ending.push(id.clone());
            }
        }
        for id in ending {
            let task = running.get_mut(&id).expect("listed above");
            let _ = (&mut task.handle).await;
            running.remove(&id);
            match want
                .remove(&id)
                .and_then(|config| self.spawn(&id, config, &mut start))
            {
                Some(replacement) => {
                    counts.restarted += 1;
                    running.insert(id, replacement);
                }
                None => counts.stopped += 1,
            }
        }
        for (id, config) in want {
            if running.contains_key(&id) {
                continue;
            }
            if let Some(task) = self.spawn(&id, config, &mut start) {
                counts.started += 1;
                running.insert(id, task);
            }
        }
        counts
    }

    /// Reconcile against `desired` now, on each [`notify`](Self::notify), and
    /// 60 s after the last pass when nothing notifies, until `stop` fires; then
    /// stop every task and wait for each.
    ///
    /// A failed read is logged and leaves the running tasks as they are.
    /// Dropped part-way, this stops every task without waiting.
    pub async fn run<D, Fut, I, E, S, F>(
        &self,
        stop: CancellationToken,
        mut desired: D,
        mut start: S,
    ) where
        D: FnMut() -> Fut,
        Fut: Future<Output = Result<I, E>>,
        I: IntoIterator<Item = (K, T)>,
        E: Display,
        S: FnMut(&K, &T, CancellationToken) -> Option<F>,
        F: Future<Output = ()> + Send + 'static,
    {
        let _stop_all = self.root.clone().drop_guard();
        loop {
            match stop.run_until_cancelled(desired()).await {
                None => break,
                Some(Ok(rows)) => {
                    let counts = self.reconcile(rows, &mut start).await;
                    if counts != Reconciled::default() {
                        tracing::info!(
                            table = self.name,
                            started = counts.started,
                            stopped = counts.stopped,
                            restarted = counts.restarted,
                            "reconciled the task table"
                        );
                    }
                }
                Some(Err(e)) => tracing::warn!(
                    table = self.name,
                    error = %e,
                    "could not read which tasks should run"
                ),
            }
            let woken = tokio::time::timeout(RESYNC, self.wake.notified());
            if stop.run_until_cancelled(woken).await.is_none() {
                break;
            }
        }

        self.root.cancel();
        let running = std::mem::take(&mut *self.running.lock().await);
        for task in running.into_values() {
            let _ = task.handle.await;
        }
    }

    fn spawn<F>(
        &self,
        id: &K,
        config: T,
        start: &mut impl FnMut(&K, &T, CancellationToken) -> Option<F>,
    ) -> Option<Running<T>>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let cancel = self.root.child_token();
        let task = start(id, &config, cancel.clone())?;
        Some(Running {
            handle: tokio::spawn(task),
            config,
            cancel,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use super::*;

    fn table() -> TaskTable<&'static str, u32> {
        TaskTable::default()
    }

    fn idle(
        _: &&'static str,
        _: &u32,
        stop: CancellationToken,
    ) -> Option<impl Future<Output = ()> + Send + use<>> {
        Some(async move { stop.cancelled().await })
    }

    #[tokio::test]
    async fn the_same_desired_set_twice_is_a_pass_that_does_nothing() {
        let table = table();
        let counts = table.reconcile([("a", 1), ("b", 2)], idle).await;
        assert_eq!(counts.started, 2);
        assert_eq!(
            table.reconcile([("a", 1), ("b", 2)], idle).await,
            Reconciled::default(),
            "or the resync would restart every task once a minute"
        );
    }

    #[tokio::test]
    async fn a_changed_row_restarts_and_a_departed_one_stops() {
        let table = table();
        table.reconcile([("a", 1), ("b", 2)], idle).await;
        let was = table.running.lock().await["a"].cancel.clone();

        assert_eq!(
            table.reconcile([("a", 99)], idle).await,
            Reconciled {
                started: 0,
                stopped: 1,
                restarted: 1
            }
        );
        assert!(was.is_cancelled(), "the superseded task was left running");
        let running = table.running.lock().await;
        assert_eq!(running["a"].config, 99);
        assert!(!running.contains_key("b"));
    }

    #[tokio::test]
    async fn a_task_that_ended_by_itself_is_started_again() {
        let table = table();
        let ends_at_once = |_: &&str, _: &u32, _| Some(async {});
        table.reconcile([("a", 1)], ends_at_once).await;
        while !table.running.lock().await["a"].handle.is_finished() {
            tokio::task::yield_now().await;
        }

        assert_eq!(
            table.reconcile([("a", 1)], idle).await.restarted,
            1,
            "an unchanged row is not evidence of a running task"
        );
    }

    #[tokio::test]
    async fn a_row_that_cannot_start_is_tried_again_next_pass() {
        let table = table();
        let refuse = |_: &&str, _: &u32, _| None::<std::future::Ready<()>>;
        assert_eq!(
            table.reconcile([("a", 1)], refuse).await,
            Reconciled::default()
        );
        assert_eq!(table.reconcile([("a", 1)], idle).await.started, 1);
    }

    /// Each task marks the row held and, once cancelled, lingers before
    /// releasing it: a replacement started before the release would find it
    /// held.
    #[tokio::test]
    async fn a_restarted_row_is_released_before_its_replacement_starts() {
        let table = table();
        let held = Arc::new(AtomicBool::new(false));
        let overlaps = Arc::new(AtomicUsize::new(0));
        let start = |_: &&str, _: &u32, stop: CancellationToken| {
            let (held, overlaps) = (held.clone(), overlaps.clone());
            Some(async move {
                if held.swap(true, Ordering::SeqCst) {
                    overlaps.fetch_add(1, Ordering::SeqCst);
                }
                stop.cancelled().await;
                tokio::time::sleep(Duration::from_millis(20)).await;
                held.store(false, Ordering::SeqCst);
            })
        };
        for config in 1..=3 {
            table.reconcile([("a", config)], start).await;
            tokio::task::yield_now().await;
        }
        assert_eq!(overlaps.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_pass_dropped_while_stopping_leaves_the_task_to_the_next() {
        let table = table();
        let slow = |_: &&str, _: &u32, stop: CancellationToken| {
            Some(async move {
                stop.cancelled().await;
                tokio::time::sleep(Duration::from_millis(50)).await;
            })
        };
        table.reconcile([("a", 1)], slow).await;
        let dropped =
            tokio::time::timeout(Duration::from_millis(5), table.reconcile([("a", 2)], idle)).await;
        assert!(dropped.is_err(), "the pass was still waiting for the stop");

        let old = table.running.lock().await["a"].cancel.clone();
        assert!(old.is_cancelled(), "the old task is still in the table");
        let counts = table.reconcile([("a", 2)], idle).await;
        assert_eq!(counts.restarted, 1, "{counts:?}");
        assert_ne!(
            table.running.lock().await["a"].config,
            1,
            "the replacement runs"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn run_follows_a_notify_and_the_resync_and_drains_on_stop() {
        let stop = CancellationToken::new();
        let table = Arc::new(TaskTable::<&str, u32>::default());
        let rows = Arc::new(std::sync::Mutex::new(vec![("a", 1)]));
        let live = Arc::new(AtomicUsize::new(0));
        let running = tokio::spawn({
            let (table, rows, live, stop) =
                (table.clone(), rows.clone(), live.clone(), stop.clone());
            async move {
                table
                    .run(
                        stop,
                        || {
                            let rows = rows.lock().unwrap().clone();
                            async move { Ok::<_, std::convert::Infallible>(rows) }
                        },
                        |_, _, stop: CancellationToken| {
                            let live = live.clone();
                            live.fetch_add(1, Ordering::SeqCst);
                            Some(async move {
                                stop.cancelled().await;
                                tokio::time::sleep(Duration::from_millis(5)).await;
                                live.fetch_sub(1, Ordering::SeqCst);
                            })
                        },
                    )
                    .await
            }
        });
        let settle = || tokio::time::sleep(Duration::from_millis(1));
        settle().await;
        assert_eq!(live.load(Ordering::SeqCst), 1);

        rows.lock().unwrap().push(("b", 1));
        table.notify();
        settle().await;
        assert_eq!(live.load(Ordering::SeqCst), 2, "a notify is a pass");

        rows.lock().unwrap().push(("c", 1));
        settle().await;
        assert_eq!(live.load(Ordering::SeqCst), 2);
        tokio::time::sleep(RESYNC).await;
        assert_eq!(live.load(Ordering::SeqCst), 3, "the resync is a pass");

        stop.cancel();
        running.await.expect("run returns");
        assert_eq!(
            live.load(Ordering::SeqCst),
            0,
            "every task ended before run returned"
        );
        assert_eq!(
            table.reconcile([("d", 1)], idle).await,
            Reconciled::default(),
            "and nothing starts after it"
        );
    }

    #[tokio::test]
    async fn a_run_that_is_dropped_still_stops_its_tasks() {
        let table = Arc::new(TaskTable::<&str, u32>::default());
        let token = Arc::new(std::sync::Mutex::new(None));
        let running = tokio::spawn({
            let (table, token) = (table.clone(), token.clone());
            async move {
                table
                    .run(
                        CancellationToken::new(),
                        || async { Ok::<_, std::convert::Infallible>([("a", 1)]) },
                        |_, _, stop: CancellationToken| {
                            *token.lock().unwrap() = Some(stop.clone());
                            Some(async move { stop.cancelled().await })
                        },
                    )
                    .await
            }
        });
        while token.lock().unwrap().is_none() {
            tokio::task::yield_now().await;
        }
        running.abort();
        let _ = running.await;
        assert!(token.lock().unwrap().as_ref().unwrap().is_cancelled());
    }

    #[tokio::test]
    async fn a_pass_that_changed_something_names_its_table() {
        for (table, name) in [
            (TaskTable::named("widget links"), "widget links"),
            (TaskTable::default(), "unnamed"),
        ] {
            let logs = wslib_telemetry::Logs::new(&["wslib_tasks"]);
            let _logging = tracing::subscriber::set_default(logs.subscriber());
            let stop = CancellationToken::new();
            table
                .run(
                    stop.clone(),
                    || async { Ok::<_, std::convert::Infallible>([("a", 1)]) },
                    |_, _, task: CancellationToken| {
                        stop.cancel();
                        Some(async move { task.cancelled().await })
                    },
                )
                .await;

            let records = logs.snapshot().records;
            let reconciled = records
                .iter()
                .find(|r| r.message == "reconciled the task table")
                .unwrap_or_else(|| panic!("no pass logged: {records:?}"));
            assert!(
                reconciled
                    .fields
                    .contains(&("table".to_string(), name.to_string())),
                "{:?}",
                reconciled.fields
            );
        }
    }
}
