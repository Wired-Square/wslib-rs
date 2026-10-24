//! What a Windows service tells the service control manager as it starts, runs
//! and stops, apart from the calls that tell it, so the sequence is tested on
//! every platform.

use std::sync::{Arc, Mutex};

use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum State {
    Starting,
    Running,
    Stopping,
    Stopped { failed: bool },
}

/// `checkpoint` counts up while starting or stopping, and is 0 otherwise.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Status {
    pub(crate) state: State,
    pub(crate) checkpoint: u32,
}

pub(crate) struct Progress<R> {
    status: Mutex<Status>,
    report: R,
}

impl<R: Fn(Status)> Progress<R> {
    pub(crate) fn starting(report: R) -> Self {
        let status = Status {
            state: State::Starting,
            checkpoint: 1,
        };
        report(status);
        Self {
            status: Mutex::new(status),
            report,
        }
    }

    /// False once stopped, when there is nothing left to tick.
    pub(crate) fn tick(&self) -> bool {
        let now = self.change(|status| match status.state {
            State::Starting | State::Stopping => Some(Status {
                checkpoint: status.checkpoint + 1,
                ..status
            }),
            _ => None,
        });
        !matches!(now.state, State::Stopped { .. })
    }

    pub(crate) fn running(&self) {
        self.change(|status| {
            (status.state == State::Starting).then_some(Status::settled(State::Running))
        });
    }

    pub(crate) fn stopping(&self) {
        self.change(|status| {
            matches!(status.state, State::Starting | State::Running).then_some(Status {
                state: State::Stopping,
                checkpoint: 1,
            })
        });
    }

    /// A service asked to stop has not failed, whatever it returned, and one
    /// that ends unasked has.
    pub(crate) fn stopped(&self, asked: bool) {
        self.change(|_| Some(Status::settled(State::Stopped { failed: !asked })));
    }

    /// Reports under the lock, so two changes are never reported out of order.
    fn change(&self, next: impl FnOnce(Status) -> Option<Status>) -> Status {
        let mut status = self.status.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(next) = next(*status) {
            *status = next;
            (self.report)(next);
        }
        *status
    }
}

impl Status {
    fn settled(state: State) -> Self {
        Self {
            state,
            checkpoint: 0,
        }
    }
}

/// Reports running when first polled, as serving starts, and stopping once
/// `requested` fires.
pub(crate) async fn stop<R: Fn(Status)>(progress: Arc<Progress<R>>, requested: CancellationToken) {
    progress.running();
    requested.cancelled().await;
    progress.stopping();
}

#[cfg(test)]
mod tests {
    use super::*;

    type Reports = Arc<Mutex<Vec<Status>>>;

    fn recorded() -> (Progress<impl Fn(Status) + Send + Sync + 'static>, Reports) {
        let reports = Arc::new(Mutex::new(Vec::new()));
        let progress = {
            let reports = reports.clone();
            Progress::starting(move |status| reports.lock().unwrap().push(status))
        };
        (progress, reports)
    }

    fn at(state: State, checkpoint: u32) -> Status {
        Status { state, checkpoint }
    }

    #[test]
    fn a_service_asked_to_stop_counts_through_both_pending_states_and_succeeds() {
        let (progress, reports) = recorded();
        assert!(progress.tick());
        progress.running();
        assert!(progress.tick(), "running, with nothing to count");
        progress.stopping();
        progress.stopping();
        assert!(progress.tick());
        progress.stopped(true);
        assert!(!progress.tick());

        assert_eq!(
            *reports.lock().unwrap(),
            [
                at(State::Starting, 1),
                at(State::Starting, 2),
                at(State::Running, 0),
                at(State::Stopping, 1),
                at(State::Stopping, 2),
                at(State::Stopped { failed: false }, 0),
            ]
        );
    }

    #[test]
    fn a_service_that_ends_unasked_has_failed_and_one_asked_has_not() {
        for asked in [false, true] {
            let (progress, reports) = recorded();
            progress.running();
            progress.stopped(asked);
            assert_eq!(
                reports.lock().unwrap().last(),
                Some(&at(State::Stopped { failed: !asked }, 0)),
                "asked {asked}"
            );
        }
    }

    #[tokio::test]
    async fn the_stop_future_reports_running_once_awaited_and_stopping_once_requested() {
        let (progress, reports) = recorded();
        let progress = Arc::new(progress);
        let requested = CancellationToken::new();
        let stopping = stop(progress.clone(), requested.clone());
        assert_eq!(reports.lock().unwrap().len(), 1, "nothing until awaited");

        let stopped = tokio::spawn(stopping);
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while reports.lock().unwrap().len() < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("reports running");
        requested.cancel();
        stopped.await.unwrap();

        assert_eq!(
            reports.lock().unwrap()[1..],
            [at(State::Running, 0), at(State::Stopping, 1)]
        );
    }

    #[test]
    fn a_service_that_fails_while_starting_never_reports_running() {
        let (progress, reports) = recorded();
        progress.stopped(false);
        progress.running();
        assert_eq!(
            *reports.lock().unwrap(),
            [
                at(State::Starting, 1),
                at(State::Stopped { failed: true }, 0)
            ]
        );
    }
}
