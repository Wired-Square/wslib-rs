use std::{
    collections::VecDeque,
    sync::{Arc, Weak},
};

use tokio::{
    sync::broadcast::{self, error::RecvError},
    time::{Duration, Instant, sleep_until},
};

use super::{Bounds, Update, bounds::BoundChecker, lock, port::Port};
use crate::EndReason;

/// One subscriber's view of a port: the monitor's state when it subscribed,
/// the replay its bounds ask for, then live updates until a bound ends it.
/// Dropping it takes it out of the roster.
pub struct Subscription {
    id: u64,
    baud: u32,
    /// Weak, so a released port's last strong reference goes and its
    /// subscribers read the end.
    port: Weak<Port>,
    events: broadcast::Receiver<Update>,
    queued: VecDeque<Update>,
    session: bool,
    checker: BoundChecker,
    deadline: Option<(Instant, EndReason)>,
    ended: bool,
}

impl Port {
    pub(super) fn subscribe(self: &Arc<Self>, id: u64, bounds: Bounds) -> Subscription {
        let now = Instant::now();
        let since = bounds
            .since_ms
            .and_then(|ms| now.checked_sub(Duration::from_millis(ms)));
        let (events, history, (state, message)) = {
            let ring = lock(&self.ring);
            let history = match bounds.tail.is_some() || bounds.since_ms.is_some() {
                true => ring.snapshot(bounds.tail, since),
                false => Vec::new(),
            };
            (self.events.subscribe(), history, lock(&self.status).clone())
        };
        let mut checker = BoundChecker::new(&bounds);
        let mut queued = VecDeque::from([Update::State { state, message }]);
        let mut end = None;
        if !history.is_empty() {
            end = checker.check(&history);
            queued.push_back(Update::Output {
                bytes: history.into(),
                spans: Vec::new(),
            });
        }
        if let Some(reason) = end.or(bounds.replay_only().then_some(EndReason::Closed)) {
            queued.push_back(Update::End(reason));
        }
        Subscription {
            id,
            baud: self.baud,
            port: Arc::downgrade(self),
            events,
            queued,
            session: false,
            checker,
            deadline: bounds.deadline(now),
            ended: false,
        }
    }
}

impl Subscription {
    /// The rate the port is open at, which its first subscriber chose.
    pub fn baud(&self) -> u32 {
        self.baud
    }

    /// `None` after [`Update::End`]. Cancel-safe.
    pub async fn next(&mut self) -> Option<Update> {
        if self.ended {
            return None;
        }
        let update = match self.queued.pop_front() {
            Some(update) => update,
            None => self.receive().await,
        };
        self.ended = matches!(update, Update::End(_));
        Some(update)
    }

    /// Puts `names` in the session as attached through this subscription,
    /// replacing any it had, and from now on tells it what only the session
    /// is told: whose echo is whose, unechoed input and the roster.
    pub fn join(&mut self, via: &str, names: Vec<String>) {
        self.session = true;
        let Some(port) = self.port.upgrade() else {
            return;
        };
        if !port.set_participants(self.id, via, names) {
            self.queued
                .push_back(Update::Participants(port.participants()));
        }
    }

    async fn receive(&mut self) -> Update {
        loop {
            let received = match self.deadline {
                Some((at, reason)) => tokio::select! {
                    biased;
                    () = sleep_until(at) => return Update::End(reason),
                    received = self.events.recv() => received,
                },
                None => self.events.recv().await,
            };
            match received {
                Ok(Update::Output { bytes, spans }) => {
                    if let Some(reason) = self.checker.check(&bytes) {
                        self.queued.push_back(Update::End(reason));
                    }
                    let spans = if self.session { spans } else { Vec::new() };
                    return Update::Output { bytes, spans };
                }
                Ok(Update::Unechoed { .. } | Update::Participants(_)) if !self.session => {}
                Ok(update) => return update,
                Err(RecvError::Lagged(_)) => {}
                Err(RecvError::Closed) => return Update::End(EndReason::Released),
            }
        }
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        if let Some(port) = self.port.upgrade() {
            port.set_participants(self.id, "", Vec::new());
        }
    }
}
