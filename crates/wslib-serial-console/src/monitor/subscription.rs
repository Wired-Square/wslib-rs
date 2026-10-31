use std::{
    collections::VecDeque,
    sync::{Arc, Mutex, Weak},
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
    baud: u32,
    seat: Seat,
    events: broadcast::Receiver<Update>,
    queued: VecDeque<Update>,
    checker: BoundChecker,
    deadline: Option<(Instant, EndReason)>,
    ended: bool,
}

/// A subscription's place in the session, which any task can join or change.
#[derive(Clone)]
pub struct Seat(Arc<Place>);

struct Place {
    id: u64,
    /// Weak, so a released port's last strong reference goes and its
    /// subscribers read the end.
    port: Weak<Port>,
    /// Held across each roster change, so a join can't land after the leave.
    state: Mutex<Joined>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Joined {
    No,
    Yes,
    Left,
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
            baud: self.baud,
            seat: Seat(Arc::new(Place {
                id,
                port: Arc::downgrade(self),
                state: Mutex::new(Joined::No),
            })),
            events,
            queued,
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
        if let Some(port) = self.seat.take(via, names) {
            self.queued
                .push_back(Update::Participants(port.participants()));
        }
    }

    /// This subscription's place in the session, for a task that doesn't
    /// hold it.
    pub fn seat(&self) -> Seat {
        self.seat.clone()
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
                    let spans = if self.seat.joined() {
                        spans
                    } else {
                        Vec::new()
                    };
                    return Update::Output { bytes, spans };
                }
                Ok(Update::Unechoed { .. } | Update::Participants(_)) if !self.seat.joined() => {}
                Ok(update) => return update,
                Err(RecvError::Lagged(_)) => {}
                Err(RecvError::Closed) => return Update::End(EndReason::Released),
            }
        }
    }
}

impl Seat {
    /// As [`Subscription::join`], from any task; once the subscription is
    /// dropped it does nothing.
    pub fn join(&self, via: &str, names: Vec<String>) {
        if let Some(port) = self.take(via, names) {
            let _ = port.events.send(Update::Participants(port.participants()));
        }
    }

    /// The port when this first join left the roster as it was, so the joiner
    /// has yet to be told it.
    fn take(&self, via: &str, names: Vec<String>) -> Option<Arc<Port>> {
        let mut state = lock(&self.0.state);
        let first = match *state {
            Joined::Left => return None,
            Joined::No => true,
            Joined::Yes => false,
        };
        *state = Joined::Yes;
        let port = self.0.port.upgrade()?;
        let changed = port.set_participants(self.0.id, via, names);
        (first && !changed).then_some(port)
    }

    fn joined(&self) -> bool {
        *lock(&self.0.state) == Joined::Yes
    }

    fn leave(&self) {
        let mut state = lock(&self.0.state);
        *state = Joined::Left;
        if let Some(port) = self.0.port.upgrade() {
            port.set_participants(self.0.id, "", Vec::new());
        }
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        self.seat.leave();
    }
}
