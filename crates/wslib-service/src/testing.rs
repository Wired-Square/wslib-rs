//! A [`Stop`] for a consumer's tests, outside [`Daemon::run`](crate::Daemon::run):
//! nothing is told, and a [`Recorder`] keeps what would have been.

use std::sync::{Arc, Mutex};

use crate::{CancellationToken, Manager, Stop, Tell};

/// A [`Stop`] under [`Manager::Detached`], and the [`Recorder`] that stops it
/// and keeps what it said. Works in any Tokio runtime, or none.
pub fn stop() -> (Stop, Recorder) {
    let manager = CancellationToken::new();
    let recorder = Recorder {
        told: Arc::default(),
        readied: CancellationToken::new(),
        token: manager.child_token(),
        manager,
    };
    let stop = Stop::new(Manager::Detached, recorder.token.clone(), recorder.clone());
    (stop, recorder)
}

/// What a test [`Stop`] told its service manager.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Told {
    /// Whether ready was said, and the status it carried.
    pub ready: Option<Option<String>>,
    /// Every status sent alone, in order, before or after ready.
    pub statuses: Vec<String>,
    /// Whether the service cancelled its [`Stop::token`] without
    /// [`Recorder::stop`].
    pub stopped_itself: bool,
}

/// The service manager of a [`stop`]: the stop it asks for, and what it was told.
#[derive(Clone, Debug)]
pub struct Recorder {
    told: Arc<Mutex<Told>>,
    readied: CancellationToken,
    manager: CancellationToken,
    token: CancellationToken,
}

impl Recorder {
    /// The service manager's stop, as a signal or a stop control would be.
    pub fn stop(&self) {
        self.manager.cancel();
    }

    /// Resolves once ready has been sent, with the status it carried.
    pub async fn ready(&self) -> Option<String> {
        self.readied.cancelled().await;
        self.lock().ready.clone().flatten()
    }

    pub fn told(&self) -> Told {
        Told {
            stopped_itself: self.token.is_cancelled() && !self.manager.is_cancelled(),
            ..self.lock().clone()
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Told> {
        self.told.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl Tell for Recorder {
    fn ready(&self, status: Option<&str>) {
        self.lock().ready = Some(status.map(str::to_string));
        self.readied.cancel();
    }

    fn status(&self, status: &str) {
        self.lock().statuses.push(status.to_string());
    }
}
