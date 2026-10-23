//! A fake `op` that answers from a script and records each call.

use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Mutex, PoisonError};

use crate::{Call, Output, Runner};

/// Answers each call with the next scripted [`Output`], in order, and fails a
/// call nothing was scripted for. Clones share one script and one record.
#[derive(Clone, Default)]
pub struct FakeRunner {
    state: Arc<Mutex<State>>,
}

#[derive(Default)]
struct State {
    script: VecDeque<io::Result<Output>>,
    calls: Vec<Call>,
    files: Vec<Vec<u8>>,
}

impl FakeRunner {
    /// A fake with nothing scripted.
    pub fn new() -> Self {
        Self::default()
    }

    /// Answers the next unanswered call with `output`.
    pub fn respond(&self, output: Output) -> &Self {
        self.state().script.push_back(Ok(output));
        self
    }

    /// Fails the next unanswered call to run at all: `TimedOut` for a timeout,
    /// `NotFound` for no `op`.
    pub fn fail_to_run(&self, kind: io::ErrorKind) -> &Self {
        self.state().script.push_back(Err(kind.into()));
        self
    }

    /// Every call so far, in order.
    pub fn calls(&self) -> Vec<Call> {
        self.state().calls.clone()
    }

    /// The contents of every argument that named a file, read during the call,
    /// since a document's temporary file is gone once it returns.
    pub fn files(&self) -> Vec<Vec<u8>> {
        self.state().files.clone()
    }

    /// Whether every scripted answer has been given.
    pub fn is_done(&self) -> bool {
        self.state().script.is_empty()
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Runner for FakeRunner {
    fn run(&self, call: &Call) -> io::Result<Output> {
        let mut state = self.state();
        state.calls.push(call.clone());
        let files = call
            .args()
            .iter()
            .filter(|arg| std::path::Path::new(arg).is_absolute())
            .filter_map(|arg| std::fs::read(arg).ok());
        state.files.extend(files.collect::<Vec<_>>());
        state
            .script
            .pop_front()
            .unwrap_or_else(|| Err(io::Error::other(format!("nothing scripted for `{call}`"))))
    }
}
