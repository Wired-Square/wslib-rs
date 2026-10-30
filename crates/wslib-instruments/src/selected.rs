use std::time::{Duration, Instant};

use crate::{
    probe::{Probe, ProbeError},
    sample::Sample,
    signal::SignalKey,
};

pub struct Selected {
    inner: Box<dyn Probe>,
    keys: Vec<SignalKey>,
}

impl Selected {
    pub fn new(inner: Box<dyn Probe>, keys: Vec<SignalKey>) -> Self {
        Self { inner, keys }
    }
}

impl Probe for Selected {
    fn name(&self) -> String {
        self.inner.name()
    }

    fn signals(&self) -> Vec<SignalKey> {
        self.keys.clone()
    }

    fn display_name(&self, key: &SignalKey) -> Option<&'static str> {
        self.inner.display_name(key)
    }

    fn next(&mut self, deadline: Instant) -> Result<Vec<Sample>, ProbeError> {
        let samples = self.inner.next(deadline)?;
        Ok(samples
            .into_iter()
            .filter(|sample| self.keys.contains(&sample.key))
            .collect())
    }

    fn max_interval(&self) -> Duration {
        self.inner.max_interval()
    }
}
