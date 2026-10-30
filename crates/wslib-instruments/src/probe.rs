use std::{
    error::Error,
    fmt,
    time::{Duration, Instant},
};

use crate::{sample::Sample, signal::SignalKey};

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProbeError {
    Timeout,
    Stale(Duration),
    Disconnected(String),
    NotAdvertising(String),
    /// The probe's backend is behind a feature this build left out.
    FeatureDisabled(&'static str),
}

impl fmt::Display for ProbeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProbeError::Timeout => f.write_str("no reading before the deadline"),
            ProbeError::Stale(age) => write!(f, "no reading for {:.1} s", age.as_secs_f64()),
            ProbeError::Disconnected(why) => write!(f, "disconnected: {why}"),
            ProbeError::NotAdvertising(what_to_do) => write!(f, "not advertising: {what_to_do}"),
            ProbeError::FeatureDisabled(feature) => {
                write!(
                    f,
                    "this build leaves it out; enable wslib-instruments' `{feature}` feature"
                )
            }
        }
    }
}

impl Error for ProbeError {}

/// An instrument read by blocking calls. Implement it for a probe of your own
/// to run it in a [`Cluster`](crate::cluster::Cluster) beside these.
pub trait Probe: Send + 'static {
    fn name(&self) -> String;
    fn signals(&self) -> Vec<SignalKey>;

    /// The instrument's own name for a signal, where it has one.
    fn display_name(&self, _key: &SignalKey) -> Option<&'static str> {
        None
    }

    /// Blocks until a reading or `deadline`. The 121GW returns its newest
    /// reading; a WiredReflow returns every one queued since the last call.
    fn next(&mut self, deadline: Instant) -> Result<Vec<Sample>, ProbeError>;
    fn max_interval(&self) -> Duration;
}
