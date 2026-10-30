use std::{
    error::Error,
    fmt,
    time::{Duration, Instant},
};

use crate::{sample::Sample, signal::SignalKey};

#[derive(Debug, Clone, PartialEq, Eq)]
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

pub trait Probe: Send + 'static {
    fn name(&self) -> String;
    fn signals(&self) -> Vec<SignalKey>;
    fn display_name(&self, key: &SignalKey) -> Option<&'static str>;
    fn next(&mut self, deadline: Instant) -> Result<Vec<Sample>, ProbeError>;
    fn max_interval(&self) -> Duration;
}
