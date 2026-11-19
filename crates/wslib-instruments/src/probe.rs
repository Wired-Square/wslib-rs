use std::{
    error::Error,
    fmt, io,
    sync::Arc,
    time::{Duration, Instant},
};

use wslib_can_bus::{CanBus, OpenError};
use wslib_framelink_protocol::can_id::device_id_text;

use crate::{sample::Sample, signal::SignalKey, wiredreflow::bus::out_of_reach, worker};

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ProbeError {
    Timeout,
    Stale(Duration),
    /// The instrument is out of reach: `why` is this crate's sentence, and
    /// the source, where there is one, is the error that cut it off.
    Disconnected {
        why: String,
        source: Option<Arc<dyn Error + Send + Sync>>,
    },
    NotAdvertising(String),
}

impl ProbeError {
    pub(crate) fn disconnected(why: impl Into<String>) -> Self {
        ProbeError::Disconnected {
            why: why.into(),
            source: None,
        }
    }

    pub(crate) fn cut_off(why: impl Into<String>, source: Arc<dyn Error + Send + Sync>) -> Self {
        ProbeError::Disconnected {
            why: why.into(),
            source: Some(source),
        }
    }
}

impl fmt::Display for ProbeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProbeError::Timeout => f.write_str("no reading before the deadline"),
            ProbeError::Stale(age) => write!(f, "no reading for {:.1} s", age.as_secs_f64()),
            ProbeError::Disconnected { why, .. } => write!(f, "disconnected: {why}"),
            ProbeError::NotAdvertising(what_to_do) => write!(f, "not advertising: {what_to_do}"),
        }
    }
}

impl Error for ProbeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            ProbeError::Disconnected {
                source: Some(source),
                ..
            } => Some(&**source),
            _ => None,
        }
    }
}

/// Why a probe did not start.
#[derive(Debug)]
#[non_exhaustive]
pub enum StartError {
    /// The probe's backend is behind a feature this build left out.
    FeatureDisabled(&'static str),
    /// This platform doesn't reach the bus's adapter this way.
    Unreachable(CanBus),
    /// The WiredReflow's CAN bus did not open.
    Bus(OpenError),
    /// The probe's thread did not start.
    Thread(io::Error),
    /// The tokio runtime on the probe's thread did not start.
    Runtime(io::Error),
    /// The probe's thread stopped before it opened its instrument.
    Stopped,
    /// No WiredReflow was heard on `on` within `window`; `lost`, the
    /// source, is why the adapter was lost while listening.
    NoWiredReflow {
        on: CanBus,
        window: Duration,
        lost: Option<Arc<dyn Error + Send + Sync>>,
    },
    /// More than one WiredReflow was heard on `on`.
    ManyWiredReflows { on: CanBus, devices: Vec<u32> },
    /// The bus ended while listening for a WiredReflow; the source, where
    /// there is one, is why.
    Ended {
        on: CanBus,
        source: Option<Arc<dyn Error + Send + Sync>>,
    },
}

impl StartError {
    /// The `io::ErrorKind` a caller may sort it by.
    pub fn kind(&self) -> io::ErrorKind {
        match self {
            StartError::FeatureDisabled(_) | StartError::Unreachable(_) => {
                io::ErrorKind::Unsupported
            }
            StartError::Bus(e) => e.kind(),
            StartError::Thread(e) | StartError::Runtime(e) => e.kind(),
            StartError::NoWiredReflow { .. } => io::ErrorKind::NotFound,
            StartError::ManyWiredReflows { .. } => io::ErrorKind::InvalidInput,
            StartError::Stopped | StartError::Ended { .. } => io::ErrorKind::Other,
        }
    }
}

const LIST_SEPARATOR: &str = ", ";

impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StartError::FeatureDisabled(feature) => write!(
                f,
                "this build leaves it out; enable wslib-instruments' `{feature}` feature"
            ),
            StartError::Unreachable(bus) => f.write_str(&out_of_reach(bus)),
            StartError::Bus(_) => f.write_str("the CAN bus did not open"),
            StartError::Thread(_) => f.write_str("the probe's thread did not start"),
            StartError::Runtime(_) => f.write_str("the probe's tokio runtime did not start"),
            StartError::Stopped => {
                f.write_str("the probe's thread stopped before it opened its instrument")
            }
            StartError::NoWiredReflow { on, window, lost } => {
                write!(
                    f,
                    "no WiredReflow on {on} within {} s; is it powered and is {on} up?",
                    window.as_secs_f64()
                )?;
                if lost.is_some() {
                    f.write_str(" The adapter was lost while listening")?;
                }
                Ok(())
            }
            StartError::ManyWiredReflows { on, devices } => {
                let ids: Vec<String> = devices.iter().copied().map(device_id_text).collect();
                write!(
                    f,
                    "more than one WiredReflow on {on} ({}); choose one with @<device-id>",
                    ids.join(LIST_SEPARATOR)
                )
            }
            StartError::Ended { on, .. } => {
                write!(f, "{on} ended while listening for a WiredReflow")
            }
        }
    }
}

impl Error for StartError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            StartError::Bus(e) => Some(e),
            StartError::Thread(e) | StartError::Runtime(e) => Some(e),
            StartError::NoWiredReflow {
                lost: Some(source), ..
            }
            | StartError::Ended {
                source: Some(source),
                ..
            } => Some(&**source),
            StartError::FeatureDisabled(_)
            | StartError::Unreachable(_)
            | StartError::Stopped
            | StartError::NoWiredReflow { lost: None, .. }
            | StartError::ManyWiredReflows { .. }
            | StartError::Ended { source: None, .. } => None,
        }
    }
}

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

    /// The longest dropping it waits for what it holds to be released.
    fn release_within(&self) -> Duration {
        worker::RELEASE_WITHIN
    }
}
