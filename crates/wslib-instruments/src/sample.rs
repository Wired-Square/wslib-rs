use std::time::{Instant, SystemTime};

use crate::{signal::SignalKey, value::Value};

/// When a reading was taken, on the process's clock and on the wall clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stamp {
    pub at: Instant,
    pub wall_clock: SystemTime,
}

impl Stamp {
    pub fn now() -> Self {
        Self {
            at: Instant::now(),
            wall_clock: SystemTime::now(),
        }
    }
}

/// Under `serde`, `key` is its slug and `wall_clock` microseconds since the
/// Unix epoch. `at` is exact only in the process that took the reading: it is
/// not serialised, and deserialising estimates it from `wall_clock` (or now, if
/// this clock can't reach back), so it carries any skew between the two wall
/// clocks. A receiver orders and ages samples by `wall_clock`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(into = "wire::Sample", try_from = "wire::Sample")
)]
pub struct Sample {
    pub key: SignalKey,
    pub value: Value,
    pub at: Instant,
    pub wall_clock: SystemTime,
}

impl Sample {
    pub const fn new(key: SignalKey, value: Value, stamp: Stamp) -> Self {
        Self {
            key,
            value,
            at: stamp.at,
            wall_clock: stamp.wall_clock,
        }
    }
}

#[cfg(feature = "serde")]
mod wire {
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use serde::{Deserialize, Serialize};

    use crate::{signal, value::Value};

    #[derive(Serialize, Deserialize)]
    pub struct Sample {
        key: String,
        value: Value,
        wall_clock: i64,
    }

    fn unix_micros(time: SystemTime) -> i64 {
        let micros = |span: Duration| i64::try_from(span.as_micros()).unwrap_or(i64::MAX);
        match time.duration_since(UNIX_EPOCH) {
            Ok(after) => micros(after),
            Err(before) => -micros(before.duration()),
        }
    }

    fn from_unix_micros(micros: i64) -> Option<SystemTime> {
        let span = Duration::from_micros(micros.unsigned_abs());
        if micros < 0 {
            UNIX_EPOCH.checked_sub(span)
        } else {
            UNIX_EPOCH.checked_add(span)
        }
    }

    fn on_this_clock(wall_clock: SystemTime) -> Instant {
        let (now, wall_now) = (Instant::now(), SystemTime::now());
        let mapped = match wall_now.duration_since(wall_clock) {
            Ok(ago) => now.checked_sub(ago),
            Err(ahead) => now.checked_add(ahead.duration()),
        };
        mapped.unwrap_or(now)
    }

    impl From<super::Sample> for Sample {
        fn from(sample: super::Sample) -> Self {
            Self {
                key: signal::slug(&sample.key),
                value: sample.value,
                wall_clock: unix_micros(sample.wall_clock),
            }
        }
    }

    impl TryFrom<Sample> for super::Sample {
        type Error = String;

        fn try_from(wire: Sample) -> Result<Self, Self::Error> {
            let wall_clock = from_unix_micros(wire.wall_clock).ok_or_else(|| {
                format!(
                    "{} µs from the Unix epoch is out of range here",
                    wire.wall_clock
                )
            })?;
            Ok(Self {
                key: signal::parse(&wire.key)?,
                value: wire.value,
                at: on_this_clock(wall_clock),
                wall_clock,
            })
        }
    }
}
