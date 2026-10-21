//! TOTP (RFC 6238) as authenticator apps run it: HMAC-SHA1, six digits,
//! thirty-second steps, a 160-bit key handed over in unpadded base32
//! (RFC 4648). A code is accepted one step either side of the server's clock.
//!
//! [`Key::accepted_step`] is the step the code matched. A code is good once:
//! the caller keeps the last step spent and refuses a step no later than it.
//!
//! The browser's clock is the authenticator's, near enough, since its code was
//! just read off a phone beside it. When it and the server's disagree by more
//! than codes can bridge, [`check_clocks`] answers the [`ClockSkew`]: before a
//! first code is checked, and in place of "wrong code" when a code misses.
//!
//! Without the default `codes` feature only [`ClockSkew`] and
//! [`check_clocks`] are left, for a crate that carries the types alone.

use std::fmt;
use std::time::{Duration, SystemTime};

#[cfg(feature = "codes")]
pub use key::Key;

#[cfg(feature = "codes")]
mod key;

const STEP_SECONDS: u64 = 30;
const CLOCK_TOLERANCE: Duration = Duration::from_secs(2 * STEP_SECONDS);

/// Refuses clocks more than two steps apart, as the [`ClockSkew`].
pub fn check_clocks(browser: SystemTime, now: SystemTime) -> Result<(), ClockSkew> {
    let (apart, server_ahead) = match now.duration_since(browser) {
        Ok(ahead) => (ahead, true),
        Err(behind) => (behind.duration(), false),
    };
    if apart <= CLOCK_TOLERANCE {
        return Ok(());
    }
    let minutes = i32::try_from(apart.as_secs().saturating_add(30) / 60).unwrap_or(i32::MAX);
    Err(ClockSkew {
        minutes: if server_ahead { minutes } else { -minutes },
    })
}

/// The server's clock and the browser's disagree by more than codes can bridge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct ClockSkew {
    /// How far the server's clock is ahead of the browser's, to the nearest
    /// minute; negative when it is behind.
    pub minutes: i32,
}

impl fmt::Display for ClockSkew {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let n = self.minutes.unsigned_abs();
        let unit = if n == 1 { "minute" } else { "minutes" };
        write!(
            f,
            "the server's clock is {n} {unit} off; codes won't match until it is set (check its time sync)"
        )
    }
}

impl std::error::Error for ClockSkew {}

#[cfg(test)]
mod tests {
    use std::time::UNIX_EPOCH;

    use super::*;

    fn at(seconds: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(seconds)
    }

    const NOW: u64 = 1_700_000_015;

    #[test]
    fn clocks_more_than_two_steps_apart_are_refused_in_signed_minutes() {
        let now = at(NOW);
        assert!(check_clocks(now - CLOCK_TOLERANCE, now).is_ok());
        assert!(check_clocks(now + CLOCK_TOLERANCE, now).is_ok());
        let skew = |browser| check_clocks(browser, now).expect_err("apart").minutes;
        assert_eq!(
            skew(now - Duration::from_secs(61)),
            1,
            "the server is ahead"
        );
        assert_eq!(
            skew(now + Duration::from_secs(61)),
            -1,
            "the server is behind"
        );
        assert_eq!(skew(now - Duration::from_secs(7 * 60 + 29)), 7);
        assert_eq!(skew(now - Duration::from_secs(7 * 60 + 30)), 8);
        assert_eq!(
            ClockSkew { minutes: -1 }.to_string(),
            "the server's clock is 1 minute off; codes won't match until it is set (check its time sync)"
        );
    }
}
