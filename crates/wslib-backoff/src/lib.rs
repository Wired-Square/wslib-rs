//! Capped exponential backoff that restarts from its initial delay on success.
//!
//! ```
//! use std::time::Duration;
//! use wslib_backoff::Backoff;
//!
//! let mut backoff = Backoff::default();
//! assert_eq!(backoff.next(), Duration::from_secs(1));
//! assert_eq!(backoff.next(), Duration::from_secs(2));
//! backoff.reset();
//! assert_eq!(backoff.next(), Duration::from_secs(1));
//! ```
//!
//! The `tokio` feature adds `retry` and `reconnect`, which run the loop too.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::time::Duration;

#[cfg(feature = "tokio")]
mod run;
#[cfg(feature = "tokio")]
pub use run::{Attempt, reconnect, retry};

/// Delays growing by a multiplier from an initial value up to a cap, restarting
/// on [`reset`](Self::reset).
#[derive(Debug)]
pub struct Backoff {
    initial: Duration,
    max: Duration,
    multiplier: u32,
    jitter: f64,
    failures: u32,
    rng: u64,
}

impl Backoff {
    /// Doubling from `initial` to `max`, without jitter.
    pub fn new(initial: Duration, max: Duration) -> Self {
        Self {
            initial,
            max,
            multiplier: 2,
            jitter: 0.0,
            failures: 0,
            rng: seed(),
        }
    }

    /// Grows each delay by `multiplier` instead of doubling; 0 is taken as 1.
    pub fn multiplier(mut self, multiplier: u32) -> Self {
        self.multiplier = multiplier.max(1);
        self
    }

    /// Shortens each delay from [`next`](Self::next) by a random share of up to
    /// `fraction` (clamped to 0..=1), so peers that failed together do not
    /// retry together.
    pub fn jitter(mut self, fraction: f64) -> Self {
        self.jitter = if fraction > 0.0 {
            fraction.min(1.0)
        } else {
            0.0
        };
        self
    }

    /// The delay after `failures` consecutive failures, without jitter.
    pub fn delay(&self, failures: u32) -> Duration {
        self.multiplier
            .checked_pow(failures)
            .and_then(|factor| self.initial.checked_mul(factor))
            .map_or(self.max, |delay| delay.min(self.max))
    }

    /// The wait before the next attempt, counting one more failure.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Duration {
        let delay = self.delay(self.failures);
        self.failures = self.failures.saturating_add(1);
        if self.jitter == 0.0 {
            return delay;
        }
        delay.mul_f64(1.0 - self.jitter * self.random_fraction())
    }

    /// Restarts from the initial delay, after a success.
    pub fn reset(&mut self) {
        self.failures = 0;
    }

    // xorshift64*, top 53 bits.
    fn random_fraction(&mut self) -> f64 {
        self.rng ^= self.rng >> 12;
        self.rng ^= self.rng << 25;
        self.rng ^= self.rng >> 27;
        (self.rng.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// 1 s to 30 s, doubling, without jitter.
impl Default for Backoff {
    fn default() -> Self {
        Self::new(Duration::from_secs(1), Duration::from_secs(30))
    }
}

/// A clone draws its own jitter: copying the generator would have clones of one
/// template retry in lockstep, which is what jitter is there to prevent.
impl Clone for Backoff {
    fn clone(&self) -> Self {
        Self {
            rng: seed(),
            ..*self
        }
    }
}

/// `RandomState` is seeded per process and varies per instance; xorshift needs
/// a non-zero state.
fn seed() -> u64 {
    RandomState::new().build_hasher().finish() | 1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(s: u64) -> Duration {
        Duration::from_secs(s)
    }

    fn take(backoff: &mut Backoff, n: usize) -> Vec<Duration> {
        (0..n).map(|_| backoff.next()).collect()
    }

    #[test]
    fn the_default_doubles_from_one_second_to_thirty() {
        let mut backoff = Backoff::default();
        assert_eq!(
            take(&mut backoff, 7),
            [1, 2, 4, 8, 16, 30, 30].map(secs).to_vec()
        );
    }

    #[test]
    fn a_reset_restarts_from_the_initial_delay() {
        let mut backoff = Backoff::default();
        take(&mut backoff, 4);
        backoff.reset();
        assert_eq!(take(&mut backoff, 2), [secs(1), secs(2)]);
    }

    #[test]
    fn the_cap_holds_however_long_the_failures_run() {
        let mut backoff = Backoff::new(Duration::from_millis(1), secs(3600));
        assert!(take(&mut backoff, 200).iter().all(|d| *d <= secs(3600)));
        assert_eq!(backoff.next(), secs(3600));
        assert_eq!(backoff.delay(u32::MAX), secs(3600));
        assert_eq!(Backoff::new(Duration::MAX, secs(5)).delay(1), secs(5));
    }

    #[test]
    fn an_initial_delay_above_the_cap_is_capped() {
        assert_eq!(Backoff::new(secs(60), secs(30)).next(), secs(30));
    }

    #[test]
    fn the_delay_for_a_failure_count_matches_the_sequence() {
        let backoff = Backoff::new(Duration::from_millis(250), secs(8));
        let mut stepped = backoff.clone();
        for failures in 0..10 {
            assert_eq!(backoff.delay(failures), stepped.next());
        }
    }

    #[test]
    fn the_multiplier_sets_the_growth() {
        let mut tripling = Backoff::new(secs(1), secs(100)).multiplier(3);
        assert_eq!(take(&mut tripling, 6), [1, 3, 9, 27, 81, 100].map(secs));
        let mut constant = Backoff::new(secs(5), secs(100)).multiplier(0);
        assert_eq!(take(&mut constant, 3), [secs(5); 3]);
    }

    #[test]
    fn jitter_only_ever_shortens_and_stays_within_its_fraction() {
        let mut backoff = Backoff::new(secs(8), secs(8)).jitter(0.25);
        let delays = take(&mut backoff, 1000);
        assert!(
            delays
                .iter()
                .all(|d| (Duration::from_secs(6)..=secs(8)).contains(d))
        );
        assert!(delays.iter().any(|d| *d < Duration::from_millis(7500)));
        assert!(delays.iter().any(|d| *d > Duration::from_millis(7500)));
    }

    #[test]
    fn full_jitter_stays_within_zero_and_the_delay() {
        let mut backoff = Backoff::new(secs(1), secs(1)).jitter(7.0);
        assert!(take(&mut backoff, 1000).iter().all(|d| *d <= secs(1)));
    }

    #[test]
    fn a_meaningless_jitter_is_none() {
        for fraction in [0.0, -1.0, f64::NAN] {
            let mut backoff = Backoff::default().jitter(fraction);
            assert_eq!(take(&mut backoff, 3), [secs(1), secs(2), secs(4)]);
        }
    }

    #[test]
    fn clones_jitter_independently() {
        let template = Backoff::new(secs(30), secs(30)).jitter(1.0);
        let (mut a, mut b) = (template.clone(), template.clone());
        assert_ne!(take(&mut a, 8), take(&mut b, 8));
    }
}
