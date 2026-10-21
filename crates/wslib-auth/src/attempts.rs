use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::hash::Hash;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// Wrong attempts per key (an account, an address), limited to a number per
/// sliding window. Kept in memory, so a restart forgets it; `Clone` shares it.
#[derive(Debug)]
pub struct Attempts<K> {
    wrong: Arc<Mutex<HashMap<K, VecDeque<Instant>>>>,
    max_wrong: usize,
    window: Duration,
}

impl<K> Clone for Attempts<K> {
    fn clone(&self) -> Self {
        Self {
            wrong: Arc::clone(&self.wrong),
            max_wrong: self.max_wrong,
            window: self.window,
        }
    }
}

impl<K: Hash + Eq + Clone> Default for Attempts<K> {
    /// Five wrong attempts per fifteen minutes.
    fn default() -> Self {
        Self::new(5, Duration::from_secs(15 * 60))
    }
}

/// An admitted attempt, counted as wrong unless it [`succeeded`](Attempt::succeeded)
/// or is [`uncounted`](Attempt::uncounted).
#[must_use]
pub struct Attempt<'a, K: Hash + Eq + Clone> {
    attempts: &'a Attempts<K>,
    key: K,
    at: Instant,
}

impl<K: Hash + Eq + Clone> Attempt<'_, K> {
    /// Clears the key's count.
    pub fn succeeded(self) {
        self.attempts.lock().remove(&self.key);
    }

    /// Withdraws this attempt alone, as when it failed for a reason not the caller's.
    pub fn uncounted(self) {
        let mut map = self.attempts.lock();
        if let Some(wrong) = map.get_mut(&self.key)
            && let Some(at) = wrong.iter().position(|&at| at == self.at)
        {
            wrong.remove(at);
        }
    }
}

impl<K: Hash + Eq + Clone> Attempts<K> {
    /// At most `max_wrong` wrong attempts per key in any `window`.
    pub fn new(max_wrong: usize, window: Duration) -> Self {
        Self {
            wrong: Arc::default(),
            max_wrong,
            window,
        }
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<K, VecDeque<Instant>>> {
        self.wrong.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Admits an attempt for `key`, or refuses it while the key is at its limit.
    ///
    /// Counted as wrong on admission, so attempts in flight at once cannot all
    /// slip under the limit.
    pub fn admit(&self, key: K) -> Result<Attempt<'_, K>, TooManyAttempts> {
        self.admit_at(key, Instant::now())
    }

    fn admit_at(&self, key: K, now: Instant) -> Result<Attempt<'_, K>, TooManyAttempts> {
        let mut map = self.lock();
        map.retain(|_, wrong| {
            while wrong
                .front()
                .is_some_and(|&at| now.duration_since(at) >= self.window)
            {
                wrong.pop_front();
            }
            !wrong.is_empty()
        });
        let wrong = map.entry(key.clone()).or_default();
        if let Some(&oldest) = wrong.front().filter(|_| wrong.len() >= self.max_wrong) {
            return Err(TooManyAttempts {
                retry_after: self.window - now.duration_since(oldest),
            });
        }
        wrong.push_back(now);
        Ok(Attempt {
            attempts: self,
            key,
            at: now,
        })
    }
}

/// The key is at its limit until `retry_after` has passed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TooManyAttempts {
    pub retry_after: Duration,
}

impl fmt::Display for TooManyAttempts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let minutes = self.retry_after.as_secs().div_ceil(60);
        let unit = if minutes == 1 { "minute" } else { "minutes" };
        write!(f, "too many attempts; try again in {minutes} {unit}")
    }
}

impl std::error::Error for TooManyAttempts {}

#[cfg(test)]
mod tests {
    use super::*;

    const WINDOW: Duration = Duration::from_secs(15 * 60);

    fn refused_for(attempts: &Attempts<&str>, key: &'static str, now: Instant) -> Option<Duration> {
        attempts.admit_at(key, now).err().map(|e| e.retry_after)
    }

    #[test]
    fn the_attempt_past_the_limit_is_refused_until_the_first_ages_out() {
        let attempts = Attempts::default();
        let start = Instant::now();
        for i in 0..5 {
            assert_eq!(
                refused_for(&attempts, "u1", start + Duration::from_secs(i)),
                None
            );
        }
        assert_eq!(
            refused_for(&attempts, "u1", start + Duration::from_secs(60)),
            Some(WINDOW - Duration::from_secs(60))
        );
        assert_eq!(
            refused_for(&attempts, "u2", start + Duration::from_secs(60)),
            None,
            "another key has its own count"
        );
        assert_eq!(refused_for(&attempts, "u1", start + WINDOW), None);
        assert!(
            refused_for(&attempts, "u1", start + WINDOW).is_some(),
            "only the one that aged out was freed"
        );
    }

    #[test]
    fn a_success_clears_the_count_and_an_uncounted_attempt_frees_its_place() {
        let attempts = Attempts::new(2, WINDOW);
        let now = Instant::now();
        let _ = attempts.admit_at("u1", now).unwrap();
        attempts.admit_at("u1", now).unwrap().succeeded();
        let _ = attempts.admit_at("u1", now).unwrap();
        attempts.admit_at("u1", now).unwrap().uncounted();
        let _ = attempts.admit_at("u1", now).unwrap();
        assert!(refused_for(&attempts, "u1", now).is_some());
    }

    #[test]
    fn the_refusal_reads_in_whole_minutes() {
        let refusal = TooManyAttempts {
            retry_after: Duration::from_secs(61),
        };
        assert_eq!(
            refusal.to_string(),
            "too many attempts; try again in 2 minutes"
        );
    }
}
