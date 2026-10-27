//! The limit on second-factor codes: TOTP and recovery codes together, per
//! account, apart from anything the password goes through. Kept in memory, so
//! a restart forgets it.

use std::time::Duration;

use wslib_auth::{Attempt, Attempts};

use crate::AuthError;

const MAX_WRONG: usize = 5;
const WINDOW: Duration = Duration::from_secs(15 * 60);

/// How many codes each account has got wrong lately. One per process, shared
/// by every route that checks a code; `Clone` shares it.
#[derive(Debug, Clone)]
pub struct CodeAttempts(Attempts<String>);

impl Default for CodeAttempts {
    fn default() -> Self {
        Self(Attempts::new(MAX_WRONG, WINDOW))
    }
}

impl CodeAttempts {
    /// Admit a code for `user_id`, counted as wrong until it succeeds or is
    /// uncounted, or refuse with [`AuthError::TooManyCodes`].
    pub(crate) fn admit(&self, user_id: &str) -> Result<Attempt<String>, AuthError> {
        self.0
            .admit(user_id.to_owned())
            .map_err(|refusal| AuthError::TooManyCodes(refusal.retry_after))
    }

    #[cfg(test)]
    pub(crate) fn wrong_count(&self, user_id: &str) -> usize {
        let free: Vec<_> = std::iter::from_fn(|| self.admit(user_id).ok()).collect();
        let wrong = MAX_WRONG - free.len();
        free.into_iter().for_each(Attempt::uncounted);
        wrong
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sixth_wrong_code_is_refused_and_another_account_has_its_own_count() {
        let attempts = CodeAttempts::default();
        for _ in 0..MAX_WRONG {
            let _ = attempts.admit("u1").expect("admitted");
        }
        match attempts.admit("u1") {
            Err(AuthError::TooManyCodes(wait)) => {
                let window = Duration::from_secs(15 * 60);
                assert!(window - wait < Duration::from_secs(5), "{wait:?}")
            }
            other => panic!("{:?}", other.map(drop)),
        }
        let _ = attempts
            .admit("u2")
            .expect("another account has its own count");
        assert_eq!(attempts.wrong_count("u1"), MAX_WRONG);
        assert_eq!(attempts.wrong_count("u2"), 1);
    }
}
