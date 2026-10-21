//! The challenges a ceremony is begun with: made here, held in memory, and
//! spent by the first response whose client data names it. A sign-in's lives
//! two minutes, a registration's or a reauthentication's five.
//!
//! The counter is not the replay defence, since an authenticator that keeps
//! none repeats zero; a challenge spent once is. An account holds one of each
//! kind of its own at a time. Sign-ins, which anybody may begin, are capped,
//! and past the cap the oldest unfinished one is dropped: a flood can still
//! push out honest sign-ins, but only while it is kept up, and never an
//! account's registration or reauthentication.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::random_bytes;

pub(crate) const CHALLENGE_BYTES: usize = 32;
const SIGN_IN_LIFETIME: Duration = Duration::from_secs(2 * 60);
const ACCOUNT_LIFETIME: Duration = Duration::from_secs(5 * 60);
const MAX_SIGN_INS: usize = 1024;

pub(crate) type Challenge = [u8; CHALLENGE_BYTES];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Purpose {
    Register { user_id: String },
    SignIn,
    Reauthenticate { user_id: String },
}

impl Purpose {
    pub(crate) fn lifetime(&self) -> Duration {
        match self {
            Self::SignIn => SIGN_IN_LIFETIME,
            Self::Register { .. } | Self::Reauthenticate { .. } => ACCOUNT_LIFETIME,
        }
    }
}

#[derive(Debug)]
struct Issued {
    purpose: Purpose,
    rp_id: String,
    at: Instant,
}

impl Issued {
    fn live_at(&self, now: Instant) -> bool {
        now.duration_since(self.at) < self.purpose.lifetime()
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct Challenges(Arc<Mutex<HashMap<Challenge, Issued>>>);

impl Challenges {
    fn lock(&self) -> MutexGuard<'_, HashMap<Challenge, Issued>> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub(crate) fn issue(
        &self,
        purpose: Purpose,
        rp_id: &str,
    ) -> Result<Challenge, getrandom::Error> {
        self.issue_at(purpose, rp_id, Instant::now())
    }

    /// Whether `challenge` was issued for `purpose` on `rp_id` within its
    /// lifetime; it is spent either way.
    pub(crate) fn take(&self, challenge: &[u8], purpose: &Purpose, rp_id: &str) -> bool {
        self.take_at(challenge, purpose, rp_id, Instant::now())
    }

    fn issue_at(
        &self,
        purpose: Purpose,
        rp_id: &str,
        now: Instant,
    ) -> Result<Challenge, getrandom::Error> {
        let mut map = self.lock();
        map.retain(|_, issued| {
            issued.live_at(now) && (purpose == Purpose::SignIn || issued.purpose != purpose)
        });
        if purpose == Purpose::SignIn {
            let sign_ins = map.iter().filter(|(_, i)| i.purpose == Purpose::SignIn);
            if sign_ins.clone().count() >= MAX_SIGN_INS
                && let Some(oldest) = sign_ins.min_by_key(|(_, i)| i.at).map(|(c, _)| *c)
            {
                map.remove(&oldest);
            }
        }
        let challenge = random_bytes::<CHALLENGE_BYTES>()?;
        map.insert(
            challenge,
            Issued {
                purpose,
                rp_id: rp_id.to_owned(),
                at: now,
            },
        );
        Ok(challenge)
    }

    fn take_at(&self, challenge: &[u8], purpose: &Purpose, rp_id: &str, now: Instant) -> bool {
        let Ok(challenge) = Challenge::try_from(challenge) else {
            return false;
        };
        self.lock().remove(&challenge).is_some_and(|issued| {
            issued.purpose == *purpose && issued.rp_id == rp_id && issued.live_at(now)
        })
    }

    #[cfg(test)]
    pub(crate) fn insert(&self, challenge: Challenge, purpose: Purpose, rp_id: &str) {
        let issued = Issued {
            purpose,
            rp_id: rp_id.to_owned(),
            at: Instant::now(),
        };
        self.lock().insert(challenge, issued);
    }

    #[cfg(test)]
    pub(crate) fn age(&self, by: Duration) {
        for issued in self.lock().values_mut() {
            issued.at -= by;
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.lock().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn register(user_id: &str) -> Purpose {
        Purpose::Register {
            user_id: user_id.into(),
        }
    }

    #[test]
    fn a_challenge_is_thirty_two_random_bytes_and_spent_on_first_sight() {
        let challenges = Challenges::default();
        let a = challenges
            .issue(Purpose::SignIn, "box.local")
            .expect("issued");
        let b = challenges
            .issue(Purpose::SignIn, "box.local")
            .expect("issued");
        assert_ne!(a, b);
        assert!(challenges.take(&a, &Purpose::SignIn, "box.local"));
        assert!(
            !challenges.take(&a, &Purpose::SignIn, "box.local"),
            "replayed"
        );
    }

    #[test]
    fn a_challenge_answers_only_what_it_was_issued_for_and_is_spent_by_a_wrong_use() {
        let challenges = Challenges::default();
        let wrong_uses = [
            (Purpose::SignIn, "box.local"),
            (register("u2"), "box.local"),
            (
                Purpose::Reauthenticate {
                    user_id: "u1".into(),
                },
                "box.local",
            ),
            (register("u1"), "other.local"),
        ];
        for (purpose, rp_id) in wrong_uses {
            let issued = challenges
                .issue(register("u1"), "box.local")
                .expect("issued");
            assert!(
                !challenges.take(&issued, &purpose, rp_id),
                "{purpose:?} {rp_id}"
            );
            assert!(
                !challenges.take(&issued, &register("u1"), "box.local"),
                "spent by the wrong use"
            );
        }
        assert!(!challenges.take(&[0; 16], &Purpose::SignIn, "box.local"));
    }

    #[test]
    fn an_accounts_challenge_expires_after_five_minutes_and_a_sign_ins_after_two() {
        let challenges = Challenges::default();
        let now = Instant::now();
        for (purpose, lifetime) in [
            (register("u1"), Duration::from_secs(300)),
            (Purpose::SignIn, Duration::from_secs(120)),
        ] {
            let issued = challenges
                .issue_at(purpose.clone(), "box.local", now)
                .expect("issued");
            assert!(!challenges.take_at(&issued, &purpose, "box.local", now + lifetime));
            let issued = challenges
                .issue_at(purpose.clone(), "box.local", now)
                .expect("issued");
            let just_in_time = now + lifetime - Duration::from_secs(1);
            assert!(challenges.take_at(&issued, &purpose, "box.local", just_in_time));
        }
    }

    #[test]
    fn an_account_holds_one_challenge_of_each_kind() {
        let challenges = Challenges::default();
        let first = challenges
            .issue(register("u1"), "box.local")
            .expect("issued");
        let reauth = Purpose::Reauthenticate {
            user_id: "u1".into(),
        };
        let other = challenges
            .issue(reauth.clone(), "box.local")
            .expect("issued");
        let second = challenges
            .issue(register("u1"), "box.local")
            .expect("issued");
        challenges
            .issue(register("u2"), "box.local")
            .expect("issued");
        assert_eq!(challenges.len(), 3);
        assert!(
            !challenges.take(&first, &register("u1"), "box.local"),
            "replaced"
        );
        assert!(challenges.take(&second, &register("u1"), "box.local"));
        assert!(challenges.take(&other, &reauth, "box.local"));
    }

    #[test]
    fn past_the_cap_the_oldest_sign_in_is_dropped_and_the_newest_works() {
        let challenges = Challenges::default();
        let start = Instant::now();
        let at = |i: u64| start + Duration::from_millis(i);
        let account = challenges
            .issue_at(register("u1"), "box.local", start)
            .expect("issued");
        let issued: Vec<Challenge> = (0..=MAX_SIGN_INS as u64)
            .map(|i| {
                challenges
                    .issue_at(Purpose::SignIn, "box.local", at(i))
                    .expect("never refused")
            })
            .collect();
        assert_eq!(
            challenges.len(),
            MAX_SIGN_INS + 1,
            "the cap and the account's"
        );

        let now = at(MAX_SIGN_INS as u64 + 1);
        assert!(!challenges.take_at(&issued[0], &Purpose::SignIn, "box.local", now));
        assert!(challenges.take_at(&issued[1], &Purpose::SignIn, "box.local", now));
        let newest = issued.last().expect("issued");
        assert!(challenges.take_at(newest, &Purpose::SignIn, "box.local", now));
        assert!(
            challenges.take_at(&account, &register("u1"), "box.local", now),
            "an account's own is not dropped for sign-ins"
        );
    }
}
