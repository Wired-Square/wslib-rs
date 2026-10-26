//! Sign-ins waiting for their second step: an account that proved its
//! password and has TOTP on, or must enrol it, held in memory for five minutes
//! under a token the browser carries to that step, beside a digest of the
//! password hash it was proved against.
//!
//! An account holds a few at once, so somebody else who has its password
//! cannot push its owner's out; past that, and past the cap for every
//! account, the oldest is dropped. A code step takes one out, so two steps
//! cannot share it, and gives it back unless the step issued the session.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use subtle::ConstantTimeEq;
use wslib_crypto::Fingerprint;
use wslib_secret::Secret;

use crate::{AuthError, random_bytes};

const LIFETIME: Duration = Duration::from_secs(5 * 60);
const MAX_PENDING: usize = 1024;
const MAX_PER_ACCOUNT: usize = 8;

type Token = [u8; 32];

#[derive(Debug)]
struct Waiting {
    user_id: String,
    password: [u8; 32],
    awaiting: Awaiting,
    at: Instant,
}

/// What a waiting sign-in needs before it becomes a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Awaiting {
    /// A TOTP or recovery code.
    Code,
    /// A TOTP key enrolled and confirmed, an administrator having required it.
    Enrolment,
}

/// The sign-ins waiting for a second step. One per process; `Clone` shares it.
#[derive(Debug, Clone, Default)]
pub struct PendingSignIns(Arc<Mutex<HashMap<Token, Waiting>>>);

/// A new waiting sign-in: its token, and how many others its account
/// already had waiting, each a password proved and no code yet.
#[derive(Debug)]
pub struct Begun {
    pub token: Secret,
    pub others: usize,
}

/// A waiting sign-in, taken out for one code step: back in when dropped,
/// unless [`spent`](Self::spend).
#[derive(Debug)]
pub struct Pending {
    sign_ins: PendingSignIns,
    token: Token,
    waiting: Option<Waiting>,
}

impl Pending {
    /// The account that proved its password.
    pub fn user_id(&self) -> &str {
        &self.waiting().user_id
    }

    /// Whether `password_hash` is still the hash the password was proved
    /// against; a change since ends the sign-in.
    pub fn began_under(&self, password_hash: &str) -> bool {
        bool::from(self.waiting().password.ct_eq(&hashed(password_hash)))
    }

    /// The code step issued the session; this sign-in is over.
    pub fn spend(mut self) {
        self.waiting = None;
    }

    fn waiting(&self) -> &Waiting {
        self.waiting.as_ref().expect("held until dropped")
    }
}

impl Drop for Pending {
    fn drop(&mut self) {
        let Some(waiting) = self.waiting.take() else {
            return;
        };
        let mut map = self.sign_ins.lock();
        let held = map.values().filter(|w| w.user_id == waiting.user_id);
        if held.count() < MAX_PER_ACCOUNT {
            map.insert(self.token, waiting);
        }
    }
}

fn hashed(password_hash: &str) -> [u8; 32] {
    *Fingerprint::of(password_hash.as_bytes()).as_bytes()
}

impl PendingSignIns {
    fn lock(&self) -> MutexGuard<'_, HashMap<Token, Waiting>> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Hold a sign-in for `user_id`, whose password, stored as
    /// `password_hash`, was right, until what it is `awaiting`.
    pub fn begin(
        &self,
        user_id: &str,
        password_hash: &str,
        awaiting: Awaiting,
    ) -> Result<Begun, AuthError> {
        self.begin_at(user_id, password_hash, awaiting, Instant::now())
    }

    fn begin_at(
        &self,
        user_id: &str,
        password_hash: &str,
        awaiting: Awaiting,
        now: Instant,
    ) -> Result<Begun, AuthError> {
        let token = random_bytes::<32>()?;
        let mut map = self.lock();
        map.retain(|_, w| now.duration_since(w.at) < LIFETIME);
        let oldest = |map: &HashMap<Token, Waiting>, of: Option<&str>| {
            map.iter()
                .filter(|(_, w)| of.is_none_or(|id| w.user_id == id))
                .min_by_key(|(_, w)| w.at)
                .map(|(token, _)| *token)
        };
        let others = map.values().filter(|w| w.user_id == user_id).count();
        if others >= MAX_PER_ACCOUNT
            && let Some(token) = oldest(&map, Some(user_id))
        {
            map.remove(&token);
        }
        if map.len() >= MAX_PENDING
            && let Some(token) = oldest(&map, None)
        {
            map.remove(&token);
        }
        map.insert(
            token,
            Waiting {
                user_id: user_id.to_owned(),
                password: hashed(password_hash),
                awaiting,
                at: now,
            },
        );
        Ok(Begun {
            token: Secret::new(URL_SAFE_NO_PAD.encode(token)),
            others,
        })
    }

    /// The live sign-in `token` names, if it is `awaiting` this, taken out
    /// until the step is done.
    pub fn take(&self, token: &Secret, awaiting: Awaiting) -> Option<Pending> {
        self.take_at(token, awaiting, Instant::now())
    }

    fn take_at(&self, token: &Secret, awaiting: Awaiting, now: Instant) -> Option<Pending> {
        let token = Token::try_from(URL_SAFE_NO_PAD.decode(token.expose()).ok()?).ok()?;
        let mut map = self.lock();
        if map.get(&token)?.awaiting != awaiting {
            return None;
        }
        let waiting = map
            .remove(&token)
            .filter(|w| now.duration_since(w.at) < LIFETIME)?;
        drop(map);
        Some(Pending {
            sign_ins: self.clone(),
            token,
            waiting: Some(waiting),
        })
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.lock().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &str = "$argon2id$v=19$the-hash";
    const CODE: Awaiting = Awaiting::Code;

    fn sign_ins() -> PendingSignIns {
        crate::tests::with_provider();
        PendingSignIns::default()
    }

    fn begin(pending: &PendingSignIns, user_id: &str) -> Secret {
        pending.begin(user_id, HASH, CODE).unwrap().token
    }

    impl PendingSignIns {
        fn code(&self, token: &Secret) -> Option<Pending> {
            self.take(token, CODE)
        }
    }

    #[test]
    fn a_sign_in_is_taken_only_for_what_it_awaits() {
        let pending = sign_ins();
        let token = pending
            .begin("u1", HASH, Awaiting::Enrolment)
            .unwrap()
            .token;
        assert!(pending.code(&token).is_none(), "not a code step's");
        assert!(
            pending.take(&token, Awaiting::Enrolment).is_some(),
            "and still waiting"
        );
    }

    #[test]
    fn a_sign_in_is_named_by_its_token_and_gone_once_spent() {
        let pending = sign_ins();
        let token = begin(&pending, "u1");
        let taken = pending.code(&token).expect("waiting");
        assert_eq!(taken.user_id(), "u1");
        assert!(pending.code(&token).is_none(), "taken out while in use");
        taken.spend();
        assert!(pending.code(&token).is_none(), "spent");
    }

    #[test]
    fn a_step_that_issues_nothing_gives_the_sign_in_back() {
        let pending = sign_ins();
        let token = begin(&pending, "u1");
        drop(pending.code(&token).expect("waiting"));
        assert_eq!(pending.code(&token).expect("back").user_id(), "u1");
    }

    #[test]
    fn a_second_sign_in_leaves_the_first_and_says_it_is_there() {
        let pending = sign_ins();
        let first = pending.begin("u1", HASH, CODE).unwrap();
        assert_eq!(first.others, 0);
        let second = pending.begin("u1", HASH, CODE).unwrap();
        assert_eq!(second.others, 1);
        assert!(
            pending.code(&first.token).is_some(),
            "the owner's still waits"
        );
        assert!(pending.code(&second.token).is_some());
        assert_eq!(pending.begin("u2", HASH, CODE).unwrap().others, 0);
    }

    #[test]
    fn past_eight_for_one_account_its_oldest_goes() {
        let pending = sign_ins();
        let now = Instant::now();
        let oldest = pending.begin_at("u1", HASH, CODE, now).unwrap().token;
        for n in 1..=MAX_PER_ACCOUNT {
            let at = now + Duration::from_millis(n as u64);
            pending.begin_at("u1", HASH, CODE, at).unwrap();
        }
        assert_eq!(pending.len(), MAX_PER_ACCOUNT);
        assert!(pending.code(&oldest).is_none());
    }

    #[test]
    fn a_sign_in_knows_the_password_it_was_proved_against() {
        let pending = sign_ins();
        let token = begin(&pending, "u1");
        let taken = pending.code(&token).expect("waiting");
        assert!(taken.began_under(HASH));
        assert!(!taken.began_under("$argon2id$v=19$changed"));
    }

    #[test]
    fn an_expired_or_made_up_token_names_nothing() {
        let pending = sign_ins();
        let now = Instant::now();
        let token = pending.begin_at("u1", HASH, CODE, now).unwrap().token;
        assert!(pending.take_at(&token, CODE, now + LIFETIME).is_none());
        assert_eq!(pending.len(), 0, "and it is not given back");
        for made_up in ["", "not base64!", "AAAA"] {
            assert!(pending.code(&Secret::new(made_up)).is_none(), "{made_up:?}");
        }
    }

    #[test]
    fn past_the_cap_the_oldest_goes() {
        let pending = sign_ins();
        let now = Instant::now();
        let oldest = pending.begin_at("u0", HASH, CODE, now).unwrap().token;
        for n in 1..=MAX_PENDING {
            let at = now + Duration::from_millis(n as u64);
            pending.begin_at(&format!("u{n}"), HASH, CODE, at).unwrap();
        }
        assert_eq!(pending.len(), MAX_PENDING);
        assert!(pending.code(&oldest).is_none());
    }
}
