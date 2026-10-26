//! TOTP over [`wslib_auth_totp`], against the store: a code accepted one step
//! either side of the box's clock, the key stored in base32.
//!
//! Every check is handed the browser's clock. A confirmation is refused
//! unchecked while it and the box's are more than two steps apart, since the
//! code was just read off a phone that agrees with the browser. A sign-in's
//! code is checked first: a match means the phone agrees with the box, and the
//! step written is always the one matched, so a box merely running ahead
//! writes nothing. A miss with the clocks apart answers the skew instead of a
//! wrong code. A step from the future is written only when the box and the
//! authenticator share a wrong clock; resetting the password clears it.
//!
//! Turning TOTP off is `Store::clear_totp`, once the route has had a code
//! through [`verify_totp`] or the password again.

use std::time::SystemTime;

use wslib_appliance_store::Store;
use wslib_appliance_types::User;
use wslib_appliance_types::totp::{RecoveryCodes, TotpEnrolment};
use wslib_auth::Attempt;
use wslib_auth_totp::{Key, check_clocks};
use wslib_secret::Secret;

use crate::recovery::fresh_recovery_codes;
use crate::{AuthError, CodeAttempts};

/// Start a TOTP enrolment for `user`, replacing one still waiting, and hand
/// back what an authenticator app needs; `issuer` names the appliance there.
pub async fn enrol_totp(
    store: &Store,
    user: &User,
    issuer: &str,
) -> Result<TotpEnrolment, AuthError> {
    let key = Key::generate().map_err(|_| AuthError::Random)?;
    let secret = key.to_base32();
    if !store.enrol_totp(&user.id, &secret).await? {
        return Err(AuthError::TotpAlreadyOn);
    }
    Ok(TotpEnrolment {
        uri: key.otpauth_uri(issuer, &user.username),
        secret,
    })
}

/// Turn on the waiting enrolment with its first code, read when the browser's
/// clock said `browser_time`, and issue the account's recovery codes.
pub async fn confirm_totp(
    store: &Store,
    attempts: &CodeAttempts,
    user_id: &str,
    code: &str,
    browser_time: SystemTime,
) -> Result<RecoveryCodes, AuthError> {
    confirm_totp_at(
        store,
        attempts,
        user_id,
        code,
        browser_time,
        SystemTime::now(),
    )
    .await
}

async fn confirm_totp_at(
    store: &Store,
    attempts: &CodeAttempts,
    user_id: &str,
    code: &str,
    browser_time: SystemTime,
    now: SystemTime,
) -> Result<RecoveryCodes, AuthError> {
    let secret = match store.totp(user_id).await? {
        Some(totp) if totp.confirmed => return Err(AuthError::TotpAlreadyOn),
        Some(totp) => totp.secret,
        None => return Err(AuthError::TotpNotEnrolled),
    };
    check_clocks(browser_time, now).map_err(AuthError::ClockSkew)?;
    let (step, attempt) = accept(attempts, user_id, &secret, code, browser_time, now)?;
    let (codes, hashes) = fresh_recovery_codes()?;
    if store.confirm_totp(user_id, &secret, step, &hashes).await? {
        attempt.succeeded();
        return Ok(codes);
    }
    if store
        .totp(user_id)
        .await?
        .is_some_and(|totp| totp.confirmed)
    {
        attempt.succeeded();
        return Err(AuthError::TotpAlreadyOn);
    }
    Err(AuthError::TotpNotEnrolled)
}

/// Check a sign-in's code, read when the browser's clock said `browser_time`,
/// and spend its step. A code matching a step within the window that is no
/// later than the last one spent is [`AuthError::CodeUsed`]; it is told apart
/// only once the limit admits the attempt, and then does not count against it.
pub async fn verify_totp(
    store: &Store,
    attempts: &CodeAttempts,
    user_id: &str,
    code: &str,
    browser_time: SystemTime,
) -> Result<(), AuthError> {
    verify_totp_at(
        store,
        attempts,
        user_id,
        code,
        browser_time,
        SystemTime::now(),
    )
    .await
}

async fn verify_totp_at(
    store: &Store,
    attempts: &CodeAttempts,
    user_id: &str,
    code: &str,
    browser_time: SystemTime,
    now: SystemTime,
) -> Result<(), AuthError> {
    let totp = store
        .totp(user_id)
        .await?
        .filter(|totp| totp.confirmed)
        .ok_or(AuthError::TotpNotEnrolled)?;
    let (step, attempt) = accept(attempts, user_id, &totp.secret, code, browser_time, now)?;
    if !store.use_totp_step(user_id, step).await? {
        attempt.uncounted();
        return Err(AuthError::CodeUsed);
    }
    attempt.succeeded();
    Ok(())
}

/// The step `code` is accepted for once the limit admits it; a miss is the
/// clocks' skew when they disagree. The attempt counts as wrong until it
/// succeeds, or is withdrawn as a used code.
fn accept(
    attempts: &CodeAttempts,
    user_id: &str,
    secret: &Secret,
    code: &str,
    browser_time: SystemTime,
    now: SystemTime,
) -> Result<(u64, Attempt<String>), AuthError> {
    let key = key(secret, user_id)?;
    let attempt = attempts.admit(user_id)?;
    match key.accepted_step(code, now) {
        Some(step) => Ok((step, attempt)),
        None => {
            check_clocks(browser_time, now).map_err(AuthError::ClockSkew)?;
            Err(AuthError::CodeRefused)
        }
    }
}

/// A stored key that is not 160 bits in base32 signs nobody in, like a
/// password hash that cannot be read.
fn key(secret: &Secret, user_id: &str) -> Result<Key, AuthError> {
    Key::from_base32(secret.expose()).ok_or_else(|| {
        tracing::error!(user_id, "a stored TOTP key is unreadable");
        AuthError::CodeRefused
    })
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use super::*;
    use crate::tests::{store, user};
    use wslib_appliance_types::Role;
    use wslib_appliance_types::totp::ClockSkew;

    fn at(seconds: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(seconds)
    }

    /// Mid-step, so a code taken one step either side is unambiguous.
    const NOW: u64 = 1_700_000_015;

    fn key_of(secret: &Secret) -> Key {
        Key::from_base32(secret.expose()).expect("a key")
    }

    fn step_at(time: SystemTime) -> u64 {
        time.duration_since(UNIX_EPOCH)
            .expect("after 1970")
            .as_secs()
            / 30
    }

    fn code_at(secret: &Secret, time: SystemTime) -> String {
        key_of(secret).code_at(time)
    }

    fn wrong_code(secret: &Secret, time: SystemTime) -> String {
        let key = key_of(secret);
        (0..)
            .map(|n| format!("{n:06}"))
            .find(|code| key.accepted_step(code, time).is_none())
            .expect("three steps cannot cover every code")
    }

    async fn enrolled(store: &Store) -> (User, Secret) {
        let admin = user(store, "admin", Role::Admin).await;
        let enrolment = enrol_totp(store, &admin, "Box").await.expect("enrol");
        (admin, enrolment.secret)
    }

    async fn confirmed(store: &Store, attempts: &CodeAttempts) -> (User, Secret) {
        let (admin, secret) = enrolled(store).await;
        confirm_totp_at(
            store,
            attempts,
            &admin.id,
            &code_at(&secret, at(NOW)),
            at(NOW),
            at(NOW),
        )
        .await
        .expect("confirm");
        (admin, secret)
    }

    async fn is_confirmed(store: &Store, user_id: &str) -> bool {
        store
            .totp(user_id)
            .await
            .expect("read")
            .expect("row")
            .confirmed
    }

    async fn last_step(store: &Store, user_id: &str) -> Option<u64> {
        store
            .totp(user_id)
            .await
            .expect("read")
            .expect("row")
            .last_step
    }

    #[tokio::test]
    async fn an_enrolment_is_a_160_bit_key_and_replaces_one_still_waiting() {
        let store = store().await;
        let (admin, first) = enrolled(&store).await;
        assert_eq!(first.expose().len(), 32);
        key_of(&first);

        let second = enrol_totp(&store, &admin, "Box").await.expect("again");
        assert!(!first.matches(&second.secret));
        assert!(second.uri.expose().contains(second.secret.expose()));
    }

    #[tokio::test]
    async fn confirming_turns_totp_on_and_issues_ten_recovery_codes() {
        let store = store().await;
        let attempts = CodeAttempts::default();
        let (admin, _) = confirmed(&store, &attempts).await;

        let totp = store.totp(&admin.id).await.expect("read").expect("row");
        assert!(totp.confirmed);
        assert_eq!(totp.last_step, Some(step_at(at(NOW))));
        assert_eq!(
            store.recovery_codes_left(&admin.id).await.expect("count"),
            10
        );

        assert!(matches!(
            enrol_totp(&store, &admin, "Box").await,
            Err(AuthError::TotpAlreadyOn)
        ));
    }

    #[tokio::test]
    async fn of_two_confirmations_with_one_right_code_the_loser_is_already_on_and_not_wrong() {
        let store = store().await;
        let attempts = CodeAttempts::default();
        let (admin, secret) = enrolled(&store).await;
        let right = code_at(&secret, at(NOW));
        let confirm = || confirm_totp_at(&store, &attempts, &admin.id, &right, at(NOW), at(NOW));

        let (first, second) = tokio::join!(confirm(), confirm());
        let mut outcomes = [first.is_ok(), second.is_ok()];
        outcomes.sort();
        assert_eq!(outcomes, [false, true], "{first:?} {second:?}");
        let loser = if first.is_ok() { second } else { first };
        assert!(matches!(loser, Err(AuthError::TotpAlreadyOn)), "{loser:?}");
        assert_eq!(attempts.wrong_count(&admin.id), 0);
    }

    #[tokio::test]
    async fn a_wrong_first_code_leaves_the_enrolment_waiting() {
        let store = store().await;
        let attempts = CodeAttempts::default();
        let (admin, secret) = enrolled(&store).await;
        let wrong = wrong_code(&secret, at(NOW));

        let e = confirm_totp_at(&store, &attempts, &admin.id, &wrong, at(NOW), at(NOW)).await;
        assert!(matches!(e, Err(AuthError::CodeRefused)), "{e:?}");
        assert!(!is_confirmed(&store, &admin.id).await);
        assert_eq!(
            store.recovery_codes_left(&admin.id).await.expect("count"),
            0
        );
    }

    #[tokio::test]
    async fn a_confirmation_with_the_clocks_apart_is_refused_before_the_code() {
        let store = store().await;
        let attempts = CodeAttempts::default();
        let (admin, secret) = enrolled(&store).await;
        let box_ahead = at(NOW + 3600);
        let right = code_at(&secret, box_ahead);

        for _ in 0..6 {
            let e = confirm_totp_at(&store, &attempts, &admin.id, &right, at(NOW), box_ahead).await;
            assert!(
                matches!(e, Err(AuthError::ClockSkew(ClockSkew { minutes: 60 }))),
                "{e:?}"
            );
        }
        assert!(!is_confirmed(&store, &admin.id).await);
        confirm_totp_at(&store, &attempts, &admin.id, &right, box_ahead, box_ahead)
            .await
            .expect("no refusal for the skew counted against the limit");
    }

    #[tokio::test]
    async fn a_right_code_signs_in_whatever_the_browser_clock_says() {
        let store = store().await;
        let attempts = CodeAttempts::default();
        let (admin, secret) = confirmed(&store, &attempts).await;
        let later = at(NOW + 60);

        verify_totp_at(
            &store,
            &attempts,
            &admin.id,
            &code_at(&secret, later),
            at(NOW + 3600),
            later,
        )
        .await
        .expect("the phone agrees with the box");
        assert_eq!(last_step(&store, &admin.id).await, Some(step_at(later)));
    }

    #[tokio::test]
    async fn a_wrong_code_with_the_clocks_apart_answers_the_skew_and_counts() {
        let store = store().await;
        let attempts = CodeAttempts::default();
        let (admin, secret) = confirmed(&store, &attempts).await;
        let later = at(NOW + 60);
        let browser = at(NOW + 60 - 5 * 60);
        let wrong = wrong_code(&secret, later);

        for _ in 0..5 {
            let e = verify_totp_at(&store, &attempts, &admin.id, &wrong, browser, later).await;
            assert!(
                matches!(e, Err(AuthError::ClockSkew(ClockSkew { minutes: 5 }))),
                "{e:?}"
            );
        }
        let right = code_at(&secret, later);
        let e = verify_totp_at(&store, &attempts, &admin.id, &right, later, later).await;
        assert!(matches!(e, Err(AuthError::TooManyCodes(_))), "{e:?}");
        assert_eq!(last_step(&store, &admin.id).await, Some(step_at(at(NOW))));
    }

    #[test]
    fn a_stored_key_of_the_wrong_length_signs_nobody_in() {
        for stored in ["", "A", "MZXW6YTBOI", &"A".repeat(40)] {
            assert!(
                matches!(key(&Secret::new(stored), "u1"), Err(AuthError::CodeRefused)),
                "{stored:?}"
            );
        }
        assert!(key(&Secret::new("A".repeat(32)), "u1").is_ok());
    }

    #[tokio::test]
    async fn a_code_signs_in_once_and_never_an_earlier_step_after_it() {
        let store = store().await;
        let attempts = CodeAttempts::default();
        let (admin, secret) = confirmed(&store, &attempts).await;
        let later = at(NOW + 60);
        let verify = |code: String| {
            let (store, attempts, id) = (&store, &attempts, admin.id.clone());
            async move { verify_totp_at(store, attempts, &id, &code, later, later).await }
        };

        verify(code_at(&secret, later)).await.expect("signs in");
        assert_eq!(last_step(&store, &admin.id).await, Some(step_at(later)));

        let replayed = verify(code_at(&secret, later)).await;
        assert!(matches!(replayed, Err(AuthError::CodeUsed)), "{replayed:?}");
        let earlier = verify(code_at(&secret, at(NOW + 30))).await;
        assert!(matches!(earlier, Err(AuthError::CodeUsed)), "{earlier:?}");
        let wrong = verify(wrong_code(&secret, later)).await;
        assert!(matches!(wrong, Err(AuthError::CodeRefused)), "{wrong:?}");
        assert_eq!(attempts.wrong_count(&admin.id), 1);
    }

    #[tokio::test]
    async fn a_used_code_retried_never_locks_out_and_wrong_codes_still_do() {
        let store = store().await;
        let attempts = CodeAttempts::default();
        let (admin, secret) = confirmed(&store, &attempts).await;
        let verify = |code: String| {
            let (store, attempts, id) = (&store, &attempts, admin.id.clone());
            async move { verify_totp_at(store, attempts, &id, &code, at(NOW), at(NOW)).await }
        };
        let used = code_at(&secret, at(NOW));
        let wrong = wrong_code(&secret, at(NOW));

        for _ in 0..6 {
            let e = verify(used.clone()).await;
            assert!(matches!(e, Err(AuthError::CodeUsed)), "{e:?}");
        }
        for _ in 0..4 {
            let e = verify(wrong.clone()).await;
            assert!(matches!(e, Err(AuthError::CodeRefused)), "{e:?}");
        }
        let e = verify(used.clone()).await;
        assert!(matches!(e, Err(AuthError::CodeUsed)), "{e:?}");
        assert_eq!(
            attempts.wrong_count(&admin.id),
            4,
            "a used code takes nothing off either"
        );
        let e = verify(wrong).await;
        assert!(matches!(e, Err(AuthError::CodeRefused)), "{e:?}");
        let e = verify(used).await;
        assert!(matches!(e, Err(AuthError::TooManyCodes(_))), "{e:?}");
    }

    #[tokio::test]
    async fn the_code_that_confirmed_totp_is_used_and_not_wrong() {
        let store = store().await;
        let attempts = CodeAttempts::default();
        let (admin, secret) = confirmed(&store, &attempts).await;
        let again = code_at(&secret, at(NOW));
        let e = verify_totp_at(&store, &attempts, &admin.id, &again, at(NOW), at(NOW)).await;
        assert!(matches!(e, Err(AuthError::CodeUsed)), "{e:?}");
        assert_eq!(
            e.unwrap_err().to_string(),
            "that code has just been used; wait for the next one"
        );
    }

    #[tokio::test]
    async fn a_code_is_not_asked_of_an_account_without_totp_on() {
        let store = store().await;
        let attempts = CodeAttempts::default();
        let (admin, secret) = enrolled(&store).await;
        let e = verify_totp_at(
            &store,
            &attempts,
            &admin.id,
            &code_at(&secret, at(NOW)),
            at(NOW),
            at(NOW),
        )
        .await;
        assert!(matches!(e, Err(AuthError::TotpNotEnrolled)), "{e:?}");
    }

    #[tokio::test]
    async fn past_the_limit_a_right_code_is_refused_and_writes_nothing() {
        let store = store().await;
        let attempts = CodeAttempts::default();
        let (admin, secret) = confirmed(&store, &attempts).await;
        let later = at(NOW + 60);
        let wrong = wrong_code(&secret, later);
        for _ in 0..5 {
            let e = verify_totp_at(&store, &attempts, &admin.id, &wrong, later, later).await;
            assert!(matches!(e, Err(AuthError::CodeRefused)), "{e:?}");
        }

        let right = code_at(&secret, later);
        let e = verify_totp_at(&store, &attempts, &admin.id, &right, later, later).await;
        assert!(matches!(e, Err(AuthError::TooManyCodes(_))), "{e:?}");
        assert_eq!(last_step(&store, &admin.id).await, Some(step_at(at(NOW))));
    }

    #[tokio::test]
    async fn a_right_code_clears_the_wrong_ones_before_it() {
        let store = store().await;
        let attempts = CodeAttempts::default();
        let (admin, secret) = confirmed(&store, &attempts).await;
        let later = at(NOW + 60);
        let wrong = wrong_code(&secret, later);
        let verify = |code: String| {
            let (store, attempts, id) = (&store, &attempts, admin.id.clone());
            async move { verify_totp_at(store, attempts, &id, &code, later, later).await }
        };

        for _ in 0..4 {
            let e = verify(wrong.clone()).await;
            assert!(matches!(e, Err(AuthError::CodeRefused)), "{e:?}");
        }
        verify(code_at(&secret, later)).await.expect("signs in");
        for _ in 0..5 {
            let e = verify(wrong.clone()).await;
            assert!(matches!(e, Err(AuthError::CodeRefused)), "{e:?}");
        }
    }
}
