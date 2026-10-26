//! Recovery codes: [`wslib_auth_totp`]'s ten, of which the store keeps only
//! the hashes, spending one only while TOTP is on.

use wslib_appliance_store::Store;
use wslib_appliance_types::totp::RecoveryCodes;
use wslib_auth_totp::{generate_recovery_codes, recovery_code_hash};

use crate::{AuthError, CodeAttempts};

/// Replace the recovery codes of an account with TOTP on with ten new ones,
/// returned this once.
pub async fn issue_recovery_codes(
    store: &Store,
    user_id: &str,
) -> Result<RecoveryCodes, AuthError> {
    if !store
        .totp(user_id)
        .await?
        .is_some_and(|totp| totp.confirmed)
    {
        return Err(AuthError::TotpNotEnrolled);
    }
    let (codes, hashes) = fresh_recovery_codes()?;
    store.set_recovery_codes(user_id, &hashes).await?;
    Ok(codes)
}

/// Ten codes, and the hashes the store keeps of them.
pub(crate) fn fresh_recovery_codes() -> Result<(RecoveryCodes, Vec<String>), AuthError> {
    let (codes, hashes) = generate_recovery_codes().map_err(|_| AuthError::Random)?;
    Ok((RecoveryCodes { codes }, hashes))
}

/// Sign in with a recovery code in place of a TOTP code, spending it.
pub async fn use_recovery_code(
    store: &Store,
    attempts: &CodeAttempts,
    user_id: &str,
    code: &str,
) -> Result<(), AuthError> {
    let attempt = attempts.admit(user_id)?;
    if !store
        .use_recovery_code(user_id, &recovery_code_hash(code))
        .await?
    {
        return Err(AuthError::CodeRefused);
    }
    attempt.succeeded();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{store, user};
    use std::time::SystemTime;
    use wslib_appliance_types::Role;
    use wslib_secret::Secret;

    const KEY: &str = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

    async fn with_totp_on(store: &Store) -> String {
        let admin = user(store, "admin", Role::Admin).await;
        let secret = Secret::new(KEY);
        assert!(store.enrol_totp(&admin.id, &secret).await.expect("enrol"));
        assert!(
            store
                .confirm_totp(&admin.id, &secret, 1, &[])
                .await
                .expect("confirm")
        );
        admin.id
    }

    #[tokio::test]
    async fn ten_distinct_codes_of_sixteen_base32_characters_in_four_groups() {
        let store = store().await;
        let id = with_totp_on(&store).await;
        let issued = issue_recovery_codes(&store, &id).await.expect("issue");

        assert_eq!(issued.codes.len(), 10);
        let mut seen = std::collections::BTreeSet::new();
        for code in &issued.codes {
            let groups: Vec<&str> = code.expose().split('-').collect();
            assert_eq!(groups.len(), 4, "{}", code.expose());
            assert!(groups.iter().all(|g| {
                g.len() == 4
                    && g.bytes()
                        .all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b))
            }));
            assert!(seen.insert(code.expose().to_owned()), "a repeated code");
        }
        assert_eq!(store.recovery_codes_left(&id).await.expect("count"), 10);
    }

    #[tokio::test]
    async fn no_codes_are_issued_without_totp_on() {
        let store = store().await;
        let admin = user(&store, "admin", Role::Admin).await;
        let e = issue_recovery_codes(&store, &admin.id).await;
        assert!(matches!(e, Err(AuthError::TotpNotEnrolled)), "{e:?}");

        store
            .enrol_totp(&admin.id, &Secret::new(KEY))
            .await
            .expect("enrol");
        let e = issue_recovery_codes(&store, &admin.id).await;
        assert!(matches!(e, Err(AuthError::TotpNotEnrolled)), "{e:?}");
        assert_eq!(
            store.recovery_codes_left(&admin.id).await.expect("count"),
            0
        );
    }

    #[tokio::test]
    async fn a_recovery_code_signs_in_once() {
        let store = store().await;
        let attempts = CodeAttempts::default();
        let id = with_totp_on(&store).await;
        let issued = issue_recovery_codes(&store, &id).await.expect("issue");
        let typed = issued.codes[3].expose().to_lowercase().replace('-', " ");

        use_recovery_code(&store, &attempts, &id, &typed)
            .await
            .expect("signs in");
        assert_eq!(store.recovery_codes_left(&id).await.expect("count"), 9);
        let again = use_recovery_code(&store, &attempts, &id, &typed).await;
        assert!(matches!(again, Err(AuthError::CodeRefused)), "{again:?}");
    }

    #[tokio::test]
    async fn recovery_codes_count_against_the_limit_codes_share() {
        let store = store().await;
        let attempts = CodeAttempts::default();
        let id = with_totp_on(&store).await;
        let issued = issue_recovery_codes(&store, &id).await.expect("issue");
        for _ in 0..5 {
            let e = use_recovery_code(&store, &attempts, &id, "AAAA-AAAA-AAAA-AAAA").await;
            assert!(matches!(e, Err(AuthError::CodeRefused)), "{e:?}");
        }

        let e = use_recovery_code(&store, &attempts, &id, issued.codes[0].expose()).await;
        assert!(matches!(e, Err(AuthError::TooManyCodes(_))), "{e:?}");
        let totp = crate::verify_totp(&store, &attempts, &id, "123456", SystemTime::now()).await;
        assert!(matches!(totp, Err(AuthError::TooManyCodes(_))), "{totp:?}");
        assert_eq!(
            store.recovery_codes_left(&id).await.expect("count"),
            10,
            "a refused attempt spends nothing"
        );
    }

    #[tokio::test]
    async fn a_right_recovery_code_clears_the_wrong_ones_before_it() {
        let store = store().await;
        let attempts = CodeAttempts::default();
        let id = with_totp_on(&store).await;
        let issued = issue_recovery_codes(&store, &id).await.expect("issue");
        let wrong = || use_recovery_code(&store, &attempts, &id, "AAAA-AAAA-AAAA-AAAA");

        for _ in 0..4 {
            let e = wrong().await;
            assert!(matches!(e, Err(AuthError::CodeRefused)), "{e:?}");
        }
        use_recovery_code(&store, &attempts, &id, issued.codes[0].expose())
            .await
            .expect("signs in");
        for _ in 0..5 {
            let e = wrong().await;
            assert!(matches!(e, Err(AuthError::CodeRefused)), "{e:?}");
        }
    }
}
