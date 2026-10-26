//! argon2id through `wslib-auth-password`, and the sign-in path that uses it.
//!
//! The stored value is a PHC string — algorithm, parameters and salt all
//! travel with the hash — so a hash made at parameters weaker than
//! `wslib-auth-password`'s is re-hashed by the next successful password
//! sign-in, without a migration and without ending the account's sessions.

use wslib_appliance_store::{Account, Store};
use wslib_appliance_types::{MAX_PASSWORD_BYTES, MIN_PASSWORD_LEN};
use wslib_auth_password::{PasswordError, Policy};
use wslib_secret::Secret;

use crate::{AuthError, off_thread};

/// Counted in characters, not bytes, so a passphrase in a language that does
/// not spell its words in ASCII is not held to a longer one.
const POLICY: Policy = Policy::with_min_chars(MIN_PASSWORD_LEN);

impl From<PasswordError> for AuthError {
    fn from(e: PasswordError) -> Self {
        match e {
            PasswordError::TooShort { min_chars } => Self::PasswordTooShort(min_chars),
            PasswordError::TooLong { max_bytes } => Self::PasswordTooLong(max_bytes),
            PasswordError::Hash(e) => Self::Hash(e),
        }
    }
}

/// Hash a password for storage. **Blocks.** See the crate doc.
pub fn hash_password(password: &str) -> Result<String, AuthError> {
    Ok(POLICY.hash(password)?)
}

/// Whether `password` matches `account`'s stored PHC string. **Blocks.**
///
/// False rather than an error on a hash this cannot parse, or a password over
/// [`MAX_PASSWORD_BYTES`]. A corrupt row must authenticate nobody, and neither
/// must look different from a wrong password to whoever is trying — the log
/// lines below are where they are visible instead.
pub fn verify_password(account: &Account, password: &str) -> bool {
    let stored = account.password_hash.expose();
    let verified = wslib_auth_password::verify(stored, password);
    if verified {
        return true;
    }
    let user_id = &account.user.id;
    if let Err(e) = argon2::PasswordHash::new(stored) {
        tracing::error!(%user_id, error = %e, "a stored password hash is unreadable");
    }
    if password.len() > MAX_PASSWORD_BYTES {
        tracing::warn!(%user_id, "a password tried is over the maximum, so it cannot verify");
    }
    false
}

/// Whether no new account may take `name`: one containing `:`, or starting with
/// `control-socket` in any case, would pass for a control socket's audit actor,
/// and `onboarding` in any case for the actor of a write before the box is claimed.
#[doc(hidden)]
pub fn is_reserved_username(name: &str) -> bool {
    const SOCKET: &str = "control-socket";
    name.contains(':')
        || name.eq_ignore_ascii_case("onboarding")
        || name
            .get(..SOCKET.len())
            .is_some_and(|start| start.eq_ignore_ascii_case(SOCKET))
}

/// Check a username and password.
///
/// Every refusal is [`AuthError::Refused`] and an `audit` event (see the crate
/// doc); an unknown name [`is_reserved_username`] refuses is recorded quoted.
/// A success is no `audit` event and is not a sign-in yet: whatever issues the
/// session stamps the login and writes that row.
///
/// Every path takes one `spawn_blocking` hop and one argon2 call, and the
/// password is verified before the account's enabled-ness, so the three
/// refusals cost the same; answering a disabled account early would not.
///
/// A hash that `needs_rehash` is rewritten once the sign-in has passed every
/// check, and the account is returned with the hash now stored. A rewrite lost
/// to another sign-in's returns that one's hash; one lost to a password change,
/// or failed, returns the account as it was verified.
pub async fn authenticate(
    store: &Store,
    username: &str,
    password: &str,
) -> Result<Account, AuthError> {
    let account = store.user_by_username(username).await?;

    let tried = account.clone();
    let candidate = password.to_string();
    let verified = off_thread(move || match &tried {
        Some(tried) => verify_password(tried, &candidate),
        None => wslib_auth_password::verify_absent(&candidate),
    })
    .await?;

    let Some(account) = account else {
        let tried = if is_reserved_username(username) {
            format!("{username:?}")
        } else {
            username.to_owned()
        };
        tracing::warn!(
            name: "audit",
            actor = %tried,
            method = "password",
            "sign-in refused: no such account"
        );
        return Err(AuthError::Refused);
    };

    if !verified {
        tracing::warn!(
            name: "audit",
            actor = %account.user.username,
            user_id = %account.user.id,
            method = "password",
            "sign-in refused: wrong password"
        );
        return Err(AuthError::Refused);
    }

    if !account.user.enabled {
        tracing::warn!(
            name: "audit",
            actor = %account.user.username,
            user_id = %account.user.id,
            method = "password",
            "sign-in refused: the account is disabled"
        );
        return Err(AuthError::Refused);
    }

    Ok(rehashed(store, account, password).await)
}

async fn rehashed(store: &Store, account: Account, password: &str) -> Account {
    if !wslib_auth_password::needs_rehash(account.password_hash.expose()) {
        return account;
    }
    match rewrite(store, &account, password).await {
        Ok(Some(rewritten)) => return rewritten,
        Ok(None) => tracing::info!(
            user_id = %account.user.id,
            "the password changed while its hash was re-made; the change stands"
        ),
        Err(e) => tracing::warn!(
            user_id = %account.user.id,
            error = %e,
            "a password hash at old parameters was not re-hashed"
        ),
    }
    account
}

/// `account` as stored once its hash is re-made, by this write or by a
/// concurrent sign-in's; `None` if the password has changed since.
async fn rewrite(
    store: &Store,
    account: &Account,
    password: &str,
) -> Result<Option<Account>, AuthError> {
    let candidate = password.to_owned();
    let fresh = off_thread(move || wslib_auth_password::rehash(&candidate)).await??;
    let (id, verified) = (&account.user.id, account.password_hash.expose());
    if store.rehash_password(id, verified, &fresh).await? {
        let password_hash = Secret::new(fresh);
        return Ok(Some(Account {
            password_hash,
            ..account.clone()
        }));
    }
    let Some(stored) = store.user_by_id(id).await? else {
        return Ok(None);
    };
    let candidate = password.to_owned();
    off_thread(move || verify_password(&stored, &candidate).then_some(stored)).await
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;
    use crate::tests::{
        PASSWORD, STRONG_HASH, WEAK_HASH, hash_of_password, store, user, user_with_hash,
    };
    use wslib_appliance_store::sqlx;
    use wslib_appliance_types::Role;

    async fn stored(store: &Store, id: &str) -> Account {
        store.user_by_id(id).await.expect("read").expect("row")
    }

    #[test]
    fn the_length_bounds_are_the_wire_constants() {
        assert_eq!(MAX_PASSWORD_BYTES, wslib_auth_password::MAX_BYTES);
        assert!(matches!(
            hash_password(&"x".repeat(MIN_PASSWORD_LEN - 1)),
            Err(AuthError::PasswordTooShort(MIN_PASSWORD_LEN))
        ));
        assert!(matches!(
            hash_password(&"x".repeat(MAX_PASSWORD_BYTES + 1)),
            Err(AuthError::PasswordTooLong(MAX_PASSWORD_BYTES))
        ));
    }

    #[tokio::test]
    async fn a_right_password_returns_the_account_and_stamps_no_sign_in() {
        let store = store().await;
        let created = user(&store, "admin", Role::Admin).await;

        let account = authenticate(&store, "admin", PASSWORD)
            .await
            .expect("the password");
        assert_eq!(account.user.id, created.id);

        let after = stored(&store, &created.id).await;
        assert_eq!(
            after.user.last_login_at, None,
            "a code may still be asked; the session's issue stamps it"
        );
    }

    #[tokio::test]
    async fn all_three_refusals_are_the_same_answer() {
        let store = store().await;
        user(&store, "admin", Role::Admin).await;
        let disabled = user(&store, "disabled", Role::Viewer).await;
        store
            .set_enabled(&disabled.id, false)
            .await
            .expect("disable");

        for (username, password) in [
            ("nobody", PASSWORD),
            ("admin", "the wrong password"),
            ("disabled", PASSWORD),
        ] {
            let e = authenticate(&store, username, password)
                .await
                .expect_err("must refuse");
            assert!(matches!(e, AuthError::Refused), "{e:?}");
            assert_eq!(e.to_string(), "the username or password is incorrect");
        }
    }

    #[tokio::test]
    async fn a_corrupt_row_refuses_rather_than_erroring_differently() {
        let store = store().await;
        let created = user(&store, "admin", Role::Admin).await;
        store
            .set_password(&created.id, "not a phc string")
            .await
            .expect("corrupt the row");

        let e = authenticate(&store, "admin", PASSWORD)
            .await
            .expect_err("must refuse");
        assert!(matches!(e, AuthError::Refused), "{e:?}");
    }

    #[tokio::test]
    async fn a_hash_under_weaker_parameters_is_rewritten_on_sign_in() {
        let store = store().await;
        let created = user_with_hash(&store, WEAK_HASH).await;

        let account = authenticate(&store, "admin", PASSWORD)
            .await
            .expect("sign in");
        let rewritten = stored(&store, &created.id).await.password_hash;
        assert_ne!(rewritten.expose(), WEAK_HASH);
        assert_eq!(
            account.password_hash.expose(),
            rewritten.expose(),
            "returned as written"
        );
    }

    #[tokio::test]
    async fn a_hash_under_stronger_parameters_is_kept_on_sign_in() {
        let store = store().await;
        let created = user_with_hash(&store, STRONG_HASH).await;

        authenticate(&store, "admin", PASSWORD)
            .await
            .expect("sign in");
        let kept = stored(&store, &created.id).await.password_hash;
        assert_eq!(kept.expose(), STRONG_HASH);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_password_change_while_the_sign_in_re_hashes_wins() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let store = Store::open(dir.path().join("appliance.db"), None)
            .await
            .expect("store");
        let created = user_with_hash(&store, WEAK_HASH).await;

        let mut held = store.begin().await.expect("the change's write lock");
        sqlx::query("UPDATE users SET password_hash = 'changed' WHERE id = ?")
            .bind(&created.id)
            .execute(&mut *held)
            .await
            .expect("the change");
        let signing_in = tokio::spawn({
            let store = store.clone();
            async move { authenticate(&store, "admin", PASSWORD).await }
        });
        // Only the re-hash's write holds a connection this long: the read
        // before it is over in well under a millisecond.
        let deadline = Instant::now() + Duration::from_secs(4);
        let mut blocked_since = None;
        while blocked_since.is_none_or(|at: Instant| at.elapsed() < Duration::from_millis(100)) {
            assert!(Instant::now() < deadline, "the re-hash never blocked");
            let in_use = store.pool().size() as usize - store.pool().num_idle();
            blocked_since = (in_use >= 2).then(|| blocked_since.unwrap_or_else(Instant::now));
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        held.commit().await.expect("commit");

        let account = signing_in
            .await
            .expect("the task")
            .expect("not a failed sign-in");
        assert_eq!(
            account.password_hash.expose(),
            WEAK_HASH,
            "the hash it verified"
        );
        let after = stored(&store, &created.id).await;
        assert_eq!(after.password_hash.expose(), "changed");
    }

    #[test]
    fn the_hashes_the_other_tests_reuse_are_real_ones() {
        for hash in [hash_of_password(), WEAK_HASH, STRONG_HASH] {
            assert!(wslib_auth_password::verify(hash, PASSWORD));
            assert!(!wslib_auth_password::verify(hash, "something else"));
        }
        assert!(wslib_auth_password::needs_rehash(WEAK_HASH));
    }
}
