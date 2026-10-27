//! Passwords, TOTP, recovery codes, passkeys, the sign-ins waiting for a second
//! step, and sessions with the three checks that make revocation immediate.
//!
//! A session holds the account's id, its expiry, and when its credentials were
//! proved and last proved again. The role, whether the account still exists,
//! is disabled, or has had its sessions ended are re-read on **every request**,
//! so disabling an account takes effect on the next one. The caller begins a
//! [`Proof`] before checking any credential; a session issued on it is refused
//! if the account's sessions were ended after it began.
//!
//! [`authenticate`] runs argon2id on `spawn_blocking`, the dummy verification
//! for an unknown name included; [`hash_password`] and [`verify_password`]
//! block.
//!
//! An unknown username, a wrong password and a disabled account are one
//! [`AuthError::Refused`]. Each is logged with its cause as a `tracing` event
//! named `audit` whose `actor` is the username tried.

use std::time::Duration;

use wslib_appliance_types::totp::ClockSkew;

mod attempts;
mod password;
mod pending;
mod recovery;
mod session;
mod totp;
mod webauthn;

pub use attempts::CodeAttempts;
pub use password::{authenticate, hash_password, is_reserved_username, verify_password};
pub use pending::{Awaiting, Begun, Pending, PendingSignIns};
pub use recovery::{issue_recovery_codes, use_recovery_code};
pub use session::Sessions;
pub use totp::{confirm_totp, enrol_totp, verify_totp};
pub use webauthn::{
    Ceremony, PasskeySignIn, Passkeys, RelyingParty, claimed_user_id, passkey_name,
};
pub use wslib_auth::{Proof, SessionToken};

/// Why an authentication attempt did not produce an identity.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuthError {
    /// **Every** sign-in refusal, whatever the cause.
    #[error("the username or password is incorrect")]
    Refused,

    /// No usable session: absent, expired, unknown, or proved before the
    /// account's sessions were ended.
    #[error("not signed in")]
    NoSession,

    #[error("password must be at least {0} characters")]
    PasswordTooShort(usize),

    #[error("password must be at most {0} bytes")]
    PasswordTooLong(usize),

    /// A TOTP code that is wrong, or a recovery code that is wrong or spent.
    #[error("the code is incorrect")]
    CodeRefused,

    /// A TOTP code matching a step within the window no later than the last one
    /// spent.
    #[error("that code has just been used; wait for the next one")]
    CodeUsed,

    /// At confirmation, refused before the code is looked at; at sign-in, the
    /// answer to a code that missed while the clocks are apart.
    #[error("{0}")]
    ClockSkew(ClockSkew),

    /// Too many wrong codes for this account lately; carries how long until
    /// the next is checked.
    #[error("too many wrong codes; try again in {}", in_minutes(*.0))]
    TooManyCodes(Duration),

    #[error("TOTP is already on for this account")]
    TotpAlreadyOn,

    /// No enrolment waiting, for a confirm; TOTP not on, for a code.
    #[error("TOTP is not set up for this account")]
    TotpNotEnrolled,

    /// A passkey's response that did not verify; the journal names the check.
    #[error("the passkey was not accepted")]
    PasskeyRefused(Ceremony),

    /// A passkey whose signature verified with a counter that did not move
    /// past the stored one: possibly a cloned authenticator.
    #[error("the passkey was not accepted")]
    PasskeyCounterDidNotMove(Ceremony),

    #[error(
        "passkeys don't work at an IP address: open this box by its name, with a certificate \
         the browser trusts"
    )]
    NotOnAnIpAddress,

    #[error("the address this box was reached at is not a name a passkey can be made on")]
    BadHost,

    #[error("this account has no passkey made on {0}")]
    NoPasskeysHere(String),

    #[error(
        "a passkey's name must be 1 to {} characters",
        wslib_appliance_types::passkey::MAX_PASSKEY_NAME_LEN
    )]
    PasskeyName,

    #[error("the system's random source failed")]
    Random,

    #[error("hashing: {0}")]
    Hash(String),

    #[error(transparent)]
    Store(#[from] wslib_appliance_store::StoreError),
}

fn in_minutes(wait: Duration) -> String {
    match wait.as_secs().div_ceil(60) {
        1 => "1 minute".to_string(),
        n => format!("{n} minutes"),
    }
}

fn random_bytes<const N: usize>() -> Result<[u8; N], AuthError> {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes).map_err(|_| AuthError::Random)?;
    Ok(bytes)
}

async fn off_thread<T, F>(f: F) -> Result<T, AuthError>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| AuthError::Hash(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wslib_appliance_store::Store;
    use wslib_appliance_types::Role;

    pub(crate) const PASSWORD: &str = "correct horse battery";

    /// One argon2 hash of [`PASSWORD`] for the whole suite, made at the current
    /// parameters.
    pub(crate) fn hash_of_password() -> &'static str {
        static HASH: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        HASH.get_or_init(|| hash_password(PASSWORD).expect("hash"))
    }

    /// [`PASSWORD`] at weaker parameters than `wslib-auth-password`'s.
    pub(crate) const WEAK_HASH: &str = "$argon2id$v=19$m=8192,t=1,p=1$+uybDU2NtBoGgAnkxKZNcw$\
                                        1u9I1O+Sy58/3m++vRqSlZxB+w6KChDjox0kKAgquYo";

    /// [`PASSWORD`] at stronger parameters than `wslib-auth-password`'s.
    pub(crate) const STRONG_HASH: &str = "$argon2id$v=19$m=19456,t=3,p=1$c3Ryb25nZXJwYXJhbXM$\
                                          //tTmM90bHi9H6olo2K4JJvH1yXpwVIYxzDXx2YgNVY";

    pub(crate) async fn store() -> Store {
        Store::open_in_memory(None).await.expect("in-memory store")
    }

    pub(crate) async fn user(
        store: &Store,
        username: &str,
        role: Role,
    ) -> wslib_appliance_types::User {
        store
            .create_user(username, hash_of_password(), role)
            .await
            .expect("create")
    }

    /// An admin named `admin` whose password is [`PASSWORD`], stored as `hash`.
    pub(crate) async fn user_with_hash(store: &Store, hash: &str) -> wslib_appliance_types::User {
        store
            .create_user("admin", hash, Role::Admin)
            .await
            .expect("create")
    }

    #[test]
    fn the_wait_for_another_code_is_whole_minutes_rounded_up() {
        let wait = |secs| AuthError::TooManyCodes(std::time::Duration::from_secs(secs)).to_string();
        assert_eq!(wait(1), "too many wrong codes; try again in 1 minute");
        assert_eq!(wait(60), "too many wrong codes; try again in 1 minute");
        assert_eq!(wait(61), "too many wrong codes; try again in 2 minutes");
        assert_eq!(wait(900), "too many wrong codes; try again in 15 minutes");
    }

    #[test]
    fn two_tokens_are_never_the_same() {
        assert_ne!(random_bytes::<32>().unwrap(), random_bytes::<32>().unwrap());
    }
}
