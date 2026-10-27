//! Passkeys: [`wslib_auth_passkey`]'s ceremonies over the store's passkeys and
//! accounts.
//!
//! Every refusal of a response is one error outward, [`AuthError::PasskeyRefused`],
//! and a journal line inward naming the check; a counter that did not move is
//! its own, [`AuthError::PasskeyCounterDidNotMove`], as a sign of a cloned
//! authenticator.

use wslib_appliance_store::{Account, NewPasskey, Passkey, PasskeyUse, Store};
use wslib_appliance_types::User;
use wslib_appliance_types::passkey::{
    AssertionCredential, CreationOptions, MAX_PASSKEY_NAME_LEN, PasskeyView,
    RegistrationCredential, RequestOptions,
};
use wslib_auth_passkey::{Assertion, Ceremonies, HostError, Refused, StoredPasskey};
pub use wslib_auth_passkey::{RelyingParty, claimed_user_id};

use crate::AuthError;

#[cfg(test)]
mod tests;

/// Which ceremony a refusal came from, which decides how it is answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ceremony {
    Registration,
    SignIn,
    Reauthentication,
}

/// Who a passkey signed in, and with which of their passkeys.
#[derive(Debug)]
pub struct PasskeySignIn {
    pub account: Account,
    pub passkey_id: String,
}

/// The ceremonies under way. One per process, shared by every route that runs
/// one; `Clone` shares it.
#[derive(Debug, Clone, Default)]
pub struct Passkeys {
    ceremonies: Ceremonies,
}

impl Passkeys {
    /// Options to make a passkey for `user` on `rp`, which `rp_name` names to
    /// the person making it.
    pub async fn begin_registration(
        &self,
        store: &Store,
        rp: &RelyingParty,
        user: &User,
        rp_name: &str,
    ) -> Result<CreationOptions, AuthError> {
        let existing = store.passkeys(&user.id).await?;
        self.ceremonies
            .begin_registration(
                rp,
                rp_name,
                &user.id,
                &user.username,
                existing.iter().map(|passkey| &passkey.credential_id),
            )
            .map_err(|_| AuthError::Random)
    }

    /// Verify a new passkey for `user_id` and keep it under `name`. One already
    /// registered, to anybody, is `StoreError::PasskeyTaken`.
    pub async fn finish_registration(
        &self,
        store: &Store,
        rp: &RelyingParty,
        user_id: &str,
        name: &str,
        credential: &RegistrationCredential,
    ) -> Result<PasskeyView, AuthError> {
        let name = passkey_name(name)?;
        let new = self
            .ceremonies
            .finish_registration(rp, user_id, credential)
            .map_err(|refusal| refused(Ceremony::Registration, None, refusal))?;
        let passkey = store
            .add_passkey(
                user_id,
                NewPasskey {
                    credential_id: new.credential_id,
                    public_key: new.public_key,
                    sign_count: new.sign_count,
                    name,
                    rp_id: rp.id().to_owned(),
                },
            )
            .await?;
        Ok(passkey.view())
    }

    /// Options for a sign-in on `rp` with whichever passkey the person picks.
    pub fn begin_sign_in(&self, rp: &RelyingParty) -> Result<RequestOptions, AuthError> {
        self.ceremonies
            .begin_sign_in(rp)
            .map_err(|_| AuthError::Random)
    }

    /// Verify a sign-in by the enabled account the passkey names; whatever
    /// issues the session stamps it.
    pub async fn finish_sign_in(
        &self,
        store: &Store,
        rp: &RelyingParty,
        credential: &AssertionCredential,
    ) -> Result<PasskeySignIn, AuthError> {
        let ceremony = Ceremony::SignIn;
        let assertion = self
            .ceremonies
            .read_sign_in(rp, credential)
            .map_err(|refusal| refused(ceremony, None, refusal))?;
        let (passkey, sign_count) = verify(store, ceremony, &assertion).await?;
        let account = store
            .user_by_id(&passkey.user_id)
            .await?
            .ok_or_else(|| rejected(ceremony, "the passkey's account is gone"))?;
        if !account.user.enabled {
            return Err(rejected(ceremony, "the account is disabled"));
        }
        count(store, ceremony, &passkey, sign_count).await?;
        Ok(PasskeySignIn {
            account,
            passkey_id: passkey.id,
        })
    }

    /// Options for `user_id` to prove itself again with one of its passkeys
    /// on `rp`; [`AuthError::NoPasskeysHere`] when it has none there.
    pub async fn begin_reauthentication(
        &self,
        store: &Store,
        rp: &RelyingParty,
        user_id: &str,
    ) -> Result<RequestOptions, AuthError> {
        let here: Vec<Passkey> = store
            .passkeys(user_id)
            .await?
            .into_iter()
            .filter(|passkey| passkey.rp_id == rp.id())
            .collect();
        if here.is_empty() {
            return Err(AuthError::NoPasskeysHere(rp.id().to_owned()));
        }
        self.ceremonies
            .begin_reauthentication(
                rp,
                user_id,
                here.iter().map(|passkey| &passkey.credential_id),
            )
            .map_err(|_| AuthError::Random)
    }

    /// Verify that `user_id` proved itself with one of its own passkeys;
    /// answers which one.
    pub async fn finish_reauthentication(
        &self,
        store: &Store,
        rp: &RelyingParty,
        user_id: &str,
        credential: &AssertionCredential,
    ) -> Result<String, AuthError> {
        let ceremony = Ceremony::Reauthentication;
        let assertion = self
            .ceremonies
            .read_reauthentication(rp, user_id, credential)
            .map_err(|refusal| refused(ceremony, None, refusal))?;
        let (passkey, sign_count) = verify(store, ceremony, &assertion).await?;
        count(store, ceremony, &passkey, sign_count).await?;
        Ok(passkey.id)
    }
}

/// A passkey's name as kept: trimmed, one to [`MAX_PASSKEY_NAME_LEN`]
/// characters, no control characters.
pub fn passkey_name(name: &str) -> Result<String, AuthError> {
    let name = name.trim();
    let length = name.chars().count();
    if !(1..=MAX_PASSKEY_NAME_LEN).contains(&length) || name.chars().any(char::is_control) {
        return Err(AuthError::PasskeyName);
    }
    Ok(name.to_owned())
}

impl From<HostError> for AuthError {
    fn from(error: HostError) -> Self {
        match error {
            HostError::IpAddress => Self::NotOnAnIpAddress,
            HostError::NotAName => Self::BadHost,
        }
    }
}

/// The stored passkey that signed, and the count it signed with.
async fn verify(
    store: &Store,
    ceremony: Ceremony,
    assertion: &Assertion,
) -> Result<(Passkey, u32), AuthError> {
    let passkey = store
        .passkey_by_credential_id(assertion.credential_id())
        .await?
        .ok_or_else(|| rejected(ceremony, "no such passkey"))?;
    let sign_count = assertion
        .verify(&StoredPasskey {
            user_id: &passkey.user_id,
            rp_id: &passkey.rp_id,
            public_key: &passkey.public_key,
        })
        .map_err(|refusal| refused(ceremony, Some(&passkey.id), refusal))?;
    Ok((passkey, sign_count))
}

/// §7.2 step 22, through the store's compare-and-swap.
async fn count(
    store: &Store,
    ceremony: Ceremony,
    passkey: &Passkey,
    sign_count: u32,
) -> Result<(), AuthError> {
    match store.use_passkey(&passkey.id, sign_count).await? {
        PasskeyUse::Used => Ok(()),
        PasskeyUse::CounterDidNotMove => {
            tracing::warn!(
                user_id = %passkey.user_id,
                passkey_id = %passkey.id,
                ?ceremony,
                "passkey refused: its counter did not move, so it may have been cloned"
            );
            Err(AuthError::PasskeyCounterDidNotMove(ceremony))
        }
        PasskeyUse::NoSuchPasskey => Err(rejected(ceremony, "the passkey was removed")),
    }
}

fn refused(ceremony: Ceremony, passkey_id: Option<&str>, refusal: Refused) -> AuthError {
    if let Refused::StoredKey(why) = refusal {
        tracing::error!(passkey_id, why, "a stored passkey key is unreadable");
        return AuthError::PasskeyRefused(ceremony);
    }
    rejected(ceremony, refusal.reason())
}

fn rejected(ceremony: Ceremony, reason: &'static str) -> AuthError {
    tracing::warn!(?ceremony, reason, "passkey refused");
    #[cfg(test)]
    tests::LAST_REFUSAL.set(Some(reason));
    AuthError::PasskeyRefused(ceremony)
}
