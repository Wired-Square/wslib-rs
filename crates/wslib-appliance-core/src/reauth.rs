//! Asking a signed-in caller for their password, or a passkey, again, for a
//! route whose consequence outlives the session: the extractor decided the rung,
//! and this asks whether whoever holds the cookie knows the password behind it.

use std::time::Duration;

use chrono::Utc;
use wslib_appliance_auth::{AuthError, Passkeys};
use wslib_appliance_store::{Account, Store};
use wslib_appliance_types::STALE_PROOF;
use wslib_appliance_types::passkey::AssertionCredential;
use wslib_appliance_types::session::{Reauthentication, SignInMethod};
use wslib_secret::Secret;

use crate::extract::{Identity, Principal, Vouches};
use crate::{ApiError, ApplianceState, Reached};

/// How long a resolver's [`Principal::reauthenticated_at`] stands in for the
/// password, for an account the store does not hold.
pub const REAUTHENTICATION_WINDOW: Duration = Duration::from_secs(5 * 60);

/// Prove the password or a passkey behind `who`'s session or store account, or
/// refuse; answers the method proved, or `None` where a recent proof stood in.
/// `what` names the action in the audit log, for a refusal and a proof alike.
///
/// A passkey in `proof` answers a challenge from `Passkeys::begin_reauthentication`
/// on the relying party `reached` names. The control socket has nothing to prove
/// and is answered 404; a route that must refuse it uses
/// [`SessionAdmin`](crate::SessionAdmin).
///
/// Under `Callers::resolved_from_store` the window never stands in. Any other
/// resolver's account proves itself only by its [`Principal::reauthenticated_at`],
/// no older than [`REAUTHENTICATION_WINDOW`] and not in the future; neither a
/// password nor a passkey is read for it, and nothing is looked up in the store.
///
/// A wrong or missing proof is 403, not 401, which would send the caller back to
/// sign in; the attempt is audited under the account it was tried against.
pub async fn reauthenticate(
    app: &ApplianceState,
    who: &Identity,
    reached: &Reached,
    proof: Reauthentication,
    what: &'static str,
) -> Proved {
    let proved = match proof.passkey {
        Some(credential) => {
            passkey_in(
                &app.store,
                &app.passkeys,
                app.vouches,
                who,
                reached,
                &credential,
                what,
            )
            .await?
        }
        None => reauthenticate_in(&app.store, app.vouches, who, proof.password, what).await?,
    };
    if let Some(method) = proved {
        crate::audit!(app, who, "re-authenticated", "what" => what, "method" => method.as_str())
            .await;
    }
    Ok(proved)
}

/// The method that proved the caller just now, or `None` where a recent proof
/// stood in.
pub type Proved = Result<Option<SignInMethod>, ApiError>;

async fn reauthenticate_in(
    store: &Store,
    vouches: Vouches,
    who: &Identity,
    password: Option<Secret>,
    what: &'static str,
) -> Proved {
    let (id, username) = match (who, vouches) {
        (Identity::Resolved(principal), Vouches::StoreAccounts) => {
            (&principal.id, &principal.username)
        }
        (Identity::Resolved(principal), _) => return recently(principal, what).map(|()| None),
        _ => {
            let user = who.signed_in()?;
            (&user.id, &user.username)
        }
    };
    let password = password
        .filter(|p| !p.is_empty())
        .ok_or_else(|| wrong_password(username, id, what))?;
    prove_password(store, id, password, what).await?;
    Ok(Some(SignInMethod::Password))
}

async fn passkey_in(
    store: &Store,
    passkeys: &Passkeys,
    vouches: Vouches,
    who: &Identity,
    reached: &Reached,
    credential: &AssertionCredential,
    what: &'static str,
) -> Proved {
    let (id, username) = match who {
        Identity::Resolved(principal) if vouches == Vouches::StoreAccounts => {
            (&principal.id, &principal.username)
        }
        Identity::Resolved(principal) => return recently(principal, what).map(|()| None),
        _ => {
            let user = who.signed_in()?;
            (&user.id, &user.username)
        }
    };
    let rp = reached.relying_party()?;
    let refusal = match passkeys
        .finish_reauthentication(store, &rp, id, credential)
        .await
    {
        Ok(_) => return Ok(Some(SignInMethod::Passkey)),
        Err(e @ AuthError::PasskeyRefused(_)) => (e, "the passkey was not accepted"),
        Err(e @ AuthError::PasskeyCounterDidNotMove(_)) => (
            e,
            "the passkey's counter did not move, so it may have been cloned",
        ),
        Err(e) => return Err(e.into()),
    };
    tracing::warn!(
        name: "audit",
        actor = %username,
        actor_id = %id,
        user_id = %id,
        what,
        method = "passkey",
        "re-authentication refused: {}",
        refusal.1
    );
    Err(refusal.0.into())
}

fn recently(principal: &Principal, what: &'static str) -> Result<(), ApiError> {
    let now = Utc::now();
    let recent = principal.reauthenticated_at.is_some_and(|at| {
        (now - at)
            .to_std()
            .is_ok_and(|age| age <= REAUTHENTICATION_WINDOW)
    });
    if recent {
        return Ok(());
    }
    tracing::warn!(
        name: "audit",
        actor = %principal.username,
        actor_id = %principal.id,
        user_id = %principal.id,
        what,
        "re-authentication refused: the password was not confirmed recently"
    );
    Err(ApiError::ProofRefused(format!(
        "{STALE_PROOF} in the last {} minutes",
        REAUTHENTICATION_WINDOW.as_secs() / 60
    )))
}

pub(crate) fn wrong_password(username: &str, id: &str, what: &'static str) -> ApiError {
    tracing::warn!(
        name: "audit",
        actor = %username,
        actor_id = %id,
        user_id = %id,
        what,
        method = "password",
        "re-authentication refused: the password is wrong"
    );
    ApiError::ProofRefused("the password is incorrect".to_string())
}

/// Prove the password of the caller's own store account `id`, handing back the
/// account, hash included; a wrong password is 403 and audited under `what`.
/// No dummy verification: the caller is already signed in as this account.
pub async fn prove_password(
    store: &Store,
    id: &str,
    password: Secret,
    what: &'static str,
) -> Result<Account, ApiError> {
    let account = store
        .user_by_id(id)
        .await?
        .ok_or(ApiError::Unauthenticated)?;

    let tried = account.clone();
    let verified = tokio::task::spawn_blocking(move || {
        wslib_appliance_auth::verify_password(&tried, password.expose())
    })
    .await
    .map_err(|e| ApiError::internal("check the password", &e))?;

    match verified {
        true => Ok(account),
        false => Err(wrong_password(&account.user.username, id, what)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, TimeDelta};
    use wslib_appliance_types::Role;

    /// An account the store has never heard of, as a resolver vouches for it.
    fn resolved(reauthenticated_at: Option<DateTime<Utc>>) -> Identity {
        Identity::Resolved(Principal {
            id: "console:7".to_string(),
            username: "admin".to_string(),
            role: Role::Admin,
            reauthenticated_at,
        })
    }

    async fn attempt(who: &Identity) -> Proved {
        let store = Store::open_in_memory(None).await.expect("store");
        reauthenticate_in(&store, Vouches::Unsaid, who, None, "a test").await
    }

    /// A store row whose password is `correct horse battery`.
    async fn store_account(reauthenticated_at: Option<DateTime<Utc>>) -> (Store, Identity) {
        let store = Store::open_in_memory(None).await.expect("store");
        let hash = wslib_appliance_auth::hash_password("correct horse battery").expect("hash");
        let user = store
            .create_user("admin", &hash, Role::Admin)
            .await
            .expect("an account");
        let who = Identity::Resolved(Principal {
            id: user.id,
            username: user.username,
            role: Role::Admin,
            reauthenticated_at,
        });
        (store, who)
    }

    fn is_wrong_password(refused: &ApiError) -> bool {
        matches!(refused, ApiError::ProofRefused(message) if message == "the password is incorrect")
    }

    #[tokio::test]
    async fn a_store_accounts_password_is_proved_against_its_own_row_and_a_gone_one_is_signed_out()
    {
        for reauthenticated_at in [None, Some(Utc::now())] {
            let (store, who) = store_account(reauthenticated_at).await;
            let prove = |password: &str| {
                let password = Some(Secret::new(password));
                reauthenticate_in(&store, Vouches::StoreAccounts, &who, password, "a test")
            };

            prove("correct horse battery").await.expect("the password");
            let refused = prove("not it").await.expect_err("the wrong password");
            assert!(
                is_wrong_password(&refused),
                "{reauthenticated_at:?}: {refused:?}"
            );

            store
                .delete_user(who.account_id().expect("an account"))
                .await
                .expect("delete");
            let gone = prove("correct horse battery")
                .await
                .expect_err("no account");
            assert!(matches!(gone, ApiError::Unauthenticated), "{gone:?}");
        }
    }

    #[tokio::test]
    async fn a_store_accounts_blank_password_is_refused_inside_the_window() {
        let (store, who) = store_account(Some(Utc::now())).await;
        let logs = crate::logs(&[]).ring().clone();
        let _logging = tracing::subscriber::set_default(logs.subscriber());

        for blank in [None, Some(Secret::new(""))] {
            let refused = reauthenticate_in(&store, Vouches::StoreAccounts, &who, blank, "a test")
                .await
                .expect_err("no password");
            assert!(is_wrong_password(&refused), "{refused:?}");
        }
        let records = logs.snapshot().records;
        assert_eq!(records.len(), 2, "{records:?}");
        assert!(
            records
                .iter()
                .all(|r| r.message == "re-authentication refused: the password is wrong"),
            "{records:?}"
        );
    }

    #[tokio::test]
    async fn a_consoles_account_is_never_proved_by_a_password() {
        let window = TimeDelta::from_std(REAUTHENTICATION_WINDOW).expect("in range");
        let (store, who) = store_account(Some(Utc::now() - window - TimeDelta::seconds(1))).await;
        let password = Some(Secret::new("correct horse battery"));
        let refused = reauthenticate_in(&store, Vouches::Console, &who, password, "a test")
            .await
            .expect_err("stale");
        assert!(
            matches!(&refused, ApiError::ProofRefused(message) if message.contains("5 minutes")),
            "{refused:?}"
        );
    }

    #[tokio::test]
    async fn a_recent_reauthentication_stands_in_for_the_password() {
        let recent = Utc::now() - TimeDelta::minutes(4);
        let proved = attempt(&resolved(Some(recent)))
            .await
            .expect("re-authenticated four minutes ago");
        assert_eq!(proved, None, "nothing proved just now");
    }

    #[tokio::test]
    async fn none_stale_or_future_is_refused_without_a_store_lookup() {
        let window = TimeDelta::from_std(REAUTHENTICATION_WINDOW).expect("in range");
        let now = Utc::now();
        for at in [
            None,
            Some(now - window - TimeDelta::seconds(1)),
            Some(now + TimeDelta::minutes(1)),
        ] {
            let refused = attempt(&resolved(at)).await.expect_err("not recent");
            assert!(
                matches!(&refused, ApiError::ProofRefused(message) if message.contains("5 minutes")),
                "{at:?}: {refused:?}"
            );
        }
    }

    #[tokio::test]
    async fn the_right_password_proves_an_account_and_a_wrong_one_or_a_gone_one_does_not() {
        let store = Store::open_in_memory(None).await.expect("store");
        let hash = wslib_appliance_auth::hash_password("correct horse battery").expect("hash");
        let user = store
            .create_user("admin", &hash, Role::Admin)
            .await
            .expect("an account");
        let prove =
            |password: &str| prove_password(&store, &user.id, Secret::new(password), "a test");

        let account = prove("correct horse battery").await.expect("the password");
        assert_eq!(account.user.id, user.id);
        let refused = prove("not it").await.expect_err("the wrong password");
        assert!(is_wrong_password(&refused), "{refused:?}");

        store.delete_user(&user.id).await.expect("delete");
        let gone = prove("correct horse battery")
            .await
            .expect_err("no account");
        assert!(matches!(gone, ApiError::Unauthenticated), "{gone:?}");
    }

    fn unverifiable() -> AssertionCredential {
        use wslib_appliance_types::passkey::AssertionResponse;
        AssertionCredential {
            id: "AQ".into(),
            raw_id: "AQ".into(),
            kind: "public-key".into(),
            response: AssertionResponse {
                client_data_json: "e30".into(),
                authenticator_data: "AA".into(),
                signature: "AA".into(),
                user_handle: None,
            },
        }
    }

    async fn by_passkey(store: &Store, vouches: Vouches, who: &Identity) -> Proved {
        let reached = Reached::at("box.local", 443);
        let passkeys = Passkeys::default();
        passkey_in(
            store,
            &passkeys,
            vouches,
            who,
            &reached,
            &unverifiable(),
            "a test",
        )
        .await
    }

    #[tokio::test]
    async fn a_refused_passkey_is_a_403_audited_under_the_account() {
        let (store, resolved) = store_account(None).await;
        let Identity::Resolved(principal) = &resolved else {
            unreachable!()
        };
        let session =
            Identity::Session(store.user_by_id(&principal.id).await.unwrap().unwrap().user);
        let logs = crate::logs(&[]).ring().clone();
        let _logging = tracing::subscriber::set_default(logs.subscriber());

        for (vouches, who) in [
            (Vouches::StoreAccounts, &resolved),
            (Vouches::Unsaid, &session),
        ] {
            let refused = by_passkey(&store, vouches, who).await.expect_err("refused");
            assert!(
                matches!(&refused, ApiError::ProofRefused(m) if m == "the passkey was not accepted"),
                "{refused:?}"
            );
        }
        let audited = logs
            .snapshot()
            .records
            .iter()
            .filter(|r| {
                r.message
                    .contains("re-authentication refused: the passkey was not accepted")
            })
            .count();
        assert_eq!(audited, 2);
    }

    #[tokio::test]
    async fn a_consoles_account_and_the_socket_are_not_proved_by_a_passkey() {
        let store = Store::open_in_memory(None).await.expect("store");
        let stale = by_passkey(&store, Vouches::Console, &resolved(None))
            .await
            .expect_err("stale");
        assert!(
            matches!(&stale, ApiError::ProofRefused(m) if m.contains("5 minutes")),
            "{stale:?}"
        );
        let recent = by_passkey(&store, Vouches::Console, &resolved(Some(Utc::now())))
            .await
            .expect("the recent proof stands in");
        assert_eq!(recent, None, "and the passkey proved nothing");
        let refused = by_passkey(&store, Vouches::Unsaid, &Identity::Local)
            .await
            .expect_err("nobody");
        assert!(matches!(refused, ApiError::NotFound(_)), "{refused:?}");
    }

    #[tokio::test]
    async fn the_control_socket_is_not_anybody_and_has_nothing_to_prove() {
        for socket in [
            Identity::Local,
            Identity::LocalPeer("control-socket:root".into()),
            Identity::Socket {
                ceiling: Role::Admin,
                peer: None,
            },
            Identity::Socket {
                ceiling: Role::Admin,
                peer: Some("control-socket:root".into()),
            },
        ] {
            let refused = attempt(&socket).await.expect_err("nobody");
            assert!(matches!(refused, ApiError::NotFound(_)), "{refused:?}");
        }
    }
}
