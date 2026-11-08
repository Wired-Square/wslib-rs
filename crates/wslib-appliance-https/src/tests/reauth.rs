//! `reauthenticate` for a session, against accounts the harness made.

use tracing::instrument::WithSubscriber;
use wslib_appliance_core::backend;
use wslib_appliance_types::Role;
use wslib_appliance_types::session::Reauthentication;
use wslib_secret::Secret;

use crate::testing::Harness;
use crate::{ApiError, Identity, Reached, reauthenticate};

/// An account, and the identity a request from it carries.
async fn session_of(app: &Harness, username: &str, role: Role) -> Identity {
    app.create(username, role).await;
    let account = app
        .store()
        .user_by_username(username)
        .await
        .expect("read")
        .expect("exists");
    Identity::Session(account.user)
}

fn password(password: &str) -> Reauthentication {
    Reauthentication {
        password: Some(Secret::new(password)),
        passkey: None,
    }
}

async fn prove(app: &Harness, who: &Identity, proof: Reauthentication) -> Result<(), ApiError> {
    reauthenticate(app.state(), who, &Reached::default(), proof, "a test")
        .await
        .map(drop)
}

#[tokio::test]
async fn the_control_socket_has_no_password_to_prove() {
    let app = Harness::new().await;
    let refused = prove(&app, &Identity::Local, password(Harness::PASSWORD))
        .await
        .expect_err("the socket is nobody");
    assert!(matches!(refused, ApiError::NotFound(_)), "{refused:?}");
}

#[tokio::test]
async fn a_wrong_or_missing_password_is_refused_and_the_session_is_not() {
    let app = Harness::new().await;
    let who = session_of(&app, "admin", Role::Admin).await;

    for attempt in [
        password("not it"),
        password(""),
        Reauthentication::default(),
    ] {
        let refused = prove(&app, &who, attempt)
            .await
            .expect_err("no right password");
        assert!(
            matches!(&refused, ApiError::ProofRefused(message) if message == "the password is incorrect"),
            "{refused:?}"
        );
    }
}

#[tokio::test]
async fn the_right_password_proves_the_session_again_into_the_audit_log() {
    let app = Harness::new().await;
    let who = session_of(&app, "operator", Role::Operator).await;

    prove(&app, &who, password(Harness::PASSWORD))
        .await
        .expect("the password behind the session");
    let row = app.audit_row("re-authenticated").await;
    assert_eq!(row.actor, "operator");
    assert_eq!(
        row.fields,
        [
            ("what".to_string(), "a test".to_string()),
            ("method".to_string(), "password".to_string())
        ]
    );
}

#[tokio::test]
async fn an_account_deleted_under_a_live_session_is_signed_out_rather_than_checked() {
    let app = Harness::new().await;
    let who = session_of(&app, "admin", Role::Admin).await;
    app.store()
        .delete_user(&who.user().expect("a session").id)
        .await
        .expect("delete");

    let refused = prove(&app, &who, password(Harness::PASSWORD))
        .await
        .expect_err("no account to check against");
    assert!(matches!(refused, ApiError::Unauthenticated), "{refused:?}");
}

#[tokio::test]
async fn a_wrong_password_is_audited_under_the_signed_in_account() {
    let app = Harness::new().await;
    let who = session_of(&app, "admin", Role::Admin).await;
    let logs = backend::ring(backend::logs(app.state()));
    prove(&app, &who, password("not it"))
        .with_subscriber(logs.subscriber())
        .await
        .expect_err("the wrong password");

    let row = app
        .audit_row("re-authentication refused: the password is wrong")
        .await;
    assert_eq!(row.actor, "admin");
    assert_eq!(row.actor_id.as_deref(), who.account_id());
}
