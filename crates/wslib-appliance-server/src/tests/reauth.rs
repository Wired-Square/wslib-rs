//! `reauthenticate`, into an assembled appliance's audit log.

use tracing::instrument::WithSubscriber;
use wslib_appliance_core::backend;
use wslib_appliance_types::Role;

use crate::testing::Harness;
use crate::{Identity, Principal, reauthenticate};

#[tokio::test]
async fn a_resolvers_account_without_a_recent_proof_is_refused_into_the_audit_log() {
    let app = Harness::new().await;
    let who = Identity::Resolved(Principal {
        id: "console:7".to_string(),
        username: "console-admin".to_string(),
        role: Role::Admin,
        reauthenticated_at: None,
    });
    let logs = backend::ring(backend::logs(app.state()));
    let reached = crate::Reached::default();
    reauthenticate(
        app.state(),
        &who,
        &reached,
        Default::default(),
        "factory reset",
    )
    .with_subscriber(logs.subscriber())
    .await
    .expect_err("never re-authenticated");

    let row = app
        .audit_row("re-authentication refused: the password was not confirmed recently")
        .await;
    assert_eq!(row.actor, "console-admin");
    assert_eq!(row.level, "WARN");
    let field = |name: &str| {
        row.fields
            .iter()
            .find(|(field, _)| field == name)
            .map(|(_, value)| value.as_str())
    };
    assert_eq!(row.actor_id.as_deref(), Some("console:7"));
    assert_eq!(field("user_id"), Some("console:7"));
    assert_eq!(field("what"), Some("factory reset"));
}
