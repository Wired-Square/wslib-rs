//! `audit!`, through the harness.

use crate::testing::Harness;
use crate::{Identity, Principal};

fn somebody(username: &str) -> Identity {
    Identity::Resolved(Principal {
        id: "an-id".to_string(),
        username: username.to_string(),
        role: wslib_appliance_types::Role::Admin,
        reauthenticated_at: None,
    })
}

#[tokio::test]
async fn an_event_reaches_the_table_with_its_actor_and_fields() {
    let app = Harness::new().await;
    crate::audit!(
        app.state(),
        &somebody("admin"),
        "did a thing",
        "to" => "widget-01",
    )
    .await;

    let page = app.store().audit(10, None).await.expect("read");
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].actor, "admin");
    assert_eq!(page.items[0].actor_id.as_deref(), Some("an-id"));
    assert_eq!(page.items[0].message, "did a thing");
    assert_eq!(
        page.items[0].fields,
        [("to".to_string(), "widget-01".to_string())]
    );
    assert!(
        page.items[0].target.starts_with("wslib_appliance_server"),
        "module_path! is what keeps the target honest: {}",
        page.items[0].target
    );
}

#[tokio::test]
async fn the_control_socket_is_recorded_as_itself() {
    let app = Harness::new().await;
    crate::audit!(app.state(), &Identity::Local, "did a thing").await;

    let page = app.store().audit(10, None).await.expect("read");
    assert_eq!(page.items[0].actor, crate::LOCAL_ACTOR);
    assert_eq!(page.items[0].actor_id, None);
}

#[tokio::test]
async fn a_resolvers_account_is_recorded_under_its_permanent_id() {
    let app = Harness::new().await;
    let who = Identity::Resolved(crate::Principal {
        id: "console:7".to_string(),
        username: "renamed".to_string(),
        role: wslib_appliance_types::Role::Operator,
        reauthenticated_at: None,
    });
    crate::audit!(app.state(), &who, "did a thing").await;

    let page = app.store().audit(10, None).await.expect("read");
    assert_eq!(page.items[0].actor, "renamed");
    assert_eq!(page.items[0].actor_id.as_deref(), Some("console:7"));
}
