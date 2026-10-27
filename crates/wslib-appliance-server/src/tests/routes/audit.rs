//! Reading the audit log, through the harness.

use crate::Identity;
use crate::testing::{Harness, body_json, console};
use crate::tests::admin;
use axum::http::StatusCode;
use wslib_appliance_types::Role;

#[tokio::test]
async fn an_admin_reads_the_log_newest_first_and_pages_through_it() {
    let app = Harness::new().await;
    let admin = admin();
    for change in ["one", "two", "three"] {
        crate::audit!(app.state(), &Identity::Local, "changed something", "which" => change).await;
    }

    let first = app
        .get("/api/audit?limit=2")
        .from_console(&admin)
        .send()
        .await;
    assert_eq!(first.status(), StatusCode::OK);
    let body = body_json(first).await;
    assert_eq!(body["items"].as_array().unwrap().len(), 2);

    let cursor = body["next"].as_str().expect("more to come").to_string();
    let second = app
        .get(&format!("/api/audit?limit=2&cursor={cursor}"))
        .from_console(&admin)
        .send()
        .await;
    assert_eq!(second.status(), StatusCode::OK);
    assert!(
        !body_json(second).await["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn a_cursor_that_is_not_ours_is_the_callers_mistake_not_a_broken_box() {
    let app = Harness::new().await;
    let response = app
        .get("/api/audit?cursor=nonsense")
        .from_console(&admin())
        .send()
        .await;
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "a 500 here would send somebody looking at the daemon"
    );
}

#[tokio::test]
async fn reading_the_log_is_not_an_operators_privilege() {
    let app = Harness::new().await;
    assert_eq!(
        app.get("/api/audit")
            .from_console(&console("operator", Role::Operator))
            .send()
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        app.get("/api/audit").send().await.status(),
        StatusCode::UNAUTHORIZED
    );
}
