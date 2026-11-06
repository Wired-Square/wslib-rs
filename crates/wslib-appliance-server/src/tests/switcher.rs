//! The console's app switcher, as the harness answers it in front of a product.

use axum::http::StatusCode;
use serde_json::{Value, json};
use wslib_appliance_types::Role;

use crate::testing::{Harness, body_json, console};

async fn behind_a_console() -> Harness {
    Harness::builder()
        .base_path("/apps/widgets/".parse().unwrap())
        .console_app("widgets", &["ann", "bob"])
        .console_app("gauges", &["bob"])
        .console_app("dials", &[])
        .build()
        .await
}

async fn switcher(app: &Harness, username: &str) -> Value {
    let response = app
        .get("/api/switcher")
        .from_console(&console(username, Role::Viewer))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    body_json(response).await
}

#[tokio::test]
async fn the_switcher_lists_the_console_first_then_only_the_apps_the_caller_may_open() {
    let app = behind_a_console().await;
    let console = json!({"name": "console", "href": "/"});
    assert_eq!(
        switcher(&app, "ann").await,
        json!([console, {"name": "widgets", "href": "/apps/widgets/"}])
    );
    assert_eq!(
        switcher(&app, "bob").await,
        json!([
            console,
            {"name": "widgets", "href": "/apps/widgets/"},
            {"name": "gauges", "href": "/apps/gauges/"},
        ])
    );
    assert_eq!(switcher(&app, "cat").await, json!([console]));
}

#[tokio::test]
async fn the_switcher_refuses_a_caller_the_console_does_not_assert() {
    let app = behind_a_console().await;
    let response = app.get("/api/switcher").send().await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn the_product_is_still_served_beneath_the_switcher() {
    let app = behind_a_console().await;
    let response = app.get("/apps/widgets/healthz").send().await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn a_product_alone_does_not_answer_the_switcher() {
    let app = Harness::new().await;
    let response = app
        .get("/api/switcher")
        .from_console(&console("ann", Role::Viewer))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
