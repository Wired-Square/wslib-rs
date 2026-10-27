//! The extractors, as a route reaches them through the assembled router.

use axum::Router;
use axum::http::StatusCode;
use axum::routing::{get, post};
use wslib_appliance_store::Store;
use wslib_appliance_types::Role;

use crate::testing::{Harness, HarnessBuilder, body_bytes, body_json, console, unclaimed};
use crate::{Admin, ApiError, ApplianceState, ResolveCaller, SessionAdmin, Unclaimed};

/// Through `Server::api`, so the extractor is reached in the nest, behind the same fallback.
async fn with_product_routes() -> Harness {
    async fn stop(SessionAdmin(who): SessionAdmin) -> String {
        who.actor().to_string()
    }
    Harness::builder()
        .api(
            Router::new()
                .route("/devices", get(|_: Admin| async {}))
                .route("/stop", post(stop)),
        )
        .build()
        .await
}

#[tokio::test]
async fn a_request_the_console_vouches_for_nobody_on_is_not_signed_in() {
    let app = with_product_routes().await;
    let response = app.get("/api/devices").send().await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_refusal_for_the_wrong_role_is_not_a_refusal_for_nobody() {
    let app = with_product_routes().await;
    let viewer = console("viewer", Role::Viewer);
    assert_eq!(
        app.get("/api/devices")
            .from_console(&viewer)
            .send()
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        app.get("/api/devices").send().await.status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn the_control_socket_satisfies_every_role_with_no_account_at_all() {
    let app = with_product_routes().await;
    assert_eq!(app.store().user_count().await.unwrap(), 0);

    let response = app.get("/api/devices").local().send().await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn local_authority_cannot_be_asked_for_by_a_client() {
    let app = with_product_routes().await;
    let response = app
        .get("/api/devices")
        .header("x-local-authority", "true")
        .header("local-authority", "1")
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn an_administrator_may_stop_the_appliance() {
    let app = with_product_routes().await;
    let response = app
        .post("/api/stop")
        .from_console(&crate::tests::admin())
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        String::from_utf8_lossy(&body_bytes(response).await),
        "admin",
        "and the handler has the identity it needs to audit the change"
    );
}

#[tokio::test]
async fn the_control_socket_may_not_stop_the_appliance() {
    let app = with_product_routes().await;

    let response = app.post("/api/stop").local().send().await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let body = body_json(response).await;
    assert!(
        body["error"].as_str().is_some_and(|e| e.contains("socket")),
        "the refusal has to name the socket, or it reads as a role problem: {body}"
    );
}

#[tokio::test]
async fn an_asserted_caller_on_a_socket_request_does_not_become_the_caller() {
    let app = with_product_routes().await;
    assert_eq!(
        app.post("/api/stop")
            .local()
            .from_console(&crate::tests::admin())
            .send()
            .await
            .status(),
        StatusCode::FORBIDDEN,
        "an administrator asserted on a socket request is still the socket"
    );
}

#[tokio::test]
async fn the_socket_refusal_is_not_a_way_around_the_ladder() {
    let app = with_product_routes().await;
    assert_eq!(
        app.post("/api/stop")
            .from_console(&console("viewer", Role::Viewer))
            .send()
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        app.post("/api/stop").send().await.status(),
        StatusCode::UNAUTHORIZED,
        "and nobody at all is still 401, not 403"
    );
}

struct Nobody;

impl ResolveCaller for Nobody {
    async fn resolve(
        &self,
        _: &axum::http::request::Parts,
    ) -> Result<Option<crate::Principal>, ApiError> {
        Ok(None)
    }
}

/// Answers the account count `hold`'s transaction saw.
fn with_an_unclaimed_route() -> HarnessBuilder {
    async fn claim(
        unclaimed: Unclaimed,
        axum::extract::State(app): axum::extract::State<ApplianceState>,
    ) -> Result<String, ApiError> {
        let mut tx = unclaimed.hold(&app.store).await?;
        let count = Store::user_count_in(&mut tx).await?;
        Ok(count.to_string())
    }
    Harness::builder()
        .resolver_from_store(Nobody)
        .api(Router::new().route("/claim", post(claim)))
}

async fn an_account(app: &Harness, role: Role) {
    app.store()
        .create_user("admin", "unverified", role)
        .await
        .expect("an account");
}

#[tokio::test]
async fn unclaimed_refuses_the_control_socket() {
    let app = with_an_unclaimed_route().build().await;
    let response = app.post("/api/claim").local().send().await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = body_json(response).await;
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|e| e.contains("control socket")),
        "the refusal names the socket: {body}"
    );
}

#[tokio::test]
async fn unclaimed_refuses_a_box_that_already_has_an_account() {
    let app = with_an_unclaimed_route().build().await;
    assert_eq!(
        app.post("/api/claim").send().await.status(),
        StatusCode::OK,
        "an empty box is offered"
    );
    an_account(&app, Role::Viewer).await;
    assert_eq!(
        app.post("/api/claim").send().await.status(),
        StatusCode::CONFLICT,
        "any account at all, whatever its role, claims the box"
    );
}

#[tokio::test]
async fn hold_refuses_a_box_claimed_between_the_check_and_the_write() {
    let app = Harness::new().await;
    let unclaimed = unclaimed();
    an_account(&app, Role::Admin).await;

    let refused = unclaimed
        .hold(app.store())
        .await
        .expect_err("the box was claimed");
    assert!(matches!(refused, ApiError::Conflict(_)), "{refused:?}");
}
