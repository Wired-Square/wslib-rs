//! The extractors over a session, as a route reaches them through the
//! assembled router.

use axum::Router;
use axum::http::StatusCode;
use wslib_appliance_store::Store;
use wslib_appliance_types::Role;

use crate::testing::{Harness, body_bytes, body_json, body_text, unclaimed};
use crate::tests::rungs;
use crate::{ApiError, ApplianceState, SessionAdmin, Unclaimed};

async fn with_users() -> Harness {
    Harness::builder().users_routes().build().await
}

#[tokio::test]
async fn a_request_with_no_cookie_is_not_signed_in() {
    let app = with_users().await;
    let response = app.get("/api/users").send().await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_token_this_box_did_not_sign_is_not_signed_in() {
    let app = with_users().await;
    for token in ["", "not.a.token", "a.b.c"] {
        let response = app.get("/api/users").cookie(token).send().await;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{token:?} must not resolve"
        );
    }
}

#[tokio::test]
async fn the_ladder_is_at_least_not_exactly() {
    let app = with_users().await;
    let admin = app.signed_in("admin", Role::Admin).await;
    let operator = app.signed_in("operator", Role::Operator).await;
    let viewer = app.signed_in("viewer", Role::Viewer).await;

    // An admin satisfies the rungs below it.
    assert_eq!(
        app.get("/api/session").cookie(&admin).send().await.status(),
        StatusCode::OK
    );
    assert_eq!(
        app.get("/api/users").cookie(&admin).send().await.status(),
        StatusCode::OK
    );

    // And a lower rung does not reach up.
    for token in [&operator, &viewer] {
        let response = app.get("/api/users").cookie(token).send().await;
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "only an admin may list accounts"
        );
    }
    assert_eq!(
        app.get("/api/session")
            .cookie(&viewer)
            .send()
            .await
            .status(),
        StatusCode::OK,
        "but a viewer is signed in"
    );
}

#[tokio::test]
async fn a_refusal_for_the_wrong_role_is_not_a_refusal_for_no_session() {
    let app = with_users().await;
    let viewer = app.signed_in("viewer", Role::Viewer).await;

    assert_eq!(
        app.get("/api/users").cookie(&viewer).send().await.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        app.get("/api/users").send().await.status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn the_control_socket_satisfies_every_role_with_no_account_at_all() {
    let app = with_users().await;
    assert_eq!(app.store().user_count().await.unwrap(), 0);

    let response = app.get("/api/users").local().send().await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn local_authority_cannot_be_asked_for_by_a_client() {
    let app = with_users().await;
    let response = app
        .get("/api/users")
        .header("x-local-authority", "true")
        .header("local-authority", "1")
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_disabled_account_loses_its_session_on_the_very_next_request() {
    let app = with_users().await;
    let token = app.signed_in("admin", Role::Admin).await;
    assert_eq!(
        app.get("/api/users").cookie(&token).send().await.status(),
        StatusCode::OK
    );

    let id = app.user_id("admin").await;
    app.store().set_enabled(&id, false).await.unwrap();

    assert_eq!(
        app.get("/api/users").cookie(&token).send().await.status(),
        StatusCode::UNAUTHORIZED,
        "disabling an account takes effect on the next request"
    );
}

/// One route behind [`SessionAdmin`], mounted through `Server::api`.
async fn with_a_session_only_route() -> Harness {
    async fn stop(SessionAdmin(who): SessionAdmin) -> String {
        who.actor().to_string()
    }
    Harness::builder()
        .api(Router::new().route("/stop", axum::routing::post(stop)))
        .build()
        .await
}

#[tokio::test]
async fn a_signed_in_administrator_may_stop_the_appliance() {
    let app = with_a_session_only_route().await;
    let token = app.admin("admin").await;

    let response = app.post("/api/stop").cookie(&token).send().await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        String::from_utf8_lossy(&body_bytes(response).await),
        "admin",
        "and the handler has the identity it needs to audit the change"
    );
}

#[tokio::test]
async fn the_control_socket_may_not_stop_the_appliance() {
    let app = with_a_session_only_route().await;

    let response = app.post("/api/stop").local().send().await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let body = body_json(response).await;
    assert!(
        body["error"].as_str().is_some_and(|e| e.contains("socket")),
        "the refusal has to name the socket, or it reads as a role problem: {body}"
    );
}

#[tokio::test]
async fn a_cookie_on_a_socket_request_does_not_become_the_caller() {
    let app = with_a_session_only_route().await;
    let admin = app.admin("admin").await;

    assert_eq!(
        app.post("/api/stop")
            .local()
            .cookie(&admin)
            .send()
            .await
            .status(),
        StatusCode::FORBIDDEN,
        "a valid admin session on a socket request is still the socket"
    );
}

#[tokio::test]
async fn the_socket_refusal_is_not_a_way_around_the_ladder() {
    let app = with_a_session_only_route().await;
    let viewer = app.signed_in("viewer", Role::Viewer).await;

    assert_eq!(
        app.post("/api/stop").cookie(&viewer).send().await.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        app.post("/api/stop").send().await.status(),
        StatusCode::UNAUTHORIZED,
        "and no session at all is still 401, not 403"
    );
}

/// Answers the account count it saw inside `hold`'s transaction.
fn with_an_unclaimed_route() -> crate::testing::HarnessBuilder {
    async fn claim(
        unclaimed: Unclaimed,
        axum::extract::State(app): axum::extract::State<ApplianceState>,
    ) -> Result<String, ApiError> {
        let mut tx = unclaimed.hold(&app.store).await?;
        let count = Store::user_count_in(&mut tx).await?;
        Ok(count.to_string())
    }
    Harness::builder().api(Router::new().route("/claim", axum::routing::post(claim)))
}

#[tokio::test]
async fn unclaimed_refuses_the_control_socket() {
    let app = with_an_unclaimed_route().build().await;
    let response = app.post("/api/claim").local().send().await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn unclaimed_refuses_a_box_that_already_has_an_account() {
    let app = with_an_unclaimed_route().build().await;
    assert_eq!(
        app.post("/api/claim").send().await.status(),
        StatusCode::OK,
        "an empty box is offered"
    );
    app.create("admin", Role::Viewer).await;
    assert_eq!(
        app.post("/api/claim").send().await.status(),
        StatusCode::CONFLICT,
        "any account at all, whatever its role, claims the box"
    );
}

#[tokio::test]
async fn unclaimed_refuses_a_deployment_that_onboards_over_the_socket_only() {
    let app = with_an_unclaimed_route()
        .deployed(|b| b.browser_onboarding = false)
        .build()
        .await;
    assert_eq!(
        app.post("/api/claim").send().await.status(),
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn satisfies_agrees_with_the_rungs_for_a_session() {
    use axum::extract::Path;
    use axum::routing::get;

    let satisfies = get(
        |crate::Viewer(who): crate::Viewer, Path(role): Path<Role>| async move {
            who.satisfies(role).to_string()
        },
    );
    let app = Harness::builder()
        .api(rungs().route("/satisfies/{role}", satisfies))
        .build()
        .await;
    for held in Role::LADDER {
        let session = app.signed_in(held.as_str(), held).await;
        for needed in Role::LADDER {
            let rung = app.get(&format!("/api/rung/{needed}")).cookie(&session);
            let admitted = rung.send().await.status() == StatusCode::OK;
            let says = app.get(&format!("/api/satisfies/{needed}"));
            assert_eq!(
                body_text(says.cookie(&session).send().await).await,
                admitted.to_string(),
                "{held} session, {needed}"
            );
        }
    }
}

#[tokio::test]
async fn hold_refuses_a_box_claimed_between_the_check_and_the_write() {
    let app = with_users().await;
    let unclaimed = unclaimed();
    app.create("admin", Role::Admin).await;

    let refused = unclaimed
        .hold(app.store())
        .await
        .expect_err("the box was claimed");
    assert!(matches!(refused, ApiError::Conflict(_)), "{refused:?}");
}
