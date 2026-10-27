//! The first account, offered to the browser on a box that has none: the first
//! caller to reach it owns it. `GET` is public; `POST /api/onboarding` takes
//! [`Unclaimed`], makes an administrator only while the box has no
//! accounts at all, and signs the caller in. Without
//! `Bootstrap::browser_onboarding`, `POST` is refused and `GET` answers `false`,
//! and the first account is the control socket's `POST /api/users`.

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use wslib_appliance_core::backend::{self, claimed};
use wslib_appliance_types::session::{FirstAccount, Onboarding};
use wslib_appliance_types::{Role, User};

use crate::routes::session::{SetCookie, issued_after_writing};
use crate::routes::users::{clean_new_username, hash};
use crate::{ApiError, ApplianceState, Identity, Unclaimed, audit};

pub(crate) fn routes() -> Router<ApplianceState> {
    Router::new().route("/onboarding", get(status).post(create))
}

/// Public: a browser asks before it has a session.
async fn status(State(app): State<ApplianceState>) -> Result<Json<Onboarding>, ApiError> {
    Ok(Json(Onboarding {
        needed: backend::onboarding(&app) && app.store.user_count().await? == 0,
    }))
}

/// The store checks the box is empty in the statement that writes, so two
/// racing browsers get one 201 and one 409.
async fn create(
    _: Unclaimed,
    State(app): State<ApplianceState>,
    Json(body): Json<FirstAccount>,
) -> Result<(StatusCode, SetCookie, Json<User>), ApiError> {
    backend::sessions(&app)?;
    let username = clean_new_username(&body.username)?;
    let hash = hash(body.password).await?;

    let user = app
        .store
        .create_first_user(&username, &hash, Role::Admin)
        .await?
        .ok_or_else(claimed)?;
    app.store.stamp_login(&user.id).await?;
    let cookie = issued_after_writing(&app, &user, user.created_at).await?;

    let who = Identity::Session(user.clone());
    audit!(&app, &who, "made the first account and signed in").await;

    Ok((StatusCode::CREATED, cookie, Json(user)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{Harness, body_json};
    use wslib_appliance_types::Role;

    fn first(username: &str, password: &str) -> serde_json::Value {
        serde_json::json!({ "username": username, "password": password })
    }

    async fn needed(app: &Harness) -> bool {
        let response = app.get("/api/onboarding").send().await;
        assert_eq!(response.status(), StatusCode::OK);
        body_json(response).await["needed"].as_bool().unwrap()
    }

    #[tokio::test]
    async fn an_empty_box_offers_its_first_account_and_then_stops_offering() {
        let app = Harness::new().await;
        assert!(needed(&app).await);

        let response = app
            .post("/api/onboarding")
            .json(first("owner", Harness::PASSWORD))
            .send()
            .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let token = Harness::session_from(&response).expect("signed in as the new account");
        let body = body_json(response).await;
        assert_eq!(body["username"], "owner");
        assert_eq!(body["role"], "admin");

        let me = app.get("/api/session").cookie(&token).send().await;
        assert_eq!(me.status(), StatusCode::OK);
        assert_eq!(body_json(me).await["username"], "owner");

        assert!(!needed(&app).await);
    }

    #[tokio::test]
    async fn a_box_with_an_account_refuses_a_second_first_one() {
        let app = Harness::new().await;
        app.create("admin", Role::Viewer).await;
        assert!(!needed(&app).await);

        let response = app
            .post("/api/onboarding")
            .json(first("intruder", Harness::PASSWORD))
            .send()
            .await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(
            Harness::session_from(&response).is_none(),
            "a refusal must not hand out a cookie"
        );
        assert!(!app.signs_in("intruder", Harness::PASSWORD).await);
        assert_eq!(app.store().user_count().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn the_screen_is_offered_only_where_the_deployment_onboards_in_the_browser() {
        for browser in [true, false] {
            let app = Harness::builder()
                .deployed(|b| b.browser_onboarding = browser)
                .build()
                .await;
            assert_eq!(needed(&app).await, browser);
        }
    }

    #[tokio::test]
    async fn a_deployment_that_onboards_over_the_socket_says_so_once() {
        let app = Harness::builder()
            .deployed(|b| b.browser_onboarding = false)
            .build()
            .await;
        assert!(!needed(&app).await, "the screen must not be offered");

        let response = app
            .post("/api/onboarding")
            .json(first("owner", Harness::PASSWORD))
            .send()
            .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(app.store().user_count().await.unwrap(), 0);
        let response = app
            .post("/api/users")
            .local()
            .json(serde_json::json!({
                "username": "owner", "password": Harness::PASSWORD, "role": "admin"
            }))
            .send()
            .await;
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn the_control_socket_is_sent_to_its_own_route() {
        let app = Harness::new().await;
        let response = app
            .post("/api/onboarding")
            .local()
            .json(first("owner", Harness::PASSWORD))
            .send()
            .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(app.store().user_count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn the_first_account_goes_through_the_same_checks_as_any_other() {
        let app = Harness::new().await;

        let response = app
            .post("/api/onboarding")
            .json(first("owner", "short"))
            .send()
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(
            body_json(response).await["error"]
                .as_str()
                .unwrap()
                .contains(&wslib_appliance_types::MIN_PASSWORD_LEN.to_string())
        );

        for username in ["  ", "control-socket:owner"] {
            let response = app
                .post("/api/onboarding")
                .json(first(username, Harness::PASSWORD))
                .send()
                .await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{username:?}");
        }

        assert!(needed(&app).await, "a refused attempt leaves the box empty");
    }

    #[tokio::test]
    async fn the_first_account_is_signed_in_as_far_as_the_users_screen_can_tell() {
        let app = Harness::builder().users_routes().build().await;
        let response = app
            .post("/api/onboarding")
            .json(first("owner", Harness::PASSWORD))
            .send()
            .await;
        let token = Harness::session_from(&response).expect("signed in");

        let users = app.get("/api/users").cookie(&token).send().await;
        assert_eq!(users.status(), StatusCode::OK);
        let users = body_json(users).await;
        assert_eq!(users[0]["username"], "owner");
        assert!(!users[0]["last_login_at"].is_null(), "{users}");
    }

    #[tokio::test]
    async fn making_the_first_account_is_written_to_the_audit_log_as_that_account() {
        let app = Harness::new().await;
        app.post("/api/onboarding")
            .json(first("owner", Harness::PASSWORD))
            .send()
            .await;

        let page = app.store().audit(10, None).await.unwrap();
        assert_eq!(page.items[0].actor, "owner");
        assert_eq!(
            page.items[0].message,
            "made the first account and signed in"
        );
    }
}
