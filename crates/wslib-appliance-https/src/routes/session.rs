//! Signing in, signing out, and changing your own password; the second factors
//! are core's, mounted over these sessions. These sessions keep no window of a
//! recent proof, so a route that asks for proof takes it in its body.

use axum::extract::State;
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{post, put};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use wslib_appliance_core::backend::{prove_password, sessions, signed_in};
use wslib_appliance_core::{
    HostSessions, Proof, issue_session, password_proved, prove_caller, session_cookie,
};
use wslib_appliance_store::Account;
use wslib_appliance_types::User;
use wslib_appliance_types::session::{PasswordChange, SignIn};

use crate::routes::users::{clean_username, hash};
use crate::{ApiError, ApplianceState, Reached, Viewer, audit};

/// Inside the `/api` nest; `routes::users` names it in a refusal.
pub(crate) const OWN_PASSWORD_ROUTE: &str = "/session/password";

pub(crate) fn routes() -> Router<ApplianceState> {
    Router::new()
        .route("/session", post(sign_in).delete(sign_out))
        .route(OWN_PASSWORD_ROUTE, put(change_password))
        .merge(wslib_appliance_core::second_factor_routes(Cookies))
}

/// Public: it is how a session comes to exist. Every refusal is one 401 with
/// one message. A name no account could have (blank, over the bound, a control
/// character) gets that same answer and writes no audit row, since the row's
/// actor is the name tried. An account with TOTP on is answered 202 with no
/// session, and signs in at `POST /api/session/code`.
async fn sign_in(
    State(app): State<ApplianceState>,
    Json(body): Json<SignIn>,
) -> Result<Response, ApiError> {
    sessions(&app)?;
    let username = clean_username(&body.username).map_err(|_| ApiError::Refused)?;
    let proof = Proof::begin();
    let account =
        wslib_appliance_auth::authenticate(&app.store, &username, body.password.expose()).await?;
    password_proved(&app, &Cookies, account, proof).await
}

#[derive(Clone)]
pub(crate) struct Cookies;

impl HostSessions for Cookies {
    async fn issue(
        &self,
        app: &ApplianceState,
        account: &Account,
        proof: Proof,
    ) -> Result<HeaderValue, ApiError> {
        issue_session(app, &account.user, account.sessions_valid_from, proof).await
    }
}

/// Public, so a dead cookie can still be cleared, and not audited. The removal
/// is sent at the base path whether or not a cookie came, and beside the error
/// when the row could not be ended.
async fn sign_out(State(app): State<ApplianceState>, headers: HeaderMap) -> Response {
    let cookie = session_cookie(&app);
    let ended = async {
        if let Some(token) = cookie.token_in(&headers) {
            sessions(&app)?.end(&token).await?;
        }
        Ok::<_, ApiError>(())
    }
    .await;
    let gone = set_cookie(cookie.clear());
    match ended {
        Ok(()) => (gone, StatusCode::NO_CONTENT).into_response(),
        Err(e) => (gone, e).into_response(),
    }
}

/// The only way to change your own password over HTTPS, at every rung:
/// somebody else's needs a role, your own needs the current password. It is
/// safe at Viewer because its path names no account. The control socket has no
/// account, so is a 404 here. A wrong current password is
/// 403, not 401, as the session stays good. While TOTP is on it also takes a
/// code, a recovery code or a passkey.
async fn change_password(
    Viewer(who): Viewer,
    State(app): State<ApplianceState>,
    reached: Reached,
    Json(body): Json<PasswordChange>,
) -> Result<(SetCookie, StatusCode), ApiError> {
    sessions(&app)?;
    let user = signed_in(&who)?;
    let account = prove_password(
        &app.store,
        &user.id,
        body.current_password,
        "password change",
    )
    .await?;
    let hash = hash(body.new_password).await?;
    if app.store.totp(&user.id).await?.is_some_and(|t| t.confirmed) {
        prove_caller(&app, &who, &reached, body.proof, "password change").await?;
    }

    // Guarded on the verified hash: an unguarded write could land after an
    // administrator's reset and undo it.
    let written = app
        .store
        .set_password_if_unchanged(&user.id, account.password_hash.expose(), &hash)
        .await?;
    let Some(valid_from) = written else {
        tracing::warn!(
            name: "audit",
            actor = %user.username,
            actor_id = %user.id,
            user_id = %user.id,
            "password change refused: the password changed after it was verified"
        );
        return Err(ApiError::Conflict(
            "this account's password was changed by something else while that request was \
             in flight, so nothing was written. If an administrator was resetting it for \
             you, ask them for the new one. If not, treat this account as compromised."
                .to_string(),
        ));
    };
    audit!(&app, &who, "changed their own password").await;

    // The write ended every session, this one included.
    let cookie = issued_after_writing(&app, user, valid_from).await?;
    Ok((cookie, StatusCode::NO_CONTENT))
}

/// A session for `user` after this request wrote its password; its proof begins now.
pub(crate) async fn issued_after_writing(
    app: &ApplianceState,
    user: &User,
    valid_from: DateTime<Utc>,
) -> Result<SetCookie, ApiError> {
    let cookie = issue_session(app, user, valid_from, Proof::begin()).await?;
    Ok(set_cookie(cookie))
}

pub(crate) type SetCookie = [(HeaderName, HeaderValue); 1];

fn set_cookie(value: HeaderValue) -> SetCookie {
    [(header::SET_COOKIE, value)]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{Harness, body_json};
    use wslib_appliance_core::backend::SESSION_COOKIE;
    use wslib_appliance_types::Role;

    fn password_route() -> String {
        format!("/api{OWN_PASSWORD_ROUTE}")
    }

    fn change_to(current: &str, new: &str) -> serde_json::Value {
        serde_json::json!({ "current_password": current, "new_password": new })
    }

    #[tokio::test]
    async fn signing_in_hands_back_the_account_and_a_cookie_that_works() {
        let app = Harness::new().await;
        app.create("admin", Role::Admin).await;

        let response = app
            .post("/api/session")
            .json(serde_json::json!({ "username": "admin", "password": Harness::PASSWORD }))
            .send()
            .await;
        assert_eq!(response.status(), StatusCode::OK);

        let token = Harness::session_from(&response).expect("a session cookie");
        let body = body_json(response).await;
        assert_eq!(body["username"], "admin");
        assert_eq!(body["role"], "admin");
        assert!(body.get("password_hash").is_none(), "{body}");

        let who = app.get("/api/session").cookie(&token).send().await;
        assert_eq!(who.status(), StatusCode::OK);
        let who = body_json(who).await;
        assert_eq!(who["id"], body["id"]);
        let fields =
            |v: &serde_json::Value| v.as_object().unwrap().keys().cloned().collect::<Vec<_>>();
        assert_eq!(
            fields(&who),
            fields(&body),
            "an account, shaped as signing in gave it"
        );
    }

    #[tokio::test]
    async fn the_session_cookie_cannot_be_read_by_script_or_sent_in_clear() {
        let app = Harness::new().await;
        app.create("admin", Role::Admin).await;

        let response = app
            .post("/api/session")
            .json(serde_json::json!({ "username": "admin", "password": Harness::PASSWORD }))
            .send()
            .await;

        let set = response
            .headers()
            .get(axum::http::header::SET_COOKIE)
            .expect("Set-Cookie")
            .to_str()
            .expect("ascii")
            .to_string();

        assert!(set.contains("HttpOnly"), "{set}");
        assert!(set.contains("Secure"), "{set}");
        assert!(set.contains("SameSite=Strict"), "{set}");
        assert!(set.contains("Path=/"), "{set}");
        assert!(
            !set.contains("Max-Age") && !set.contains("Expires"),
            "the row's own expiry is the deadline, and a second one would drift: {set}"
        );
    }

    #[tokio::test]
    async fn a_host_issuing_its_own_session_hands_out_a_cookie_the_backend_accepts() {
        let app = Harness::builder()
            .base_path("/apps/x/".parse().unwrap())
            .build()
            .await;
        app.create("ann", Role::Viewer).await;
        let account = app.store().accounts().await.unwrap().remove(0);

        let issued = crate::issue_session(
            app.state(),
            &account.user,
            account.sessions_valid_from,
            Proof::begin(),
        )
        .await
        .unwrap();
        let set = issued.to_str().unwrap();
        assert!(
            set.ends_with("; Path=/apps/x/; HttpOnly; SameSite=Strict; Secure"),
            "{set}"
        );

        let token = Harness::session_from(&set_cookie(issued).into_response()).unwrap();
        let who = app.get("/apps/x/api/session").cookie(&token).send().await;
        assert_eq!(who.status(), StatusCode::OK);
        assert_eq!(body_json(who).await["username"], "ann");
    }

    #[tokio::test]
    async fn every_refusal_is_the_same_answer_with_the_same_message() {
        let app = Harness::new().await;
        app.create("admin", Role::Admin).await;
        let disabled = app.create("disabled", Role::Viewer).await;
        app.store().set_enabled(&disabled, false).await.unwrap();

        for (username, password) in [
            ("nobody", Harness::PASSWORD),
            ("admin", "the wrong password"),
            ("disabled", Harness::PASSWORD),
        ] {
            let response = app
                .post("/api/session")
                .json(serde_json::json!({ "username": username, "password": password }))
                .send()
                .await;

            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{username}");
            assert!(
                Harness::session_from(&response).is_none(),
                "a refusal must not hand out a cookie"
            );
            assert_eq!(
                body_json(response).await["error"],
                "the username or password is incorrect"
            );
        }
    }

    #[tokio::test]
    async fn signing_out_ends_the_session_and_not_the_accounts_others() {
        let app = Harness::new().await;
        let token = app.signed_in("viewer", Role::Viewer).await;
        let other = app.sign_in("viewer").await;

        let response = app.delete("/api/session").cookie(&token).send().await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let who = |token: &str| app.get("/api/session").cookie(token).send();
        assert_eq!(who(&token).await.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(who(&other).await.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn signing_out_clears_the_cookie_even_when_the_row_cannot_be_ended() {
        let app = Harness::new().await;
        let token = app.signed_in("viewer", Role::Viewer).await;
        wslib_appliance_store::sqlx::query(&format!(
            "DROP TABLE {}",
            wslib_appliance_store::SESSIONS_TABLE
        ))
        .execute(app.store().pool())
        .await
        .unwrap();

        let response = app.delete("/api/session").cookie(&token).send().await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let set = response.headers()[axum::http::header::SET_COOKIE]
            .to_str()
            .unwrap();
        assert!(set.starts_with(&format!("{SESSION_COOKIE}=;")), "{set}");
    }

    #[tokio::test]
    async fn two_values_under_the_session_cookie_are_nobody() {
        let app = Harness::new().await;
        let token = app.signed_in("viewer", Role::Viewer).await;
        let other = app.sign_in("viewer").await;

        let both = format!("{SESSION_COOKIE}={token}; {SESSION_COOKIE}={other}");
        let response = app.get("/api/session").header("cookie", &both).send().await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn signing_out_clears_the_cookie_and_works_without_a_good_one() {
        let app = Harness::new().await;
        let response = app.delete("/api/session").send().await;
        assert_eq!(
            response.status(),
            StatusCode::NO_CONTENT,
            "a dead cookie must still be clearable"
        );

        let set = response
            .headers()
            .get(axum::http::header::SET_COOKIE)
            .expect("Set-Cookie")
            .to_str()
            .unwrap()
            .to_string();
        assert!(set.contains(SESSION_COOKIE), "{set}");
        assert!(
            set.contains("Path=/"),
            "a removal at the wrong path leaves the cookie exactly where it was: {set}"
        );
    }

    #[tokio::test]
    async fn a_204_carries_no_content_length_over_h2() {
        let app = Harness::new().await;
        let address = app.serve_tls().await;
        let request = axum::http::Request::delete("https://box/api/session")
            .body(())
            .expect("a request");
        let answered = crate::tests::over_h2(&app, address, request).await;
        assert_eq!(answered.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            answered.headers().get(axum::http::header::CONTENT_LENGTH),
            None,
            "{:?}",
            answered.headers()
        );
    }

    #[tokio::test]
    async fn a_sign_in_is_written_to_the_audit_log() {
        let app = Harness::new().await;
        app.create("admin", Role::Admin).await;
        app.sign_in("admin").await;

        let page = app.store().audit(10, None).await.unwrap();
        assert_eq!(page.items[0].actor, "admin");
        assert_eq!(page.items[0].message, "signed in");
        assert_eq!(
            page.items[0].fields,
            [("method".to_string(), "password".to_string())]
        );
    }

    #[tokio::test]
    async fn a_refused_sign_in_reaches_the_audit_log_through_the_bridge() {
        let app = Harness::new().await;
        assert!(!app.signs_in("nobody", Harness::PASSWORD).await);

        let row = app.audit_row("sign-in refused: no such account").await;
        assert_eq!(row.actor, "nobody");
        assert_eq!(row.level, "WARN");
        assert!(
            row.target.starts_with("wslib_appliance_auth"),
            "{}",
            row.target
        );
        assert_eq!(
            row.fields,
            [("method".to_string(), "password".to_string())],
            "the actor is a column and is not repeated"
        );
    }

    #[tokio::test]
    async fn a_wrong_password_names_its_target_without_an_actor_id() {
        let app = Harness::new().await;
        let id = app.create("admin", Role::Admin).await;
        assert!(!app.signs_in("admin", "not it").await);

        let row = app.audit_row("sign-in refused: wrong password").await;
        assert_eq!(row.actor_id, None);
        assert_eq!(
            row.fields,
            [
                ("user_id".to_string(), id),
                ("method".to_string(), "password".to_string())
            ]
        );
    }

    #[tokio::test]
    async fn a_username_no_account_could_have_is_refused_without_a_row() {
        let app = Harness::new().await;
        for forged in ["admin\nWARN forged: signed in", &"a".repeat(2000)] {
            let response = app
                .post("/api/session")
                .json(serde_json::json!({ "username": forged, "password": Harness::PASSWORD }))
                .send()
                .await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(
                body_json(response).await["error"],
                "the username or password is incorrect",
                "the same answer as a wrong password, so the bound is not an oracle"
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(
            app.store().audit(10, None).await.unwrap().items.is_empty(),
            "nothing reached the table"
        );
    }

    #[tokio::test]
    async fn an_unknown_name_that_would_pass_for_another_actor_is_recorded_quoted() {
        for tried in [
            "control-socket",
            "control-socket:root",
            "onboarding",
            "Onboarding",
        ] {
            let app = Harness::new().await;
            let response = app
                .post("/api/session")
                .json(serde_json::json!({ "username": tried, "password": Harness::PASSWORD }))
                .send()
                .await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(
                body_json(response).await["error"],
                "the username or password is incorrect"
            );
            let row = app.audit_row("sign-in refused: no such account").await;
            assert_eq!(row.actor, format!("{tried:?}"));
        }
    }

    #[tokio::test]
    async fn somebody_who_is_not_an_administrator_can_change_their_own_password() {
        let app = Harness::new().await;
        let token = app.signed_in("viewer", Role::Viewer).await;

        let response = app
            .put(&password_route())
            .cookie(&token)
            .json(change_to(Harness::PASSWORD, Harness::NEW_PASSWORD))
            .send()
            .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        assert!(app.signs_in("viewer", Harness::NEW_PASSWORD).await);
        assert!(
            !app.signs_in("viewer", Harness::PASSWORD).await,
            "the password that was replaced must stop working"
        );
    }

    #[tokio::test]
    async fn changing_your_own_password_hands_back_a_working_session_and_deletes_the_rest() {
        let app = Harness::new().await;
        let token = app.signed_in("viewer", Role::Viewer).await;
        app.sign_in("viewer").await;

        let response = app
            .put(&password_route())
            .cookie(&token)
            .json(change_to(Harness::PASSWORD, Harness::NEW_PASSWORD))
            .send()
            .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let reissued = Harness::session_from(&response).expect("a replacement cookie");
        assert_eq!(
            app.get("/api/session")
                .cookie(&reissued)
                .send()
                .await
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            app.get("/api/session").cookie(&token).send().await.status(),
            StatusCode::UNAUTHORIZED,
            "and the cookie the rotation invalidated is genuinely dead"
        );
        assert_eq!(app.session_rows().await, 1, "only the replacement is left");
    }

    #[tokio::test]
    async fn a_wrong_current_password_is_refused_as_a_403_and_changes_nothing() {
        let app = Harness::new().await;
        let token = app.signed_in("viewer", Role::Viewer).await;

        let response = app
            .put(&password_route())
            .cookie(&token)
            .json(change_to("not the current password", Harness::NEW_PASSWORD))
            .send()
            .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(
            Harness::session_from(&response).is_none(),
            "a refusal must not reissue a session"
        );
        assert!(
            app.signs_in("viewer", Harness::PASSWORD).await,
            "the password must be exactly as it was"
        );
        assert_eq!(
            app.get("/api/session").cookie(&token).send().await.status(),
            StatusCode::OK,
            "and the session is untouched, which is what makes 403 the honest answer"
        );
    }

    // The guarded write is tested in `wslib-appliance-store`: an ordered pair
    // of requests cannot be past verification when a reset lands.

    #[tokio::test]
    async fn a_new_password_below_the_minimum_is_refused_with_the_number_in_it() {
        let app = Harness::new().await;
        let token = app.signed_in("viewer", Role::Viewer).await;

        let response = app
            .put(&password_route())
            .cookie(&token)
            .json(change_to(Harness::PASSWORD, "short"))
            .send()
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(
            body_json(response).await["error"]
                .as_str()
                .unwrap()
                .contains(&wslib_appliance_types::MIN_PASSWORD_LEN.to_string())
        );
        assert!(app.signs_in("viewer", Harness::PASSWORD).await);
    }

    #[tokio::test]
    async fn changing_a_password_needs_a_session_rather_than_a_username() {
        let app = Harness::new().await;
        app.create("viewer", Role::Viewer).await;

        let response = app
            .put(&password_route())
            .json(change_to(Harness::PASSWORD, Harness::NEW_PASSWORD))
            .send()
            .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(app.signs_in("viewer", Harness::PASSWORD).await);
    }

    #[tokio::test]
    async fn the_control_socket_has_no_password_of_its_own_to_change() {
        let app = Harness::new().await;
        app.create("viewer", Role::Viewer).await;

        let response = app
            .put(&password_route())
            .local()
            .json(change_to(Harness::PASSWORD, Harness::NEW_PASSWORD))
            .send()
            .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(app.signs_in("viewer", Harness::PASSWORD).await);
    }

    #[tokio::test]
    async fn changing_your_own_password_is_written_to_the_audit_log() {
        let app = Harness::new().await;
        let token = app.signed_in("viewer", Role::Viewer).await;

        app.put(&password_route())
            .cookie(&token)
            .json(change_to(Harness::PASSWORD, Harness::NEW_PASSWORD))
            .send()
            .await;

        let page = app.store().audit(10, None).await.unwrap();
        assert_eq!(page.items[0].actor, "viewer");
        assert_eq!(page.items[0].message, "changed their own password");
    }
}
