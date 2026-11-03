//! Local accounts, always on the control socket and on the TLS listener only by
//! [`Server::users_routes`](crate::Server::users_routes), with the policies
//! that turn on which listener asked or whose account it is.
//!
//! - A password reset refuses the caller's own account; your own changes at
//!   `PUT /api/session/password`, which asks for the current one.
//! - Over HTTPS the last enabled administrator cannot be demoted, disabled or
//!   deleted; over the control socket it can.
//! - Only a signed-in host admin makes a host admin or changes one's account,
//!   and the socket never does. The store refuses losing the last host admin.
//!   Every write on another account goes through `store_for`, whose statement
//!   spares a host admin's account when the caller is not one.
//! - Making, enabling, disabling or deleting an account, changing a role,
//!   resetting a password, requiring TOTP and removing a passkey each ask the
//!   administrator's fresh proof over HTTPS; the socket gives none. The target
//!   is checked first, so a refused change spends no code.

use axum::body::HttpBody;
use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequest, OptionalFromRequest, Path, Request, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use wslib_appliance_types::account::{EnabledChange, NewUser, PasswordReset, RoleChange};
use wslib_appliance_types::passkey::PasskeyView;
use wslib_appliance_types::totp::FactorProof;
use wslib_appliance_types::{ListedUser, MAX_USERNAME_LEN, Role, User};
use wslib_secret::Secret;

use axum::extract::DefaultBodyLimit;
use wslib_appliance_core::backend::{self, store_for};
use wslib_appliance_core::prove_acting_admin;
use wslib_appliance_store::StoreError;

use crate::routes::session::OWN_PASSWORD_ROUTE;
use crate::{Admin, ApiError, ApplianceState, Identity, Reached, audit, clean_name};

pub(crate) fn routes() -> Router<ApplianceState> {
    Router::new()
        .route("/users", get(list).post(create))
        .route("/users/{id}", delete(remove).layer(capped()))
        .route("/users/{id}/role", put(set_role))
        .route("/users/{id}/enabled", put(set_enabled))
        .route("/users/{id}/password", put(set_password))
        .route("/users/{id}/passkeys", get(passkeys))
        .route(
            "/users/{id}/require-totp",
            post(require_totp).layer(capped()),
        )
        .route(
            "/users/{id}/passkeys/{passkey_id}/remove",
            post(remove_passkey).layer(capped()),
        )
}

fn capped() -> DefaultBodyLimit {
    DefaultBodyLimit::max(backend::MAX_FACTOR_BODY)
}

/// 404 for no such account; a host admin's only to a host admin.
async fn passkeys(
    Admin(who): Admin,
    State(app): State<ApplianceState>,
    Path(id): Path<String>,
) -> Result<Json<Vec<PasskeyView>>, ApiError> {
    let store = store_for(&app, &who);
    store.writable(&id).await?;
    let passkeys = store.passkeys(&id).await?;
    Ok(Json(
        passkeys.iter().map(|passkey| passkey.view()).collect(),
    ))
}

async fn require_totp(
    Admin(who): Admin,
    State(app): State<ApplianceState>,
    Path(id): Path<String>,
    reached: Reached,
    Json(proof): Json<FactorProof>,
) -> Result<StatusCode, ApiError> {
    wslib_appliance_core::require_totp_enrolment(&app, &who, &reached, &id, proof).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn remove_passkey(
    Admin(who): Admin,
    State(app): State<ApplianceState>,
    Path((id, passkey_id)): Path<(String, String)>,
    reached: Reached,
    Json(proof): Json<FactorProof>,
) -> Result<StatusCode, ApiError> {
    wslib_appliance_core::remove_account_passkey(&app, &who, &reached, &id, &passkey_id, proof)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list(
    Admin(_): Admin,
    State(app): State<ApplianceState>,
) -> Result<Json<Vec<ListedUser>>, ApiError> {
    Ok(Json(app.store.listed_users().await?))
}

/// Creates and only creates: a taken name is a 409. Over the control socket it
/// makes a box's first administrator with no accounts at all. It has no
/// self-check: making an account, signing in as it and resetting your
/// original account's password from it is the recovery path for an
/// administrator with no shell.
async fn create(
    Admin(who): Admin,
    State(app): State<ApplianceState>,
    reached: Reached,
    Json(body): Json<NewUser>,
) -> Result<(StatusCode, Json<User>), ApiError> {
    refuse_making_a_host_admin(&who, body.role)?;
    let username = clean_new_username(&body.username)?;
    if app.store.user_by_username(&username).await?.is_some() {
        return Err(StoreError::UsernameTaken(username).into());
    }
    let hash = hash(body.password).await?;
    prove_acting_admin(&app, &who, &reached, body.proof, "creating an account").await?;

    let user = app.store.create_user(&username, &hash, body.role).await?;
    audit!(
        &app,
        &who,
        "created an account",
        "username" => &username,
        "role" => body.role.as_str(),
    )
    .await;

    Ok((StatusCode::CREATED, Json(user)))
}

/// No self-check: it writes no credential, and a session re-reads its role on
/// every request.
async fn set_role(
    Admin(who): Admin,
    State(app): State<ApplianceState>,
    Path(id): Path<String>,
    reached: Reached,
    Json(body): Json<RoleChange>,
) -> Result<StatusCode, ApiError> {
    refuse_making_a_host_admin(&who, body.role)?;
    if !body.role.allows(Role::Admin) {
        refuse_if_last_admin(&app, &who, &id, "demote").await?;
    }
    let store = store_for(&app, &who);
    store.writable(&id).await?;
    prove_acting_admin(&app, &who, &reached, body.proof, "a role change").await?;
    store.set_role(&id, body.role).await?;
    audit!(
        &app,
        &who,
        "changed an account's role",
        "user_id" => &id,
        "role" => body.role.as_str(),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

async fn set_enabled(
    Admin(who): Admin,
    State(app): State<ApplianceState>,
    Path(id): Path<String>,
    reached: Reached,
    Json(body): Json<EnabledChange>,
) -> Result<StatusCode, ApiError> {
    if !body.enabled {
        refuse_if_last_admin(&app, &who, &id, "disable").await?;
    }
    let store = store_for(&app, &who);
    store.writable(&id).await?;
    let what = if body.enabled {
        "enabling an account"
    } else {
        "disabling an account"
    };
    prove_acting_admin(&app, &who, &reached, body.proof, what).await?;
    store.set_enabled(&id, body.enabled).await?;
    audit!(
        &app,
        &who,
        if body.enabled {
            "enabled an account"
        } else {
            "disabled an account"
        },
        "user_id" => &id,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

/// Reset somebody else's password without its current one, clearing its second
/// factors. Refuses the caller's own account; the control socket has none, so
/// resets anybody's.
///
/// The refusal is narrow: a stolen administrator session cannot outlive itself
/// through the account it borrowed, but can still promote another account or
/// create one, each of which shows in the account list and the audit log.
async fn set_password(
    Admin(who): Admin,
    State(app): State<ApplianceState>,
    Path(id): Path<String>,
    reached: Reached,
    Json(body): Json<PasswordReset>,
) -> Result<StatusCode, ApiError> {
    refuse_if_your_own(&who, &id)?;
    let store = store_for(&app, &who);
    store.writable(&id).await?;
    let hash = hash(body.password).await?;
    prove_acting_admin(&app, &who, &reached, body.proof, "password reset").await?;

    let cleared = store.set_password(&id, &hash).await?;
    let required = store.totp_required(&id).await?;
    audit!(
        &app, &who, "changed an account's password",
        "user_id" => &id,
        "second_factors" => if cleared { "cleared" } else { "none" },
        "totp_required" => if required { "kept" } else { "none" },
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

/// Compared by account id, and audited.
fn refuse_if_your_own(who: &Identity, id: &str) -> Result<(), ApiError> {
    if who.account_id() != Some(id) {
        return Ok(());
    }
    tracing::warn!(
        name: "audit",
        actor = who.actor(),
        actor_id = id,
        user_id = id,
        "password reset refused: aimed at the caller's own account"
    );
    Err(ApiError::Forbidden(format!(
        "this route resets somebody else's password and asks for no proof, so it is not \
         the way to change your own. Use PUT /api{OWN_PASSWORD_ROUTE}, which asks for your \
         current password. If you have forgotten it, another administrator or the control \
         socket can reset it for you."
    )))
}

async fn remove(
    Admin(who): Admin,
    State(app): State<ApplianceState>,
    Path(id): Path<String>,
    reached: Reached,
    OptionalProof(proof): OptionalProof,
) -> Result<StatusCode, ApiError> {
    refuse_if_last_admin(&app, &who, &id, "delete").await?;
    let store = store_for(&app, &who);
    store.writable(&id).await?;
    prove_acting_admin(&app, &who, &reached, proof, "deleting an account").await?;
    store.delete_user(&id).await?;
    audit!(&app, &who, "deleted an account", "user_id" => &id).await;
    Ok(StatusCode::NO_CONTENT)
}

/// A DELETE's proof, read as none when it has no body or no content type.
struct OptionalProof(FactorProof);

impl<S: Send + Sync> FromRequest<S> for OptionalProof {
    type Rejection = JsonRejection;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        if req.body().size_hint().exact() == Some(0) {
            return Ok(Self(FactorProof::default()));
        }
        let body = <Json<FactorProof> as OptionalFromRequest<S>>::from_request(req, state).await?;
        Ok(Self(body.map(|Json(proof)| proof).unwrap_or_default()))
    }
}

fn refuse_making_a_host_admin(who: &Identity, role: Role) -> Result<(), ApiError> {
    if role == Role::HostAdmin && !who.is_host_admin() {
        return Err(ApiError::Forbidden(
            "only a host admin, signed in, makes a host admin".to_string(),
        ));
    }
    Ok(())
}

/// `verb` completes "to … it": `"demote"`, `"disable"`, `"delete"`.
async fn refuse_if_last_admin(
    app: &ApplianceState,
    who: &Identity,
    id: &str,
    verb: &str,
) -> Result<(), ApiError> {
    if who.is_local() {
        return Ok(());
    }

    let users = app.store.users().await?;
    let is_admin = |user: &User| user.enabled && user.role.allows(Role::Admin);

    // A host admin is the store's to refuse.
    let target_holds_the_box = users
        .iter()
        .any(|u| u.id == id && is_admin(u) && u.role != Role::HostAdmin)
        && !users.iter().any(|u| u.id != id && is_admin(u));

    if target_holds_the_box {
        return Err(ApiError::Forbidden(format!(
            "this is the last enabled administrator, and to {verb} it would leave the \
             appliance with no way in through the browser. The control socket can do it \
             if that is what you mean."
        )));
    }
    Ok(())
}

/// On a blocking thread, as argon2id is tens of milliseconds.
pub(crate) async fn hash(password: Secret) -> Result<String, ApiError> {
    tokio::task::spawn_blocking(move || wslib_appliance_auth::hash_password(password.expose()))
        .await
        .map_err(|e| ApiError::internal("hash the password", &e))?
        .map_err(ApiError::from)
}

pub(crate) fn clean_username(raw: &str) -> Result<String, ApiError> {
    clean_name(raw, "username", MAX_USERNAME_LEN)
}

/// Sign-in does not apply this, so an account named before the rule still signs in.
pub(crate) fn clean_new_username(raw: &str) -> Result<String, ApiError> {
    let username = clean_username(raw)?;
    if wslib_appliance_auth::is_reserved_username(&username) {
        return Err(ApiError::BadRequest(
            "a username may not contain a colon, start with \"control-socket\" or be \
             \"onboarding\""
                .to_string(),
        ));
    }
    Ok(username)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{Harness, Req, body_json};

    async fn app() -> Harness {
        Harness::builder().users_routes().build().await
    }

    /// The acting administrator's password again, as a change's proof.
    fn proof() -> serde_json::Value {
        serde_json::json!({ "password": Harness::PASSWORD })
    }

    /// A reset to [`Harness::NEW_PASSWORD`], the acting administrator proving
    /// `theirs` again.
    fn reset_by(theirs: &str) -> serde_json::Value {
        serde_json::json!({
            "password": Harness::NEW_PASSWORD,
            "proof": { "password": theirs },
        })
    }

    #[tokio::test]
    async fn a_reset_asks_the_administrator_to_prove_themselves_and_changes_nothing_without() {
        let app = app().await;
        let token = app.admin("admin").await;
        let member = app.create("member", Role::Viewer).await;
        for body in [
            serde_json::json!({ "password": Harness::NEW_PASSWORD }),
            reset_by("not it"),
        ] {
            let refused = app
                .put(&format!("/api/users/{member}/password"))
                .cookie(&token)
                .json(body)
                .send()
                .await;
            assert_eq!(refused.status(), StatusCode::FORBIDDEN);
            assert_eq!(
                body_json(refused).await["error"],
                "the password is incorrect"
            );
        }
        assert!(app.signs_in("member", Harness::PASSWORD).await);
    }

    #[tokio::test]
    async fn a_short_password_is_refused_before_the_administrators_recovery_code_is_spent() {
        let app = app().await;
        let token = app.admin("admin").await;
        let admin = app.user_id("admin").await;
        let key = Secret::new("JBSWY3DPEHPK3PXP");
        assert!(app.store().enrol_totp(&admin, &key).await.unwrap());
        assert!(
            app.store()
                .confirm_totp(&admin, &key, 1, &[])
                .await
                .unwrap()
        );
        let codes = wslib_appliance_auth::issue_recovery_codes(app.store(), &admin)
            .await
            .unwrap();
        let refused = app
            .post("/api/users")
            .cookie(&token)
            .json(serde_json::json!({
                "username": "member", "password": "short", "role": "viewer",
                "proof": { "code": codes.codes[0].expose(), "recovery": true },
            }))
            .send()
            .await;
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
        assert_eq!(app.store().recovery_codes_left(&admin).await.unwrap(), 10);
    }

    #[tokio::test]
    async fn a_reset_says_in_the_audit_log_whether_it_cleared_second_factors() {
        let app = app().await;
        let token = app.admin("admin").await;
        let member = app.create("member", Role::Viewer).await;
        let other = app.create("other", Role::Viewer).await;
        app.store()
            .enrol_totp(&member, &Secret::new("JBSWY3DPEHPK3PXP"))
            .await
            .unwrap();

        for (id, cleared) in [(&member, "cleared"), (&other, "none")] {
            let reset = app
                .put(&format!("/api/users/{id}/password"))
                .cookie(&token)
                .json(reset_by(Harness::PASSWORD))
                .send()
                .await;
            assert_eq!(reset.status(), StatusCode::NO_CONTENT);
            let rows = app.store().audit(10, None).await.unwrap().items;
            let row = rows
                .iter()
                .find(|row| {
                    row.fields
                        .contains(&("user_id".to_string(), id.to_string()))
                })
                .expect("the reset's row");
            assert_eq!(row.message, "changed an account's password");
            assert!(
                row.fields
                    .contains(&("second_factors".to_string(), cleared.to_string())),
                "{:?}",
                row.fields
            );
        }
        assert!(app.store().totp(&member).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn the_listener_serves_the_routes_only_when_asked_for() {
        let without = Harness::new().await;
        let token = without.admin("admin").await;
        let id = without.user_id("admin").await;
        for response in [
            without.get("/api/users").cookie(&token).send().await,
            without
                .put(&format!("/api/users/{id}/password"))
                .cookie(&token)
                .json(serde_json::json!({ "password": Harness::NEW_PASSWORD }))
                .send()
                .await,
        ] {
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }

        let with = app().await;
        let token = with.admin("admin").await;
        let response = with.get("/api/users").cookie(&token).send().await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn the_socket_creates_an_account_and_resets_a_password_without_the_opt_in() {
        let app = Harness::new().await;

        let created = app
            .post("/api/users")
            .local()
            .json(serde_json::json!({
                "username": "admin", "password": Harness::PASSWORD, "role": "admin", "proof": proof(),
            }))
            .send()
            .await;
        assert_eq!(created.status(), StatusCode::CREATED);
        let id = body_json(created).await["id"].as_str().unwrap().to_string();

        let reset = app
            .put(&format!("/api/users/{id}/password"))
            .local()
            .json(serde_json::json!({ "password": Harness::NEW_PASSWORD }))
            .send()
            .await;
        assert_eq!(reset.status(), StatusCode::NO_CONTENT);
        assert!(app.signs_in("admin", Harness::NEW_PASSWORD).await);
    }

    #[tokio::test]
    async fn an_admin_can_create_list_and_delete_accounts() {
        let app = app().await;
        let token = app.admin("admin").await;

        let created = app
            .post("/api/users")
            .cookie(&token)
            .json(serde_json::json!({
                "username": "member",
                "password": Harness::PASSWORD,
                "role": "operator", "proof": proof(),
            }))
            .send()
            .await;
        assert_eq!(created.status(), StatusCode::CREATED);
        let body = body_json(created).await;
        assert_eq!(body["username"], "member");
        assert_eq!(body["role"], "operator");
        let id = body["id"].as_str().unwrap().to_string();

        app.store().require_totp(&id).await.unwrap();
        let listed = app.get("/api/users").cookie(&token).send().await;
        let listed = body_json(listed).await;
        assert_eq!(listed.as_array().unwrap().len(), 2);
        assert_eq!(
            listed[1],
            serde_json::json!({
                "id": id, "username": "member", "role": "operator", "enabled": true,
                "created_at": listed[1]["created_at"], "last_login_at": null,
                "totp": false, "passkeys": 0, "totp_required": true,
            }),
            "the account's own fields beside its factors, flat"
        );

        let removed = app
            .delete(&format!("/api/users/{id}"))
            .cookie(&token)
            .json(proof())
            .send()
            .await;
        assert_eq!(removed.status(), StatusCode::NO_CONTENT);
        assert_eq!(app.store().user_count().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn the_new_account_can_sign_in_with_the_password_it_was_given() {
        let app = app().await;
        let token = app.admin("admin").await;

        app.post("/api/users")
            .cookie(&token)
            .json(serde_json::json!({
                "username": "member",
                "password": Harness::PASSWORD,
                "role": "viewer", "proof": proof(),
            }))
            .send()
            .await;

        let response = app
            .post("/api/session")
            .json(serde_json::json!({ "username": "member", "password": Harness::PASSWORD }))
            .send()
            .await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn a_password_below_the_minimum_is_refused_with_the_number_in_it() {
        let app = app().await;
        let token = app.admin("admin").await;

        let response = app
            .post("/api/users")
            .cookie(&token)
            .json(serde_json::json!({
                "username": "member", "password": "short", "role": "viewer", "proof": proof(),
            }))
            .send()
            .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let error = body_json(response).await;
        assert!(
            error["error"]
                .as_str()
                .unwrap()
                .contains(&wslib_appliance_types::MIN_PASSWORD_LEN.to_string()),
            "a form cannot show what it does not know: {error}"
        );
    }

    #[tokio::test]
    async fn a_username_that_would_forge_a_log_line_is_refused() {
        let app = app().await;
        let token = app.admin("admin").await;

        for username in ["", "   ", "member\nadmin signed in", "a\u{0}b"] {
            let response = app
                .post("/api/users")
                .cookie(&token)
                .json(serde_json::json!({
                    "username": username, "password": Harness::PASSWORD, "role": "viewer", "proof": proof(),
                }))
                .send()
                .await;
            assert_eq!(
                response.status(),
                StatusCode::BAD_REQUEST,
                "{username:?} must be refused"
            );
        }
    }

    #[tokio::test]
    async fn a_new_username_that_would_pass_for_a_control_socket_is_refused() {
        let app = app().await;
        let token = app.admin("admin").await;

        for username in [
            "control-socket",
            "Control-Socket",
            "control-socket:root",
            "control-socket\u{ff1a}root",
            "a:b",
        ] {
            let response = app
                .post("/api/users")
                .cookie(&token)
                .json(serde_json::json!({
                    "username": username, "password": Harness::PASSWORD, "role": "viewer", "proof": proof(),
                }))
                .send()
                .await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{username:?}");
            let error = body_json(response).await["error"].to_string();
            assert!(error.contains("may not contain a colon"), "{error}");
        }
    }

    #[tokio::test]
    async fn a_new_username_that_would_pass_for_the_onboarding_actor_is_refused() {
        let app = app().await;
        let token = app.admin("admin").await;

        for username in ["onboarding", "Onboarding"] {
            let response = app
                .post("/api/users")
                .cookie(&token)
                .json(serde_json::json!({
                    "username": username, "password": Harness::PASSWORD, "role": "viewer", "proof": proof(),
                }))
                .send()
                .await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{username:?}");
            let error = body_json(response).await["error"].to_string();
            assert!(error.contains("onboarding"), "{error}");
        }
    }

    #[tokio::test]
    async fn an_account_named_before_the_colon_rule_still_signs_in() {
        let app = app().await;
        app.create("site:admin", Role::Viewer).await;
        assert!(app.signs_in("site:admin", Harness::PASSWORD).await);
    }

    #[tokio::test]
    async fn an_account_named_onboarding_before_the_rule_still_signs_in() {
        let app = app().await;
        app.create("onboarding", Role::Viewer).await;
        assert!(app.signs_in("onboarding", Harness::PASSWORD).await);
    }

    #[tokio::test]
    async fn a_username_already_taken_is_a_conflict_not_a_500() {
        let app = app().await;
        let token = app.admin("admin").await;

        let response = app
            .post("/api/users")
            .cookie(&token)
            .json(serde_json::json!({
                "username": "ADMIN", "password": Harness::PASSWORD, "role": "viewer", "proof": proof(),
            }))
            .send()
            .await;
        assert_eq!(
            response.status(),
            StatusCode::CONFLICT,
            "the column is case-insensitive, and so is the answer"
        );
    }

    #[tokio::test]
    async fn the_browser_cannot_remove_the_last_administrator() {
        let app = app().await;
        let token = app.admin("admin").await;
        let id = app.user_id("admin").await;

        let refusals = [
            app.put(&format!("/api/users/{id}/role"))
                .cookie(&token)
                .json(serde_json::json!({ "role": "viewer", "proof": proof() }))
                .send()
                .await,
            app.put(&format!("/api/users/{id}/enabled"))
                .cookie(&token)
                .json(serde_json::json!({ "enabled": false }))
                .send()
                .await,
            app.delete(&format!("/api/users/{id}"))
                .cookie(&token)
                .send()
                .await,
        ];

        for response in refusals {
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            let body = body_json(response).await;
            assert!(
                body["error"].as_str().unwrap().contains("control socket"),
                "the refusal must say where it can be done: {body}"
            );
        }
        let still = app.store().user_by_id(&id).await.unwrap().unwrap();
        assert_eq!(still.user.role, Role::Admin);
        assert!(still.user.enabled);
    }

    #[tokio::test]
    async fn enabling_disabling_or_deleting_asks_the_administrator_to_prove_themselves() {
        let app = app().await;
        let token = app.admin("admin").await;
        let member = app.create("member", Role::Viewer).await;
        let enabled = |enabled: bool, proof: serde_json::Value| {
            app.put(&format!("/api/users/{member}/enabled"))
                .cookie(&token)
                .json(serde_json::json!({ "enabled": enabled, "proof": proof }))
        };
        let deleted = || app.delete(&format!("/api/users/{member}")).cookie(&token);
        let wrong = serde_json::json!({ "password": "not it" });

        for refused in [
            app.put(&format!("/api/users/{member}/enabled"))
                .cookie(&token)
                .json(serde_json::json!({ "enabled": false }))
                .send()
                .await,
            enabled(false, wrong.clone()).send().await,
            deleted().send().await,
            deleted().json(wrong).send().await,
        ] {
            assert_eq!(refused.status(), StatusCode::FORBIDDEN);
            assert_eq!(
                body_json(refused).await["error"],
                "the password is incorrect"
            );
        }
        assert!(app.signs_in("member", Harness::PASSWORD).await);

        for on in [false, true] {
            assert_eq!(
                enabled(on, proof()).send().await.status(),
                StatusCode::NO_CONTENT
            );
            let user = app.store().user_by_id(&member).await.unwrap().unwrap().user;
            assert_eq!(user.enabled, on);
        }
        assert_eq!(
            deleted().json(proof()).send().await.status(),
            StatusCode::NO_CONTENT
        );
        assert!(app.store().user_by_id(&member).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn the_socket_disables_and_deletes_with_no_proof_and_no_body() {
        let app = app().await;
        let members = [
            app.create("member", Role::Viewer).await,
            app.create("other", Role::Viewer).await,
        ];

        let disabled = app
            .put(&format!("/api/users/{}/enabled", members[0]))
            .local()
            .json(serde_json::json!({ "enabled": false }))
            .send()
            .await;
        assert_eq!(disabled.status(), StatusCode::NO_CONTENT);
        let bare = app.delete(&format!("/api/users/{}", members[0])).local();
        let empty_json = app
            .delete(&format!("/api/users/{}", members[1]))
            .local()
            .body("application/json", Vec::new());
        for request in [bare, empty_json] {
            assert_eq!(request.send().await.status(), StatusCode::NO_CONTENT);
        }
        assert_eq!(app.store().user_count().await.unwrap(), 0);
    }

    async fn changes_to(
        app: &Harness,
        id: &str,
        who: impl Fn(Req) -> Req,
    ) -> Vec<axum::response::Response> {
        let at = |path: &str| format!("/api/users/{id}{path}");
        vec![
            who(app.put(&at("/role")))
                .json(serde_json::json!({ "role": "viewer", "proof": proof() }))
                .send()
                .await,
            who(app.put(&at("/enabled")))
                .json(serde_json::json!({ "enabled": false, "proof": proof() }))
                .send()
                .await,
            who(app.put(&at("/password")))
                .json(reset_by(Harness::PASSWORD))
                .send()
                .await,
            who(app.delete(&at(""))).json(proof()).send().await,
        ]
    }

    #[tokio::test]
    async fn neither_an_admin_nor_the_socket_makes_or_touches_a_host_admin() {
        let app = app().await;
        let token = app.admin("admin").await;
        let owner = app.create("owner", Role::HostAdmin).await;
        let member = app.create("member", Role::Viewer).await;
        let as_admin = |req: Req| req.cookie(&token);

        let mut refused = changes_to(&app, &owner, as_admin).await;
        refused.extend(changes_to(&app, &owner, Req::local).await);
        let callers: [&dyn Fn(Req) -> Req; 2] = [&as_admin, &Req::local];
        for who in callers {
            refused.push(
                who(app.put(&format!("/api/users/{member}/role")))
                    .json(serde_json::json!({ "role": "hostadmin", "proof": proof() }))
                    .send()
                    .await,
            );
            refused.push(
                who(app.post("/api/users"))
                    .json(serde_json::json!({
                        "username": "usurper", "password": Harness::PASSWORD, "role": "hostadmin", "proof": proof(),
                    }))
                    .send()
                    .await,
            );
        }
        for response in refused {
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            let error = body_json(response).await["error"].to_string();
            assert!(error.contains("only a host admin"), "{error}");
        }
        let kept = app.store().user_by_id(&owner).await.unwrap().unwrap().user;
        assert_eq!((kept.role, kept.enabled), (Role::HostAdmin, true));
        assert!(app.signs_in("owner", Harness::PASSWORD).await);
        assert!(
            app.store()
                .user_by_username("usurper")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_host_admin_makes_and_changes_host_admins_and_the_last_one_stays() {
        let app = app().await;
        let token = app.signed_in("owner", Role::HostAdmin).await;
        let owner = app.user_id("owner").await;
        let member = app.create("member", Role::Viewer).await;

        let promoted = app
            .put(&format!("/api/users/{member}/role"))
            .cookie(&token)
            .json(serde_json::json!({ "role": "hostadmin", "proof": proof() }))
            .send()
            .await;
        assert_eq!(promoted.status(), StatusCode::NO_CONTENT);
        for response in changes_to(&app, &member, |req| req.cookie(&token)).await {
            assert!(response.status().is_success(), "{}", response.status());
        }

        let refused = app
            .put(&format!("/api/users/{owner}/role"))
            .cookie(&token)
            .json(serde_json::json!({ "role": "admin", "proof": proof() }))
            .send()
            .await;
        assert_eq!(refused.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn a_second_administrator_makes_the_first_removable() {
        let app = app().await;
        let token = app.admin("admin").await;
        app.create("other", Role::Admin).await;
        let id = app.user_id("admin").await;

        let response = app
            .put(&format!("/api/users/{id}/role"))
            .cookie(&token)
            .json(serde_json::json!({ "role": "viewer", "proof": proof() }))
            .send()
            .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn a_disabled_administrator_does_not_count_as_the_one_holding_the_box() {
        let app = app().await;
        let token = app.admin("admin").await;
        let spare = app.create("other", Role::Admin).await;
        app.store().set_enabled(&spare, false).await.unwrap();
        let id = app.user_id("admin").await;

        let response = app
            .delete(&format!("/api/users/{id}"))
            .cookie(&token)
            .send()
            .await;
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "a disabled admin cannot let anybody back in"
        );
    }

    #[tokio::test]
    async fn the_control_socket_may_remove_the_last_administrator() {
        let app = app().await;
        app.admin("admin").await;
        let id = app.user_id("admin").await;

        let response = app.delete(&format!("/api/users/{id}")).local().send().await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(app.store().user_count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn a_freshly_imaged_box_gets_its_first_admin_through_the_socket() {
        let app = app().await;
        assert_eq!(app.store().user_count().await.unwrap(), 0);

        let response = app
            .post("/api/users")
            .local()
            .json(serde_json::json!({
                "username": "admin", "password": Harness::PASSWORD, "role": "admin", "proof": proof(),
            }))
            .send()
            .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let over_https = app
            .post("/api/users")
            .json(serde_json::json!({
                "username": "intruder", "password": Harness::PASSWORD, "role": "admin", "proof": proof(),
            }))
            .send()
            .await;
        assert_eq!(over_https.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_session_cannot_be_turned_into_the_password_behind_it() {
        // The refusal and the route it points at, as a pair.
        let app = app().await;
        let token = app.admin("admin").await;
        let id = app.user_id("admin").await;

        let refused = app
            .put(&format!("/api/users/{id}/password"))
            .cookie(&token)
            .json(serde_json::json!({ "password": Harness::NEW_PASSWORD }))
            .send()
            .await;
        assert_eq!(refused.status(), StatusCode::FORBIDDEN);

        let body = body_json(refused).await;
        assert!(
            body["error"].as_str().unwrap().contains(OWN_PASSWORD_ROUTE),
            "the refusal must name the route that does ask for proof: {body}"
        );
        let row = app
            .audit_row("password reset refused: aimed at the caller's own account")
            .await;
        assert_eq!(row.actor, "admin");
        assert_eq!(row.actor_id.as_deref(), Some(id.as_str()));
        assert!(app.signs_in("admin", Harness::PASSWORD).await);

        let accepted = app
            .put(&format!("/api{OWN_PASSWORD_ROUTE}"))
            .cookie(&token)
            .json(serde_json::json!({
                "current_password": Harness::PASSWORD,
                "new_password": Harness::NEW_PASSWORD,
            }))
            .send()
            .await;
        assert_eq!(accepted.status(), StatusCode::NO_CONTENT);
        assert!(app.signs_in("admin", Harness::NEW_PASSWORD).await);
    }

    /// A resolver backend mounts no users routes, so the guard is tested alone.
    #[test]
    fn a_resolvers_account_with_a_store_id_cannot_reset_its_own_password() {
        let who = Identity::Resolved(crate::Principal {
            id: "an-id".to_string(),
            username: "console-admin".to_string(),
            role: Role::Admin,
            reauthenticated_at: None,
        });
        let refused = refuse_if_your_own(&who, "an-id").expect_err("its own account");
        assert!(matches!(refused, ApiError::Forbidden(_)), "{refused:?}");
        refuse_if_your_own(&who, "another-id").expect("somebody else's");
    }

    #[tokio::test]
    async fn the_control_socket_may_still_reset_any_password() {
        let app = app().await;
        app.admin("admin").await;
        let id = app.user_id("admin").await;

        let response = app
            .put(&format!("/api/users/{id}/password"))
            .local()
            .json(serde_json::json!({ "password": Harness::NEW_PASSWORD }))
            .send()
            .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(app.signs_in("admin", Harness::NEW_PASSWORD).await);
    }

    #[tokio::test]
    async fn changing_somebody_elses_password_locks_them_out_and_not_you() {
        let app = app().await;
        let token = app.admin("admin").await;
        app.create("member", Role::Viewer).await;
        let member = app.sign_in("member").await;
        let member_id = app.user_id("member").await;

        let response = app
            .put(&format!("/api/users/{member_id}/password"))
            .cookie(&token)
            .json(reset_by(Harness::PASSWORD))
            .send()
            .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        assert_eq!(
            app.get("/api/session")
                .cookie(&member)
                .send()
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            app.get("/api/session").cookie(&token).send().await.status(),
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn a_write_against_an_account_that_is_not_there_is_a_404() {
        let app = app().await;
        let token = app.admin("admin").await;

        let response = app
            .put("/api/users/nobody/role")
            .cookie(&token)
            .json(serde_json::json!({ "role": "viewer", "proof": proof() }))
            .send()
            .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn every_change_is_written_to_the_audit_log_with_who_did_it() {
        let app = app().await;
        let token = app.admin("admin").await;
        let member = app.create("member", Role::Viewer).await;

        app.put(&format!("/api/users/{member}/role"))
            .cookie(&token)
            .json(serde_json::json!({ "role": "operator", "proof": proof() }))
            .send()
            .await;

        let page = app.store().audit(10, None).await.unwrap();
        let latest = &page.items[0];
        assert_eq!(latest.actor, "admin");
        assert_eq!(latest.message, "changed an account's role");
        assert!(
            latest
                .fields
                .contains(&("role".to_string(), "operator".to_string())),
            "{:?}",
            latest.fields
        );
    }
}
