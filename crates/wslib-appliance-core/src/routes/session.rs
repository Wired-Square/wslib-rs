//! Asking who you are: a control endpoint's local authority at its ceiling,
//! the account a console or the ingress proxy asserts, or one of the store's.

use axum::extract::State;
use axum::routing::get;
use axum::{Extension, Json, Router};
use wslib_appliance_types::session::{Caller, LocalIdentity};

use crate::console::asserted_caller;
use crate::extract::{Identity, LocalAuthority, Viewer, Vouches};
use crate::state::ApplianceState;
use crate::{ApiError, console, ingress};

pub(crate) fn routes() -> Router<ApplianceState> {
    Router::new().route("/session", get(current))
}

async fn current(
    Viewer(who): Viewer,
    State(app): State<ApplianceState>,
    local: Option<Extension<LocalAuthority>>,
) -> Result<Json<Caller>, ApiError> {
    if let Some(Extension(LocalAuthority { ceiling, .. })) = local {
        return Ok(Json(Caller::Local(LocalIdentity::new(
            who.actor(),
            ceiling,
        ))));
    }
    let principal = match who {
        Identity::Session(user) => return Ok(Json(Caller::Account(user))),
        Identity::Resolved(principal) => principal,
        _ => return Err(ApiError::Unauthenticated),
    };
    match app.vouches {
        Vouches::Console => Ok(Json(asserted_caller(principal, console::ID_PREFIX))),
        Vouches::Ingress => Ok(Json(asserted_caller(principal, ingress::ID_PREFIX))),
        Vouches::StoreAccounts => {
            let mut account = app.store.user_by_id(&principal.id).await?.ok_or_else(|| {
                ApiError::internal(
                    "answer who is asking",
                    &"the resolver vouched for an account the store does not have",
                )
            })?;
            account.user.role = principal.role;
            Ok(Json(Caller::Account(account.user)))
        }
        Vouches::Unsaid => Err(ApiError::NotFound(
            "this caller has no session on this box".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use crate::backend::{Callers, LogsRung};
    #[cfg(unix)]
    use crate::probe::NAMELESS_UID;
    use crate::probe::Probe;
    use crate::testing::{Req, body_json};
    use axum::http::StatusCode;
    use wslib_appliance_types::Role;
    use wslib_appliance_types::console::IDENTITY_HEADER;

    #[tokio::test]
    async fn a_control_endpoint_is_answered_with_its_actor_and_ceiling() {
        for probe in [Probe::new().await, Probe::callerless(LogsRung::Admin).await] {
            for ceiling in Role::LADDER {
                let actors = [
                    crate::LOCAL_ACTOR.to_string(),
                    #[cfg(unix)]
                    format!("control-socket:uid={NAMELESS_UID}"),
                ];
                let answers = probe.local(ceiling, "/api/session").await;
                assert_eq!(answers.len(), actors.len());
                for (response, actor) in answers.into_iter().zip(actors) {
                    assert_eq!(response.status(), StatusCode::OK);
                    assert_eq!(
                        body_json(response).await,
                        serde_json::json!({
                            "username": actor,
                            "role": ceiling.min(Role::Admin),
                            "local": true,
                        })
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn a_store_account_is_answered_as_its_row() {
        let probe = Probe::new().await;
        let token = probe.admin_token().await;
        let response = probe.https("/api/session", Some(&token)).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["username"], "admin");
        assert_eq!(body["enabled"], true);
        assert!(body.get("local").is_none(), "{body}");

        let response = probe.https("/api/session", None).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn the_consoles_account_is_answered_as_it_asserted_it() {
        let probe = Probe::with_callers(Callers::asserted_by_console(), true).await;
        let response = Req::new(probe.https.clone(), "GET", "/api/session")
            .on_app_socket()
            .header(IDENTITY_HEADER, "v1; id=4f1c; user=Zo%C3%AB; role=operator")
            .send()
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            body_json(response).await,
            serde_json::json!({ "id": "4f1c", "username": "Zoë", "role": "operator" })
        );
    }
}
