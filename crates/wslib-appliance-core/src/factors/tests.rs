//! The routes as a console mounts them: callers resolved to the store's
//! accounts, its own sign-in route handing a proved password to
//! [`password_proved`], its own sessions issued through [`HostSessions`], and
//! its window of a recent proof marked through [`ReauthenticationWindow`].

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::http::{HeaderValue, StatusCode};
use axum::response::Response;
use axum::routing::post;
use serde_json::{Value, json};
use wslib_appliance_types::Role;

use super::*;
use crate::probe::{ACCOUNT, PORT, Probe};
use crate::testing::{Req, SoftPasskey, body_json};
use crate::{AboveAdmin, Mount};

const PASSWORD: &str = "correct horse battery";

type Proofs = std::sync::Arc<std::sync::Mutex<Vec<Proof>>>;

/// Names the account in a cookie of its own, as a console's session table
/// would, and keeps the proof of each session issued and each marked as
/// proved again.
#[derive(Clone, Default)]
struct ConsoleSessions {
    issued: Proofs,
    marked: Proofs,
}

impl HostSessions for ConsoleSessions {
    async fn issue(
        &self,
        _: &ApplianceState,
        account: &Account,
        proof: Proof,
    ) -> Result<HeaderValue, ApiError> {
        self.issued.lock().unwrap().push(proof);
        let cookie = format!("console={}", account.user.id);
        Ok(HeaderValue::try_from(cookie).expect("a header"))
    }
}

impl ReauthenticationWindow for ConsoleSessions {
    async fn mark_reauthenticated(
        &self,
        _: &ApplianceState,
        headers: &HeaderMap,
        proof: Proof,
    ) -> Result<(), ApiError> {
        assert!(headers.contains_key(ACCOUNT), "the request's own headers");
        self.marked.lock().unwrap().push(proof);
        Ok(())
    }
}

/// A console's own `POST /api/session`.
async fn sign_in(
    State(app): State<ApplianceState>,
    Extension(sessions): Extension<ConsoleSessions>,
    Json(body): Json<wslib_appliance_types::session::SignIn>,
) -> Result<Response, ApiError> {
    let proof = Proof::begin();
    let account =
        wslib_appliance_auth::authenticate(&app.store, &body.username, body.password.expose())
            .await?;
    password_proved(&app, &sessions, account, proof).await
}

async fn console() -> Probe {
    console_marking(ConsoleSessions::default()).await
}

/// The routes nested under a prefix of the console's choosing, as it may.
async fn console_marking(sessions: ConsoleSessions) -> Probe {
    let routes = Router::new()
        .route("/session", post(sign_in).layer(Extension(sessions.clone())))
        .merge(reauthentication_route(sessions.clone()))
        .merge(second_factor_routes(sessions));
    Probe::hosting(AboveAdmin::Present, vec![Mount::from(routes)], |c| c).await
}

/// An account with a password, as the console's resolver vouches for it.
async fn account(probe: &Probe, name: &str) -> String {
    let hash = wslib_appliance_auth::hash_password(PASSWORD).expect("hash");
    let user = probe.store().create_user(name, &hash, Role::Viewer).await;
    user.expect("an account").id
}

fn request(probe: &Probe, method: &'static str, path: &str, id: Option<&str>) -> Req {
    let request =
        Req::new(probe.https.clone(), method, path).header("host", &format!("box.local:{PORT}"));
    match id {
        Some(id) => request.header(ACCOUNT, id),
        None => request,
    }
}

fn millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

async fn post_json(probe: &Probe, path: &str, id: Option<&str>, body: Value) -> Response {
    request(probe, "POST", path, id).json(body).send().await
}

#[tokio::test]
async fn a_consoles_own_sign_in_answers_a_session_or_a_second_step() {
    let probe = console().await;
    let id = account(&probe, "member").await;
    let sign_in = json!({ "username": "member", "password": PASSWORD });

    let session = post_json(&probe, "/api/session", None, sign_in.clone()).await;
    assert_eq!(session.status(), StatusCode::OK);
    assert_eq!(session.headers()["set-cookie"], format!("console={id}"));

    let proof = json!({ "password": PASSWORD });
    let enrolment = post_json(&probe, "/api/session/totp", Some(&id), proof).await;
    assert_eq!(enrolment.status(), StatusCode::OK);
    let secret = body_json(enrolment).await["secret"]
        .as_str()
        .unwrap()
        .to_string();
    let code = code_at(&secret, SystemTime::now());
    let confirm = json!({ "code": code, "browser_time": millis() });
    let confirmed = post_json(&probe, "/api/session/totp/confirm", Some(&id), confirm).await;
    assert_eq!(confirmed.status(), StatusCode::OK);

    let waiting = post_json(&probe, "/api/session", None, sign_in).await;
    assert_eq!(waiting.status(), StatusCode::ACCEPTED);
    assert!(!waiting.headers().contains_key("set-cookie"));
    let pending = body_json(waiting).await["pending"].clone();
    let code = code_at(&secret, SystemTime::now() + Duration::from_secs(30));
    let step = json!({ "pending": pending, "code": code, "browser_time": millis() });
    let signed_in = post_json(&probe, "/api/session/code", None, step).await;
    assert_eq!(signed_in.status(), StatusCode::OK);
    assert_eq!(signed_in.headers()["set-cookie"], format!("console={id}"));
}

const AT_WEAKER_PARAMETERS: &str = "$argon2id$v=19$m=8192,t=1,p=1$+uybDU2NtBoGgAnkxKZNcw$\
                                    1u9I1O+Sy58/3m++vRqSlZxB+w6KChDjox0kKAgquYo";
const TOTP_KEY: &str = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

/// `member`, with TOTP on and its password hashed at weaker parameters.
async fn weakly_hashed_with_totp(probe: &Probe) -> String {
    let store = probe.store();
    let user = store.create_user("member", AT_WEAKER_PARAMETERS, Role::Viewer);
    let id = user.await.expect("an account").id;
    let key = wslib_secret::Secret::new(TOTP_KEY);
    assert!(store.enrol_totp(&id, &key).await.unwrap());
    assert!(store.confirm_totp(&id, &key, 1, &[]).await.unwrap());
    id
}

/// The code step for a 202 `waiting`, with the code at `at`.
async fn code_step(probe: &Probe, waiting: Response, at: SystemTime) -> StatusCode {
    let pending = body_json(waiting).await["pending"].clone();
    let code = code_at(TOTP_KEY, at);
    let step = json!({ "pending": pending, "code": code, "browser_time": millis() });
    post_json(probe, "/api/session/code", None, step)
        .await
        .status()
}

#[tokio::test]
async fn a_sign_in_that_re_hashes_the_password_still_takes_its_code() {
    let probe = console().await;
    let id = weakly_hashed_with_totp(&probe).await;

    let sign_in = json!({ "username": "member", "password": PASSWORD });
    let waiting = post_json(&probe, "/api/session", None, sign_in).await;
    assert_eq!(waiting.status(), StatusCode::ACCEPTED);
    let stored = probe.store().user_by_id(&id).await.unwrap().unwrap();
    assert_ne!(stored.password_hash.expose(), AT_WEAKER_PARAMETERS);

    let signed_in = code_step(&probe, waiting, SystemTime::now()).await;
    assert_eq!(signed_in, StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_sign_ins_racing_one_re_hash_both_take_their_code() {
    let probe = console().await;
    weakly_hashed_with_totp(&probe).await;
    let store = probe.store();

    let held = store.begin().await.expect("a write lock");
    let release = async move {
        // Both re-hashes blocked on the lock, beside it: so both read the old hash.
        let deadline = Instant::now() + Duration::from_secs(4);
        let mut blocked_since = None;
        while blocked_since.is_none_or(|at: Instant| at.elapsed() < Duration::from_millis(100)) {
            assert!(Instant::now() < deadline, "the re-hashes never blocked");
            let in_use = store.pool().size() as usize - store.pool().num_idle();
            blocked_since = (in_use >= 3).then(|| blocked_since.unwrap_or_else(Instant::now));
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        held.commit().await.expect("release");
    };
    let sign_in = json!({ "username": "member", "password": PASSWORD });
    let (a, b, ()) = tokio::join!(
        post_json(&probe, "/api/session", None, sign_in.clone()),
        post_json(&probe, "/api/session", None, sign_in),
        release,
    );
    assert_eq!(
        (a.status(), b.status()),
        (StatusCode::ACCEPTED, StatusCode::ACCEPTED)
    );

    let now = SystemTime::now();
    assert_eq!(code_step(&probe, a, now).await, StatusCode::OK);
    let next = now + Duration::from_secs(30);
    assert_eq!(code_step(&probe, b, next).await, StatusCode::OK);
}

#[tokio::test]
async fn a_resolvers_account_proves_itself_again_by_passkey() {
    let probe = console().await;
    let id = account(&probe, "member").await;
    let origin = format!("https://box.local:{PORT}");
    let proof = json!({ "password": PASSWORD });
    let options = post_json(&probe, "/api/session/passkeys/options", Some(&id), proof).await;
    assert_eq!(options.status(), StatusCode::OK);
    let mut passkey = SoftPasskey::new();
    let credential = passkey.register(
        &serde_json::from_value(body_json(options).await).unwrap(),
        &origin,
    );
    let made = json!({ "name": "Key", "credential": credential });
    let made = post_json(&probe, "/api/session/passkeys", Some(&id), made).await;
    assert_eq!(made.status(), StatusCode::CREATED);

    let options = request(
        &probe,
        "POST",
        "/api/session/reauthentication/options",
        Some(&id),
    )
    .send()
    .await;
    assert_eq!(options.status(), StatusCode::OK);
    let assertion = passkey.answer(
        &serde_json::from_value(body_json(options).await).unwrap(),
        &origin,
    );
    let codes = json!({ "passkey": assertion });
    let refused = post_json(&probe, "/api/session/recovery-codes", Some(&id), codes).await;
    assert_eq!(
        refused.status(),
        StatusCode::CONFLICT,
        "proved, and TOTP is not on to make codes for"
    );
    let rows = probe.store().audit(10, None).await.unwrap().items;
    let proved = rows
        .iter()
        .find(|row| row.message == "re-authenticated")
        .expect("the proof's row");
    assert!(
        proved.fields.contains(&("method".into(), "passkey".into())),
        "{:?}",
        proved.fields
    );
}

#[tokio::test]
async fn a_resolver_that_does_not_vouch_for_the_stores_accounts_has_no_account_here() {
    let window = ConsoleSessions::default();
    let routes = vec![Mount::from(
        second_factor_routes(window.clone()).merge(reauthentication_route(window.clone())),
    )];
    let probe = Probe::resolving_hosting(Elsewhere(Some(chrono::Utc::now())), routes).await;
    let garbage = json!({ "passkey": {
        "id": "AQ", "rawId": "AQ", "type": "public-key",
        "response": { "clientDataJSON": "e30", "authenticatorData": "AA", "signature": "AA" },
    }});
    let unmarked = post_json(&probe, "/api/session/reauthenticate", None, garbage).await;
    assert_eq!(unmarked.status(), StatusCode::NOT_FOUND);
    assert!(window.marked.lock().unwrap().is_empty());
    for (method, path) in [
        ("GET", "/api/session/totp"),
        ("GET", "/api/session/passkeys"),
        ("POST", "/api/session/reauthentication/options"),
    ] {
        let response = request(&probe, method, path, None).send().await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
    }
    let enrol = post_json(
        &probe,
        "/api/session/totp",
        None,
        json!({ "password": PASSWORD }),
    )
    .await;
    assert_eq!(enrol.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn proving_again_marks_the_hosts_session_and_proving_nothing_does_not() {
    let sessions = ConsoleSessions::default();
    let probe = console_marking(sessions.clone()).await;
    let id = account(&probe, "member").await;
    let marked = || sessions.marked.lock().unwrap().len();
    for nothing in [json!({}), json!({ "password": "" })] {
        let refused = post_json(&probe, "/api/session/reauthenticate", Some(&id), nothing).await;
        assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    }
    let wrong = json!({ "password": "not it" });
    let refused = post_json(&probe, "/api/session/reauthenticate", Some(&id), wrong).await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert_eq!(marked(), 0);

    let right = json!({ "password": PASSWORD });
    let proved = post_json(&probe, "/api/session/reauthenticate", Some(&id), right).await;
    assert_eq!(proved.status(), StatusCode::NO_CONTENT);
    assert_eq!(marked(), 1);
}

/// The last proof in `proofs` was begun after `since`, during the request
/// that was answered by now.
fn begun_in_the_request(proofs: &Proofs, since: chrono::DateTime<chrono::Utc>) {
    let last = proofs.lock().unwrap().last().expect("a proof").at();
    assert!(since <= last && last <= wslib_auth::now(), "{since} {last}");
}

#[tokio::test]
async fn every_step_that_ends_in_a_session_or_a_mark_carries_a_proof_of_its_own() {
    let sessions = ConsoleSessions::default();
    let probe = console_marking(sessions.clone()).await;
    let origin = format!("https://box.local:{PORT}");
    let id = account(&probe, "member").await;
    let sign_in = json!({ "username": "member", "password": PASSWORD });

    let since = wslib_auth::now();
    let signed = post_json(&probe, "/api/session", None, sign_in.clone()).await;
    assert_eq!(signed.status(), StatusCode::OK);
    begun_in_the_request(&sessions.issued, since);

    let since = wslib_auth::now();
    let proof = json!({ "password": PASSWORD });
    let proved = post_json(&probe, "/api/session/reauthenticate", Some(&id), proof).await;
    assert_eq!(proved.status(), StatusCode::NO_CONTENT);
    begun_in_the_request(&sessions.marked, since);

    let proof = json!({ "password": PASSWORD });
    let options = post_json(&probe, "/api/session/passkeys/options", Some(&id), proof).await;
    let mut passkey = SoftPasskey::new();
    let credential = passkey.register(
        &serde_json::from_value(body_json(options).await).unwrap(),
        &origin,
    );
    let made = json!({ "name": "Key", "credential": credential });
    let made = post_json(&probe, "/api/session/passkeys", Some(&id), made).await;
    assert_eq!(made.status(), StatusCode::CREATED);
    let options = request(&probe, "POST", "/api/session/passkey/options", None)
        .send()
        .await;
    let assertion = passkey.answer(
        &serde_json::from_value(body_json(options).await).unwrap(),
        &origin,
    );
    let since = wslib_auth::now();
    let assertion = serde_json::to_value(assertion).unwrap();
    let signed = post_json(&probe, "/api/session/passkey", None, assertion).await;
    assert_eq!(signed.status(), StatusCode::OK);
    begun_in_the_request(&sessions.issued, since);

    probe.store().require_totp(&id).await.unwrap();
    let waiting = post_json(&probe, "/api/session", None, sign_in.clone()).await;
    assert_eq!(waiting.status(), StatusCode::ACCEPTED);
    let pending = body_json(waiting).await["pending"].clone();
    let enrolment = json!({ "pending": pending });
    let enrolment = post_json(&probe, "/api/session/enrolment", None, enrolment).await;
    let secret = body_json(enrolment).await["secret"]
        .as_str()
        .unwrap()
        .to_string();
    let code = code_at(&secret, SystemTime::now());
    let confirm = json!({ "pending": pending, "code": code, "browser_time": millis() });
    let since = wslib_auth::now();
    let enrolled = post_json(&probe, "/api/session/enrolment/confirm", None, confirm).await;
    assert_eq!(enrolled.status(), StatusCode::OK);
    begun_in_the_request(&sessions.issued, since);

    let waiting = post_json(&probe, "/api/session", None, sign_in).await;
    assert_eq!(waiting.status(), StatusCode::ACCEPTED);
    let pending = body_json(waiting).await["pending"].clone();
    let code = code_at(&secret, SystemTime::now() + Duration::from_secs(30));
    let step = json!({ "pending": pending, "code": code, "browser_time": millis() });
    let since = wslib_auth::now();
    let signed = post_json(&probe, "/api/session/code", None, step).await;
    assert_eq!(signed.status(), StatusCode::OK);
    begun_in_the_request(&sessions.issued, since);
}

#[tokio::test]
async fn a_page_is_told_whether_a_passkey_can_run_where_it_was_reached() {
    let probe = console().await;
    let availability = |host: &str| {
        Req::new(
            probe.https.clone(),
            "GET",
            "/api/session/passkey/availability",
        )
        .header("host", host)
        .send()
    };
    let here = body_json(availability(&format!("box.local:{PORT}")).await).await;
    assert_eq!(here, json!({ "state": "ready", "via": "box.local" }));
    let address = body_json(availability(&format!("192.168.1.20:{PORT}")).await).await;
    assert_eq!(address["state"], "unsupported");
    assert!(
        address["because"].as_str().unwrap().contains("IP address"),
        "{address}"
    );
}

#[tokio::test]
async fn a_sign_in_page_is_told_the_names_the_boxs_passkeys_were_made_on_and_no_more() {
    let probe = console().await;
    let hosts = || request(&probe, "GET", "/api/session/passkey/hosts", None).send();
    assert_eq!(body_json(hosts().await).await, json!([]));
    for (who, rp_id, byte) in [
        ("member", "box.local", 1),
        ("other", "old.local", 2),
        ("third", "box.local", 3),
    ] {
        let id = account(&probe, who).await;
        let passkey = wslib_appliance_store::NewPasskey {
            credential_id: vec![byte; 16],
            public_key: vec![0xa5],
            sign_count: 0,
            name: "Phone".into(),
            rp_id: rp_id.into(),
        };
        probe.store().add_passkey(&id, passkey).await.unwrap();
    }
    assert_eq!(
        body_json(hosts().await).await,
        json!(["box.local", "old.local"])
    );
}

/// A console's own users routes, over the core's functions.
async fn console_with_users() -> Probe {
    use axum::extract::Path;
    let users = Router::new()
        .route(
            "/users/{id}/require-totp",
            post(
                |crate::Admin(who): crate::Admin,
                 State(app): State<ApplianceState>,
                 Path(id): Path<String>,
                 reached: Reached,
                 Json(proof): Json<FactorProof>| async move {
                    require_totp_enrolment(&app, &who, &reached, &id, proof).await
                },
            ),
        )
        .route(
            "/users/{id}/passkeys/{passkey}/remove",
            post(
                |crate::Admin(who): crate::Admin,
                 State(app): State<ApplianceState>,
                 Path((id, passkey)): Path<(String, String)>,
                 reached: Reached,
                 Json(proof): Json<FactorProof>| async move {
                    remove_account_passkey(&app, &who, &reached, &id, &passkey, proof).await
                },
            ),
        );
    Probe::hosting(AboveAdmin::Present, vec![Mount::from(users)], |c| c).await
}

#[tokio::test]
async fn a_console_calls_the_admin_functions_for_a_resolvers_account() {
    let probe = console_with_users().await;
    let admin = account(&probe, "admin").await;
    probe.store().set_role(&admin, Role::Admin).await.unwrap();
    let member = account(&probe, "member").await;
    let passkey = probe
        .store()
        .add_passkey(
            &member,
            wslib_appliance_store::NewPasskey {
                credential_id: vec![7; 16],
                public_key: vec![0xa5],
                sign_count: 0,
                name: "Phone".into(),
                rp_id: "box.local".into(),
            },
        )
        .await
        .unwrap();
    let proof = json!({ "password": PASSWORD });

    let own = format!("/api/users/{admin}/require-totp");
    let refused = post_json(&probe, &own, Some(&admin), proof.clone()).await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    let unproved = format!("/api/users/{member}/require-totp");
    let refused = post_json(&probe, &unproved, Some(&admin), json!({})).await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    let required = post_json(&probe, &unproved, Some(&admin), proof.clone()).await;
    assert_eq!(required.status(), StatusCode::OK);
    assert!(probe.store().totp_required(&member).await.unwrap());

    let removal = format!("/api/users/{member}/passkeys/{}/remove", passkey.id);
    let removed = post_json(&probe, &removal, Some(&admin), proof).await;
    assert_eq!(removed.status(), StatusCode::OK);
    assert!(probe.store().passkeys(&member).await.unwrap().is_empty());
    let rows = probe.store().audit(10, None).await.unwrap().items;
    let row = rows
        .iter()
        .find(|row| row.message == "removed a passkey")
        .expect("audited");
    assert_eq!(row.actor_id.as_deref(), Some(admin.as_str()));
    assert!(row.fields.contains(&("name".into(), "Phone".into())));
}

#[tokio::test]
async fn the_control_socket_reaches_the_rung_and_is_nobody() {
    let probe = console().await;
    for response in probe.local(Role::Admin, "/api/session/totp").await {
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            body_json(response).await["error"],
            "the control socket is not signed in as anybody"
        );
    }
}

/// A console's own routes that ask the caller, and an acting admin, for fresh
/// proof.
fn proving() -> Mount {
    let prove = |acting: bool| {
        post(
            move |Viewer(who): Viewer,
                  State(app): State<ApplianceState>,
                  reached: Reached,
                  Json(proof): Json<FactorProof>| async move {
                match acting {
                    true => prove_acting_admin(&app, &who, &reached, proof, "a console's change")
                        .await
                        .map(|()| "proved"),
                    false => prove_caller(&app, &who, &reached, proof, "a console's change").await,
                }
            },
        )
    };
    Mount::from(
        Router::new()
            .route("/prove", prove(false))
            .route("/prove-acting", prove(true)),
    )
}

async fn console_proving() -> Probe {
    Probe::hosting(AboveAdmin::Present, vec![proving()], |c| c).await
}

#[tokio::test]
async fn a_store_accounts_recent_sign_in_never_stands_in_for_its_proof() {
    let probe = console_proving().await;
    let id = account(&probe, "member").await;
    probe.store().set_role(&id, Role::Admin).await.unwrap();
    let logs = crate::logs(&[]).ring().clone();
    let _logging = tracing::subscriber::set_default(logs.subscriber());
    for path in ["/api/prove", "/api/prove-acting"] {
        for nothing in [json!({}), json!({ "password": "" })] {
            let refused = post_json(&probe, path, Some(&id), nothing).await;
            assert_eq!(refused.status(), StatusCode::FORBIDDEN, "{path}");
            assert_eq!(
                body_json(refused).await["error"],
                "the password is incorrect"
            );
        }
        let proved = post_json(&probe, path, Some(&id), json!({ "password": PASSWORD })).await;
        assert_eq!(proved.status(), StatusCode::OK, "{path}");
    }
    let refusals = logs
        .snapshot()
        .records
        .iter()
        .filter(|r| r.message == "re-authentication refused: the password is wrong")
        .count();
    assert_eq!(refusals, 4);
}

/// An admin the store does not hold, re-authenticated at `.0`.
struct Elsewhere(Option<chrono::DateTime<chrono::Utc>>);

impl crate::ResolveCaller for Elsewhere {
    async fn resolve(
        &self,
        _: &axum::http::request::Parts,
    ) -> Result<Option<crate::Principal>, ApiError> {
        Ok(Some(crate::Principal {
            id: "console:7".into(),
            username: "asserted".into(),
            role: Role::Admin,
            reauthenticated_at: self.0,
        }))
    }
}

#[tokio::test]
async fn a_recent_proof_stands_in_for_an_account_the_store_does_not_hold() {
    let stale = chrono::Utc::now() - chrono::TimeDelta::minutes(6);
    for (at, status) in [
        (Some(chrono::Utc::now()), StatusCode::OK),
        (Some(stale), StatusCode::FORBIDDEN),
    ] {
        let probe = Probe::resolving_hosting(Elsewhere(at), vec![proving()]).await;
        for path in ["/api/prove", "/api/prove-acting"] {
            let response = post_json(&probe, path, None, json!({})).await;
            assert_eq!(response.status(), status, "{path} {at:?}");
        }
    }
}

#[tokio::test]
async fn a_caller_with_totp_on_proves_itself_with_a_code_and_never_the_password_alone() {
    let probe = console_proving().await;
    let id = account(&probe, "member").await;
    let password = json!({ "password": PASSWORD });
    let proved = post_json(&probe, "/api/prove", Some(&id), password.clone()).await;
    assert_eq!(proved.status(), StatusCode::OK);

    let key = wslib_secret::Secret::new("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP");
    assert!(probe.store().enrol_totp(&id, &key).await.unwrap());
    assert!(probe.store().confirm_totp(&id, &key, 1, &[]).await.unwrap());
    let refused = post_json(&probe, "/api/prove", Some(&id), password).await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert!(
        body_json(refused).await["error"]
            .as_str()
            .unwrap()
            .starts_with("while TOTP is on")
    );
    let code = code_at(key.expose(), SystemTime::now());
    let by_code = json!({ "code": code, "browser_time": millis() });
    let proved = post_json(&probe, "/api/prove", Some(&id), by_code).await;
    assert_eq!(proved.status(), StatusCode::OK);
}

#[tokio::test]
async fn every_refused_proof_is_marked_beside_its_status_and_sentence() {
    let probe = console_proving().await;
    let id = account(&probe, "member").await;
    let prove = |body: Value| post_json(&probe, "/api/prove", Some(id.as_str()), body);
    let garbage_passkey = json!({ "passkey": {
        "id": "AQ", "rawId": "AQ", "type": "public-key",
        "response": { "clientDataJSON": "e30", "authenticatorData": "AA", "signature": "AA" },
    }});
    let mut refusals = vec![
        (
            prove(json!({ "password": "not it" })).await,
            "the password is incorrect".to_string(),
        ),
        (
            prove(garbage_passkey).await,
            "the passkey was not accepted".to_string(),
        ),
    ];

    let key = wslib_secret::Secret::new(TOTP_KEY);
    assert!(probe.store().enrol_totp(&id, &key).await.unwrap());
    assert!(probe.store().confirm_totp(&id, &key, 1, &[]).await.unwrap());
    let code = code_at(TOTP_KEY, SystemTime::now());
    let wrong = format!("{}{}", &code[..5], (code.as_bytes()[5] - b'0' + 1) % 10);
    let by = |code: &str| json!({ "code": code, "browser_time": millis() });
    assert_eq!(prove(by(&code)).await.status(), StatusCode::OK);
    refusals.extend([
        (
            prove(json!({ "password": PASSWORD })).await,
            "while TOTP is on, this needs a code from the authenticator app, a recovery code \
             or a passkey"
                .to_string(),
        ),
        (prove(by(&wrong)).await, "the code is incorrect".to_string()),
        (
            prove(by(&code)).await,
            "that code has just been used; wait for the next one".to_string(),
        ),
    ]);

    let stale = Some(chrono::Utc::now() - chrono::TimeDelta::minutes(6));
    let elsewhere = Probe::resolving_hosting(Elsewhere(stale), vec![proving()]).await;
    refusals.push((
        post_json(&elsewhere, "/api/prove", None, json!({})).await,
        format!(
            "{} in the last 5 minutes",
            wslib_appliance_types::STALE_PROOF
        ),
    ));

    for (response, sentence) in refusals {
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{sentence}");
        let body = body_json(response).await;
        assert_eq!(body["error"], sentence);
        assert_eq!(body["proof"], "refused", "{body}");
    }
}

#[tokio::test]
async fn a_refusal_that_is_not_of_a_proof_is_not_marked() {
    let probe = console_with_users().await;
    let admin = account(&probe, "admin").await;
    probe.store().set_role(&admin, Role::Admin).await.unwrap();
    let member = account(&probe, "member").await;
    let proof = json!({ "password": PASSWORD });

    let admins = format!("/api/users/{admin}/require-totp");
    let own = post_json(&probe, &admins, Some(&admin), proof.clone()).await;
    let unranked = post_json(&probe, &admins, Some(&member), proof).await;
    let plain = ApiError::Forbidden("no".into()).into_response();
    for refused in [own, unranked, plain] {
        assert_eq!(refused.status(), StatusCode::FORBIDDEN);
        let body = body_json(refused).await;
        assert!(body.get("proof").is_none(), "{body}");
    }
}

#[tokio::test]
async fn the_control_socket_has_no_factor_to_prove() {
    let probe = console_proving().await;
    let socket = probe.control.clone().with_local_authority(Role::Admin);
    let refused = Req::new(socket, "POST", "/api/prove")
        .json(json!({}))
        .send()
        .await;
    assert_eq!(refused.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        body_json(refused).await["error"],
        "the control socket is not signed in as anybody"
    );
}

fn code_at(secret: &str, at: SystemTime) -> String {
    wslib_auth_totp::Key::from_base32(secret)
        .expect("a key")
        .code_at(at)
}

/// A console whose sessions are rows of `platform_sessions`: its resolver
/// reports each one's stamp, and its window stamps it.
#[cfg(feature = "sessions")]
mod platform_sessions {
    use axum::http::request::Parts;
    use wslib_appliance_auth::Sessions;
    use wslib_auth::SessionCookie;

    use super::*;
    use crate::backend::{Callers, LogsRung};
    use crate::testing::body_text;
    use crate::{Principal, ResolveCaller};

    const COOKIE: SessionCookie = SessionCookie::new("console_session");

    struct Resolver(Store);

    impl ResolveCaller for Resolver {
        async fn resolve(&self, request: &Parts) -> Result<Option<Principal>, ApiError> {
            let Some(token) = COOKIE.token_in(&request.headers) else {
                return Ok(None);
            };
            match Sessions::new(&self.0)
                .resolve_with_reauthenticated_at(&self.0, &token)
                .await
            {
                Ok((user, at)) => Ok(Some(Principal {
                    id: user.id,
                    username: user.username,
                    role: user.role,
                    reauthenticated_at: Some(at),
                })),
                Err(AuthError::NoSession) => Ok(None),
                Err(e) => Err(e.into()),
            }
        }
    }

    #[derive(Clone)]
    struct Window;

    impl ReauthenticationWindow for Window {
        async fn mark_reauthenticated(
            &self,
            app: &ApplianceState,
            headers: &HeaderMap,
            proof: Proof,
        ) -> Result<(), ApiError> {
            let token = COOKIE.token_in(headers).ok_or(ApiError::Unauthenticated)?;
            let sessions = Sessions::new(&app.store);
            Ok(sessions.reauthenticated(&app.store, &token, proof).await?)
        }
    }

    async fn stamp(Viewer(who): Viewer) -> String {
        match who {
            Identity::Resolved(principal) => {
                wslib_auth::stamp(principal.reauthenticated_at.unwrap())
            }
            other => panic!("{other:?}"),
        }
    }

    async fn stamp_of(probe: &Probe, cookie: &str) -> chrono::DateTime<chrono::Utc> {
        let response = request(probe, "GET", "/api/stamp", None)
            .header("cookie", cookie)
            .send()
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        wslib_auth::parse_stamp(&body_text(response).await).expect("a stamp")
    }

    #[tokio::test]
    async fn re_authenticating_stamps_the_platform_session_its_resolver_reports() {
        let routes = reauthentication_route(Window).route("/stamp", get(stamp));
        let probe = Probe::build(
            |store| Callers::resolved_from_store(Resolver(store.clone())),
            LogsRung::SessionAdmin,
            AboveAdmin::Present,
            vec![Mount::from(routes)],
            |c| c,
            true,
        )
        .await;
        let store = probe.store();
        let id = account(&probe, "member").await;
        let account = store.user_by_id(&id).await.unwrap().expect("the account");
        let signed_in = Proof::begin();
        let token = Sessions::new(store)
            .issue(store, &account.user, account.sessions_valid_from, signed_in)
            .await
            .expect("issue");
        let cookie = format!("console_session={}", token.expose());
        assert_eq!(stamp_of(&probe, &cookie).await, signed_in.at());

        let since = wslib_auth::now();
        let proved = request(&probe, "POST", "/api/session/reauthenticate", None)
            .header("cookie", &cookie)
            .json(json!({ "password": PASSWORD }))
            .send()
            .await;
        assert_eq!(proved.status(), StatusCode::NO_CONTENT);
        let stamped = stamp_of(&probe, &cookie).await;
        assert!(
            since <= stamped && stamped <= wslib_auth::now(),
            "{since} {stamped}"
        );
    }
}
