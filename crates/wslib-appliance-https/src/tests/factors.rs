//! The second-factor routes over this backend's own sessions: the code step,
//! passkey sign-in, the account screen's routes, and passkey reauthentication.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::http::StatusCode;
use axum::response::Response;
use serde_json::{Value, json};
use wslib_appliance_core::backend;
use wslib_appliance_types::passkey::{CreationOptions, RequestOptions};
use wslib_appliance_types::{AuditRecord, Role};

use crate::testing::{Harness, Req, SoftPasskey, body_json};

const PORT: u16 = 8443;
const HOST: &str = "box.local:8443";
const ORIGIN: &str = "https://box.local:8443";

async fn harness() -> Harness {
    let app = Harness::new().await;
    app.serving_on(PORT);
    app
}

fn proof() -> Value {
    json!({ "password": Harness::PASSWORD })
}

fn millis(at: SystemTime) -> u64 {
    at.duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

fn now() -> u64 {
    millis(SystemTime::now())
}

/// The code an authenticator shows `ahead` seconds from now.
fn code_at(secret: &str, ahead: u64) -> String {
    wslib_auth_totp::Key::from_base32(secret)
        .expect("a key")
        .code_at(SystemTime::now() + Duration::from_secs(ahead))
}

/// `username`, signed in with TOTP turned on: its session, its key and its
/// recovery codes. The key's next code is [`code_at`] 30 seconds ahead.
async fn with_totp(app: &Harness, username: &str) -> (String, String, Vec<String>) {
    let token = app.signed_in(username, Role::Viewer).await;
    let enrolled = app
        .post("/api/session/totp")
        .cookie(&token)
        .json(proof())
        .send()
        .await;
    assert_eq!(enrolled.status(), StatusCode::OK);
    let secret = body_json(enrolled).await["secret"]
        .as_str()
        .unwrap()
        .to_string();
    let confirmed = app
        .post("/api/session/totp/confirm")
        .cookie(&token)
        .json(json!({ "code": code_at(&secret, 0), "browser_time": now() }))
        .send()
        .await;
    assert_eq!(confirmed.status(), StatusCode::OK);
    let codes = body_json(confirmed).await["codes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|code| code.as_str().unwrap().to_string())
        .collect();
    (token, secret, codes)
}

/// The waiting sign-in a right password answers for an account with TOTP on.
async fn pending(app: &Harness, username: &str) -> String {
    let response = app
        .post("/api/session")
        .json(json!({ "username": username, "password": Harness::PASSWORD }))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert!(Harness::session_from(&response).is_none(), "no session yet");
    body_json(response).await["pending"]
        .as_str()
        .unwrap()
        .to_string()
}

async fn code_step(app: &Harness, pending: &str, code: &str, browser_time: u64) -> Response {
    app.post("/api/session/code")
        .json(json!({ "pending": pending, "code": code, "browser_time": browser_time }))
        .send()
        .await
}

async fn recovery_step(app: &Harness, pending: &str, code: &str) -> Response {
    app.post("/api/session/code")
        .json(json!({ "pending": pending, "code": code, "recovery": true, "browser_time": now() }))
        .send()
        .await
}

/// Every audit row, newest first.
async fn rows(app: &Harness) -> Vec<AuditRecord> {
    tokio::time::sleep(Duration::from_millis(50)).await;
    app.store().audit(100, None).await.unwrap().items
}

fn field<'a>(row: &'a AuditRecord, name: &str) -> Option<&'a str> {
    row.fields
        .iter()
        .find(|(field, _)| field == name)
        .map(|(_, value)| value.as_str())
}

/// That no row carries any of `secrets`, in its message or a field.
async fn no_row_carries(app: &Harness, secrets: &[&str]) {
    for row in rows(app).await {
        let text = format!("{} {:?}", row.message, row.fields);
        for secret in secrets {
            assert!(!text.contains(secret), "{secret:?} in {text}");
        }
    }
}

fn at_box(request: Req) -> Req {
    request.header("host", HOST)
}

async fn registration_options(app: &Harness, token: &str, proof: Value) -> Response {
    at_box(app.post("/api/session/passkeys/options"))
        .cookie(token)
        .json(proof)
        .send()
        .await
}

/// A passkey made for the account behind `token`, which has no TOTP, named
/// `name`: its listing.
async fn registered(app: &Harness, token: &str, passkey: &mut SoftPasskey, name: &str) -> Value {
    registered_by(app, token, passkey, name, proof()).await
}

/// [`registered`], proving the account by `proof`.
async fn registered_by(
    app: &Harness,
    token: &str,
    passkey: &mut SoftPasskey,
    name: &str,
    proof: Value,
) -> Value {
    let options = registration_options(app, token, proof).await;
    assert_eq!(options.status(), StatusCode::OK);
    let options: CreationOptions = serde_json::from_value(body_json(options).await).unwrap();
    let credential = passkey.register(&options, ORIGIN);
    let made = at_box(app.post("/api/session/passkeys"))
        .cookie(token)
        .json(json!({ "name": name, "credential": credential }))
        .send()
        .await;
    assert_eq!(made.status(), StatusCode::CREATED);
    body_json(made).await
}

async fn sign_in_options(app: &Harness) -> RequestOptions {
    let options = at_box(app.post("/api/session/passkey/options"))
        .send()
        .await;
    assert_eq!(options.status(), StatusCode::OK);
    serde_json::from_value(body_json(options).await).unwrap()
}

async fn reauthentication_options(app: &Harness, token: &str) -> RequestOptions {
    let options = at_box(app.post("/api/session/reauthentication/options"))
        .cookie(token)
        .send()
        .await;
    assert_eq!(options.status(), StatusCode::OK);
    serde_json::from_value(body_json(options).await).unwrap()
}

#[tokio::test]
async fn a_password_with_totp_on_signs_in_only_after_its_code() {
    let app = harness().await;
    let (_, secret, _) = with_totp(&app, "member").await;
    let pending = pending(&app, "member").await;
    let waiting = app.audit_row("password accepted; waiting for a code").await;
    assert_eq!((waiting.actor.as_str(), waiting.actor_id), ("member", None));

    let code = code_at(&secret, 30);
    let signed_in = code_step(&app, &pending, &code, now()).await;
    assert_eq!(signed_in.status(), StatusCode::OK);
    let token = Harness::session_from(&signed_in).expect("a session");
    assert_eq!(body_json(signed_in).await["username"], "member");
    let who = app.get("/api/session").cookie(&token).send().await;
    assert_eq!(who.status(), StatusCode::OK);

    let row = app.audit_row("signed in").await;
    assert_eq!(field(&row, "method"), Some("password+totp"));
    no_row_carries(&app, &[&code, &pending, &secret]).await;
}

#[tokio::test]
async fn a_second_password_holder_pushes_out_no_waiting_sign_in_and_is_audited() {
    let app = harness().await;
    let (_, _, codes) = with_totp(&app, "member").await;
    let owners = pending(&app, "member").await;
    let theirs = pending(&app, "member").await;
    let row = app
        .audit_row(
            "password accepted while another sign-in waits for its code, a sign the password is known",
        )
        .await;
    assert_eq!((row.actor.as_str(), row.level.as_str()), ("member", "WARN"));
    for (pending, code) in [(&owners, &codes[0]), (&theirs, &codes[1])] {
        let signed_in = recovery_step(&app, pending, code).await;
        assert_eq!(signed_in.status(), StatusCode::OK, "each still waits");
    }
}

#[tokio::test]
async fn a_password_changed_since_ends_the_waiting_sign_in() {
    let app = harness().await;
    let (token, _, codes) = with_totp(&app, "member").await;
    let pending = pending(&app, "member").await;
    let changed = app
        .put("/api/session/password")
        .cookie(&token)
        .json(json!({
            "current_password": Harness::PASSWORD, "new_password": "a whole new password",
            "code": codes[1], "recovery": true,
        }))
        .send()
        .await;
    assert_eq!(changed.status(), StatusCode::NO_CONTENT);
    for _ in 0..2 {
        let refused = recovery_step(&app, &pending, &codes[0]).await;
        assert_eq!(
            refused.status(),
            StatusCode::UNAUTHORIZED,
            "and stays ended"
        );
    }
}

#[tokio::test]
async fn a_password_awaiting_its_code_is_no_sign_in_yet() {
    let app = harness().await;
    let (_, _, codes) = with_totp(&app, "member").await;
    let last_login = || async {
        let id = app.user_id("member").await;
        let row = app.store().user_by_id(&id).await.unwrap().unwrap();
        row.user.last_login_at
    };
    let before = last_login().await;
    let pending = pending(&app, "member").await;
    assert_eq!(last_login().await, before, "a 202 stamps nothing");
    let sign_ins = rows(&app)
        .await
        .into_iter()
        .filter(|r| r.message == "signed in");
    assert_eq!(sign_ins.count(), 1, "only the one that made the session");

    assert_eq!(
        recovery_step(&app, &pending, &codes[0]).await.status(),
        StatusCode::OK
    );
    assert_ne!(last_login().await, before, "the session's issue stamps it");
}

#[tokio::test]
async fn a_pending_sign_in_signs_in_once_and_a_made_up_one_never() {
    let app = harness().await;
    let (_, _, codes) = with_totp(&app, "member").await;
    let pending = pending(&app, "member").await;
    assert_eq!(
        recovery_step(&app, &pending, &codes[0]).await.status(),
        StatusCode::OK
    );
    for spent_or_made_up in [pending.as_str(), "bm90IGEgcGVuZGluZyBzaWduLWlu"] {
        let refused = recovery_step(&app, spent_or_made_up, &codes[1]).await;
        assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
        assert!(Harness::session_from(&refused).is_none());
    }
    let row = app.audit_row("signed in").await;
    assert_eq!(field(&row, "method"), Some("recovery-code"));
}

#[tokio::test]
async fn a_recovery_code_signs_in_once() {
    let app = harness().await;
    let (_, _, codes) = with_totp(&app, "member").await;
    let first = pending(&app, "member").await;
    assert_eq!(
        recovery_step(&app, &first, &codes[3].to_lowercase())
            .await
            .status(),
        StatusCode::OK
    );
    let second = pending(&app, "member").await;
    let spent = recovery_step(&app, &second, &codes[3]).await;
    assert_eq!(spent.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_json(spent).await["error"], "the code is incorrect");
    let row = app
        .audit_row("sign-in with a recovery code refused: the code is wrong")
        .await;
    assert_eq!(row.actor_id, None);
    no_row_carries(&app, &[&codes[3]]).await;
}

#[tokio::test]
async fn a_used_code_is_refused_as_used_and_a_wrong_one_as_wrong_at_sign_in_and_as_proof() {
    let app = harness().await;
    let (token, secret, _) = with_totp(&app, "member").await;
    let code = code_at(&secret, 30);
    let first = pending(&app, "member").await;
    assert_eq!(
        code_step(&app, &first, &code, now()).await.status(),
        StatusCode::OK
    );
    const USED: &str = "that code has just been used; wait for the next one";

    let again = pending(&app, "member").await;
    for (typed, error, why) in [
        (code.as_str(), USED, "the code was already used"),
        ("nonsense", "the code is incorrect", "the code is wrong"),
    ] {
        let refused = code_step(&app, &again, typed, now()).await;
        assert_eq!(refused.status(), StatusCode::FORBIDDEN, "{typed}");
        assert_eq!(body_json(refused).await["error"], error);
        app.audit_row(&format!("sign-in with a TOTP code refused: {why}"))
            .await;

        let proof = json!({ "code": typed, "browser_time": now() });
        let refused = registration_options(&app, &token, proof).await;
        assert_eq!(refused.status(), StatusCode::FORBIDDEN, "{typed}");
        assert_eq!(body_json(refused).await["error"], error);
        app.audit_row(&format!("adding a passkey refused: {why}"))
            .await;
    }
}

#[tokio::test]
async fn the_code_limit_is_the_pending_accounts_and_its_trip_is_audited() {
    let app = harness().await;
    with_totp(&app, "alice").await;
    let (_, bobs_secret, _) = with_totp(&app, "bob").await;
    let alices = pending(&app, "alice").await;
    for _ in 0..5 {
        let wrong = code_step(&app, &alices, "nonsense", now()).await;
        assert_eq!(wrong.status(), StatusCode::FORBIDDEN);
    }
    let held = code_step(&app, &alices, "nonsense", now()).await;
    assert_eq!(held.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(held.headers().contains_key("retry-after"));
    let row = app
        .audit_row(
            "sign-in with a TOTP code refused: too many wrong codes, so the password is likely known",
        )
        .await;
    assert_eq!(row.actor, "alice");
    assert_eq!(row.level, "WARN");

    let bobs = pending(&app, "bob").await;
    let code = code_at(&bobs_secret, 30);
    assert_eq!(
        code_step(&app, &bobs, &code, now()).await.status(),
        StatusCode::OK,
        "another account's codes are its own"
    );
}

#[tokio::test]
async fn a_code_that_missed_with_the_clocks_apart_answers_the_skew_itself() {
    let app = harness().await;
    with_totp(&app, "member").await;
    let pending = pending(&app, "member").await;
    let behind = millis(SystemTime::now() - Duration::from_secs(10 * 60));
    let skewed = code_step(&app, &pending, "nonsense", behind).await;
    assert_eq!(skewed.status(), StatusCode::BAD_REQUEST);
    let body = body_json(skewed).await;
    assert_eq!(body["clock_skew"]["minutes"], 10, "{body}");
    assert!(body["error"].as_str().unwrap().contains("10 minutes off"));

    let overflowed = code_step(&app, &pending, "nonsense", u64::MAX).await;
    assert_eq!(overflowed.status(), StatusCode::BAD_REQUEST);
    let minutes = body_json(overflowed).await["clock_skew"]["minutes"]
        .as_i64()
        .unwrap();
    assert!(
        minutes <= -i64::from(i32::MAX),
        "as far behind as the minutes say, whether the time overflowed or only saturated: {minutes}"
    );
}

#[tokio::test]
async fn confirming_with_the_clocks_apart_is_refused_with_the_skew() {
    let app = harness().await;
    let token = app.signed_in("member", Role::Viewer).await;
    let enrolled = app
        .post("/api/session/totp")
        .cookie(&token)
        .json(proof())
        .send()
        .await;
    let secret = body_json(enrolled).await["secret"]
        .as_str()
        .unwrap()
        .to_string();
    let ahead = millis(SystemTime::now() + Duration::from_secs(5 * 60));
    let refused = app
        .post("/api/session/totp/confirm")
        .cookie(&token)
        .json(json!({ "code": code_at(&secret, 0), "browser_time": ahead }))
        .send()
        .await;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(refused).await["clock_skew"]["minutes"], -5);
}

#[tokio::test]
async fn a_stolen_session_turns_on_nothing_and_strips_nothing_without_fresh_proof() {
    let app = harness().await;
    let (token, secret, _) = with_totp(&app, "member").await;
    let stranger = app.signed_in("stranger", Role::Viewer).await;
    for (path, body) in [
        ("/api/session/totp", json!({})),
        ("/api/session/totp", json!({ "password": "not it" })),
        ("/api/session/recovery-codes", json!({})),
        ("/api/session/totp/off", json!({})),
        (
            "/api/session/totp/off",
            json!({ "proof": { "password": "not it" } }),
        ),
    ] {
        let caller = if path.ends_with("/totp") {
            &stranger
        } else {
            &token
        };
        let refused = app.post(path).cookie(caller).json(body).send().await;
        assert_eq!(refused.status(), StatusCode::FORBIDDEN, "{path}");
    }
    let refused = at_box(app.post("/api/session/passkeys/options"))
        .cookie(&token)
        .json(json!({}))
        .send()
        .await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);

    let view = body_json(app.get("/api/session/totp").cookie(&token).send().await).await;
    assert_eq!(view, json!({ "on": true, "recovery_codes_left": 10 }));
    let off_by_code = app
        .post("/api/session/totp/off")
        .cookie(&token)
        .json(json!({ "code": code_at(&secret, 30), "browser_time": now() }))
        .send()
        .await;
    assert_eq!(off_by_code.status(), StatusCode::NO_CONTENT);
    let row = app.audit_row("turned TOTP off").await;
    assert_eq!(field(&row, "method"), Some("totp"));
    let view = body_json(app.get("/api/session/totp").cookie(&token).send().await).await;
    assert_eq!(view, json!({ "on": false, "recovery_codes_left": 0 }));
}

#[tokio::test]
async fn new_recovery_codes_replace_the_old_and_a_recovery_code_turns_totp_off() {
    let app = harness().await;
    let (token, _, old) = with_totp(&app, "member").await;
    let fresh = app
        .post("/api/session/recovery-codes")
        .cookie(&token)
        .json(json!({ "code": old[0], "recovery": true }))
        .send()
        .await;
    assert_eq!(fresh.status(), StatusCode::OK);
    let fresh: Vec<String> = body_json(fresh).await["codes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap().to_string())
        .collect();
    app.audit_row("made new recovery codes").await;
    let pending = pending(&app, "member").await;
    let spent = recovery_step(&app, &pending, &old[1]).await;
    assert_eq!(spent.status(), StatusCode::FORBIDDEN, "the old ones went");

    let off = app
        .post("/api/session/totp/off")
        .cookie(&token)
        .json(json!({ "code": fresh[0], "recovery": true }))
        .send()
        .await;
    assert_eq!(off.status(), StatusCode::NO_CONTENT);
    let row = app.audit_row("turned TOTP off").await;
    assert_eq!(field(&row, "method"), Some("recovery-code"));
    let fresh: Vec<&str> = fresh.iter().map(String::as_str).collect();
    no_row_carries(&app, &fresh).await;
    assert!(app.signs_in("member", Harness::PASSWORD).await);
}

#[tokio::test]
async fn while_totp_is_on_a_factor_change_takes_a_code_or_a_passkey_never_the_password_alone() {
    let app = harness().await;
    let (token, secret, codes) = with_totp(&app, "member").await;
    let change =
        |path: &'static str, proof: Value| at_box(app.post(path)).cookie(&token).json(proof).send();
    const CHANGES: [&str; 3] = [
        "/api/session/recovery-codes",
        "/api/session/passkeys/options",
        "/api/session/totp/off",
    ];
    for path in CHANGES {
        let refused = change(path, proof()).await;
        assert_eq!(refused.status(), StatusCode::FORBIDDEN, "{path}");
        let error = body_json(refused).await["error"].to_string();
        assert!(error.contains("while TOTP is on"), "{path}: {error}");
    }
    let left = || async {
        let view = app.get("/api/session/totp").cookie(&token).send().await;
        body_json(view).await["recovery_codes_left"]
            .as_u64()
            .unwrap()
    };

    let mut passkey = SoftPasskey::new();
    let by_code = json!({ "code": code_at(&secret, 30), "browser_time": now() });
    registered_by(&app, &token, &mut passkey, "Key", by_code).await;
    let by_recovery = json!({ "code": codes[0], "recovery": true });
    let options = change("/api/session/passkeys/options", by_recovery).await;
    assert_eq!(options.status(), StatusCode::OK);
    assert_eq!(left().await, 9, "the code used as proof is spent");
    let by_recovery = json!({ "code": codes[1], "recovery": true });
    let enrol = change("/api/session/totp", by_recovery).await;
    assert_eq!(
        enrol.status(),
        StatusCode::CONFLICT,
        "already on: turn it off first"
    );
    assert_eq!(left().await, 9, "a refused change spends no code");

    for (path, status) in
        CHANGES
            .into_iter()
            .zip([StatusCode::OK, StatusCode::OK, StatusCode::NO_CONTENT])
    {
        let assertion = passkey.answer(&reauthentication_options(&app, &token).await, ORIGIN);
        let proved = change(path, json!({ "passkey": assertion })).await;
        assert_eq!(proved.status(), status, "{path} by passkey");
    }
    let row = app.audit_row("turned TOTP off").await;
    assert_eq!(field(&row, "method"), Some("passkey"));

    let password = change("/api/session/totp", proof()).await;
    assert_eq!(
        password.status(),
        StatusCode::OK,
        "TOTP off, the password is the proof again"
    );
}

#[tokio::test]
async fn a_passkey_is_made_with_fresh_proof_listed_renamed_and_removed() {
    let app = harness().await;
    let token = app.signed_in("member", Role::Viewer).await;
    let mut passkey = SoftPasskey::new();
    let view = registered(&app, &token, &mut passkey, "Laptop").await;
    assert_eq!(view["host"], "box.local");
    let id = view["id"].as_str().unwrap().to_string();
    let added = app.audit_row("added a passkey").await;
    assert_eq!(field(&added, "name"), Some("Laptop"));
    assert_eq!(field(&added, "host"), Some("box.local"));

    let listed = body_json(app.get("/api/session/passkeys").cookie(&token).send().await).await;
    assert_eq!(listed.as_array().unwrap().len(), 1);
    let hosts = body_json(
        app.get("/api/session/passkeys/hosts")
            .cookie(&token)
            .send()
            .await,
    )
    .await;
    assert_eq!(hosts, json!([{ "host": "box.local", "passkeys": 1 }]));

    let renamed = app
        .put(&format!("/api/session/passkeys/{id}/name"))
        .cookie(&token)
        .json(json!({ "name": "  Work laptop " }))
        .send()
        .await;
    assert_eq!(renamed.status(), StatusCode::NO_CONTENT);
    let bad_name = app
        .put(&format!("/api/session/passkeys/{id}/name"))
        .cookie(&token)
        .json(json!({ "name": "" }))
        .send()
        .await;
    assert_eq!(bad_name.status(), StatusCode::BAD_REQUEST);

    let stranger = app.signed_in("stranger", Role::Admin).await;
    for response in [
        app.delete(&format!("/api/session/passkeys/{id}"))
            .cookie(&stranger)
            .send()
            .await,
        app.put(&format!("/api/session/passkeys/{id}/name"))
            .cookie(&stranger)
            .json(json!({ "name": "Mine now" }))
            .send()
            .await,
    ] {
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "another's passkey"
        );
    }

    let removed = app
        .delete(&format!("/api/session/passkeys/{id}"))
        .cookie(&token)
        .send()
        .await;
    assert_eq!(removed.status(), StatusCode::NO_CONTENT);
    let row = app.audit_row("removed a passkey").await;
    assert_eq!(field(&row, "name"), Some("Work laptop"));
    let credential = passkey.answer(&sign_in_options(&app).await, ORIGIN).raw_id;
    no_row_carries(&app, &[&credential]).await;
}

#[tokio::test]
async fn a_passkey_signs_in_with_no_code_after_it_even_with_totp_on() {
    let app = harness().await;
    let (token, _, codes) = with_totp(&app, "member").await;
    let mut passkey = SoftPasskey::new();
    let by_recovery = json!({ "code": codes[0], "recovery": true });
    registered_by(&app, &token, &mut passkey, "Phone", by_recovery).await;

    let assertion = passkey.answer(&sign_in_options(&app).await, ORIGIN);
    let signed_in = at_box(app.post("/api/session/passkey"))
        .json(json!(assertion))
        .send()
        .await;
    assert_eq!(signed_in.status(), StatusCode::OK);
    let session = Harness::session_from(&signed_in).expect("a session");
    assert_eq!(
        app.get("/api/session")
            .cookie(&session)
            .send()
            .await
            .status(),
        StatusCode::OK
    );
    let row = app.audit_row("signed in").await;
    assert_eq!(field(&row, "method"), Some("passkey"));
    assert!(field(&row, "passkey_id").is_some());
}

#[tokio::test]
async fn a_refused_passkey_sign_in_names_the_account_it_claims_or_nobody() {
    let app = harness().await;
    let token = app.signed_in("member", Role::Viewer).await;
    let mut passkey = SoftPasskey::new();
    registered(&app, &token, &mut passkey, "Phone").await;
    let id = app.user_id("member").await;
    app.store().set_enabled(&id, false).await.unwrap();

    let mut forged = passkey.answer(&sign_in_options(&app).await, ORIGIN);
    forged.response.signature = "AAAA".into();
    let refused = at_box(app.post("/api/session/passkey"))
        .json(json!(forged))
        .send()
        .await;
    assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
    assert!(Harness::session_from(&refused).is_none());
    let row = app
        .audit_row("sign-in refused: the passkey was not accepted")
        .await;
    assert_eq!(row.actor, "member");
    assert_eq!(field(&row, "method"), Some("passkey"));
    assert_eq!(field(&row, "named_by"), Some("an unverified user handle"));
    assert!(
        !rows(&app)
            .await
            .iter()
            .any(|r| r.message.contains("disabled")),
        "the reason is the check's, not the claimed account's state"
    );

    let mut nameless = passkey.answer(&sign_in_options(&app).await, ORIGIN);
    nameless.response.user_handle = None;
    let refused = at_box(app.post("/api/session/passkey"))
        .json(json!(nameless))
        .send()
        .await;
    assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
    let unknown = rows(&app)
        .await
        .into_iter()
        .find(|row| row.actor == "passkey:unknown")
        .expect("a row for the passkey that named nobody");
    assert_eq!(
        unknown.message,
        "sign-in refused: the passkey was not accepted"
    );
}

#[tokio::test]
async fn a_counter_that_went_back_is_audited_as_a_possible_clone() {
    let app = harness().await;
    let token = app.signed_in("member", Role::Viewer).await;
    let mut passkey = SoftPasskey::new();
    registered(&app, &token, &mut passkey, "Key").await;
    let earlier = passkey.answer(&sign_in_options(&app).await, ORIGIN);
    let later = passkey.answer(&sign_in_options(&app).await, ORIGIN);
    for (assertion, status) in [(later, StatusCode::OK), (earlier, StatusCode::UNAUTHORIZED)] {
        let answered = at_box(app.post("/api/session/passkey"))
            .json(json!(assertion))
            .send()
            .await;
        assert_eq!(answered.status(), status);
    }
    let row = app
        .audit_row(
            "sign-in refused: the passkey's counter did not move, so it may have been cloned",
        )
        .await;
    assert_eq!(row.actor, "member");
}

#[tokio::test]
async fn a_passkey_stands_in_for_the_password_wherever_it_is_asked() {
    let app = Harness::builder().users_routes().build().await;
    app.serving_on(PORT);
    let token = app.admin("admin").await;
    let member = app.create("member", Role::Viewer).await;
    let mut passkey = SoftPasskey::new();
    registered(&app, &token, &mut passkey, "Key").await;

    let assertion = passkey.answer(&reauthentication_options(&app, &token).await, ORIGIN);
    let reset = at_box(app.put(&format!("/api/users/{member}/password")))
        .cookie(&token)
        .json(json!({ "password": Harness::NEW_PASSWORD, "proof": { "passkey": assertion } }))
        .send()
        .await;
    assert_eq!(reset.status(), StatusCode::NO_CONTENT);
    let row = app.audit_row("re-authenticated").await;
    assert_eq!(field(&row, "method"), Some("passkey"));
    assert_eq!(field(&row, "what"), Some("password reset"));

    let assertion = passkey.answer(&reauthentication_options(&app, &token).await, ORIGIN);
    let enrolled = at_box(app.post("/api/session/totp"))
        .cookie(&token)
        .json(json!({ "passkey": assertion.clone() }))
        .send()
        .await;
    assert_eq!(enrolled.status(), StatusCode::OK);
    let replayed = at_box(app.post("/api/session/recovery-codes"))
        .cookie(&token)
        .json(json!({ "passkey": assertion }))
        .send()
        .await;
    assert_eq!(
        replayed.status(),
        StatusCode::FORBIDDEN,
        "a challenge is spent once"
    );
    let refused = app
        .audit_row("re-authentication refused: the passkey was not accepted")
        .await;
    assert_eq!(field(&refused, "method"), Some("passkey"));
}

#[tokio::test]
async fn the_name_is_the_requests_own_never_a_forwarded_one() {
    let app = harness().await;
    let options = at_box(app.post("/api/session/passkey/options"))
        .header("x-forwarded-host", "elsewhere.example")
        .header("forwarded", "host=elsewhere.example;proto=https")
        .send()
        .await;
    let options = body_json(options).await;
    assert_eq!(options["rpId"], "box.local");

    let options = app
        .post("https://box.local:8443/api/session/passkey/options")
        .header("host", "elsewhere.example:8443")
        .send()
        .await;
    assert_eq!(
        body_json(options).await["rpId"],
        "box.local",
        "h2's authority, over Host"
    );
}

#[tokio::test]
async fn a_port_the_box_does_not_serve_on_runs_no_ceremony() {
    let app = harness().await;
    for host in ["box.local:9443", "box.local", "192.168.1.20:8443"] {
        let refused = app
            .post("/api/session/passkey/options")
            .header("host", host)
            .send()
            .await;
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST, "{host}");
    }
}

#[tokio::test]
async fn behind_the_dev_proxy_the_pages_own_host_and_port_run_the_ceremony() {
    let app = Harness::builder().origin_port(5173).build().await;
    app.serving_on(PORT);
    // A development proxy keeps the browser's Host and adds forwarded headers;
    // only the Host is read.
    let through_proxy = |host: &str| {
        app.post("/api/session/passkey/options")
            .header("host", host)
            .header("x-forwarded-host", "localhost:8443")
            .header("x-forwarded-port", &PORT.to_string())
            .header("x-forwarded-proto", "https")
            .send()
    };
    let options = through_proxy("localhost:5173").await;
    assert_eq!(options.status(), StatusCode::OK);
    assert_eq!(body_json(options).await["rpId"], "localhost");
    let rewritten = through_proxy("localhost:8443").await;
    assert_eq!(
        rewritten.status(),
        StatusCode::BAD_REQUEST,
        "a Host rewritten to the target names a port the page is not on"
    );
}

#[tokio::test]
async fn this_backend_keeps_no_proof_window_and_a_page_learns_where_passkeys_run() {
    let app = harness().await;
    let token = app.signed_in("member", Role::Viewer).await;
    let unmounted = app
        .post("/api/session/reauthenticate")
        .cookie(&token)
        .json(proof())
        .send()
        .await;
    assert_eq!(unmounted.status(), StatusCode::NOT_FOUND);

    let available = at_box(app.get("/api/session/passkey/availability"))
        .send()
        .await;
    assert_eq!(
        body_json(available).await,
        json!({ "state": "ready", "via": "box.local" })
    );
}

#[tokio::test]
async fn a_ceremony_begun_on_one_name_does_not_finish_on_another() {
    let app = harness().await;
    let token = app.signed_in("member", Role::Viewer).await;
    let mut passkey = SoftPasskey::new();
    registered(&app, &token, &mut passkey, "Key").await;
    let assertion = passkey.answer(&sign_in_options(&app).await, ORIGIN);
    let refused = app
        .post("/api/session/passkey")
        .header("host", "other.local:8443")
        .json(json!(assertion))
        .send()
        .await;
    assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
    let journal = backend::ring(backend::logs(app.state())).snapshot();
    let reason = (
        "reason".to_string(),
        "the challenge is unknown, spent, expired or someone else's".to_string(),
    );
    assert!(
        journal
            .records
            .iter()
            .any(|record| record.message == "passkey refused" && record.fields.contains(&reason)),
        "the challenge was the other name's: {:?}",
        journal.records
    );
}

#[tokio::test]
async fn the_control_socket_is_nobody_on_every_account_route() {
    let app = harness().await;
    app.create("member", Role::Admin).await;
    for (method, path, body) in [
        ("GET", "/api/session/totp", None),
        ("POST", "/api/session/totp", Some(proof())),
        (
            "POST",
            "/api/session/totp/confirm",
            Some(json!({ "code": "123456", "browser_time": now() })),
        ),
        ("POST", "/api/session/totp/off", Some(json!({}))),
        ("POST", "/api/session/recovery-codes", Some(proof())),
        ("GET", "/api/session/passkeys", None),
        ("GET", "/api/session/passkeys/hosts", None),
        ("POST", "/api/session/passkeys/options", Some(proof())),
        ("POST", "/api/session/reauthentication/options", None),
        ("DELETE", "/api/session/passkeys/some-id", None),
        (
            "PUT",
            "/api/session/passkeys/some-id/name",
            Some(json!({ "name": "x" })),
        ),
    ] {
        let response = at_box(app.request(method, path))
            .maybe_json(body)
            .local()
            .send()
            .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{method} {path}");
        assert_eq!(
            body_json(response).await["error"],
            "the control socket is not signed in as anybody",
            "{method} {path}"
        );
    }
}

#[tokio::test]
async fn a_body_past_the_cap_is_not_read() {
    let app = harness().await;
    let refused = app
        .post("/api/session/code")
        .json(json!({ "pending": "x", "code": "1".repeat(32 * 1024), "browser_time": 0 }))
        .send()
        .await;
    assert_eq!(refused.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

async fn with_users() -> Harness {
    let app = Harness::builder().users_routes().build().await;
    app.serving_on(PORT);
    app
}

/// An administrator requires `member` to enrol TOTP, proving themselves.
async fn require_totp(app: &Harness, admin: &str, member: &str, proof: Value) -> Response {
    at_box(app.post(&format!("/api/users/{member}/require-totp")))
        .cookie(admin)
        .json(proof)
        .send()
        .await
}

#[tokio::test]
async fn a_required_enrolment_holds_the_next_password_sign_in_until_a_key_is_confirmed() {
    let app = with_users().await;
    let admin = app.admin("admin").await;
    with_totp(&app, "member").await;
    let member = app.user_id("member").await;
    let required = require_totp(&app, &admin, &member, proof()).await;
    assert_eq!(required.status(), StatusCode::NO_CONTENT);
    let row = app.audit_row("required TOTP re-enrolment").await;
    assert_eq!(row.actor, "admin");
    assert_eq!(field(&row, "user_id"), Some(member.as_str()));
    assert!(app.store().totp(&member).await.unwrap().is_none());

    let answered = app
        .post("/api/session")
        .json(json!({ "username": "member", "password": Harness::PASSWORD }))
        .send()
        .await;
    assert_eq!(answered.status(), StatusCode::ACCEPTED);
    assert!(Harness::session_from(&answered).is_none());
    let step = body_json(answered).await;
    assert_eq!(step["next"], "enrol");
    let pending = step["pending"].as_str().unwrap().to_string();
    app.audit_row("password accepted; waiting for TOTP enrolment")
        .await;

    let no_code_step = code_step(&app, &pending, "123456", now()).await;
    assert_eq!(
        no_code_step.status(),
        StatusCode::UNAUTHORIZED,
        "not a code step's"
    );

    let enrolment = app
        .post("/api/session/enrolment")
        .json(json!({ "pending": pending }))
        .send()
        .await;
    assert_eq!(enrolment.status(), StatusCode::OK);
    let secret = body_json(enrolment).await["secret"]
        .as_str()
        .unwrap()
        .to_string();
    let confirm = |code: String| {
        app.post("/api/session/enrolment/confirm")
            .json(json!({ "pending": pending, "code": code, "browser_time": now() }))
            .send()
    };
    let wrong = confirm("nonsense".into()).await;
    assert_eq!(wrong.status(), StatusCode::FORBIDDEN);
    let confirmed = confirm(code_at(&secret, 0)).await;
    assert_eq!(confirmed.status(), StatusCode::OK);
    let session = Harness::session_from(&confirmed).expect("a session");
    let body = body_json(confirmed).await;
    assert_eq!(body["user"]["username"], "member");
    assert_eq!(
        body["recovery_codes"]["codes"].as_array().unwrap().len(),
        10
    );
    assert_eq!(
        app.get("/api/session")
            .cookie(&session)
            .send()
            .await
            .status(),
        StatusCode::OK
    );
    assert!(!app.store().totp_required(&member).await.unwrap());
    let signed_in = app.audit_row("signed in").await;
    assert_eq!(field(&signed_in, "method"), Some("password+totp"));

    let spent = confirm(code_at(&secret, 30)).await;
    assert_eq!(spent.status(), StatusCode::UNAUTHORIZED, "used once");
    assert_eq!(pending_next(&app, "member").await, "code", "TOTP is on now");
    no_row_carries(&app, &[&pending, &secret]).await;
}

async fn pending_next(app: &Harness, username: &str) -> String {
    let answered = app
        .post("/api/session")
        .json(json!({ "username": username, "password": Harness::PASSWORD }))
        .send()
        .await;
    body_json(answered).await["next"]
        .as_str()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn a_passkey_still_signs_in_an_account_required_to_enrol() {
    let app = with_users().await;
    let admin = app.admin("admin").await;
    let token = app.signed_in("member", Role::Viewer).await;
    let member = app.user_id("member").await;
    let mut passkey = SoftPasskey::new();
    registered(&app, &token, &mut passkey, "Phone").await;
    assert_eq!(
        require_totp(&app, &admin, &member, proof()).await.status(),
        StatusCode::NO_CONTENT
    );
    let assertion = passkey.answer(&sign_in_options(&app).await, ORIGIN);
    let signed_in = at_box(app.post("/api/session/passkey"))
        .json(json!(assertion))
        .send()
        .await;
    assert_eq!(signed_in.status(), StatusCode::OK);
    assert!(
        app.store().totp_required(&member).await.unwrap(),
        "until a key is set"
    );
    assert_eq!(pending_next(&app, "member").await, "enrol");
}

#[tokio::test]
async fn an_administrator_removes_another_accounts_passkey_by_its_id() {
    let app = with_users().await;
    let admin = app.admin("admin").await;
    let token = app.signed_in("member", Role::Viewer).await;
    let member = app.user_id("member").await;
    let mut passkey = SoftPasskey::new();
    let view = registered(&app, &token, &mut passkey, "Phone").await;
    let id = view["id"].as_str().unwrap();

    let listed = app
        .get(&format!("/api/users/{member}/passkeys"))
        .cookie(&admin)
        .send()
        .await;
    assert_eq!(body_json(listed).await[0]["id"], id);
    let remove = |proof: Value| {
        at_box(app.post(&format!("/api/users/{member}/passkeys/{id}/remove")))
            .cookie(&admin)
            .json(proof)
            .send()
    };
    assert_eq!(remove(json!({})).await.status(), StatusCode::FORBIDDEN);
    assert_eq!(remove(proof()).await.status(), StatusCode::NO_CONTENT);
    assert!(app.store().passkeys(&member).await.unwrap().is_empty());
    let row = app.audit_row("removed a passkey").await;
    assert_eq!(row.actor, "admin");
    assert_eq!(field(&row, "user_id"), Some(member.as_str()));
    assert_eq!(field(&row, "name"), Some("Phone"));
    assert_eq!(field(&row, "host"), Some("box.local"));
    assert_eq!(remove(proof()).await.status(), StatusCode::NOT_FOUND);
    no_row_carries(
        &app,
        &[&passkey.answer(&sign_in_options(&app).await, ORIGIN).raw_id],
    )
    .await;
}

#[tokio::test]
async fn the_account_admin_routes_are_guarded_as_the_reset_is() {
    let app = with_users().await;
    let (admin, secret, _) = with_totp(&app, "admin").await;
    app.store()
        .set_role(&app.user_id("admin").await, Role::Admin)
        .await
        .unwrap();
    let admin_id = app.user_id("admin").await;
    let member = app.create("member", Role::Viewer).await;
    let owner = app.create("owner", Role::HostAdmin).await;

    for (target, proof, refused) in [
        (&admin_id, proof(), "your own"),
        (&member, json!({}), "while TOTP is on"),
        (&member, proof(), "while TOTP is on"),
    ] {
        let response = require_totp(&app, &admin, target, proof).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let error = body_json(response).await["error"].to_string();
        assert!(error.contains(refused), "{error}");
    }
    let by_code = json!({ "code": code_at(&secret, 30), "browser_time": now() });
    let spared = require_totp(&app, &admin, &owner, by_code).await;
    assert_eq!(spared.status(), StatusCode::FORBIDDEN);
    assert!(
        body_json(spared).await["error"]
            .to_string()
            .contains("only a host admin")
    );
    assert!(!app.store().totp_required(&owner).await.unwrap());

    let by_socket = app
        .post(&format!("/api/users/{member}/require-totp"))
        .local()
        .json(json!({}))
        .send()
        .await;
    assert_eq!(
        by_socket.status(),
        StatusCode::NO_CONTENT,
        "the socket gives no proof"
    );
    assert!(app.store().totp_required(&member).await.unwrap());
    let row = app.audit_row("required TOTP re-enrolment").await;
    assert!(row.actor.starts_with("control-socket"), "{}", row.actor);
}

/// An administrator signed in with TOTP on: the session, the key and the
/// recovery codes.
async fn totp_admin(app: &Harness) -> (String, String, Vec<String>) {
    let admin = with_totp(app, "admin").await;
    let id = app.user_id("admin").await;
    app.store().set_role(&id, Role::Admin).await.unwrap();
    admin
}

#[tokio::test]
async fn while_an_admins_totp_is_on_making_or_changing_an_account_takes_a_code_or_a_passkey() {
    let app = with_users().await;
    let (admin, secret, codes) = totp_admin(&app).await;
    let member = app.create("member", Role::Viewer).await;
    let changes = |proof: Value| {
        [
            app.post("/api/users").json(json!({
                "username": "another", "password": Harness::PASSWORD, "role": "viewer",
                "proof": proof,
            })),
            app.put(&format!("/api/users/{member}/role"))
                .json(json!({ "role": "operator", "proof": proof })),
            app.put(&format!("/api/users/{member}/password"))
                .json(json!({ "password": Harness::NEW_PASSWORD, "proof": proof })),
        ]
    };
    for request in changes(proof()) {
        let refused = at_box(request).cookie(&admin).send().await;
        assert_eq!(refused.status(), StatusCode::FORBIDDEN);
        let error = body_json(refused).await["error"].to_string();
        assert!(error.contains("while TOTP is on"), "{error}");
    }

    let mut passkey = SoftPasskey::new();
    let by_code = json!({ "code": code_at(&secret, 30), "browser_time": now() });
    registered_by(&app, &admin, &mut passkey, "Key", by_code).await;
    let [create, role, reset] = changes(json!({ "code": codes[0], "recovery": true }));
    assert_eq!(
        at_box(create).cookie(&admin).send().await.status(),
        StatusCode::CREATED
    );
    for request in [role, reset] {
        let assertion = passkey.answer(&reauthentication_options(&app, &admin).await, ORIGIN);
        let proved = at_box(request)
            .cookie(&admin)
            .json(json!({
                "role": "operator", "password": Harness::NEW_PASSWORD,
                "proof": { "passkey": assertion },
            }))
            .send()
            .await;
        assert_eq!(proved.status(), StatusCode::NO_CONTENT);
    }

    let by_socket = app
        .put(&format!("/api/users/{member}/role"))
        .local()
        .json(json!({ "role": "viewer" }))
        .send()
        .await;
    assert_eq!(
        by_socket.status(),
        StatusCode::NO_CONTENT,
        "the socket gives no proof"
    );
}

#[tokio::test]
async fn a_refused_target_spends_none_of_the_admins_codes() {
    let app = with_users().await;
    let (admin, _, codes) = totp_admin(&app).await;
    let admin_id = app.user_id("admin").await;
    let member = app.create("member", Role::Viewer).await;
    let owner = app.create("owner", Role::HostAdmin).await;
    let by = |n: usize| json!({ "code": codes[n], "recovery": true });
    let left = || async {
        let view = app.get("/api/session/totp").cookie(&admin).send().await;
        body_json(view).await["recovery_codes_left"]
            .as_u64()
            .unwrap()
    };
    let attempts = [
        (
            "/api/users/nobody/require-totp".to_string(),
            StatusCode::NOT_FOUND,
        ),
        (
            format!("/api/users/{admin_id}/require-totp"),
            StatusCode::FORBIDDEN,
        ),
        (
            format!("/api/users/{owner}/require-totp"),
            StatusCode::FORBIDDEN,
        ),
        (
            format!("/api/users/{member}/passkeys/no-such-id/remove"),
            StatusCode::NOT_FOUND,
        ),
        (
            format!("/api/users/{owner}/passkeys/no-such-id/remove"),
            StatusCode::FORBIDDEN,
        ),
    ];
    for (n, (path, status)) in attempts.into_iter().enumerate() {
        let refused = at_box(app.post(&path))
            .cookie(&admin)
            .json(by(n))
            .send()
            .await;
        assert_eq!(refused.status(), status, "{path}");
    }
    let reset = at_box(app.put("/api/users/nobody/password"))
        .cookie(&admin)
        .json(json!({ "password": Harness::NEW_PASSWORD, "proof": by(6) }))
        .send()
        .await;
    assert_eq!(reset.status(), StatusCode::NOT_FOUND);
    for (n, (account, status)) in [
        ("nobody", StatusCode::NOT_FOUND),
        (owner.as_str(), StatusCode::FORBIDDEN),
    ]
    .into_iter()
    .enumerate()
    {
        let disabled = at_box(app.put(&format!("/api/users/{account}/enabled")))
            .cookie(&admin)
            .json(json!({ "enabled": false, "proof": by(7 + n) }))
            .send()
            .await;
        assert_eq!(disabled.status(), status, "disabling {account}");
        let deleted = at_box(app.delete(&format!("/api/users/{account}")))
            .cookie(&admin)
            .json(by(7 + n))
            .send()
            .await;
        assert_eq!(deleted.status(), status, "deleting {account}");
    }
    assert_eq!(left().await, 10, "every code is still there");

    for (account, status) in [
        ("nobody", StatusCode::NOT_FOUND),
        (owner.as_str(), StatusCode::FORBIDDEN),
    ] {
        let listed = app
            .get(&format!("/api/users/{account}/passkeys"))
            .cookie(&admin)
            .send()
            .await;
        assert_eq!(listed.status(), status, "{account}");
    }
}

#[tokio::test]
async fn a_passkey_is_removed_from_no_account_of_ones_own_or_a_spared_host_admin() {
    let app = with_users().await;
    let admin = app.admin("admin").await;
    let admin_id = app.user_id("admin").await;
    let mut own = SoftPasskey::new();
    let own_key = registered(&app, &admin, &mut own, "Mine").await;
    let owner_token = app.signed_in("owner", Role::HostAdmin).await;
    let owner = app.user_id("owner").await;
    let mut theirs = SoftPasskey::new();
    let owners_key = registered(&app, &owner_token, &mut theirs, "Theirs").await;
    let remove = |account: &str, key: &Value| {
        let id = key["id"].as_str().unwrap();
        at_box(app.post(&format!("/api/users/{account}/passkeys/{id}/remove")))
    };
    let mine = remove(&admin_id, &own_key)
        .cookie(&admin)
        .json(proof())
        .send()
        .await;
    assert_eq!(mine.status(), StatusCode::FORBIDDEN);
    let spared = remove(&owner, &owners_key)
        .cookie(&admin)
        .json(proof())
        .send()
        .await;
    assert_eq!(spared.status(), StatusCode::FORBIDDEN);
    assert_eq!(app.store().passkeys(&owner).await.unwrap().len(), 1);
    let by_socket = remove(&admin_id, &own_key)
        .local()
        .json(json!({}))
        .send()
        .await;
    assert_eq!(
        by_socket.status(),
        StatusCode::NO_CONTENT,
        "the socket is nobody's own"
    );
    assert!(app.store().passkeys(&admin_id).await.unwrap().is_empty());
}

#[tokio::test]
async fn a_waiting_sign_in_ends_when_an_administrator_changes_what_it_awaits() {
    let app = with_users().await;
    let admin = app.admin("admin").await;
    let (_, secret, _) = with_totp(&app, "member").await;
    let member = app.user_id("member").await;
    let waiting_code = pending(&app, "member").await;
    assert_eq!(
        require_totp(&app, &admin, &member, proof()).await.status(),
        StatusCode::NO_CONTENT
    );
    let refused = code_step(&app, &waiting_code, &code_at(&secret, 30), now()).await;
    assert_eq!(
        refused.status(),
        StatusCode::UNAUTHORIZED,
        "sign in again, not 409"
    );

    let enrol = pending(&app, "member").await;
    let begun = app
        .post("/api/session/enrolment")
        .json(json!({ "pending": enrol }))
        .send()
        .await;
    assert_eq!(begun.status(), StatusCode::OK);
    let row = app.audit_row("TOTP enrolment begun").await;
    assert_eq!(row.actor, "member");
    let reset = at_box(app.put(&format!("/api/users/{member}/password")))
        .cookie(&admin)
        .json(json!({ "password": Harness::NEW_PASSWORD, "proof": proof() }))
        .send()
        .await;
    assert_eq!(reset.status(), StatusCode::NO_CONTENT);
    assert!(
        app.store().totp_required(&member).await.unwrap(),
        "a reset keeps it"
    );
    let row = app.audit_row("changed an account's password").await;
    assert_eq!(field(&row, "totp_required"), Some("kept"));
    let ended = app
        .post("/api/session/enrolment")
        .json(json!({ "pending": enrol }))
        .send()
        .await;
    assert_eq!(
        ended.status(),
        StatusCode::UNAUTHORIZED,
        "the old password's"
    );

    let signed_in = app
        .post("/api/session")
        .json(json!({ "username": "member", "password": Harness::NEW_PASSWORD }))
        .send()
        .await;
    assert_eq!(body_json(signed_in).await["next"], "enrol");
}

/// `PUT /api/session/password` for the session `token`, with `proof`'s fields
/// beside the two passwords.
async fn change_own_password(
    app: &Harness,
    token: &str,
    current: &str,
    new: &str,
    proof: Value,
) -> Response {
    let mut body = json!({ "current_password": current, "new_password": new });
    let fields = body.as_object_mut().unwrap();
    fields.extend(proof.as_object().unwrap().clone());
    at_box(app.put("/api/session/password"))
        .cookie(token)
        .json(body)
        .send()
        .await
}

#[tokio::test]
async fn while_totp_is_on_changing_ones_own_password_takes_a_code_or_a_passkey_as_well() {
    let app = harness().await;
    let (token, secret, codes) = with_totp(&app, "member").await;
    let mut passkey = SoftPasskey::new();
    let by_recovery = json!({ "code": codes[0], "recovery": true });
    registered_by(&app, &token, &mut passkey, "Key", by_recovery).await;

    let current = Harness::PASSWORD;
    let refused =
        change_own_password(&app, &token, current, Harness::NEW_PASSWORD, json!({})).await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert!(
        body_json(refused).await["error"]
            .to_string()
            .contains("while TOTP is on")
    );
    let by_code = json!({ "code": code_at(&secret, 30), "browser_time": now() });
    let short = change_own_password(&app, &token, current, "short", by_code.clone()).await;
    assert_eq!(
        short.status(),
        StatusCode::BAD_REQUEST,
        "refused before the code is spent"
    );

    let changed = change_own_password(&app, &token, current, Harness::NEW_PASSWORD, by_code).await;
    assert_eq!(changed.status(), StatusCode::NO_CONTENT);
    let token = Harness::session_from(&changed).expect("a fresh session");

    let assertion = passkey.answer(&reauthentication_options(&app, &token).await, ORIGIN);
    let by_passkey = json!({ "passkey": assertion });
    let changed =
        change_own_password(&app, &token, Harness::NEW_PASSWORD, current, by_passkey).await;
    assert_eq!(changed.status(), StatusCode::NO_CONTENT);
    pending(&app, "member").await;
}
