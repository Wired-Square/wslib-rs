use super::*;
use axum::http::StatusCode;
use axum::http::header;
use serde_json::json;
use tokio::sync::Notify;
use wslib_appliance_core::testing::assert_sentences;
use wslib_appliance_server::testing::{Harness, HarnessBuilder, body_json, body_text, inspect_pem};
use wslib_appliance_types::Role;

pub(crate) const PASSPHRASE: &str = "a passphrase long enough to be one";
const NAME: &str = "widget-monitor";

/// Every account [`account`] makes has this password.
pub(crate) const PASSWORD: &str = "correct horse battery";

/// The header [`StoreAccounts`] reads a username from.
pub(crate) const ACCOUNT: &str = "x-account";

/// Present on a request whose caller has not proved the password recently.
const STALE: &str = "x-stale";

/// A product's sign-in over the store's own accounts: the enabled one named
/// in [`ACCOUNT`], under its store id, re-authenticated just now unless the
/// request says [`STALE`].
struct StoreAccounts(Store);

impl wslib_appliance_server::ResolveCaller for StoreAccounts {
    async fn resolve(
        &self,
        request: &axum::http::request::Parts,
    ) -> Result<Option<wslib_appliance_server::Principal>, ApiError> {
        let Some(username) = request.headers.get(ACCOUNT).and_then(|n| n.to_str().ok()) else {
            return Ok(None);
        };
        let reauthenticated_at = (!request.headers.contains_key(STALE)).then(chrono::Utc::now);
        let account = self.0.user_by_username(username).await?;
        Ok(account
            .map(|account| account.user)
            .filter(|user| user.enabled)
            .map(|user| wslib_appliance_server::Principal {
                id: user.id,
                username: user.username,
                role: user.role,
                reauthenticated_at,
            }))
    }
}

/// A harness whose callers are the store's accounts, declared so.
pub(crate) async fn over_accounts() -> HarnessBuilder {
    let store = Store::open_in_memory(None).await.unwrap();
    Harness::builder()
        .store(store.clone())
        .resolver_from_store(StoreAccounts(store))
}

/// An account of `role` on `app`, with [`PASSWORD`]; what [`ACCOUNT`] names it by.
pub(crate) async fn account(app: &Harness, username: &str, role: Role) -> String {
    static HASH: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    let hash = HASH.get_or_init(|| wslib_appliance_auth::hash_password(PASSWORD).expect("hash"));
    app.store()
        .create_user(username, hash, role)
        .await
        .expect("an account");
    username.to_string()
}

/// Whether `username` is an enabled account on `app` whose password is
/// [`PASSWORD`].
async fn has_the_password(app: &Harness, username: &str) -> bool {
    app.store()
        .user_by_username(username)
        .await
        .unwrap()
        .is_some_and(|account| {
            account.user.enabled && wslib_appliance_auth::verify_password(&account, PASSWORD)
        })
}

pub(crate) fn warnings(report: &serde_json::Value) -> Vec<&str> {
    report["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w.as_str().unwrap())
        .collect()
}

struct Rig {
    app: Harness,
    backups: Engine<(), ()>,
}

/// The session rung over `sections`, on a builder whose directory holds the
/// files.
pub(crate) fn backups<S: Sections>(
    builder: &wslib_appliance_server::testing::HarnessBuilder,
    sections: S,
) -> Engine<S, ()> {
    Engine::session(NAME, "0.1.0-test", builder.dir(), (), sections)
}

/// The routes and the schedule over a product with no sections of its own.
async fn rig() -> Rig {
    let rig = mounted_on(over_accounts().await).await;
    tokio::spawn(rig.backups.clone().run_schedule(
        rig.app.state().clone(),
        wslib_appliance_server::CancellationToken::new(),
    ));
    tokio::task::yield_now().await;
    rig
}

/// The routes over a product with no sections of its own, and no schedule.
async fn mounted_on(builder: HarnessBuilder) -> Rig {
    let backups = backups(&builder, ());
    let app = builder.api(backups.routes(Router::new())).build().await;
    Rig { app, backups }
}

/// Switch the schedule on under `PASSPHRASE`, as the screen would, and
/// answer the view.
async fn switch_on(app: &Harness, token: &str, every_hours: u32, keep: u32) -> serde_json::Value {
    let response = app
        .put("/api/backup/schedule")
        .header(ACCOUNT, token)
        .json(json!({
            "schedule": { "enabled": true, "every_hours": every_hours, "keep": keep },
            "passphrase": PASSPHRASE,
            "password": PASSWORD
        }))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    body_json(response).await
}

async fn taking(app: &Harness, token: &str) -> Response {
    app.post("/api/backup")
        .header(ACCOUNT, token)
        .json(json!({ "passphrase": PASSPHRASE, "password": PASSWORD }))
        .send()
        .await
}

pub(crate) async fn take(app: &Harness, token: &str) -> String {
    let response = taking(app, token).await;
    assert_eq!(response.status(), StatusCode::OK);
    let disposition = response
        .headers()
        .get(header::CONTENT_DISPOSITION)
        .and_then(|d| d.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        disposition.contains(&format!("{NAME}-backup-")),
        "a browser saves it under a name that means something: {disposition}"
    );
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    body_text(response).await
}

fn everything() -> serde_json::Value {
    json!({
        "accounts": true, "settings": true, "trusted_certs": true, "trusted_cas": true,
        "serving_certificate": true, "app": []
    })
}

/// Stamped with the harness's schema version, which no product migration
/// raises above 0.
fn provenance() -> Provenance {
    Provenance {
        app_schema_version: 0,
        ..crate::envelope::tests::provenance()
    }
}

#[tokio::test]
async fn a_store_account_proves_the_password_in_the_body_even_within_the_window() {
    let Rig { app, .. } = rig().await;
    let admin = account(&app, "admin", Role::Admin).await;
    let bundle = take(&app, &admin).await;
    let empty = app
        .post("/api/backup")
        .header(ACCOUNT, &admin)
        .json(json!({ "passphrase": PASSPHRASE, "password": "" }))
        .send()
        .await;
    assert_eq!(empty.status(), StatusCode::FORBIDDEN);
    let row = app
        .audit_row("re-authentication refused: the password is wrong")
        .await;
    let account = app.store().user_by_username(&admin).await.unwrap().unwrap();
    assert_eq!(row.actor, admin);
    assert_eq!(row.actor_id, Some(account.user.id));

    for (method, path, body) in [
        ("POST", "/api/backup", json!({ "passphrase": PASSPHRASE })),
        (
            "POST",
            "/api/backup/restore",
            json!({ "passphrase": PASSPHRASE, "bundle": bundle, "sections": everything() }),
        ),
        (
            "PUT",
            "/api/backup/schedule",
            json!({
                "schedule": { "enabled": true, "every_hours": 24, "keep": 7 },
                "passphrase": PASSPHRASE
            }),
        ),
    ] {
        let send = |stale: bool, password: Option<&str>| {
            let mut body = body.clone();
            if let Some(password) = password {
                body["password"] = json!(password);
            }
            let request = app.request(method, path).header(ACCOUNT, &admin);
            match stale {
                true => request.header(STALE, "1"),
                false => request,
            }
            .json(body)
            .send()
        };
        for stale in [false, true] {
            for (password, status) in [
                (None, StatusCode::FORBIDDEN),
                (Some("not it"), StatusCode::FORBIDDEN),
                (Some(PASSWORD), StatusCode::OK),
            ] {
                assert_eq!(
                    send(stale, password).await.status(),
                    status,
                    "{path} stale: {stale} {password:?}"
                );
            }
        }
    }
}

#[tokio::test]
async fn a_resolver_not_declared_over_the_stores_accounts_never_reads_the_password() {
    for (declared, status) in [(true, StatusCode::OK), (false, StatusCode::FORBIDDEN)] {
        let app = over_store_accounts(declared).await;
        let admin = account(&app, "admin", Role::Admin).await;
        let response = app
            .post("/api/backup")
            .header(ACCOUNT, &admin)
            .header(STALE, "1")
            .json(json!({ "passphrase": PASSPHRASE, "password": PASSWORD }))
            .send()
            .await;
        assert_eq!(response.status(), status, "declared: {declared}");
    }
}

#[tokio::test]
async fn a_backup_taken_over_the_api_is_inspected_and_restored_over_it() {
    let Rig { app, .. } = rig().await;
    let admin = account(&app, "admin", Role::Admin).await;
    app.store()
        .set_setting("branding.app_name", "Before")
        .await
        .unwrap();
    let bundle = take(&app, &admin).await;

    let seen = app
        .post("/api/backup/inspect")
        .header(ACCOUNT, &admin)
        .json(json!({ "passphrase": PASSPHRASE, "bundle": bundle }))
        .send()
        .await;
    assert_eq!(seen.status(), StatusCode::OK);
    let seen = body_json(seen).await;
    assert_eq!(seen["header"]["contains"]["accounts"], 1);
    assert_eq!(seen["header"]["contains"]["serving_certificate"], true);
    assert_eq!(seen["warnings"], json!([]));
    let about = body_json(app.get("/api/about").header(ACCOUNT, &admin).send().await).await;
    assert_eq!(
        seen["header"]["box_id"], about["box_id"],
        "a box's own bundle carries the id its About reports"
    );
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    assert!(about["box_id"].is_string(), "{about}");

    // A take without a proof is refused before anything is sealed.
    assert_eq!(
        app.post("/api/backup")
            .header(ACCOUNT, &admin)
            .json(json!({ "passphrase": PASSPHRASE }))
            .send()
            .await
            .status(),
        StatusCode::FORBIDDEN
    );

    // Something to restore over, and no proof first: 403, and the box
    // untouched.
    app.store()
        .set_setting("branding.app_name", "After")
        .await
        .unwrap();
    let refused = app
        .post("/api/backup/restore")
        .header(ACCOUNT, &admin)
        .json(json!({
            "passphrase": PASSPHRASE, "bundle": bundle, "sections": everything()
        }))
        .send()
        .await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        app.store()
            .setting("branding.app_name")
            .await
            .unwrap()
            .as_deref(),
        Some("After")
    );

    let response = app
        .post("/api/backup/restore")
        .header(ACCOUNT, &admin)
        .json(json!({
            "passphrase": PASSPHRASE, "bundle": bundle, "password": PASSWORD,
            "sections": everything()
        }))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let report = body_json(response).await;
    assert_eq!(report["applied"]["accounts"], true);
    assert_eq!(report["applied"]["settings"], true);
    assert_eq!(report["applied"]["serving_certificate"], true);
    assert_eq!(report["signed_out"], true);
    assert_eq!(report["warnings"], json!([]));
    assert_eq!(
        app.store()
            .setting("branding.app_name")
            .await
            .unwrap()
            .as_deref(),
        Some("Before")
    );
    assert!(has_the_password(&app, "admin").await);
}

/// An administrator who is none of the store's accounts.
struct Elsewhere;

impl wslib_appliance_server::ResolveCaller for Elsewhere {
    async fn resolve(
        &self,
        _: &axum::http::request::Parts,
    ) -> Result<Option<wslib_appliance_server::Principal>, ApiError> {
        Ok(Some(wslib_appliance_server::Principal {
            id: "elsewhere:admin".to_string(),
            username: "admin".to_string(),
            role: Role::Admin,
            reauthenticated_at: Some(chrono::Utc::now()),
        }))
    }
}

#[tokio::test]
async fn restoring_the_accounts_signs_out_a_store_account_and_no_other_caller() {
    let Rig { app, .. } = rig().await;
    let admin = account(&app, "admin", Role::Admin).await;
    let bundle = take(&app, &admin).await;
    let report = body_json(restore_accounts(&app, &admin, &bundle).await).await;
    assert_eq!(report["signed_out"], true, "{report}");

    let without_admin = sealed_with(&[("other", Role::Admin)]).await;
    let report = body_json(restore_accounts(&app, &admin, &without_admin).await).await;
    assert_eq!(report["applied"]["accounts"], true, "{report}");
    assert_eq!(report["signed_out"], true, "{report}");

    let elsewhere = mounted_on(Harness::builder().resolver(Elsewhere)).await.app;
    let report = body_json(restore_accounts(&elsewhere, "", &bundle).await).await;
    assert_eq!(report["applied"]["accounts"], true, "{report}");
    assert_eq!(report["signed_out"], false, "{report}");
}

#[tokio::test]
async fn served_with_sessions_restoring_the_accounts_ends_every_session_minted_before_it() {
    use wslib_appliance_https::testing::Harness;

    let builder = Harness::builder();
    let backups = Engine::session(NAME, "0.1.0-test", builder.dir(), (), ());
    let app = builder.api(backups.routes(Router::new())).build().await;
    let admin = app.admin("admin").await;
    let operator = app.signed_in("operator", Role::Operator).await;
    app.store()
        .set_setting("branding.app_name", "Before")
        .await
        .unwrap();
    let bundle = app
        .post("/api/backup")
        .cookie(&admin)
        .json(json!({ "passphrase": PASSPHRASE, "password": Harness::PASSWORD }))
        .send()
        .await;
    assert_eq!(bundle.status(), StatusCode::OK);
    let bundle = body_text(bundle).await;

    let restore = |accounts: bool| {
        app.post("/api/backup/restore").cookie(&admin).json(json!({
            "passphrase": PASSPHRASE, "bundle": bundle, "password": Harness::PASSWORD,
            "sections": { "accounts": accounts, "settings": true, "app": [] }
        }))
    };
    let session = |token: &str| app.get("/api/session").cookie(token).send();

    let kept = body_json(restore(false).send().await).await;
    assert_eq!(kept["signed_out"], false, "{kept}");
    assert_eq!(session(&admin).await.status(), StatusCode::OK);

    let ended = body_json(restore(true).send().await).await;
    assert_eq!(ended["signed_out"], true, "{ended}");
    for token in [&admin, &operator] {
        assert_eq!(session(token).await.status(), StatusCode::UNAUTHORIZED);
    }
    assert_eq!(
        app.session_rows().await,
        0,
        "the restore deleted the rows, not only refused them"
    );
    assert!(app.signs_in("admin", Harness::PASSWORD).await);
}

#[tokio::test]
async fn served_with_sessions_a_missing_password_is_refused_as_a_wrong_one_is() {
    use wslib_appliance_https::testing::Harness;

    let builder = Harness::builder();
    let backups = Engine::session(NAME, "0.1.0-test", builder.dir(), (), ());
    let app = builder.api(backups.routes(Router::new())).build().await;
    tokio::spawn(backups.run_schedule(
        app.state().clone(),
        wslib_appliance_server::CancellationToken::new(),
    ));
    tokio::task::yield_now().await;
    let admin = app.admin("admin").await;
    let bundle = app
        .post("/api/backup")
        .cookie(&admin)
        .json(json!({ "passphrase": PASSPHRASE, "password": Harness::PASSWORD }))
        .send()
        .await;
    assert_eq!(bundle.status(), StatusCode::OK);
    let bundle = body_text(bundle).await;

    for (method, path, mut body) in [
        ("POST", "/api/backup", json!({ "passphrase": PASSPHRASE })),
        (
            "POST",
            "/api/backup/restore",
            json!({ "passphrase": PASSPHRASE, "bundle": bundle, "sections": everything() }),
        ),
        (
            "PUT",
            "/api/backup/schedule",
            json!({
                "schedule": { "enabled": true, "every_hours": 24, "keep": 7 },
                "passphrase": PASSPHRASE
            }),
        ),
    ] {
        let send = |body| app.request(method, path).cookie(&admin).json(body).send();
        let missing = send(body.clone()).await;
        body["password"] = json!("not it");
        let wrong = send(body).await;

        assert_eq!(wrong.status(), StatusCode::FORBIDDEN, "{path}");
        assert_eq!(missing.status(), wrong.status(), "{path}");
        assert_eq!(body_text(missing).await, body_text(wrong).await, "{path}");
    }
}

/// A box whose resolver is [`StoreAccounts`], declared or not.
async fn over_store_accounts(declared: bool) -> Harness {
    let builder = match declared {
        true => over_accounts().await,
        false => {
            let store = Store::open_in_memory(None).await.unwrap();
            Harness::builder()
                .store(store.clone())
                .resolver(StoreAccounts(store))
        }
    };
    mounted_on(builder).await.app
}

async fn first_run_restore(app: &Harness, bundle: &str) -> StatusCode {
    app.post("/api/onboarding/restore")
        .json(json!({ "passphrase": PASSPHRASE, "bundle": bundle }))
        .send()
        .await
        .status()
}

#[tokio::test]
async fn a_first_run_restore_claims_a_box_whose_resolver_is_over_the_stores_accounts() {
    let app = over_store_accounts(true).await;
    let bundle = sealed_with(&[("admin", Role::Admin)]).await;
    let as_admin = || app.get("/api/backup/schedule").header(ACCOUNT, "admin");
    assert_eq!(as_admin().send().await.status(), StatusCode::UNAUTHORIZED);

    assert_eq!(first_run_restore(&app, &bundle).await, StatusCode::OK);
    assert_eq!(as_admin().send().await.status(), StatusCode::OK);
    assert_eq!(first_run_restore(&app, &bundle).await, StatusCode::CONFLICT);
}

#[tokio::test]
async fn any_other_resolver_serves_no_first_run_restore() {
    let app = over_store_accounts(false).await;
    let bundle = sealed_with(&[("admin", Role::Admin)]).await;

    assert_eq!(
        first_run_restore(&app, &bundle).await,
        StatusCode::FORBIDDEN
    );
    assert!(app.store().users().await.unwrap().is_empty());
}

#[tokio::test]
async fn restoring_what_is_trusted_outbound_reaches_the_verifier() {
    let Rig { app, .. } = rig().await;
    let admin = account(&app, "admin", Role::Admin).await;
    let at = wslib_appliance_store::now();
    let authority = wslib_appliance_types::TrustedCa {
        sha256: "bb22".to_string(),
        subject: "CN=Widget Root".to_string(),
        not_before: at,
        not_after: at,
        added_at: at,
        added_by: "admin".to_string(),
        pem: "-----BEGIN CERTIFICATE-----\nbb22\n-----END CERTIFICATE-----\n".to_string(),
    };
    app.store().trust_ca(&authority).await.unwrap();
    let bundle = take(&app, &admin).await;
    app.store().distrust_ca("bb22").await.unwrap();

    let seen = app
        .post("/api/backup/inspect")
        .header(ACCOUNT, &admin)
        .json(json!({ "passphrase": PASSPHRASE, "bundle": bundle }))
        .send()
        .await;
    assert_eq!(
        body_json(seen).await["header"]["contains"]["trusted_cas"],
        1
    );

    let changes = app.state().outbound.subscribe();
    let response = app
        .post("/api/backup/restore")
        .header(ACCOUNT, &admin)
        .json(json!({
            "passphrase": PASSPHRASE, "bundle": bundle, "password": PASSWORD,
            "sections": { "trusted_cas": true }
        }))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let report = body_json(response).await;
    assert_eq!(report["applied"]["trusted_cas"], true);
    assert_eq!(report["applied"]["trusted_certs"], false);
    assert_eq!(app.store().trusted_cas().await.unwrap().len(), 1);
    assert!(changes.has_changed().unwrap(), "the verifier was told");
    let row = &app.store().audit(10, None).await.unwrap().items[0];
    assert!(
        row.fields
            .contains(&("trusted_cas".to_string(), "restored".to_string())),
        "{row:?}"
    );
}

#[tokio::test]
async fn a_section_the_bundle_does_not_carry_is_left_alone_and_nothing_chosen_is_refused() {
    let Rig { app, .. } = rig().await;
    let admin = account(&app, "admin", Role::Admin).await;
    app.store()
        .set_setting("branding.app_name", "Carried")
        .await
        .unwrap();
    let bundle = take(&app, &admin).await;

    // No pins in the bundle, and only pins asked for: nothing to apply.
    let response = app
        .post("/api/backup/restore")
        .header(ACCOUNT, &admin)
        .json(json!({
            "passphrase": PASSPHRASE, "bundle": bundle, "password": PASSWORD,
            "sections": { "trusted_certs": true }
        }))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Settings only: the accounts are left alone.
    let response = app
        .post("/api/backup/restore")
        .header(ACCOUNT, &admin)
        .json(json!({
            "passphrase": PASSPHRASE, "bundle": bundle, "password": PASSWORD,
            "sections": { "settings": true }
        }))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let report = body_json(response).await;
    assert_eq!(report["applied"]["accounts"], false);
    assert_eq!(report["signed_out"], false);
}

#[tokio::test]
async fn a_bundle_with_no_enabled_administrator_cannot_bring_its_accounts() {
    let Rig { app, .. } = rig().await;
    let admin = account(&app, "admin", Role::Admin).await;

    // Taken from a box whose only administrator is disabled — sealed
    // directly, since nobody on such a box can call the route.
    let id = app
        .store()
        .user_by_username(&admin)
        .await
        .unwrap()
        .expect("the account")
        .user
        .id;
    app.store().set_enabled(&id, false).await.unwrap();
    let disabled = Snapshot::capture(app.store())
        .await
        .unwrap()
        .seal(&Secret::new(PASSPHRASE), &provenance())
        .unwrap();
    app.store().set_enabled(&id, true).await.unwrap();

    let seen = body_json(
        app.post("/api/backup/inspect")
            .header(ACCOUNT, &admin)
            .json(json!({ "passphrase": PASSPHRASE, "bundle": disabled }))
            .send()
            .await,
    )
    .await;
    assert!(
        warnings(&seen)[0].contains("no enabled administrator"),
        "{seen}"
    );
    assert_sentences(warnings(&seen));

    let response = app
        .post("/api/backup/restore")
        .header(ACCOUNT, &admin)
        .json(json!({
            "passphrase": PASSPHRASE, "bundle": disabled, "password": PASSWORD,
            "sections": { "accounts": true }
        }))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);

    let Rig { app: fresh, .. } = rig().await;
    let refused = fresh
        .post("/api/onboarding/restore")
        .json(json!({ "passphrase": PASSPHRASE, "bundle": disabled }))
        .send()
        .await;
    assert_eq!(refused.status(), StatusCode::CONFLICT);
    let why = body_json(refused).await["error"].to_string();
    assert!(
        why.contains("no enabled administrator") && !why.contains("from Settings"),
        "{why}"
    );
}

#[tokio::test]
async fn a_restore_announces_the_settings_only_when_it_replaced_them() {
    let Rig { app, .. } = rig().await;
    let admin = account(&app, "admin", Role::Admin).await;
    app.store()
        .set_setting("branding.app_name", "Carried")
        .await
        .unwrap();
    let bundle = take(&app, &admin).await;
    let changed = app.store().settings_changed();

    let response = restore_accounts(&app, &admin, &bundle).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(!changed.has_changed().unwrap());

    let response = restore_chosen(&app, &admin, &bundle, json!({ "settings": true })).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(changed.has_changed().unwrap());
}

/// A bundle of a box holding `accounts`, sealed directly.
async fn sealed_with(accounts: &[(&str, Role)]) -> String {
    let store = Store::open_in_memory(None).await.unwrap();
    for (username, role) in accounts {
        store
            .create_user(username, "$argon2id$v=19$fake$hash", *role)
            .await
            .unwrap();
    }
    Snapshot::capture(&store)
        .await
        .unwrap()
        .seal(&Secret::new(PASSPHRASE), &provenance())
        .unwrap()
}

async fn restore_accounts(app: &Harness, token: &str, bundle: &str) -> Response {
    restore_chosen(app, token, bundle, json!({ "accounts": true })).await
}

async fn restore_chosen(
    app: &Harness,
    token: &str,
    bundle: &str,
    sections: serde_json::Value,
) -> Response {
    app.post("/api/backup/restore")
        .header(ACCOUNT, token)
        .json(json!({
            "passphrase": PASSPHRASE, "bundle": bundle, "password": PASSWORD,
            "sections": sections
        }))
        .send()
        .await
}

#[tokio::test]
async fn a_host_admin_restores_a_bundle_whose_only_administrator_is_a_host_admin() {
    let Rig { app, .. } = rig().await;
    let owner = account(&app, "owner", Role::HostAdmin).await;
    let bundle = take(&app, &owner).await;

    let seen = app
        .post("/api/backup/inspect")
        .header(ACCOUNT, &owner)
        .json(json!({ "passphrase": PASSPHRASE, "bundle": bundle }))
        .send()
        .await;
    assert_eq!(body_json(seen).await["warnings"], json!([]));
    assert_eq!(
        restore_accounts(&app, &owner, &bundle).await.status(),
        StatusCode::OK
    );
    assert!(has_the_password(&app, "owner").await);
}

#[tokio::test]
async fn only_a_host_admin_restores_accounts_where_one_is_on_either_side() {
    let Rig { app, .. } = rig().await;
    let admin = account(&app, "admin", Role::Admin).await;
    let forged = sealed_with(&[("admin", Role::Admin), ("usurper", Role::HostAdmin)]).await;
    let refused = restore_accounts(&app, &admin, &forged).await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert!(
        body_json(refused).await["error"]
            .to_string()
            .contains("only a host admin")
    );
    assert!(
        app.store()
            .user_by_username("usurper")
            .await
            .unwrap()
            .is_none()
    );

    let owner = account(&app, "owner", Role::HostAdmin).await;
    let plain = sealed_with(&[("admin", Role::Admin)]).await;
    assert_eq!(
        restore_accounts(&app, &admin, &plain).await.status(),
        StatusCode::FORBIDDEN,
        "an Admin cannot restore a host admin away"
    );

    assert_eq!(
        restore_accounts(&app, &owner, &plain).await.status(),
        StatusCode::CONFLICT,
        "a box that has a host admin keeps one"
    );
    assert!(has_the_password(&app, "owner").await);
}

#[tokio::test]
async fn a_bundle_with_no_accounts_is_not_told_to_untick_them() {
    let Rig { app, .. } = rig().await;
    let admin = account(&app, "admin", Role::Admin).await;

    // What a backend with no accounts writes.
    let empty = Store::open_in_memory(None).await.unwrap();
    let accountless = Snapshot::capture(&empty)
        .await
        .unwrap()
        .seal(&Secret::new(PASSPHRASE), &provenance())
        .unwrap();

    let seen = body_json(
        app.post("/api/backup/inspect")
            .header(ACCOUNT, &admin)
            .json(json!({ "passphrase": PASSPHRASE, "bundle": accountless }))
            .send()
            .await,
    )
    .await;
    assert_eq!(seen["header"]["contains"]["accounts"], 0, "{seen}");
    assert_eq!(seen["warnings"], json!([]), "{seen}");
}

#[tokio::test]
async fn every_route_refuses_the_control_socket() {
    // `SessionAdmin` on the signed-in ones; `Unclaimed` refuses the socket
    // on the first-run one because the socket has its own way in.
    let Rig { app, .. } = rig().await;
    for (method, path) in [
        ("POST", "/api/backup"),
        ("POST", "/api/backup/inspect"),
        ("POST", "/api/backup/restore"),
        ("GET", "/api/backup/schedule"),
        ("PUT", "/api/backup/schedule"),
        ("DELETE", "/api/backup/schedule/passphrase"),
        ("GET", "/api/backup/files/x.json"),
        ("DELETE", "/api/backup/files/x.json"),
        ("POST", "/api/onboarding/inspect"),
        ("POST", "/api/onboarding/restore"),
    ] {
        let response = app
            .request(method, path)
            .local()
            .json(json!({}))
            .send()
            .await;
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "{method} {path} must refuse the socket before reading its body"
        );
    }
}

#[tokio::test]
async fn the_schedule_needs_a_passphrase_and_an_edit_without_one_keeps_it() {
    let Rig { app, .. } = rig().await;
    let admin = account(&app, "admin", Role::Admin).await;

    let view = body_json(
        app.get("/api/backup/schedule")
            .header(ACCOUNT, &admin)
            .send()
            .await,
    )
    .await;
    assert_eq!(view["schedule"]["enabled"], false);
    assert_eq!(view["passphrase_set"], false);
    assert_eq!(view["runs"], true);
    assert_eq!(view["state"]["last_run_at"], serde_json::Value::Null);
    assert_eq!(view["files"], json!([]));

    let refused = app
        .put("/api/backup/schedule")
        .header(ACCOUNT, &admin)
        .json(json!({ "schedule": { "enabled": true, "every_hours": 24, "keep": 7 } }))
        .send()
        .await;
    assert_eq!(
        refused.status(),
        StatusCode::BAD_REQUEST,
        "enabled with nothing to seal with"
    );

    // A passphrase wants the caller's password proved: whoever sets it can
    // open every file the schedule writes.
    for body in [
        json!({ "schedule": { "enabled": true, "every_hours": 12, "keep": 3 }, "passphrase": PASSPHRASE }),
        json!({ "schedule": { "enabled": true, "every_hours": 12, "keep": 3 }, "passphrase": PASSPHRASE, "password": "not it" }),
    ] {
        assert_eq!(
            app.put("/api/backup/schedule")
                .header(ACCOUNT, &admin)
                .json(body)
                .send()
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
    }
    let view = switch_on(&app, &admin, 12, 3).await;
    assert_eq!(view["schedule"]["enabled"], true);
    assert_eq!(view["schedule"]["every_hours"], 12);
    assert_eq!(view["passphrase_set"], true);
    assert!(
        view.get("passphrase").is_none(),
        "the passphrase itself never comes back"
    );

    // An edit that carries no passphrase leaves the stored one alone, and
    // one below the floor is refused before anything is written.
    let view = body_json(
        app.put("/api/backup/schedule")
            .header(ACCOUNT, &admin)
            .json(json!({ "schedule": { "enabled": true, "every_hours": 6, "keep": 3 } }))
            .send()
            .await,
    )
    .await;
    assert_eq!(view["schedule"]["every_hours"], 6);
    assert_eq!(view["passphrase_set"], true);
    assert_eq!(
        app.put("/api/backup/schedule")
            .header(ACCOUNT, &admin)
            .json(json!({
                "schedule": { "enabled": true, "every_hours": 6, "keep": 3 },
                "passphrase": "short",
                "password": PASSWORD
            }))
            .send()
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn without_run_schedule_the_schedule_cannot_be_switched_on() {
    let app = mounted_on(over_accounts().await).await.app;
    let admin = account(&app, "admin", Role::Admin).await;
    let put = |enabled: bool| {
        app.put("/api/backup/schedule")
            .header(ACCOUNT, &admin)
            .json(json!({
                "schedule": { "enabled": enabled, "every_hours": 24, "keep": 7 },
                "passphrase": PASSPHRASE,
                "password": PASSWORD
            }))
    };

    assert_eq!(
        put(true).send().await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let view = body_json(
        app.get("/api/backup/schedule")
            .header(ACCOUNT, &admin)
            .send()
            .await,
    )
    .await;
    assert_eq!(
        view["passphrase_set"], false,
        "refused before anything is written"
    );
    assert_eq!(view["runs"], false);

    assert_eq!(put(false).send().await.status(), StatusCode::OK);
}

#[tokio::test]
async fn forgetting_the_passphrase_switches_the_schedule_off_and_leaves_the_files() {
    let Rig { app, backups } = rig().await;
    let admin = account(&app, "admin", Role::Admin).await;
    switch_on(&app, &admin, 1, 2).await;
    backups.check(app.state()).await.expect("check");

    // No body and no password.
    let response = app
        .delete("/api/backup/schedule/passphrase")
        .header(ACCOUNT, &admin)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let view = body_json(response).await;
    assert_eq!(view["schedule"]["enabled"], false);
    assert_eq!(
        view["schedule"]["keep"], 2,
        "the rest of the schedule is kept"
    );
    assert_eq!(view["passphrase_set"], false);
    assert_eq!(
        view["files"].as_array().unwrap().len(),
        1,
        "the file already written stays"
    );

    // A tick that would otherwise be due does nothing.
    app.store().clear_box_state(STATE_KEY).await.unwrap();
    backups.check(app.state()).await.expect("check");
    let view = body_json(
        app.get("/api/backup/schedule")
            .header(ACCOUNT, &admin)
            .send()
            .await,
    )
    .await;
    assert_eq!(view["state"]["last_run_at"], serde_json::Value::Null);

    // Nothing to forget is not an error, and leaves no row saying it was.
    assert_eq!(
        app.delete("/api/backup/schedule/passphrase")
            .header(ACCOUNT, &admin)
            .send()
            .await
            .status(),
        StatusCode::OK
    );
    let rows = app.store().audit(100, None).await.unwrap().items;
    assert_eq!(
        rows.iter()
            .filter(|row| row.message == "forgot the backup schedule's passphrase")
            .count(),
        1,
        "once: nothing to forget writes no row"
    );
}

#[tokio::test]
async fn a_due_schedule_writes_a_file_records_the_run_and_serves_it_back() {
    let Rig { app, backups } = rig().await;
    let admin = account(&app, "admin", Role::Admin).await;
    switch_on(&app, &admin, 1, 1).await;

    backups.check(app.state()).await.expect("check");
    let view = body_json(
        app.get("/api/backup/schedule")
            .header(ACCOUNT, &admin)
            .send()
            .await,
    )
    .await;
    assert!(view["state"]["last_run_at"].is_string());
    assert_eq!(view["state"]["error"], serde_json::Value::Null);
    let file = view["state"]["file"].as_str().expect("a file").to_string();
    assert_eq!(view["files"][0]["name"], file);
    assert_eq!(view["files"].as_array().unwrap().len(), 1);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let path = backups.dir.join(&file);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(&backups.dir)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }

    // Not due again: nothing changes.
    backups.check(app.state()).await.expect("check");
    assert_eq!(
        body_json(
            app.get("/api/backup/schedule")
                .header(ACCOUNT, &admin)
                .send()
                .await
        )
        .await["files"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    // The file downloads and opens with the schedule's passphrase; a name
    // that is not an entry in the directory is not a path.
    let response = app
        .get(&format!("/api/backup/files/{file}"))
        .header(ACCOUNT, &admin)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let text = body_text(response).await;
    let opened = Bundle::open(&text, &Secret::new(PASSPHRASE), 0).expect("opens");
    assert_eq!(opened.header().contains.accounts, 1);
    assert_eq!(
        app.get("/api/backup/files/..%2F..%2Fetc%2Fshadow")
            .header(ACCOUNT, &admin)
            .send()
            .await
            .status(),
        StatusCode::NOT_FOUND
    );

    // The scheduler left an audit row under its own name.
    let audit = body_json(app.get("/api/audit").header(ACCOUNT, &admin).send().await).await;
    assert!(
        audit["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["actor"] == "the backup schedule"
                && row["message"] == "took a scheduled backup"),
        "{audit}"
    );

    // A factory reset takes the files with it: they are every hash the box
    // had, sealed, and the next owner must not inherit them.
    backups.erase().expect("erase");
    assert!(
        body_json(
            app.get("/api/backup/schedule")
                .header(ACCOUNT, &admin)
                .send()
                .await
        )
        .await["files"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn an_administrator_deletes_a_stored_backup_by_its_listed_name_only() {
    let Rig { app, backups } = rig().await;
    let admin = account(&app, "admin", Role::Admin).await;
    let operator = account(&app, "operator", Role::Operator).await;
    let file = schedule::file_name(NAME, wslib_appliance_store::now());
    std::fs::create_dir_all(&backups.dir).unwrap();
    std::fs::write(backups.dir.join(&file), "{}").unwrap();
    let at = format!("/api/backup/files/{file}");

    assert_eq!(
        app.delete(&at)
            .header(ACCOUNT, &operator)
            .send()
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        app.delete("/api/backup/files/..%2F..%2Fetc%2Fshadow")
            .header(ACCOUNT, &admin)
            .send()
            .await
            .status(),
        StatusCode::NOT_FOUND
    );

    let response = app.delete(&at).header(ACCOUNT, &admin).send().await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        body_json(response).await["files"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let audit = body_json(app.get("/api/audit").header(ACCOUNT, &admin).send().await).await;
    assert!(
        audit["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["actor"] == "admin" && row["message"] == "deleted a backup"),
        "{audit}"
    );
}

#[tokio::test]
async fn a_run_on_a_clock_that_is_behind_keeps_the_file_it_wrote() {
    // With `keep = 2` and two later-stamped files on the box, a run stamped
    // in the past sorts oldest: rotated after the write it would remove
    // itself; rotated to one fewer before it, the older of the two goes.
    let Rig { app, backups } = rig().await;
    let admin = account(&app, "admin", Role::Admin).await;
    switch_on(&app, &admin, 1, 2).await;
    std::fs::create_dir_all(&backups.dir).unwrap();
    let later = |days| {
        schedule::file_name(
            NAME,
            wslib_appliance_store::now() + chrono::Duration::days(days),
        )
    };
    let (older, newer) = (later(365), later(366));
    std::fs::write(backups.dir.join(&older), "{}").unwrap();
    std::fs::write(backups.dir.join(&newer), "{}").unwrap();

    backups.check(app.state()).await.expect("check");
    let view = body_json(
        app.get("/api/backup/schedule")
            .header(ACCOUNT, &admin)
            .send()
            .await,
    )
    .await;
    let wrote = view["state"]["file"].as_str().unwrap();
    let names: Vec<&str> = view["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [newer.as_str(), wrote],
        "the run's own file is kept, beside the newer of the two"
    );
}

#[tokio::test]
async fn a_restored_schedule_with_no_passphrase_to_seal_with_is_switched_off_and_said() {
    // `backup.schedule` travels as a setting; its passphrase is a secret and
    // does not, so a replacement box would otherwise come up with the
    // schedule on and failing every interval.
    let Rig { app, .. } = rig().await;
    let admin = account(&app, "admin", Role::Admin).await;
    switch_on(&app, &admin, 12, 3).await;
    let bundle = take(&app, &admin).await;

    let mut tx = app.store().begin().await.unwrap();
    Store::erase_platform(&mut tx).await.unwrap();
    tx.commit().await.unwrap();

    let report = body_json(
        app.post("/api/onboarding/restore")
            .json(json!({ "passphrase": PASSPHRASE, "bundle": bundle }))
            .send()
            .await,
    )
    .await;
    assert!(
        warnings(&report)
            .iter()
            .any(|w| w.contains("switched off") && w.contains("passphrase")),
        "{report}"
    );
    assert_sentences(warnings(&report));
    let schedule: BackupSchedule = app.store().setting_doc(SCHEDULE_SETTING).await.unwrap();
    assert!(!schedule.enabled);
    assert_eq!(
        schedule.every_hours, 12,
        "the rest of the schedule came through"
    );
}

#[tokio::test]
async fn a_restored_schedule_on_a_box_that_does_not_run_one_is_switched_off_and_said() {
    let old = rig().await;
    let admin = account(&old.app, "admin", Role::Admin).await;
    switch_on(&old.app, &admin, 12, 3).await;
    let bundle = take(&old.app, &admin).await;

    let app = mounted_on(over_accounts().await).await.app;
    let admin = account(&app, "admin", Role::Admin).await;

    // No passphrase either, as on every first-run restore: the reason given
    // must be the one switching it on would meet first.
    let report = body_json(
        app.post("/api/backup/restore")
            .header(ACCOUNT, &admin)
            .json(json!({
                "passphrase": PASSPHRASE, "bundle": bundle, "password": PASSWORD,
                "sections": { "settings": true }
            }))
            .send()
            .await,
    )
    .await;
    assert!(
        warnings(&report)
            .iter()
            .any(|w| w.contains("switched off") && w.contains("does not run")),
        "{report}"
    );
    assert_sentences(warnings(&report));
    let schedule: BackupSchedule = app.store().setting_doc(SCHEDULE_SETTING).await.unwrap();
    assert!(!schedule.enabled);
}

#[tokio::test]
async fn a_first_run_restore_must_bring_an_administrator() {
    // A bundle with no accounts would seed settings, pins and a serving pair
    // onto a box that still looks fresh to the next person to reach it.
    let Rig { app, .. } = rig().await;
    app.store()
        .set_setting("branding.app_name", "Seeded")
        .await
        .unwrap();
    let empty = Snapshot::capture(app.store())
        .await
        .unwrap()
        .seal(&Secret::new(PASSPHRASE), &provenance())
        .unwrap();
    app.store()
        .set_setting("branding.app_name", "Fresh")
        .await
        .unwrap();

    let response = app
        .post("/api/onboarding/restore")
        .json(json!({ "passphrase": PASSPHRASE, "bundle": empty }))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        app.store()
            .setting("branding.app_name")
            .await
            .unwrap()
            .as_deref(),
        Some("Fresh"),
        "nothing was written"
    );
}

#[tokio::test]
async fn app_roles_the_routes_would_not_write_are_a_damaged_file_on_either_restore() {
    let row = |app: &str, role: Role| wslib_appliance_types::AppRole {
        user_id: "1".to_string(),
        app: app.to_string(),
        role,
    };
    let forged = [
        vec![row("widgets", Role::HostAdmin)],
        vec![row("a b", Role::Viewer)],
        vec![row(&"a".repeat(65), Role::Viewer)],
        vec![row("widgets", Role::Viewer), row("widgets", Role::Admin)],
    ];
    for rows in forged {
        let store = Store::open_in_memory(None).await.unwrap();
        store
            .create_user("admin", "$argon2id$v=19$fake$hash", Role::Admin)
            .await
            .unwrap();
        let mut snapshot = Snapshot::capture(&store).await.unwrap();
        snapshot.put_app_roles(rows.clone());
        let bundle = snapshot
            .seal(&Secret::new(PASSPHRASE), &provenance())
            .unwrap();

        let Rig { app, .. } = rig().await;
        let first_run = app
            .post("/api/onboarding/restore")
            .json(json!({ "passphrase": PASSPHRASE, "bundle": bundle }))
            .send()
            .await;
        assert_eq!(first_run.status(), StatusCode::BAD_REQUEST, "{rows:?}");
        assert_eq!(app.store().user_count().await.unwrap(), 0);

        let admin = account(&app, "admin", Role::Admin).await;
        let refused = restore_accounts(&app, &admin, &bundle).await;
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST, "{rows:?}");
        let why = body_json(refused).await["error"].to_string();
        assert!(!why.contains("share a username"), "{why}");
    }
}

#[tokio::test]
async fn a_schedule_that_cannot_seal_records_the_error_and_still_anchors_the_run() {
    let Rig { app, backups } = rig().await;
    // Enabled through the store rather than the route, which would refuse
    // it: the state a box is in after its passphrase secret was cleared.
    app.state()
        .store
        .set_setting_doc(
            SCHEDULE_SETTING,
            &BackupSchedule {
                enabled: true,
                every_hours: 1,
                keep: 1,
            },
        )
        .await
        .unwrap();

    backups.check(app.state()).await.expect("check");
    let state: BackupState = app.state().store.box_state_doc(STATE_KEY).await.unwrap();
    assert!(
        state.last_run_at.is_some(),
        "stamped whether or not it worked"
    );
    assert!(
        state
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("no passphrase")
    );
    assert_eq!(state.file, None);
}

#[tokio::test]
async fn a_box_with_no_accounts_takes_a_whole_bundle_once() {
    let Rig { app, .. } = rig().await;
    let admin = account(&app, "admin", Role::Admin).await;
    app.store()
        .set_setting("branding.app_name", "The old box")
        .await
        .unwrap();
    let bundle = take(&app, &admin).await;

    // A fresh box: everything erased.
    let mut tx = app.store().begin().await.unwrap();
    Store::erase_platform(&mut tx).await.unwrap();
    tx.commit().await.unwrap();

    let response = app
        .post("/api/onboarding/restore")
        .json(json!({ "passphrase": PASSPHRASE, "bundle": bundle }))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let report = body_json(response).await;
    assert_eq!(report["applied"]["accounts"], true);
    assert_eq!(report["signed_out"], false);
    assert_eq!(
        app.store()
            .setting("branding.app_name")
            .await
            .unwrap()
            .as_deref(),
        Some("The old box")
    );
    assert!(has_the_password(&app, "admin").await);

    // Claimed now, so the route is closed.
    assert_eq!(
        app.post("/api/onboarding/restore")
            .json(json!({ "passphrase": PASSPHRASE, "bundle": bundle }))
            .send()
            .await
            .status(),
        StatusCode::CONFLICT
    );
}

#[tokio::test]
async fn a_first_run_restore_applies_the_sections_chosen_and_always_the_accounts() {
    let Rig { app, .. } = rig().await;
    let admin = account(&app, "admin", Role::Admin).await;
    app.store()
        .set_setting("branding.app_name", "The old box")
        .await
        .unwrap();
    let bundle = take(&app, &admin).await;
    let mut tx = app.store().begin().await.unwrap();
    Store::erase_platform(&mut tx).await.unwrap();
    tx.commit().await.unwrap();
    let restore = |sections: serde_json::Value| {
        app.post("/api/onboarding/restore")
            .json(json!({ "passphrase": PASSPHRASE, "bundle": bundle, "sections": sections }))
            .send()
    };

    let refused = restore(json!({ "settings": true })).await;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    assert!(body_text(refused).await.contains("make the first account"));
    assert_eq!(app.store().user_count().await.unwrap(), 0);
    assert_eq!(
        app.store().setting("branding.app_name").await.unwrap(),
        None
    );

    let response = restore(json!({ "accounts": true })).await;
    assert_eq!(response.status(), StatusCode::OK);
    let applied = &body_json(response).await["applied"];
    assert_eq!(
        (&applied["accounts"], &applied["settings"]),
        (&json!(true), &json!(false))
    );
    assert_eq!(
        app.store().setting("branding.app_name").await.unwrap(),
        None
    );
    assert!(has_the_password(&app, "admin").await);
}

#[tokio::test]
async fn a_carried_pair_that_will_not_install_is_reported_and_the_rest_of_the_restore_stands() {
    // Two halves of two boxes' pairs: readable, and not a pair. The database
    // half commits first and cannot be undone by the install failing after
    // it, so the report says so rather than the route failing.
    let (one, other) = (rig().await, rig().await);
    let Rig { app, .. } = rig().await;
    let admin = account(&app, "admin", Role::Admin).await;
    app.store()
        .set_setting("branding.app_name", "Carried")
        .await
        .unwrap();
    let mut snapshot = Snapshot::capture(app.store()).await.unwrap();
    snapshot.put_serving_pair(ServingPair {
        cert_pem: one.app.state().tls.pair().await.unwrap().cert_pem,
        key_pem: other.app.state().tls.pair().await.unwrap().key_pem,
    });
    let mismatched = snapshot
        .seal(&Secret::new(PASSPHRASE), &provenance())
        .unwrap();
    let ours = serving_sha256(&app).await;
    app.store()
        .set_setting("branding.app_name", "Before")
        .await
        .unwrap();

    let response = app
        .post("/api/backup/restore")
        .header(ACCOUNT, &admin)
        .json(json!({
            "passphrase": PASSPHRASE, "bundle": mismatched, "password": PASSWORD,
            "sections": { "settings": true, "serving_certificate": true }
        }))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let report = body_json(response).await;
    assert_eq!(report["applied"]["settings"], true);
    assert_eq!(report["applied"]["serving_certificate"], false);
    assert!(
        report["warnings"][0]
            .as_str()
            .is_some_and(|w| w.contains("still serving its own")),
        "{report}"
    );
    assert_eq!(
        app.store()
            .setting("branding.app_name")
            .await
            .unwrap()
            .as_deref(),
        Some("Carried"),
        "the database half was restored regardless"
    );
    assert_eq!(serving_sha256(&app).await, ours);
}

/// The fingerprint of the pair on `app`'s disk.
async fn serving_sha256(app: &Harness) -> String {
    let pair = app.state().tls.pair().await.unwrap();
    inspect_pem(&pair.cert_pem).unwrap().sha256
}

#[tokio::test]
async fn the_first_run_restore_refuses_a_bundle_priced_above_its_ceiling() {
    let Rig { app: source, .. } = rig().await;
    let admin = account(&source, "admin", Role::Admin).await;
    let bundle = take(&source, &admin).await;
    // Three times what the crate writes: under the general ceiling a session
    // may pay, over the one a public route will. The ceiling answers before
    // the key is derived.
    let mut envelope: serde_json::Value = serde_json::from_str(&bundle).unwrap();
    envelope["kdf"]["m_cost"] = json!(3 * 64 * 1024);
    let dear = envelope.to_string();

    let Rig { app: fresh, .. } = rig().await;
    let refused = fresh
        .post("/api/onboarding/restore")
        .json(json!({ "passphrase": PASSPHRASE, "bundle": dear }))
        .send()
        .await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert!(
        body_json(refused).await["error"]
            .as_str()
            .is_some_and(|e| e.contains("first account")),
        "the refusal says where the larger ceiling applies"
    );
    assert_eq!(fresh.store().user_count().await.unwrap(), 0);
}

/// `/api/onboarding/{route}`, opening `bundle` under `passphrase`.
async fn first_run(app: &Harness, route: &str, passphrase: &str, bundle: &str) -> Response {
    app.post(&format!("/api/onboarding/{route}"))
        .json(json!({ "passphrase": passphrase, "bundle": bundle }))
        .send()
        .await
}

/// The first-run inspect's refusal, asserted the same as the first-run restore's.
async fn refused_as_the_first_run_restore_is(
    app: &Harness,
    passphrase: &str,
    bundle: &str,
) -> StatusCode {
    let seen = first_run(app, "inspect", passphrase, bundle).await;
    let restored = first_run(app, "restore", passphrase, bundle).await;
    let status = seen.status();
    assert_eq!(status, restored.status());
    assert_eq!(body_text(seen).await, body_text(restored).await);
    status
}

#[tokio::test]
async fn an_unclaimed_box_inspects_a_bundle_as_a_signed_in_one_does() {
    let (app, admin) = session_over(Reporting::blocking()).await;
    let bundle = take(&app, &admin).await;
    let signed_in = body_json(inspection(&app, &admin, &bundle).await).await;
    let mut tx = app.store().begin().await.unwrap();
    Store::erase_platform(&mut tx).await.unwrap();
    tx.commit().await.unwrap();

    let seen = first_run(&app, "inspect", PASSPHRASE, &bundle).await;
    assert_eq!(seen.status(), StatusCode::OK);
    let seen = body_json(seen).await;
    assert_eq!(seen["header"], signed_in["header"]);
    assert_eq!(seen["warnings"], json!(["Inspect said this first."]));
    assert_eq!(seen["blocked"], json!({ "gauges": BLOCKED }));
    assert_eq!(seen["items"], signed_in["items"]);
    assert_eq!(seen["items"]["gauges"][0]["name"], "g1");
}

#[tokio::test]
async fn the_first_run_inspect_is_refused_once_the_box_is_claimed() {
    let Rig { app, .. } = rig().await;
    let admin = account(&app, "admin", Role::Admin).await;
    let bundle = take(&app, &admin).await;
    assert_eq!(
        refused_as_the_first_run_restore_is(&app, PASSPHRASE, &bundle).await,
        StatusCode::CONFLICT
    );
}

#[tokio::test]
async fn the_first_run_inspect_refuses_what_the_first_run_restore_cannot_open() {
    let Rig { app: source, .. } = rig().await;
    let admin = account(&source, "admin", Role::Admin).await;
    let bundle = take(&source, &admin).await;
    let mut envelope: serde_json::Value = serde_json::from_str(&bundle).unwrap();
    envelope["kdf"]["m_cost"] = json!(3 * 64 * 1024);
    let dear = envelope.to_string();

    let Rig { app, .. } = rig().await;
    assert_eq!(
        refused_as_the_first_run_restore_is(&app, PASSPHRASE, &dear).await,
        StatusCode::FORBIDDEN
    );
    let wrong = "another passphrase long enough to be one";
    assert_eq!(
        refused_as_the_first_run_restore_is(&app, wrong, &bundle).await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(app.store().user_count().await.unwrap(), 0);
}

#[tokio::test]
async fn the_first_run_inspect_warns_in_the_words_the_restore_refuses_with() {
    let Rig { app, .. } = rig().await;
    let settings_only = Store::open_in_memory(None).await.unwrap();
    settings_only
        .set_setting("branding.app_name", "Carried")
        .await
        .unwrap();
    let accountless = Snapshot::capture(&settings_only)
        .await
        .unwrap()
        .seal(&Secret::new(PASSPHRASE), &provenance())
        .unwrap();
    for bundle in [
        sealed_with(&[("operator", Role::Operator)]).await,
        accountless,
    ] {
        let refused = first_run(&app, "restore", PASSPHRASE, &bundle).await;
        assert_eq!(refused.status(), StatusCode::CONFLICT);
        let why = body_json(refused).await["error"]
            .as_str()
            .unwrap()
            .to_string();

        let seen = first_run(&app, "inspect", PASSPHRASE, &bundle).await;
        assert_eq!(seen.status(), StatusCode::OK);
        let seen = body_json(seen).await;
        assert_eq!(warnings(&seen).len(), 1, "{seen}");
        assert_eq!(warnings(&seen)[0][1..], format!("{}.", &why[1..]));
        assert_sentences(warnings(&seen));
    }
}

#[tokio::test]
async fn the_first_run_inspect_leaves_the_box_as_it_was() {
    let Rig { app: source, .. } = rig().await;
    let admin = account(&source, "admin", Role::Admin).await;
    let bundle = take(&source, &admin).await;

    let Rig { app, .. } = rig().await;
    let rows = app.store().audit(100, None).await.unwrap().items.len();
    let seen = first_run(&app, "inspect", PASSPHRASE, &bundle).await;
    assert_eq!(seen.status(), StatusCode::OK);
    assert_eq!(app.store().user_count().await.unwrap(), 0);
    assert_eq!(
        app.store().audit(100, None).await.unwrap().items.len(),
        rows
    );
    assert_eq!(first_run_restore(&app, &bundle).await, StatusCode::OK);
}

#[tokio::test]
async fn a_products_first_run_refusal_is_a_first_run_inspect_warning_and_nothing_signed_in() {
    let (app, admin) = session_over(Reporting::refusing_first_run()).await;
    let bundle = take(&app, &admin).await;
    let seen = body_json(inspection(&app, &admin, &bundle).await).await;
    assert_eq!(seen["warnings"], json!(["Inspect said this first."]));
    let restored = restore_chosen(&app, &admin, &bundle, json!({ "app": ["gauges"] })).await;
    assert_eq!(restored.status(), StatusCode::OK);

    let mut tx = app.store().begin().await.unwrap();
    Store::erase_platform(&mut tx).await.unwrap();
    tx.commit().await.unwrap();
    let seen = first_run(&app, "inspect", PASSPHRASE, &bundle).await;
    assert_eq!(seen.status(), StatusCode::OK);
    let seen = body_json(seen).await;
    assert_eq!(
        seen["warnings"],
        json!(["Inspect said this first.", NOT_AT_FIRST_RUN])
    );
    assert_sentences(warnings(&seen));
    let refused = first_run(&app, "restore", PASSPHRASE, &bundle).await;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(refused).await["error"], NOT_AT_FIRST_RUN);
    assert_eq!(app.store().user_count().await.unwrap(), 0);
}

/// A product whose sections are one row, kept in memory, that says what it
/// did at each step, records what `restore` and `after_restore` were handed,
/// and may hold its restore part-way.
#[derive(Clone, Default)]
pub(crate) struct Reporting {
    restored: Arc<std::sync::Mutex<Option<Chosen>>>,
    after: Arc<std::sync::Mutex<Option<(Chosen, usize)>>>,
    held: Option<Hold>,
    blocked: bool,
    refuses_first_run: bool,
}

/// What a blocked section's product says of it.
pub(crate) const BLOCKED: &str = "The gauges' app is not running.";

/// What a product refusing a first-run restore of its gauges says.
const NOT_AT_FIRST_RUN: &str = "Gauges restore only onto a box already set up.";

impl Reporting {
    /// One of which no section asked about can be restored right now.
    pub(crate) fn blocking() -> Self {
        Self {
            blocked: true,
            ..Self::default()
        }
    }

    /// One that refuses a first-run restore of a bundle carrying its gauges.
    fn refusing_first_run() -> Self {
        Self {
            refuses_first_run: true,
            ..Self::default()
        }
    }
}

/// Signalled on the first, then waits on the second.
pub(crate) type Hold = Arc<(Notify, Notify)>;

pub(crate) async fn wait_at(hold: &Option<Hold>) {
    if let Some(hold) = hold {
        hold.0.notify_one();
        hold.1.notified().await;
    }
}

impl Sections for Reporting {
    async fn names(&self) -> Result<BTreeSet<String>, BackupError> {
        Ok(["gauges".to_string()].into())
    }

    async fn capture(&self, _: &Store, into: &mut Snapshot) -> Result<(), BackupError> {
        into.put("gauges", &json!([{ "id": "g1" }]))
    }

    async fn restore(
        &self,
        _: &mut wslib_appliance_store::sqlx::Transaction<'_, wslib_appliance_store::sqlx::Sqlite>,
        from: &Bundle,
        chosen: &Chosen,
    ) -> Result<Vec<String>, BackupError> {
        wait_at(&self.held).await;
        *self.restored.lock().unwrap() = Some(chosen.clone());
        let rows: Vec<serde_json::Value> = from.take("gauges")?.unwrap_or_default();
        Ok(vec![format!(
            "Restore wrote {} gauges for {:?}.",
            rows.len(),
            chosen.app
        )])
    }

    fn warnings(&self, _: &Bundle) -> Vec<String> {
        vec!["Inspect said this first.".to_string()]
    }

    fn items(&self, _: &Bundle) -> BTreeMap<String, Vec<SectionItem>> {
        let item = |name: &str| SectionItem {
            name: name.to_string(),
            label: name.to_uppercase(),
        };
        [
            (
                "gauges".to_string(),
                vec![item("g1"), item("g2"), item("opca.acme"), item("x~y")],
            ),
            ("dials".to_string(), vec![item("d1")]),
        ]
        .into()
    }

    async fn blocked(&self, _: &Store, names: &BTreeSet<String>) -> BTreeMap<String, String> {
        names
            .iter()
            .filter(|_| self.blocked)
            .map(|name| (name.clone(), BLOCKED.to_string()))
            .collect()
    }

    fn refuses_first_run(&self, from: &Bundle) -> Option<String> {
        (self.refuses_first_run && from.header().contains.app.contains_key("gauges"))
            .then(|| NOT_AT_FIRST_RUN.to_string())
    }

    async fn after_restore(&self, _: &Store, from: &Bundle, applied: &Chosen) -> Vec<String> {
        *self.after.lock().unwrap() = Some((applied.clone(), from.header().contains.app["gauges"]));
        vec!["The after_restore hook could not write a file.".to_string()]
    }

    async fn erase(
        &self,
        _: &mut wslib_appliance_store::sqlx::Transaction<'_, wslib_appliance_store::sqlx::Sqlite>,
    ) -> Result<(), BackupError> {
        Ok(())
    }
}

/// A product whose sections are `.0`, of which its capture puts the `.1`, a
/// row each.
#[derive(Clone)]
pub(crate) struct Named(pub &'static [&'static str], pub &'static [&'static str]);

impl Sections for Named {
    async fn names(&self) -> Result<BTreeSet<String>, BackupError> {
        Ok(self.0.iter().map(|name| name.to_string()).collect())
    }

    async fn capture(&self, _: &Store, into: &mut Snapshot) -> Result<(), BackupError> {
        for name in self.1 {
            into.put(name, &json!([{ "id": "d1" }]))?;
        }
        Ok(())
    }

    async fn restore(
        &self,
        _: &mut wslib_appliance_store::sqlx::Transaction<'_, wslib_appliance_store::sqlx::Sqlite>,
        _: &Bundle,
        _: &Chosen,
    ) -> Result<Vec<String>, BackupError> {
        Ok(Vec::new())
    }

    async fn erase(
        &self,
        _: &mut wslib_appliance_store::sqlx::Transaction<'_, wslib_appliance_store::sqlx::Sqlite>,
    ) -> Result<(), BackupError> {
        Ok(())
    }
}

/// A console's apps, a section each, installed and removed while it runs; `None`
/// while its supervisor does not answer.
#[derive(Clone, Default)]
struct Installed(
    Arc<std::sync::Mutex<Option<BTreeSet<String>>>>,
    Arc<std::sync::atomic::AtomicUsize>,
);

const UNANSWERED: &str = "The supervisor did not answer.";

impl Installed {
    fn now(&self, names: &[&str]) {
        *self.0.lock().unwrap() = Some(names.iter().map(|name| name.to_string()).collect());
    }

    fn unanswered(&self) {
        *self.0.lock().unwrap() = None;
    }

    fn reads(&self) -> usize {
        self.1.load(std::sync::atomic::Ordering::SeqCst)
    }
}

fn not_installed(name: &str) -> String {
    format!("The “{name}” app is not installed.")
}

impl Sections for Installed {
    async fn names(&self) -> Result<BTreeSet<String>, BackupError> {
        self.1.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let installed = self.0.lock().unwrap().clone();
        installed.ok_or_else(|| BackupError::Refused(UNANSWERED.to_string()))
    }

    async fn capture(&self, _: &Store, into: &mut Snapshot) -> Result<(), BackupError> {
        for name in into.names().clone() {
            into.put(&name, &json!([{ "id": "a1" }]))?;
        }
        Ok(())
    }

    async fn blocked(&self, _: &Store, names: &BTreeSet<String>) -> BTreeMap<String, String> {
        let installed = self.0.lock().unwrap().clone().unwrap_or_default();
        names
            .difference(&installed)
            .map(|name| (name.clone(), not_installed(name)))
            .collect()
    }

    async fn restore(
        &self,
        _: &mut wslib_appliance_store::sqlx::Transaction<'_, wslib_appliance_store::sqlx::Sqlite>,
        _: &Bundle,
        _: &Chosen,
    ) -> Result<Vec<String>, BackupError> {
        Ok(Vec::new())
    }

    async fn erase(
        &self,
        _: &mut wslib_appliance_store::sqlx::Transaction<'_, wslib_appliance_store::sqlx::Sqlite>,
    ) -> Result<(), BackupError> {
        Ok(())
    }
}

#[tokio::test]
async fn the_section_names_are_read_once_at_each_take_and_restore_not_at_start() {
    let installed = Installed::default();
    let (app, admin) = session_over(installed.clone()).await;
    installed.now(&["dials"]);
    let bundle = take(&app, &admin).await;
    assert_eq!(installed.reads(), 1);

    installed.now(&["gauges"]);
    let refused = restore_chosen(&app, &admin, &bundle, json!({ "app": ["dials"] })).await;
    assert_eq!(refused.status(), StatusCode::CONFLICT);
    installed.now(&["dials", "gauges"]);
    let restored = restore_chosen(&app, &admin, &bundle, json!({ "app": ["dials"] })).await;
    assert_eq!(restored.status(), StatusCode::OK);
    assert_eq!(installed.reads(), 3);
    assert_eq!(
        body_json(restored).await["applied"]["app"],
        json!(["dials"])
    );
}

async fn inspection(app: &Harness, token: &str, bundle: &str) -> Response {
    app.post("/api/backup/inspect")
        .header(ACCOUNT, token)
        .json(json!({ "passphrase": PASSPHRASE, "bundle": bundle }))
        .send()
        .await
}

#[tokio::test]
async fn names_that_fail_refuse_the_take_inspect_and_restore_with_their_error() {
    let installed = Installed::default();
    let (app, admin) = session_over(installed.clone()).await;
    installed.now(&["dials"]);
    let bundle = take(&app, &admin).await;
    installed.unanswered();

    let taken = taking(&app, &admin).await;
    let seen = inspection(&app, &admin, &bundle).await;
    let restored = restore_chosen(&app, &admin, &bundle, json!({ "app": ["dials"] })).await;
    for refused in [taken, seen, restored] {
        assert_eq!(refused.status(), StatusCode::CONFLICT);
        assert_eq!(body_json(refused).await["error"], UNANSWERED);
    }
}

#[tokio::test]
async fn an_uninstalled_apps_section_is_asked_about_and_shown_blocked() {
    let installed = Installed::default();
    let (app, admin) = session_over(installed.clone()).await;
    installed.now(&["dials", "gauges"]);
    let bundle = take(&app, &admin).await;
    installed.now(&["gauges"]);

    let seen = body_json(inspection(&app, &admin, &bundle).await).await;
    assert_eq!(seen["blocked"], json!({ "dials": not_installed("dials") }));
    let refused = restore_chosen(&app, &admin, &bundle, json!({ "app": ["dials"] })).await;
    assert_eq!(refused.status(), StatusCode::CONFLICT);
    assert_eq!(body_json(refused).await["error"], not_installed("dials"));
}

#[tokio::test]
async fn inspect_reports_a_products_items_only_for_the_sections_the_bundle_carries() {
    let (app, admin) = session_over(Reporting::default()).await;
    let bundle = take(&app, &admin).await;
    let seen = body_json(inspection(&app, &admin, &bundle).await).await;
    assert_eq!(
        seen["items"],
        json!({ "gauges": [
            { "name": "g1", "label": "G1" },
            { "name": "g2", "label": "G2" },
            { "name": "opca.acme", "label": "OPCA.ACME" },
            { "name": "x~y", "label": "X~Y" }
        ] })
    );
}

#[tokio::test]
async fn a_restore_choosing_some_items_hands_restore_exactly_those() {
    let sections = Reporting::default();
    let (app, admin) = session_over(sections.clone()).await;
    let bundle = take(&app, &admin).await;
    let restored = restore_chosen(
        &app,
        &admin,
        &bundle,
        json!({ "app": ["gauges", "dials"], "items": { "gauges": ["g2"], "dials": ["d1"] } }),
    )
    .await;
    assert_eq!(restored.status(), StatusCode::OK);
    let chosen = sections.restored.lock().unwrap().take().expect("ran");
    assert_eq!(
        chosen.items,
        [("gauges".to_string(), ["g2".to_string()].into())].into()
    );
    assert_eq!(
        body_json(restored).await["applied"]["items"],
        json!({ "gauges": ["g2"] })
    );
}

/// A product that says its gauges and dials are blocked, whatever it is asked.
#[derive(Clone)]
struct Overanswering;

impl Sections for Overanswering {
    async fn names(&self) -> Result<BTreeSet<String>, BackupError> {
        Ok(BTreeSet::new())
    }

    async fn capture(&self, _: &Store, _: &mut Snapshot) -> Result<(), BackupError> {
        Ok(())
    }

    async fn restore(
        &self,
        _: &mut wslib_appliance_store::sqlx::Transaction<'_, wslib_appliance_store::sqlx::Sqlite>,
        _: &Bundle,
        _: &Chosen,
    ) -> Result<Vec<String>, BackupError> {
        Ok(Vec::new())
    }

    async fn blocked(&self, _: &Store, _: &BTreeSet<String>) -> BTreeMap<String, String> {
        ["gauges", "dials"]
            .map(|name| (name.to_string(), BLOCKED.to_string()))
            .into()
    }

    async fn erase(
        &self,
        _: &mut wslib_appliance_store::sqlx::Transaction<'_, wslib_appliance_store::sqlx::Sqlite>,
    ) -> Result<(), BackupError> {
        Ok(())
    }
}

#[tokio::test]
async fn blocked_answers_only_what_was_asked() {
    let store = Store::open_in_memory(None).await.unwrap();
    let engine = Engine::local(NAME, "0.1.0-test", std::path::Path::new("."), Overanswering);
    let asked = ["gauges".to_string()];
    assert_eq!(
        engine.blocked(&store, &asked).await,
        [("gauges".to_string(), BLOCKED.to_string())].into()
    );
}

#[tokio::test]
async fn a_blocked_section_is_named_at_inspect_and_refused_before_the_proof_on_every_route() {
    let builder = over_accounts().await;
    let backups = backups(&builder, Reporting::blocking());
    let app = builder.api(backups.routes(Router::new())).build().await;
    let admin = account(&app, "admin", Role::Admin).await;
    app.store()
        .set_setting("branding.app_name", "Carried")
        .await
        .unwrap();
    let bundle = take(&app, &admin).await;
    let opened = json!({ "passphrase": PASSPHRASE, "bundle": bundle });
    let seen = app.post("/api/backup/inspect").header(ACCOUNT, &admin);
    let seen = body_json(seen.json(opened).send().await).await;
    assert_eq!(seen["blocked"], json!({ "gauges": BLOCKED }));

    let rows = app.store().audit(100, None).await.unwrap().items.len();
    let refused = app
        .post("/api/backup/restore")
        .header(ACCOUNT, &admin)
        .json(json!({
            "passphrase": PASSPHRASE, "bundle": bundle, "password": "not the password",
            "sections": { "settings": true, "app": ["gauges"] }
        }))
        .send()
        .await;
    assert_eq!(refused.status(), StatusCode::CONFLICT);
    assert_eq!(body_json(refused).await["error"], BLOCKED);
    assert_eq!(
        app.store().audit(100, None).await.unwrap().items.len(),
        rows,
        "no proof was judged and nothing was restored"
    );
    assert!(backups.sections.after.lock().unwrap().is_none());
    let restored = restore_chosen(&app, &admin, &bundle, json!({ "settings": true })).await;
    assert_eq!(restored.status(), StatusCode::OK);

    let mut tx = app.store().begin().await.unwrap();
    Store::erase_platform(&mut tx).await.unwrap();
    tx.commit().await.unwrap();
    let refused = app
        .post("/api/onboarding/restore")
        .json(json!({ "passphrase": PASSPHRASE, "bundle": bundle }))
        .send()
        .await;
    assert_eq!(refused.status(), StatusCode::CONFLICT);
    assert_eq!(body_json(refused).await["error"], BLOCKED);
    assert_eq!(app.store().user_count().await.unwrap(), 0);
}

#[tokio::test]
async fn an_item_named_as_an_app_is_with_a_dot_or_a_tilde_restores() {
    let sections = Reporting::default();
    let (app, admin) = session_over(sections.clone()).await;
    let bundle = take(&app, &admin).await;
    let chosen = json!({ "app": ["gauges"], "items": { "gauges": ["opca.acme", "x~y"] } });
    let restored = restore_chosen(&app, &admin, &bundle, chosen).await;
    assert_eq!(restored.status(), StatusCode::OK);
    let chosen = sections.restored.lock().unwrap().take().expect("ran");
    assert_eq!(
        chosen.items["gauges"],
        ["opca.acme".to_string(), "x~y".to_string()].into()
    );
}

#[tokio::test]
async fn an_item_the_product_does_not_list_for_its_section_is_refused_by_name() {
    let sections = Reporting::default();
    let (app, admin) = session_over(sections.clone()).await;
    let bundle = take(&app, &admin).await;
    let chosen = json!({ "app": ["gauges"], "items": { "gauges": ["g1", "nope"] } });
    let refused = restore_chosen(&app, &admin, &bundle, chosen).await;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    assert!(body_text(refused).await.contains("“nope”"));
    assert!(sections.restored.lock().unwrap().is_none());

    let installed = Installed::default();
    let (app, admin) = session_over(installed.clone()).await;
    installed.now(&["dials"]);
    let bundle = take(&app, &admin).await;
    let chosen = json!({ "app": ["dials"], "items": { "dials": ["a1"] } });
    let refused = restore_chosen(&app, &admin, &bundle, chosen).await;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    assert!(body_text(refused).await.contains("“a1”"));
}

/// Choices every restore route refuses: an item outside a chosen section, too
/// many, or one not named as an item is.
pub(crate) fn bad_item_choices() -> [serde_json::Value; 3] {
    let named = |count: usize| (0..count).map(|i| format!("i{i}")).collect::<Vec<_>>();
    [
        json!({ "app": ["gauges"], "items": { "dials": ["d1"] } }),
        json!({ "app": ["gauges", "dials"], "items": {
            "gauges": named(MOST_ITEMS_CHOSEN), "dials": ["d1"]
        } }),
        json!({ "app": ["gauges"], "items": { "gauges": ["an item"] } }),
    ]
}

#[tokio::test]
async fn a_first_run_restore_refuses_a_bad_item_choice_and_claims_nothing() {
    let (app, admin) = session_over(Reporting::default()).await;
    let bundle = take(&app, &admin).await;
    let mut tx = app.store().begin().await.unwrap();
    Store::erase_platform(&mut tx).await.unwrap();
    tx.commit().await.unwrap();
    for mut sections in bad_item_choices() {
        sections["accounts"] = json!(true);
        let refused = app
            .post("/api/onboarding/restore")
            .json(json!({ "passphrase": PASSPHRASE, "bundle": bundle, "sections": sections }))
            .send()
            .await;
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST, "{sections}");
        assert_eq!(app.store().user_count().await.unwrap(), 0);
    }
}

#[tokio::test]
async fn a_restore_choosing_a_name_that_is_not_one_or_too_many_is_refused_before_the_proof() {
    let (app, admin) = session_over(Reporting::default()).await;
    let choosing = |names: Vec<String>| {
        app.post("/api/backup/restore")
            .header(ACCOUNT, &admin)
            .json(json!({
                "passphrase": PASSPHRASE, "bundle": "", "password": "not the password",
                "sections": { "app": names }
            }))
            .send()
    };
    let named = |count: usize| (0..count).map(|i| format!("s{i}")).collect::<Vec<_>>();

    let rows = app.store().audit(100, None).await.unwrap().items.len();
    for names in [vec!["a name".to_string()], named(MOST_SECTIONS_CHOSEN + 1)] {
        assert_eq!(choosing(names).await.status(), StatusCode::BAD_REQUEST);
    }
    assert_eq!(
        app.store().audit(100, None).await.unwrap().items.len(),
        rows,
        "no proof was judged"
    );
    let judged = choosing(named(MOST_SECTIONS_CHOSEN)).await;
    assert_ne!(judged.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_restore_choosing_items_outside_a_chosen_section_too_many_or_not_named_is_refused_before_the_proof()
 {
    let (app, admin) = session_over(Reporting::default()).await;
    let choosing = |sections: serde_json::Value| {
        app.post("/api/backup/restore")
            .header(ACCOUNT, &admin)
            .json(json!({
                "passphrase": PASSPHRASE, "bundle": "", "password": "not the password",
                "sections": sections
            }))
            .send()
    };
    let named = |count: usize| (0..count).map(|i| format!("i{i}")).collect::<Vec<_>>();

    let rows = app.store().audit(100, None).await.unwrap().items.len();
    for sections in bad_item_choices() {
        assert_eq!(choosing(sections).await.status(), StatusCode::BAD_REQUEST);
    }
    assert_eq!(
        app.store().audit(100, None).await.unwrap().items.len(),
        rows,
        "no proof was judged"
    );
    let judged = choosing(json!({
        "app": ["gauges"], "items": { "gauges": named(MOST_ITEMS_CHOSEN) }
    }))
    .await;
    assert_ne!(judged.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_first_run_restore_asks_blocked_only_about_what_the_bundle_carries() {
    let (app, admin) = session_over(Reporting::blocking()).await;
    let bundle = take(&app, &admin).await;
    let mut tx = app.store().begin().await.unwrap();
    Store::erase_platform(&mut tx).await.unwrap();
    tx.commit().await.unwrap();
    let restored = app
        .post("/api/onboarding/restore")
        .json(json!({
            "passphrase": PASSPHRASE, "bundle": bundle,
            "sections": { "accounts": true, "app": ["dials"] }
        }))
        .send()
        .await;
    assert_eq!(restored.status(), StatusCode::OK);
}

/// The session rung over `sections`, and its administrator.
async fn session_over(sections: impl Sections) -> (Harness, String) {
    let builder = over_accounts().await;
    let backups = backups(&builder, sections);
    let app = builder.api(backups.routes(Router::new())).build().await;
    let admin = account(&app, "admin", Role::Admin).await;
    (app, admin)
}

#[tokio::test]
async fn a_declared_section_this_box_has_nothing_in_still_restores() {
    let (other, admin) = session_over(Named(&["gauges", "dials"], &["dials"])).await;
    let bundle = take(&other, &admin).await;
    let (app, admin) = session_over(Named(&["gauges", "dials"], &[])).await;

    let restored = restore_chosen(&app, &admin, &bundle, json!({ "app": ["dials"] })).await;
    assert_eq!(restored.status(), StatusCode::OK);
    assert_eq!(
        body_json(restored).await["applied"]["app"],
        json!(["dials"])
    );
}

#[tokio::test]
async fn with_the_appliance_half_another_products_platform_sections_alone_restore() {
    let (other, admin) = session_over(Named(&["dials"], &["dials"])).await;
    other
        .store()
        .set_setting("branding.app_name", "Carried")
        .await
        .unwrap();
    let bundle = take(&other, &admin).await;
    let (app, admin) = session_over(Named(&["gauges"], &["gauges"])).await;
    let carried = || async {
        app.store()
            .setting("branding.app_name")
            .await
            .unwrap()
            .is_some()
    };

    let seen = app
        .post("/api/backup/inspect")
        .header(ACCOUNT, &admin)
        .json(json!({ "passphrase": PASSPHRASE, "bundle": bundle }))
        .send()
        .await;
    let seen = body_json(seen).await;
    assert!(warnings(&seen).contains(&ANOTHER_PRODUCTS_APPLIANCE_HALF_RESTORES));
    assert!(!warnings(&seen).contains(&ANOTHER_PRODUCTS_NOTHING_RESTORES));

    let refused = json!({ "settings": true, "app": ["dials"] });
    let refused = restore_chosen(&app, &admin, &bundle, refused).await;
    assert_eq!(refused.status(), StatusCode::CONFLICT);
    assert!(body_text(refused).await.contains("another product"));
    assert!(!carried().await);

    let restored = restore_chosen(&app, &admin, &bundle, json!({ "settings": true })).await;
    assert_eq!(restored.status(), StatusCode::OK);
    let report = body_json(restored).await;
    assert_eq!(report["applied"]["app"], json!([]));
    assert!(
        warnings(&report).contains(&ANOTHER_PRODUCTS_APPLIANCE_HALF_RESTORES),
        "{report}"
    );
    assert!(carried().await);
}

#[tokio::test]
async fn a_carried_section_this_build_does_not_declare_is_left_out_and_said_so() {
    let (other, admin) = session_over(Named(&["gauges", "dials"], &["gauges", "dials"])).await;
    let bundle = take(&other, &admin).await;
    let (app, admin) = session_over(Named(&["gauges"], &["gauges"])).await;

    let chosen = json!({ "app": ["gauges", "dials"] });
    let restored = restore_chosen(&app, &admin, &bundle, chosen).await;
    assert_eq!(restored.status(), StatusCode::OK);
    let report = body_json(restored).await;
    assert_eq!(report["applied"]["app"], json!(["gauges"]));
    assert!(
        warnings(&report).contains(
            &"The section “dials” this backup carries is not one this build restores, and was \
              left out."
        ),
        "{report}"
    );
    assert_sentences(warnings(&report));
}

#[tokio::test]
async fn a_restore_waiting_to_open_its_file_holds_no_turn() {
    let builder = Harness::builder();
    let engine = Engine::local(NAME, "0.1.0-test", builder.dir(), Reporting::default());
    let app = builder
        .backup_hooks(crate::hooks::mount(engine.clone()))
        .api(engine.proxied_routes())
        .build()
        .await;
    let admin = wslib_appliance_types::console::ConsoleIdentity {
        reauthenticated_at: Some(chrono::Utc::now()),
        ..wslib_appliance_server::testing::console("admin", Role::Admin)
    };
    let taken = app
        .post("/api/backup")
        .from_console(&admin)
        .json(json!({ "passphrase": PASSPHRASE }))
        .send()
        .await;
    assert_eq!(taken.status(), StatusCode::OK);
    let bundle = body_text(taken).await;

    let deriving = engine.kdf.clone().acquire_owned().await.unwrap();
    let restore = tokio::spawn(
        app.post("/api/backup/restore")
            .from_console(&admin)
            .json(json!({
                "passphrase": PASSPHRASE, "bundle": bundle, "sections": { "app": ["gauges"] }
            }))
            .send(),
    );
    for _ in 0..20 {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        let captured = app.hook("POST", "/v1/backup/capture").send().await;
        assert_eq!(captured.status(), StatusCode::OK);
    }
    drop(deriving);
    assert_eq!(restore.await.unwrap().status(), StatusCode::OK);
}

#[tokio::test]
async fn what_a_products_restore_and_after_restore_say_reaches_the_report_in_order() {
    let sections = Reporting::default();
    let builder = over_accounts().await;
    let backups = backups(&builder, sections.clone());
    let app = builder.api(backups.routes(Router::new())).build().await;
    let admin = account(&app, "admin", Role::Admin).await;
    app.store()
        .set_setting("branding.app_name", "Carried")
        .await
        .unwrap();
    // Sealed in-crate so the pair it carries is one the install refuses,
    // which is how `after_restore` is shown to run after that install.
    let mut snapshot = Snapshot::capture(app.store()).await.unwrap();
    snapshot
        .capture_sections(&sections, app.store())
        .await
        .unwrap();
    snapshot.put_serving_pair(ServingPair {
        cert_pem: "not a certificate".into(),
        key_pem: Secret::new("not a key"),
    });
    let bundle = snapshot
        .seal(&Secret::new(PASSPHRASE), &provenance())
        .unwrap();

    let response = app
        .post("/api/backup/restore")
        .header(ACCOUNT, &admin)
        .json(json!({
            "passphrase": PASSPHRASE, "bundle": bundle, "password": PASSWORD,
            // Pins and a second section the bundle does not carry.
            "sections": {
                "settings": true, "trusted_certs": true, "serving_certificate": true,
                "app": ["gauges", "dials"]
            }
        }))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let report = body_json(response).await;
    let warnings = warnings(&report);
    assert_eq!(warnings.len(), 4, "{report}");
    assert_eq!(warnings[0], "Inspect said this first.");
    assert_eq!(warnings[1], "Restore wrote 1 gauges for {\"gauges\"}.");
    assert!(
        warnings[2].contains("still serving its own"),
        "the pair's install is said before the product's after_restore: {report}"
    );
    assert!(
        warnings[2].contains("converted first. This box") && !warnings[2].contains(".."),
        "the refusal's own stop is not doubled: {report}"
    );
    assert_eq!(
        warnings[3],
        "The after_restore hook could not write a file."
    );
    assert_sentences(warnings);
    let (applied, carried) = sections.after.lock().unwrap().take().expect("ran");
    assert!(applied.settings && applied.app.contains("gauges"));
    assert!(
        !applied.trusted_certs && !applied.app.contains("dials"),
        "what was applied, not what was asked for"
    );
    assert!(
        !applied.serving_certificate,
        "and what the install did, not what was going to be tried"
    );
    assert_eq!(carried, 1, "the bundle itself reaches after_restore");
}

#[tokio::test]
async fn a_take_leaves_out_the_products_sections_it_names_and_nothing_of_the_chassiss() {
    let builder = over_accounts().await;
    let backups = backups(&builder, Reporting::default());
    let app = builder.api(backups.routes(Router::new())).build().await;
    let admin = account(&app, "admin", Role::Admin).await;
    let contains = |leave_out: serde_json::Value| {
        let app = &app;
        let admin = &admin;
        async move {
            let taken = app
                .post("/api/backup")
                .header(ACCOUNT, admin)
                .json(json!({
                    "passphrase": PASSPHRASE, "password": PASSWORD, "leave_out": leave_out
                }))
                .send()
                .await;
            assert_eq!(taken.status(), StatusCode::OK);
            let seen = app
                .post("/api/backup/inspect")
                .header(ACCOUNT, admin)
                .json(json!({ "passphrase": PASSPHRASE, "bundle": body_text(taken).await }))
                .send()
                .await;
            body_json(seen).await["header"]["contains"].clone()
        }
    };

    assert_eq!(contains(json!([])).await["app"], json!({ "gauges": 1 }));
    let left = contains(json!(["gauges", "accounts", "dials"])).await;
    assert_eq!(left["app"], json!({}));
    assert_eq!(
        left["accounts"], 1,
        "a chassis section is not a product's to leave out"
    );

    contains(json!(["gauges", "not a name"])).await;
    let row = &app.store().audit(1, None).await.unwrap().items[0];
    assert_eq!(
        (row.message.as_str(), &row.fields),
        (
            "took a backup",
            &vec![("leave_out".to_string(), "gauges".to_string())]
        )
    );
}

#[tokio::test]
async fn a_restore_begun_runs_to_completion_when_its_browser_gives_up() {
    let held = Hold::default();
    let sections = Reporting {
        held: Some(held.clone()),
        ..Reporting::default()
    };
    let builder = over_accounts().await;
    let backups = backups(&builder, sections.clone());
    let app = builder.api(backups.routes(Router::new())).build().await;
    let admin = account(&app, "admin", Role::Admin).await;
    let bundle = take(&app, &admin).await;

    let request = tokio::spawn(
        app.post("/api/backup/restore")
            .header(ACCOUNT, &admin)
            .json(json!({
                "passphrase": PASSPHRASE, "bundle": bundle, "password": PASSWORD,
                "sections": { "app": ["gauges"] }
            }))
            .send(),
    );
    held.0.notified().await;
    request.abort();
    assert!(request.await.unwrap_err().is_cancelled());
    held.1.notify_one();

    app.audit_row("restored a backup").await;
    assert!(sections.after.lock().unwrap().is_some());
}

/// The second guard behind `Chassis::build`'s refusal: an account is never
/// taken at its word on the local rung.
#[tokio::test]
async fn the_local_rung_refuses_an_account_where_a_password_would_be_asked() {
    crate::install_test_provider();
    let app = Harness::new().await;
    let admin = wslib_appliance_server::Principal {
        id: "console:1".to_string(),
        username: "admin".to_string(),
        role: Role::Admin,
        reauthenticated_at: Some(chrono::Utc::now()),
    };
    let password = wslib_appliance_types::totp::FactorProof {
        password: Some(Secret::new(PASSWORD)),
        ..Default::default()
    };
    let reached = wslib_appliance_core::Reached::default();
    let refused = Admin(Identity::Resolved(admin))
        .prove(app.state(), &reached, password, "backup")
        .await;
    assert!(
        matches!(refused, Err(ApiError::Forbidden(_))),
        "{refused:?}"
    );
    assert!(
        Admin(Identity::Local)
            .prove(app.state(), &reached, Default::default(), "backup")
            .await
            .is_ok()
    );
}

/// `From<BackupError> for ApiError`, row for row.
///
/// The route tests reach only the arms a request can produce; this holds
/// the whole table.
#[test]
fn every_backup_error_answers_the_status_the_table_documents() {
    use axum::response::IntoResponse as _;
    let status = |e: BackupError| ApiError::from(e).into_response().status();
    assert_eq!(status(BackupError::NotABundle), StatusCode::BAD_REQUEST);
    assert_eq!(
        status(BackupError::Malformed("x".into())),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        status(BackupError::Passphrase("x".into())),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        status(BackupError::WrongPassphrase),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        status(BackupError::FormatTooNew { theirs: 2, ours: 1 }),
        StatusCode::CONFLICT
    );
    assert_eq!(
        status(BackupError::SchemaTooNew { theirs: 2, ours: 1 }),
        StatusCode::CONFLICT
    );
    assert_eq!(
        status(BackupError::Refused("x".into())),
        StatusCode::CONFLICT
    );
    assert_eq!(
        status(BackupError::TooDearWithoutASession),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        status(BackupError::TooLarge {
            limit: 1,
            actual: 2
        }),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert_eq!(
        status(BackupError::Internal("x".into())),
        StatusCode::INTERNAL_SERVER_ERROR
    );
}

#[tokio::test]
async fn a_refusal_answers_409_with_its_sentence_as_it_is() {
    use axum::response::IntoResponse as _;
    let refused = ApiError::from(BackupError::Refused(
        "The app “dials” is not running.".to_string(),
    ))
    .into_response();
    assert_eq!(refused.status(), StatusCode::CONFLICT);
    assert_eq!(
        body_json(refused).await["error"],
        "The app “dials” is not running."
    );
}

/// Served with sessions, an administrator whose TOTP is on takes, schedules and
/// restores with a code, a recovery code or a passkey, never the password alone.
#[tokio::test]
async fn while_totp_is_on_a_take_a_schedule_and_a_restore_take_a_code_or_a_passkey() {
    use std::time::{SystemTime, UNIX_EPOCH};
    use wslib_appliance_https::testing::{Harness, SoftPasskey};
    use wslib_appliance_types::passkey::{CreationOptions, RequestOptions};

    const ORIGIN: &str = "https://box.local:8443";
    let builder = Harness::builder();
    let backups = Engine::session(NAME, "0.1.0-test", builder.dir(), (), ());
    let app = builder.api(backups.routes(Router::new())).build().await;
    tokio::spawn(backups.run_schedule(
        app.state().clone(),
        wslib_appliance_server::CancellationToken::new(),
    ));
    tokio::task::yield_now().await;
    app.serving_on(8443);
    let admin = app.admin("admin").await;
    let at_box = |request: wslib_appliance_https::testing::Req| {
        request.cookie(&admin).header("host", "box.local:8443")
    };

    let options = at_box(app.post("/api/session/passkeys/options"))
        .json(json!({ "password": Harness::PASSWORD }))
        .send()
        .await;
    let options: CreationOptions = serde_json::from_value(body_json(options).await).unwrap();
    let mut passkey = SoftPasskey::new();
    let credential = passkey.register(&options, ORIGIN);
    let made = at_box(app.post("/api/session/passkeys"))
        .json(json!({ "name": "Key", "credential": credential }))
        .send()
        .await;
    assert_eq!(made.status(), StatusCode::CREATED);

    let id = app.user_id("admin").await;
    let key = Secret::new("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP");
    assert!(app.store().enrol_totp(&id, &key).await.unwrap());
    assert!(app.store().confirm_totp(&id, &key, 1, &[]).await.unwrap());
    let recovery = wslib_appliance_auth::issue_recovery_codes(app.store(), &id)
        .await
        .unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let code = wslib_auth_totp::Key::from_base32(key.expose())
        .expect("a key")
        .code_at(SystemTime::now());
    let by_code = json!({ "code": code, "browser_time": now });
    let by_recovery = json!({ "code": recovery.codes[0].expose(), "recovery": true });
    let challenge = || async {
        let options = at_box(app.post("/api/session/reauthentication/options"))
            .send()
            .await;
        serde_json::from_value::<RequestOptions>(body_json(options).await).unwrap()
    };
    let with = |mut body: serde_json::Value, proof: serde_json::Value| {
        body.as_object_mut()
            .unwrap()
            .extend(proof.as_object().unwrap().clone());
        body
    };
    let send = |method: &'static str, path: &'static str, body| {
        at_box(app.request(method, path)).json(body).send()
    };
    let password = json!({ "password": Harness::PASSWORD });

    let take = json!({ "passphrase": PASSPHRASE });
    let schedule = json!({
        "schedule": { "enabled": true, "every_hours": 24, "keep": 7 },
        "passphrase": PASSPHRASE,
    });
    for (method, path, body) in [
        ("POST", "/api/backup", &take),
        ("PUT", "/api/backup/schedule", &schedule),
    ] {
        let refused = send(method, path, with(body.clone(), password.clone())).await;
        assert_eq!(refused.status(), StatusCode::FORBIDDEN, "{path}");
        let by_passkey = json!({ "passkey": passkey.answer(&challenge().await, ORIGIN) });
        let proved = send(method, path, with(body.clone(), by_passkey)).await;
        assert_eq!(proved.status(), StatusCode::OK, "{path} by passkey");
    }
    let scheduled = send(
        "PUT",
        "/api/backup/schedule",
        with(schedule.clone(), by_recovery),
    )
    .await;
    assert_eq!(scheduled.status(), StatusCode::OK, "by a recovery code");
    let taken = send("POST", "/api/backup", with(take, by_code)).await;
    assert_eq!(taken.status(), StatusCode::OK, "by a TOTP code");

    let restore = json!({
        "passphrase": PASSPHRASE, "bundle": body_text(taken).await, "sections": everything(),
    });

    let spare = json!({ "code": recovery.codes[1].expose(), "recovery": true });
    let mut out_of_range = schedule.clone();
    out_of_range["schedule"]["keep"] = json!(0);
    for (method, path, body) in [
        ("POST", "/api/backup", json!({ "passphrase": "short" })),
        ("PUT", "/api/backup/schedule", out_of_range),
    ] {
        let refused = send(method, path, with(body, spare.clone())).await;
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST, "{path}");
    }
    assert_eq!(
        app.store().recovery_codes_left(&id).await.unwrap(),
        9,
        "a refused request spends no code"
    );
    let spent = send("PUT", "/api/backup/schedule", with(schedule.clone(), spare)).await;
    assert_eq!(
        spent.status(),
        StatusCode::OK,
        "the code kept was a good one"
    );

    let refused = send(
        "POST",
        "/api/backup/restore",
        with(restore.clone(), password),
    )
    .await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    let by_passkey = json!({ "passkey": passkey.answer(&challenge().await, ORIGIN) });
    let restored = send("POST", "/api/backup/restore", with(restore, by_passkey)).await;
    assert_eq!(restored.status(), StatusCode::OK);
}

/// A product whose one section is a string of as many characters as it holds.
#[derive(Clone)]
pub(crate) struct Padded(pub(crate) usize);

impl Sections for Padded {
    async fn names(&self) -> Result<BTreeSet<String>, BackupError> {
        Ok(["gauges".to_string()].into())
    }

    async fn capture(&self, _: &Store, into: &mut Snapshot) -> Result<(), BackupError> {
        into.put("gauges", &"x".repeat(self.0))
    }

    async fn restore(
        &self,
        _: &mut wslib_appliance_store::sqlx::Transaction<'_, wslib_appliance_store::sqlx::Sqlite>,
        _: &Bundle,
        _: &Chosen,
    ) -> Result<Vec<String>, BackupError> {
        Ok(Vec::new())
    }

    async fn erase(
        &self,
        _: &mut wslib_appliance_store::sqlx::Transaction<'_, wslib_appliance_store::sqlx::Sqlite>,
    ) -> Result<(), BackupError> {
        Ok(())
    }
}

#[tokio::test]
async fn a_take_scheduled_or_offline_seal_past_the_cap_is_refused_as_too_large() {
    let builder = over_accounts().await;
    let backups = backups(&builder, Padded(MAX_BUNDLE_LEN));
    let app = builder.api(backups.routes(Router::new())).build().await;
    let admin = account(&app, "admin", Role::Admin).await;

    let taken = taking(&app, &admin).await;
    assert_eq!(taken.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let passphrase = Secret::new(PASSPHRASE);
    let scheduled = backups
        .seal(app.state(), &passphrase, BTreeSet::new())
        .await;
    assert!(matches!(scheduled, Err(ApiError::PayloadTooLarge(_))));
    let pair = app.state().tls.pair().await.unwrap();
    let out = app.dir().join("offline.json");
    let offline = backups
        .seal_offline(app.store(), pair, &passphrase, &out)
        .await;
    assert!(matches!(offline, Err(BackupError::TooLarge { .. })));
    assert!(!out.exists());
}

#[tokio::test]
async fn a_bundle_at_the_cap_is_not_too_large_for_inspect_or_restore() {
    let (app, admin) = session_over(()).await;
    let bundle = "a".repeat(MAX_BUNDLE_LEN);
    let seen = inspection(&app, &admin, &bundle).await;
    assert_ne!(seen.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let restored = restore_chosen(&app, &admin, &bundle, json!({ "settings": true })).await;
    assert_ne!(restored.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

/// A failed install is either rolled back, so the box serves its own, or past
/// its commit point, where it still does and the report says what finishes the
/// restored pair.
#[test]
fn a_pair_that_was_not_installed_says_which_pair_the_box_serves() {
    let rolled_back = pair_not_installed(&TlsError::Mismatched);
    assert!(
        rolled_back.ends_with("This box is still serving its own."),
        "{rolled_back}"
    );
    let committed = pair_not_installed(&TlsError::Unfinished {
        because: "renaming: in the way".into(),
        next: "the next write, backup read or start finishes it from /var/lib/key.pem.txn, or a \
               start that cannot sets it aside and serves the pair on disk, making a fresh one \
               only if that will not load"
            .into(),
    });
    assert_eq!(
        committed,
        "The serving certificate this backup carried was written but not finished (renaming: \
         in the way); this box is still serving its own. Installing it again serves it at once, \
         and the next write, backup read or start finishes it from /var/lib/key.pem.txn, or a \
         start that cannot sets it aside and serves the pair on disk, making a fresh one only if \
         that will not load."
    );
    assert_sentences([rolled_back.as_str(), committed.as_str()]);
}
