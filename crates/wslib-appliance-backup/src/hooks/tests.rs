use std::collections::BTreeSet;
use std::sync::Mutex;

use axum::http::StatusCode;
use chrono::DateTime;
use serde_json::json;
use wslib_appliance_server::testing::{Harness, Req, body_json, body_text};
use wslib_appliance_store::Store;
use wslib_appliance_store::sqlx::{Sqlite, Transaction};
use wslib_appliance_types::backup::{Chosen, SectionItem};
use wslib_appliance_types::console::{ConsoleIdentity, IDENTITY_HEADER};
use wslib_appliance_types::{Role, STALE_PROOF};
use wslib_secret::Secret;

use super::*;
use crate::LocalBackups;
use crate::routes::ROOM_BESIDE_A_BUNDLE;
use crate::routes::tests::{BLOCKED, Hold, Named, PASSPHRASE, Padded, bad_item_choices, wait_at};

const NAME: &str = "widget-monitor";

/// A product whose one section is in memory: what `restore` wrote, whether
/// `after_restore` ran, and a capture or restore that may be held part-way.
#[derive(Clone, Default)]
struct Gauges {
    restored: Arc<Mutex<Option<Value>>>,
    after: Arc<Mutex<Option<Chosen>>>,
    fail: bool,
    panics: bool,
    held: Option<Hold>,
    held_restoring: Option<Hold>,
    blocked: bool,
}

impl Sections for Gauges {
    async fn names(&self) -> Result<BTreeSet<String>, BackupError> {
        Ok(["gauges".to_string()].into())
    }

    async fn capture(&self, _: &Store, into: &mut Snapshot) -> Result<(), BackupError> {
        wait_at(&self.held).await;
        into.put("gauges", &json!([{ "id": "g1", "secret": "hunter2" }]))
    }

    async fn restore(
        &self,
        _: &mut Transaction<'_, Sqlite>,
        from: &Bundle,
        chosen: &Chosen,
    ) -> Result<Vec<String>, BackupError> {
        wait_at(&self.held_restoring).await;
        assert!(!self.panics, "a gauge's dial came off");
        if self.fail {
            return Err(BackupError::malformed("a gauge's dial is missing"));
        }
        if chosen.app.contains("gauges") {
            *self.restored.lock().unwrap() = from.take("gauges")?;
        }
        Ok(Vec::new())
    }

    fn warnings(&self, _: &Bundle) -> Vec<String> {
        vec!["Two gauges share a dial.".to_string()]
    }

    fn items(&self, _: &Bundle) -> BTreeMap<String, Vec<SectionItem>> {
        let g1 = SectionItem {
            name: "g1".to_string(),
            label: "Gauge one".to_string(),
        };
        [("gauges".to_string(), vec![g1])].into()
    }

    async fn blocked(&self, _: &Store, names: &BTreeSet<String>) -> BTreeMap<String, String> {
        names
            .iter()
            .filter(|_| self.blocked)
            .map(|name| (name.clone(), BLOCKED.to_string()))
            .collect()
    }

    async fn after_restore(&self, _: &Store, _: &Bundle, applied: &Chosen) -> Vec<String> {
        *self.after.lock().unwrap() = Some(applied.clone());
        Vec::new()
    }

    async fn erase(&self, _: &mut Transaction<'_, Sqlite>) -> Result<(), BackupError> {
        Ok(())
    }
}

async fn app(sections: impl Sections) -> Harness {
    let builder = Harness::builder();
    let backups = LocalBackups::new(NAME, "0.1.0-test", builder.dir(), sections);
    builder
        .backup_hooks(backups.hooks())
        .api(backups.proxied_routes())
        .build()
        .await
}

fn at(seconds: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(seconds, 0).unwrap()
}

fn pin() -> TrustedCert {
    TrustedCert {
        host: "widget-02.local".to_string(),
        sha256: "aa11".to_string(),
        subject: "CN=widget-02".to_string(),
        issuer: "CN=widget-02".to_string(),
        not_before: at(1_757_000_000),
        not_after: at(1_788_536_000),
        added_at: at(1_757_000_100),
        added_by: "admin".to_string(),
    }
}

fn authority() -> TrustedCa {
    TrustedCa {
        sha256: "bb22".to_string(),
        subject: "CN=Widget Root".to_string(),
        not_before: at(1_757_000_000),
        not_after: at(2_072_536_000),
        added_at: at(1_757_000_100),
        added_by: "admin".to_string(),
        pem: "-----BEGIN CERTIFICATE-----\nbb22\n-----END CERTIFICATE-----\n".to_string(),
    }
}

/// Everything the appliance half holds, and the outbound trust beside it.
async fn furnish(store: &Store) {
    let viewer = store
        .create_user("viewer", "$argon2id$v=19$fake$hash", Role::Viewer)
        .await
        .unwrap();
    store
        .set_app_role(&viewer.id, "widgets", Some(Role::Operator))
        .await
        .unwrap();
    store
        .set_setting("branding.app_name", "Ordinary Setting")
        .await
        .unwrap();
    store
        .set_secret("sample_secret", &Secret::new("d0not1eak"))
        .await
        .unwrap();
    store.set_box_state("https.port", "9443").await.unwrap();
    store.pin_cert(&pin()).await.unwrap();
    store.trust_ca(&authority()).await.unwrap();
}

async fn capture(app: &Harness) -> Value {
    let captured = app.hook("POST", "/v1/backup/capture").send().await;
    assert_eq!(captured.status(), StatusCode::OK);
    body_json(captured).await
}

fn chosen() -> Value {
    json!({ "trusted_certs": true, "trusted_cas": true, "app": ["gauges"] })
}

#[tokio::test]
async fn a_capture_carries_the_application_half_and_nothing_of_the_appliances() {
    let app = app(Gauges::default()).await;
    furnish(app.store()).await;
    let blob = capture(&app).await;

    let keys: Vec<&str> = blob
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        [
            "app",
            "app_schema_version",
            "app_version",
            "format",
            "product",
            "taken_at",
            "trusted_cas",
            "trusted_certs",
            "version"
        ]
    );
    assert_eq!(
        (&blob["format"], &blob["version"], &blob["product"]),
        (&json!(APP_SECTIONS), &json!(1), &json!(NAME))
    );
    assert_eq!(blob["trusted_certs"][0]["sha256"], "aa11");
    assert_eq!(blob["trusted_cas"][0]["sha256"], "bb22");
    assert_eq!(blob["app"]["gauges"][0]["id"], "g1");
    let text = blob.to_string();
    for absent in [
        "viewer",
        "fake$hash",
        "widgets",
        "Ordinary Setting",
        "d0not1eak",
        "9443",
    ] {
        assert!(!text.contains(absent), "{absent}: {text}");
    }

    let sections: AppSections = serde_json::from_value(blob).unwrap();
    let logged = format!("{sections:?}");
    for absent in ["hunter2", "Widget Root", "widget-02"] {
        assert!(!logged.contains(absent), "{logged}");
    }
    assert!(logged.contains(r#"app: {"gauges": 1}"#), "{logged}");

    let row = app
        .audit_row("captured this app's sections for the console")
        .await;
    assert_eq!((row.actor.as_str(), row.actor_id), ("console:hooks", None));
}

#[tokio::test]
async fn inspect_says_what_a_blob_holds_what_this_build_says_about_it_and_its_items() {
    let app = app(Gauges::default()).await;
    furnish(app.store()).await;
    let blob = capture(&app).await;
    let seen = app
        .hook("POST", "/v1/backup/inspect")
        .json(blob)
        .send()
        .await;
    assert_eq!(seen.status(), StatusCode::OK);
    assert_eq!(
        body_json(seen).await,
        json!({
            "contains": {
                "accounts": 0, "settings": 0, "trusted_certs": 1, "trusted_cas": 1,
                "serving_certificate": false, "ssh_keys": 0, "host": false,
                "app": { "gauges": 1 }
            },
            "warnings": ["Two gauges share a dial."],
            "blocked": {},
            "items": { "gauges": [{ "name": "g1", "label": "Gauge one" }] }
        })
    );
}

#[tokio::test]
async fn a_restore_applies_the_chosen_half_in_one_transaction_and_names_the_acting_user() {
    let gauges = Gauges::default();
    let app = app(gauges.clone()).await;
    app.store().trust_ca(&authority()).await.unwrap();
    let blob = capture(&app).await;
    app.store().distrust_ca("bb22").await.unwrap();

    let acting = ConsoleIdentity {
        id: "c-17".to_string(),
        username: "ops".to_string(),
        role: Role::Viewer,
        reauthenticated_at: None,
    };
    let restored = app
        .hook("POST", "/v1/backup/restore")
        .header(IDENTITY_HEADER, &acting.to_string())
        .json(json!({ "chosen": chosen(), "sections": blob }))
        .send()
        .await;
    assert_eq!(restored.status(), StatusCode::OK);
    let report = body_json(restored).await;
    assert_eq!(report["applied"]["trusted_cas"], true);
    assert_eq!(report["applied"]["app"], json!(["gauges"]));
    assert_eq!(report["signed_out"], false);
    assert_eq!(report["warnings"], json!(["Two gauges share a dial."]));
    assert_eq!(app.store().trusted_cas().await.unwrap().len(), 1);
    assert_eq!(
        gauges.restored.lock().unwrap().as_ref().unwrap()[0]["id"],
        "g1"
    );
    assert!(gauges.after.lock().unwrap().is_some());
    let row = app.audit_row("restored a backup").await;
    assert_eq!(
        (row.actor.as_str(), row.actor_id.as_deref()),
        ("ops", Some("console:c-17"))
    );
}

/// A capture carrying an authority the box then stops trusting, and a pin it
/// then makes, so a restore that wrote anything is told apart.
async fn captured_then_changed(app: &Harness) -> Value {
    app.store().trust_ca(&authority()).await.unwrap();
    let blob = capture(app).await;
    app.store().distrust_ca("bb22").await.unwrap();
    app.store().pin_cert(&pin()).await.unwrap();
    blob
}

/// What a refused restore must not have touched.
async fn untouched(app: &Harness, gauges: &Gauges) {
    assert_eq!(app.store().trusted_certs().await.unwrap(), [pin()]);
    assert!(app.store().trusted_cas().await.unwrap().is_empty());
    assert!(gauges.restored.lock().unwrap().is_none());
    assert!(gauges.after.lock().unwrap().is_none());
    let rows = app.store().audit(100, None).await.unwrap().items;
    assert!(
        rows.iter().all(|row| row.message != "restored a backup"),
        "{rows:?}"
    );
}

#[tokio::test]
async fn a_restore_outside_the_application_half_or_of_a_blob_this_build_would_not_write_changes_nothing()
 {
    let gauges = Gauges::default();
    let app = app(gauges.clone()).await;
    let blob = captured_then_changed(&app).await;
    let edited = |field: &str, value: Value| {
        let mut blob = blob.clone();
        blob[field] = value;
        blob
    };
    let mut misnamed = blob.clone();
    misnamed["app"]["a name"] = json!([]);

    let mut cases = vec![
        (
            json!({ "chosen": chosen(), "sections": blob, "users": [] }),
            422,
        ),
        (
            json!({ "chosen": chosen(), "sections": edited("users", json!([])) }),
            400,
        ),
        (
            json!({ "chosen": chosen(), "sections": edited("settings", json!({})) }),
            400,
        ),
        (
            json!({ "chosen": chosen(), "sections": edited("format", json!("appliance-backup")) }),
            400,
        ),
        (
            json!({ "chosen": chosen(), "sections": edited("version", json!(2)) }),
            409,
        ),
        (
            json!({ "chosen": chosen(), "sections": edited("version", json!(0)) }),
            400,
        ),
        (
            json!({ "chosen": chosen(), "sections": edited("app_schema_version", json!(1)) }),
            409,
        ),
        (
            json!({ "chosen": chosen(), "sections": edited("product", json!("another")) }),
            409,
        ),
        (json!({ "chosen": chosen(), "sections": misnamed }), 400),
    ];
    for flag in [
        "accounts",
        "settings",
        "serving_certificate",
        "ssh_keys",
        "host",
    ] {
        let mut chosen = chosen();
        chosen[flag] = json!(true);
        cases.push((json!({ "chosen": chosen, "sections": blob }), 400));
    }
    for (body, status) in cases {
        let refused = app
            .hook("POST", "/v1/backup/restore")
            .json(body.clone())
            .send()
            .await;
        assert_eq!(refused.status().as_u16(), status, "{body}");
        untouched(&app, &gauges).await;
    }

    let large = json!({ "chosen": chosen(), "sections": edited("pad", json!("a".repeat(MAX_BUNDLE_LEN + ROOM_BESIDE_A_BUNDLE))) });
    let refused = app
        .hook("POST", "/v1/backup/restore")
        .json(large)
        .send()
        .await;
    assert_eq!(refused.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let large = edited("pad", json!("a".repeat(MAX_BUNDLE_LEN)));
    let refused = app
        .hook("POST", "/v1/backup/inspect")
        .json(large)
        .send()
        .await;
    assert_eq!(refused.status(), StatusCode::PAYLOAD_TOO_LARGE);
    untouched(&app, &gauges).await;
}

#[tokio::test]
async fn a_restore_refuses_a_bad_item_choice_and_changes_nothing() {
    let gauges = Gauges::default();
    let app = app(gauges.clone()).await;
    let blob = captured_then_changed(&app).await;
    for mut chosen in bad_item_choices() {
        chosen["trusted_cas"] = json!(true);
        let refused = app
            .hook("POST", "/v1/backup/restore")
            .json(json!({ "chosen": chosen, "sections": blob }))
            .send()
            .await;
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST, "{chosen}");
        untouched(&app, &gauges).await;
    }
}

#[tokio::test]
async fn a_blocked_section_is_named_at_inspect_and_refused_at_restore_by_hook_and_proxy() {
    let gauges = Gauges {
        blocked: true,
        ..Gauges::default()
    };
    let app = app(gauges.clone()).await;
    let bundle = proxied_take(&app).await;
    let blob = captured_then_changed(&app).await;

    let seen = app.hook("POST", "/v1/backup/inspect").json(blob.clone());
    let seen = body_json(seen.send().await).await;
    assert_eq!(seen["blocked"], json!({ "gauges": BLOCKED }));
    let opened = json!({ "passphrase": PASSPHRASE, "bundle": bundle });
    let seen = proxied(&app, "/api/backup/inspect", &fresh(Role::Admin), opened);
    let seen = body_json(seen.send().await).await;
    assert_eq!(seen["blocked"], json!({ "gauges": BLOCKED }));

    let restored = app.hook("POST", "/v1/backup/restore");
    let restored = restored.json(json!({ "chosen": chosen(), "sections": blob }));
    let refused = restored.send().await;
    assert_eq!(refused.status(), StatusCode::CONFLICT);
    assert_eq!(body_json(refused).await["error"], BLOCKED);
    let stale = asserted(Role::Admin, None);
    let restore = json!({
        "passphrase": PASSPHRASE, "bundle": bundle, "sections": { "app": ["gauges"] }
    });
    let refused = proxied(&app, "/api/backup/restore", &stale, restore);
    let refused = refused.send().await;
    assert_eq!(
        refused.status(),
        StatusCode::CONFLICT,
        "refused before the reauthentication is asked for"
    );
    untouched(&app, &gauges).await;

    let unblocked = json!({ "chosen": { "trusted_cas": true }, "sections": blob });
    let restored = app.hook("POST", "/v1/backup/restore").json(unblocked);
    assert_eq!(restored.send().await.status(), StatusCode::OK);
}

#[tokio::test]
async fn a_restore_asks_blocked_only_about_what_the_blob_carries() {
    let app = app(Gauges {
        blocked: true,
        ..Gauges::default()
    })
    .await;
    furnish(app.store()).await;
    let blob = capture(&app).await;
    let chosen = json!({ "trusted_cas": true, "app": ["dials"] });
    let restored = app.hook("POST", "/v1/backup/restore");
    let restored = restored.json(json!({ "chosen": chosen, "sections": blob }));
    assert_eq!(restored.send().await.status(), StatusCode::OK);
}

#[tokio::test]
async fn a_products_failed_restore_takes_the_outbound_trust_back_with_it() {
    let gauges = Gauges {
        fail: true,
        ..Gauges::default()
    };
    let app = app(gauges.clone()).await;
    let blob = captured_then_changed(&app).await;

    let failed = app
        .hook("POST", "/v1/backup/restore")
        .json(json!({ "chosen": chosen(), "sections": blob }))
        .send()
        .await;
    assert_eq!(failed.status(), StatusCode::BAD_REQUEST);
    untouched(&app, &gauges).await;
}

#[tokio::test]
async fn one_capture_or_restore_at_a_time_and_another_is_refused() {
    let held = Hold::default();
    let gauges = Gauges {
        held: Some(held.clone()),
        ..Gauges::default()
    };
    let app = app(gauges).await;
    let first = tokio::spawn(app.hook("POST", "/v1/backup/capture").send());
    held.0.notified().await;

    for (path, body) in [
        ("/v1/backup/capture", None),
        (
            "/v1/backup/restore",
            Some(json!({ "chosen": chosen(), "sections": {} })),
        ),
    ] {
        let refused = app.hook("POST", path).maybe_json(body).send();
        let refused = tokio::time::timeout(std::time::Duration::from_secs(5), refused)
            .await
            .expect("refused at once, not queued");
        assert_eq!(refused.status(), StatusCode::CONFLICT, "{path}");
        assert!(body_text(refused).await.contains("already capturing"));
    }
    held.1.notify_one();
    assert_eq!(first.await.unwrap().status(), StatusCode::OK);
}

#[tokio::test]
async fn a_reserved_name_as_the_acting_user_is_refused_and_nothing_is_captured() {
    let app = app(Gauges::default()).await;
    let reserved = ConsoleIdentity {
        id: "c-1".to_string(),
        username: "control-socket".to_string(),
        role: Role::Admin,
        reauthenticated_at: None,
    };
    let refused = app
        .hook("POST", "/v1/backup/capture")
        .header(IDENTITY_HEADER, &reserved.to_string())
        .send()
        .await;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    assert!(app.store().audit(10, None).await.unwrap().items.is_empty());
}

#[tokio::test]
async fn another_products_blob_is_refused_as_one_whatever_its_schema() {
    let app = app(Gauges::default()).await;
    let mut blob = capture(&app).await;
    blob["product"] = json!("another");
    blob["app_schema_version"] = json!(99);
    let refused = app
        .hook("POST", "/v1/backup/inspect")
        .json(blob)
        .send()
        .await;
    assert_eq!(refused.status(), StatusCode::CONFLICT);
    assert!(body_text(refused).await.contains("another product"));
}

fn restoring(app: &Harness, blob: &Value) -> impl Future<Output = Response> + 'static {
    app.hook("POST", "/v1/backup/restore")
        .json(json!({ "chosen": chosen(), "sections": blob }))
        .send()
}

#[tokio::test]
async fn a_restore_begun_runs_to_completion_when_its_caller_gives_up() {
    let held = Hold::default();
    let gauges = Gauges {
        held_restoring: Some(held.clone()),
        ..Gauges::default()
    };
    let app = app(gauges.clone()).await;
    let blob = captured_then_changed(&app).await;
    let mut trust = app.state().outbound.subscribe();
    let before = *trust.borrow_and_update();

    let request = tokio::spawn(restoring(&app, &blob));
    held.0.notified().await;
    request.abort();
    assert!(request.await.unwrap_err().is_cancelled());
    held.1.notify_one();

    app.audit_row("restored a backup").await;
    assert_eq!(app.store().trusted_cas().await.unwrap().len(), 1);
    assert!(gauges.after.lock().unwrap().is_some());
    assert!(*trust.borrow() > before);
}

#[tokio::test]
async fn a_panic_in_the_products_restore_rolls_back_and_frees_the_turn() {
    let gauges = Gauges {
        panics: true,
        ..Gauges::default()
    };
    let app = app(gauges.clone()).await;
    let blob = captured_then_changed(&app).await;
    for _ in 0..2 {
        let failed = restoring(&app, &blob).await;
        assert_eq!(failed.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!body_text(failed).await.contains("dial came off"));
        untouched(&app, &gauges).await;
    }
}

/// An account of `role` the console asserts, its password proved at `at`.
fn asserted(role: Role, at: Option<DateTime<Utc>>) -> ConsoleIdentity {
    ConsoleIdentity {
        reauthenticated_at: at,
        ..wslib_appliance_server::testing::console("admin", role)
    }
}

fn fresh(role: Role) -> ConsoleIdentity {
    asserted(role, Some(Utc::now()))
}

fn proxied(app: &Harness, path: &str, who: &ConsoleIdentity, body: Value) -> Req {
    app.post(path).from_console(who).json(body)
}

fn take_body() -> Value {
    json!({ "passphrase": PASSPHRASE })
}

async fn proxied_take(app: &Harness) -> String {
    let taken = proxied(app, "/api/backup", &fresh(Role::Admin), take_body());
    let taken = taken.send().await;
    assert_eq!(taken.status(), StatusCode::OK);
    body_text(taken).await
}

#[tokio::test]
async fn a_proxied_take_seals_the_application_half_alone_and_inspects_and_restores_it() {
    let gauges = Gauges::default();
    let app = app(gauges.clone()).await;
    furnish(app.store()).await;
    let bundle = proxied_take(&app).await;
    let file: Value = serde_json::from_str(&bundle).unwrap();
    assert_eq!(
        file["header"]["contains"],
        json!({
            "accounts": 0, "settings": 0, "trusted_certs": 1, "trusted_cas": 1,
            "serving_certificate": false, "ssh_keys": 0, "host": false,
            "app": { "gauges": 1 }
        })
    );
    let row = app.audit_row("took a backup").await;
    assert_eq!(
        (row.actor.as_str(), row.actor_id.as_deref()),
        ("admin", Some("console:admin"))
    );

    app.store().distrust_ca("bb22").await.unwrap();
    let opened = json!({ "passphrase": PASSPHRASE, "bundle": bundle });
    let seen = proxied(
        &app,
        "/api/backup/inspect",
        &fresh(Role::Admin),
        opened.clone(),
    );
    let seen = body_json(seen.send().await).await;
    assert_eq!(seen["header"]["contains"]["trusted_cas"], 1, "{seen}");
    assert_eq!(seen["warnings"], json!(["Two gauges share a dial."]));

    let mut everything = opened;
    everything["sections"] = json!({
        "accounts": true, "settings": true, "trusted_cas": true, "app": ["gauges"]
    });
    let restored = proxied(&app, "/api/backup/restore", &fresh(Role::Admin), everything);
    let restored = restored.send().await;
    assert_eq!(restored.status(), StatusCode::OK);
    let report = body_json(restored).await;
    assert_eq!(
        report["applied"],
        json!({
            "accounts": false, "settings": false, "trusted_certs": false,
            "trusted_cas": true, "serving_certificate": false, "ssh_keys": false,
            "host": false, "app": ["gauges"]
        })
    );
    assert_eq!(report["signed_out"], false);
    assert_eq!(app.store().trusted_cas().await.unwrap().len(), 1);
    assert!(gauges.restored.lock().unwrap().is_some());
    let row = app.audit_row("restored a backup").await;
    assert_eq!(row.actor_id.as_deref(), Some("console:admin"));
}

#[tokio::test]
async fn a_proxied_take_or_restore_wants_a_recent_reauth_and_an_administrator() {
    let app = app(Gauges::default()).await;
    let restore = json!({
        "passphrase": PASSPHRASE, "bundle": "{}",
        "sections": { "app": ["gauges"] }
    });
    let six_minutes_ago = Utc::now() - chrono::Duration::minutes(6);
    for at in [None, Some(six_minutes_ago)] {
        let who = asserted(Role::Admin, at);
        for (path, body) in [
            ("/api/backup", take_body()),
            ("/api/backup/restore", restore.clone()),
        ] {
            let refused = proxied(&app, path, &who, body).send().await;
            assert_eq!(refused.status(), StatusCode::FORBIDDEN, "{path} {at:?}");
            assert!(body_text(refused).await.contains(STALE_PROOF), "{path}");
        }
    }
    let inspect = json!({ "passphrase": PASSPHRASE, "bundle": "{}" });
    for (path, body) in [
        ("/api/backup", take_body()),
        ("/api/backup/inspect", inspect),
        ("/api/backup/restore", restore),
    ] {
        let refused = proxied(&app, path, &fresh(Role::Operator), body)
            .send()
            .await;
        assert_eq!(refused.status(), StatusCode::FORBIDDEN, "{path}");
    }
    proxied_take(&app).await;
}

#[tokio::test]
async fn a_proxied_take_or_restore_is_refused_while_the_hooks_capture_runs() {
    let bundle = proxied_take(&app(Gauges::default()).await).await;
    let held = Hold::default();
    let app = app(Gauges {
        held: Some(held.clone()),
        ..Gauges::default()
    })
    .await;
    let first = tokio::spawn(app.hook("POST", "/v1/backup/capture").send());
    held.0.notified().await;
    let restore = json!({
        "passphrase": PASSPHRASE, "bundle": bundle,
        "sections": { "app": ["gauges"] }
    });
    for (path, body) in [
        ("/api/backup", take_body()),
        ("/api/backup/restore", restore),
    ] {
        let refused = proxied(&app, path, &fresh(Role::Admin), body).send();
        let refused = tokio::time::timeout(std::time::Duration::from_secs(5), refused)
            .await
            .expect("refused at once, not queued");
        assert_eq!(refused.status(), StatusCode::CONFLICT, "{path}");
    }
    held.1.notify_one();
    assert_eq!(first.await.unwrap().status(), StatusCode::OK);
}

#[tokio::test]
async fn a_hooks_capture_is_refused_while_a_proxied_restore_runs() {
    let held = Hold::default();
    let app = app(Gauges {
        held_restoring: Some(held.clone()),
        ..Gauges::default()
    })
    .await;
    let bundle = proxied_take(&app).await;
    let restore = json!({
        "passphrase": PASSPHRASE, "bundle": bundle,
        "sections": { "app": ["gauges"] }
    });
    let first =
        tokio::spawn(proxied(&app, "/api/backup/restore", &fresh(Role::Admin), restore).send());
    held.0.notified().await;
    let refused = app.hook("POST", "/v1/backup/capture").send().await;
    assert_eq!(refused.status(), StatusCode::CONFLICT);
    held.1.notify_one();
    assert_eq!(first.await.unwrap().status(), StatusCode::OK);
}

/// A sealed take of another product behind the same console, carrying an
/// authority this box does not trust.
async fn taken_by(other: Named) -> Value {
    let other = app(other).await;
    other.store().trust_ca(&authority()).await.unwrap();
    json!({ "passphrase": PASSPHRASE, "bundle": proxied_take(&other).await })
}

fn restoring_everything(mut opened: Value) -> Value {
    opened["sections"] = json!({ "trusted_cas": true, "app": ["gauges", "dials"] });
    opened
}

#[tokio::test]
async fn another_products_sealed_bundle_is_refused_and_writes_nothing() {
    let opened = taken_by(Named(&["dials"], &["dials"])).await;
    let gauges = Gauges::default();
    let app = app(gauges.clone()).await;

    let seen = proxied(
        &app,
        "/api/backup/inspect",
        &fresh(Role::Admin),
        opened.clone(),
    );
    let seen = body_json(seen.send().await).await;
    assert!(
        seen["warnings"]
            .to_string()
            .contains("another app's sections and none of this one's, so it will not restore"),
        "{seen}"
    );
    let mut trust_alone = opened.clone();
    trust_alone["sections"] = json!({ "trusted_cas": true });
    for restore in [restoring_everything(opened), trust_alone] {
        let refused = proxied(&app, "/api/backup/restore", &fresh(Role::Admin), restore);
        let refused = refused.send().await;
        assert_eq!(refused.status(), StatusCode::CONFLICT);
        assert!(body_text(refused).await.contains("another product"));
    }
    assert!(app.store().trusted_cas().await.unwrap().is_empty());
    assert!(gauges.restored.lock().unwrap().is_none());
    assert!(gauges.after.lock().unwrap().is_none());
    let rows = app.store().audit(100, None).await.unwrap().items;
    assert!(rows.iter().all(|row| row.message != "restored a backup"));
}

#[tokio::test]
async fn a_sealed_bundle_sharing_some_names_restores_and_reports_only_those() {
    let opened = taken_by(Named(&["gauges", "dials"], &["gauges", "dials"])).await;
    let gauges = Gauges::default();
    let app = app(gauges.clone()).await;

    let seen = proxied(
        &app,
        "/api/backup/inspect",
        &fresh(Role::Admin),
        opened.clone(),
    );
    let seen = body_json(seen.send().await).await;
    assert_eq!(seen["warnings"], json!(["Two gauges share a dial."]));
    let restore = restoring_everything(opened);
    let restored = proxied(&app, "/api/backup/restore", &fresh(Role::Admin), restore);
    let restored = restored.send().await;
    assert_eq!(restored.status(), StatusCode::OK);
    let report = body_json(restored).await;
    assert_eq!(report["applied"]["app"], json!(["gauges"]));
    assert!(
        report["warnings"]
            .to_string()
            .contains("The section “dials” this backup carries is not one this build restores"),
        "{report}"
    );
    let after = gauges.after.lock().unwrap().clone().unwrap();
    assert_eq!(after.app, BTreeSet::from(["gauges".to_string()]));
    let row = app.audit_row("restored a backup").await;
    assert!(
        row.fields
            .contains(&("app".to_string(), "gauges".to_string())),
        "{:?}",
        row.fields
    );
}

#[tokio::test]
async fn behind_a_console_there_is_no_schedule_no_files_and_no_first_run_restore() {
    let app = app(Gauges::default()).await;
    for (method, path) in [
        ("GET", "/api/backup/schedule"),
        ("PUT", "/api/backup/schedule"),
        ("DELETE", "/api/backup/schedule/passphrase"),
        ("GET", "/api/backup/files/x.json"),
        ("DELETE", "/api/backup/files/x.json"),
        ("POST", "/api/onboarding/restore"),
    ] {
        let response = app
            .request(method, path)
            .from_console(&fresh(Role::Admin))
            .json(json!({}))
            .send()
            .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{method} {path}");
    }
}

#[cfg(unix)]
mod socket {
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    use super::*;

    /// A request to `path` whose body never finishes arriving.
    async fn unending(socket: &Path, path: &str) -> UnixStream {
        let mut stream = UnixStream::connect(socket).await.unwrap();
        let head = format!(
            "POST {path} HTTP/1.1\r\nHost: app\r\nContent-Type: application/json\r\n\
             Content-Length: 4000000\r\n\r\n{{\"chosen\":"
        );
        stream.write_all(head.as_bytes()).await.unwrap();
        stream
    }

    async fn status_line(stream: &mut UnixStream) -> String {
        let mut line = [0; 12];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut line))
            .await
            .expect("answered before the body is read")
            .unwrap();
        String::from_utf8_lossy(&line).into_owned()
    }

    #[tokio::test]
    async fn a_busy_restore_or_inspect_is_refused_before_its_body_is_read() {
        let held = Hold::default();
        let app = app(Gauges {
            held: Some(held.clone()),
            ..Gauges::default()
        })
        .await;
        let uid = std::fs::metadata(app.dir()).unwrap().uid();
        let socket = app.serve_hooks_socket(uid).await;

        let first = tokio::spawn(app.hook("POST", "/v1/backup/capture").send());
        held.0.notified().await;
        let mut refused = unending(&socket, "/v1/backup/restore").await;
        assert_eq!(status_line(&mut refused).await, "HTTP/1.1 409");
        held.1.notify_one();
        assert_eq!(first.await.unwrap().status(), StatusCode::OK);

        let _reading = unending(&socket, "/v1/backup/inspect").await;
        let inspect = || {
            app.hook("POST", "/v1/backup/inspect")
                .json(json!({}))
                .send()
        };
        tokio::time::timeout(Duration::from_secs(5), async {
            while inspect().await.status() != StatusCode::CONFLICT {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("an inspect whose body is unread holds its turn");
        held.1.notify_one();
        assert_eq!(capture(&app).await["product"], NAME);
    }

    #[tokio::test]
    async fn a_proxied_take_or_restore_holds_no_turn_while_its_body_arrives_or_once_refused() {
        let app = app(Gauges::default()).await;
        let uid = std::fs::metadata(app.dir()).unwrap().uid();
        let socket = app.serve_app_socket(uid).await;
        let stale = asserted(Role::Admin, None);
        let restore = json!({
            "passphrase": PASSPHRASE, "bundle": "{}",
            "sections": { "app": ["gauges"] }
        });
        for (who, path, body, status) in [
            (&stale, "/api/backup", take_body(), "403"),
            (&stale, "/api/backup/restore", restore, "403"),
            (&fresh(Role::Admin), "/api/backup", take_body(), "200"),
        ] {
            let body = body.to_string();
            let (sent, rest) = body.split_at(body.len() / 2);
            let mut stream = UnixStream::connect(&socket).await.unwrap();
            let head = format!(
                "POST {path} HTTP/1.1\r\nHost: app\r\n{IDENTITY_HEADER}: {who}\r\n\
                 Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{sent}",
                body.len()
            );
            stream.write_all(head.as_bytes()).await.unwrap();
            for _ in 0..20 {
                tokio::time::sleep(Duration::from_millis(10)).await;
                capture(&app).await;
            }
            stream.write_all(rest.as_bytes()).await.unwrap();
            assert_eq!(
                status_line(&mut stream).await,
                format!("HTTP/1.1 {status}"),
                "{path}"
            );
            capture(&app).await;
        }
    }
}

#[tokio::test]
async fn a_capture_past_the_cap_is_refused_as_too_large() {
    let app = app(Padded(MAX_BUNDLE_LEN)).await;
    let refused = app.hook("POST", "/v1/backup/capture").send().await;
    assert_eq!(refused.status(), StatusCode::PAYLOAD_TOO_LARGE);
}
