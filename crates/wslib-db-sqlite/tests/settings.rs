mod common;

use std::collections::BTreeMap;

use common::chain;
use wslib_db_sqlite::{Database, Error, Settings};
use wslib_secret::Secret;

const DDL: &str = "CREATE TABLE {table} (
    key        TEXT PRIMARY KEY NOT NULL,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL
) STRICT";

async fn database(table: &str) -> Database {
    let ddl = DDL.replace("{table}", table);
    Database::open_in_memory(&[chain("app", &[(1, &ddl)]).await])
        .await
        .expect("open")
}

async fn settings() -> (Database, Settings) {
    let db = database("settings").await;
    let settings = Settings::new(&db);
    (db, settings)
}

fn exposed(secret: Option<Secret>) -> Option<String> {
    secret.map(|s| s.expose().to_string())
}

fn map(rows: &[(&str, &str)]) -> BTreeMap<String, String> {
    rows.iter()
        .map(|&(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

#[tokio::test]
async fn a_setting_never_written_is_absent_rather_than_empty_and_a_rewrite_replaces() {
    let (_db, settings) = settings().await;
    assert_eq!(settings.setting("branding.app_name").await.unwrap(), None);
    settings.set_setting("branding.app_name", "").await.unwrap();
    assert_eq!(
        settings.setting("branding.app_name").await.unwrap(),
        Some(String::new())
    );
    settings
        .set_setting("branding.app_name", "second")
        .await
        .unwrap();
    assert_eq!(
        settings.setting("branding.app_name").await.unwrap(),
        Some("second".to_string())
    );
}

#[tokio::test]
async fn a_secret_is_reachable_only_through_the_calls_that_own_it() {
    let (_db, settings) = settings().await;
    settings
        .set_secret("sample", &Secret::new("d0not1eak"))
        .await
        .unwrap();
    assert_eq!(
        exposed(settings.secret("sample").await.unwrap()).as_deref(),
        Some("d0not1eak")
    );

    assert!(matches!(
        settings.setting("secret.sample").await,
        Err(Error::Reserved(_))
    ));
    assert!(matches!(
        settings.set_setting("secret.sample", "x").await,
        Err(Error::Reserved(_))
    ));

    settings.clear_secret("sample").await.unwrap();
    assert!(settings.secret("sample").await.unwrap().is_none());
}

#[tokio::test]
async fn local_state_is_reachable_only_through_the_calls_that_own_it() {
    let (_db, settings) = settings().await;
    settings
        .set_local("backup.last_run", "2026-09-19T00:00:00Z")
        .await
        .unwrap();
    assert_eq!(
        settings.local("backup.last_run").await.unwrap().as_deref(),
        Some("2026-09-19T00:00:00Z")
    );
    for refused in [
        settings.setting("local.backup.last_run").await.map(drop),
        settings.set_setting("local.backup.last_run", "x").await,
    ] {
        assert!(matches!(refused, Err(Error::Reserved(_))), "{refused:?}");
    }
    settings.clear_local("backup.last_run").await.unwrap();
    assert_eq!(settings.local("backup.last_run").await.unwrap(), None);
}

#[tokio::test]
async fn local_state_and_secrets_never_export_and_a_replace_leaves_them_alone() {
    let (db, settings) = settings().await;
    settings
        .set_local("pending_rollback", "checkpoint-7")
        .await
        .unwrap();
    settings
        .set_secret("sample", &Secret::new("d0not1eak"))
        .await
        .unwrap();
    settings
        .set_setting("branding.app_name", "Old")
        .await
        .unwrap();
    settings
        .set_setting("gone.after.restore", "x")
        .await
        .unwrap();

    let exported = settings.exportable().await.unwrap();
    assert_eq!(
        exported,
        map(&[("branding.app_name", "Old"), ("gone.after.restore", "x")])
    );
    assert!(!format!("{exported:?}").contains("d0not1eak"));

    let mut tx = db.begin().await.unwrap();
    settings
        .replace_exportable(
            &mut tx,
            &map(&[
                ("local.pending_rollback", "theirs"),
                ("secret.sample", "attacker"),
                ("branding.app_name", "New"),
            ]),
        )
        .await
        .unwrap();
    tx.commit().await.unwrap();

    assert_eq!(
        settings.local("pending_rollback").await.unwrap().as_deref(),
        Some("checkpoint-7"),
        "neither deleted nor overwritten"
    );
    assert_eq!(
        exposed(settings.secret("sample").await.unwrap()).as_deref(),
        Some("d0not1eak"),
        "a carried secret is dropped, not applied"
    );
    assert_eq!(
        settings.exportable().await.unwrap(),
        map(&[("branding.app_name", "New")]),
        "carried settings replace rather than merge"
    );
}

#[tokio::test]
async fn a_key_is_in_a_namespace_by_its_exact_prefix_on_every_side() {
    let (db, settings) = settings().await;
    for key in [
        "SECRET.pretend",
        "poller.secret_rotation_days",
        "secrets.enabled",
        "secret",
        "locals.count",
    ] {
        settings.set_setting(key, "v").await.expect(key);
    }
    assert_eq!(settings.exportable().await.unwrap().len(), 5);

    let mut tx = db.begin().await.unwrap();
    settings
        .replace_exportable(&mut tx, &BTreeMap::new())
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert!(
        settings.exportable().await.unwrap().is_empty(),
        "ordinary keys, so an empty import removes them"
    );
}

#[tokio::test]
async fn a_document_round_trips_in_both_namespaces_and_an_unreadable_one_is_its_default() {
    #[derive(Debug, Default, PartialEq, serde::Serialize, serde::Deserialize)]
    struct Doc {
        enabled: bool,
        every_hours: u32,
    }
    let doc = Doc {
        enabled: true,
        every_hours: 24,
    };
    let (_db, settings) = settings().await;

    assert_eq!(
        settings
            .setting_doc::<Doc>("backup.schedule")
            .await
            .unwrap(),
        Doc::default()
    );
    settings
        .set_setting_doc("backup.schedule", &doc)
        .await
        .unwrap();
    assert_eq!(
        settings
            .setting_doc::<Doc>("backup.schedule")
            .await
            .unwrap(),
        doc
    );
    assert!(
        settings
            .exportable()
            .await
            .unwrap()
            .contains_key("backup.schedule")
    );

    settings.set_local_doc("backup.state", &doc).await.unwrap();
    assert_eq!(
        settings.local_doc::<Doc>("backup.state").await.unwrap(),
        doc
    );
    assert!(matches!(
        settings.setting_doc::<Doc>("local.backup.state").await,
        Err(Error::Reserved(_))
    ));

    settings
        .set_local("backup.state", "not json")
        .await
        .unwrap();
    assert_eq!(
        settings.local_doc::<Doc>("backup.state").await.unwrap(),
        Doc::default()
    );
}

#[tokio::test]
async fn a_second_caller_offering_a_secret_is_handed_the_one_that_landed() {
    let (_db, settings) = settings().await;
    let first = settings
        .init_secret("sample", &Secret::new("first"))
        .await
        .unwrap();
    let second = settings
        .init_secret("sample", &Secret::new("second"))
        .await
        .unwrap();
    assert_eq!(first.expose(), "first");
    assert_eq!(second.expose(), "first");
}

#[tokio::test]
async fn a_settings_write_is_announced_and_a_secret_or_local_write_is_not() {
    let (db, settings) = settings().await;
    let mut changed = settings.changed();
    let clone = settings.clone();

    settings
        .set_secret("sample", &Secret::new("x"))
        .await
        .unwrap();
    settings
        .init_secret("other", &Secret::new("y"))
        .await
        .unwrap();
    settings.clear_secret("other").await.unwrap();
    settings.set_local("backup.last_run", "now").await.unwrap();
    settings.set_local_doc("backup.state", &1).await.unwrap();
    settings.clear_local("backup.last_run").await.unwrap();
    let mut tx = db.begin().await.unwrap();
    settings
        .set_secret_in(&mut tx, "in_tx", &Secret::new("z"))
        .await
        .unwrap();
    settings.clear_secret_in(&mut tx, "in_tx").await.unwrap();
    tx.commit().await.unwrap();
    assert!(!changed.has_changed().unwrap());

    clone.set_setting("branding.app_name", "New").await.unwrap();
    assert!(
        changed.has_changed().unwrap(),
        "a clone's write is this one's"
    );
    changed.mark_unchanged();

    settings
        .set_setting_doc("backup.schedule", &1)
        .await
        .unwrap();
    assert!(changed.has_changed().unwrap());
    changed.mark_unchanged();

    assert!(settings.set_setting("secret.x", "y").await.is_err());
    assert!(
        !changed.has_changed().unwrap(),
        "a refused write is no change"
    );

    settings.replaced();
    assert!(changed.has_changed().unwrap());
}

#[tokio::test]
async fn secret_names_lists_bare_names_under_an_exact_prefix() {
    let (_db, settings) = settings().await;
    for name in ["cred.b", "cred.a", "cred_x", "credXa", "cre", "other"] {
        settings.set_secret(name, &Secret::new("v")).await.unwrap();
    }
    settings.set_setting("cred.setting", "v").await.unwrap();
    settings.set_local("cred.local", "v").await.unwrap();

    assert_eq!(
        settings.secret_names("cred.").await.unwrap(),
        ["cred.a", "cred.b"]
    );
    assert_eq!(settings.secret_names("cred_").await.unwrap(), ["cred_x"]);
    assert_eq!(
        settings.secret_names("").await.unwrap(),
        ["cre", "cred.a", "cred.b", "credXa", "cred_x", "other"]
    );
    assert!(settings.secret_names("none").await.unwrap().is_empty());
}

#[tokio::test]
async fn a_secret_renamed_in_a_transaction_moves_only_when_it_commits() {
    let (db, settings) = settings().await;
    settings
        .set_secret("cred.old", &Secret::new("v"))
        .await
        .unwrap();

    for commit in [false, true] {
        let mut tx = db.begin().await.unwrap();
        let value = settings
            .secret_in(&mut tx, "cred.old")
            .await
            .unwrap()
            .expect("stored");
        settings
            .set_secret_in(&mut tx, "cred.new", &value)
            .await
            .unwrap();
        settings.clear_secret_in(&mut tx, "cred.old").await.unwrap();
        if commit {
            tx.commit().await.unwrap();
        } else {
            tx.rollback().await.unwrap();
            assert_eq!(settings.secret_names("cred.").await.unwrap(), ["cred.old"]);
        }
    }
    assert_eq!(settings.secret_names("cred.").await.unwrap(), ["cred.new"]);
    assert_eq!(
        exposed(settings.secret("cred.new").await.unwrap()).as_deref(),
        Some("v")
    );
}

#[tokio::test]
async fn the_table_and_local_prefix_are_the_apps_to_choose() {
    let db = database("config").await;
    let settings = Settings::new(&db)
        .table("config")
        .unwrap()
        .local_prefix("here.")
        .unwrap();
    settings.set_local("last_run", "now").await.unwrap();
    settings.set_setting("local.ordinary", "v").await.unwrap();
    assert!(matches!(
        settings.set_setting("here.last_run", "x").await,
        Err(Error::Reserved(_))
    ));
    assert_eq!(
        settings.exportable().await.unwrap(),
        map(&[("local.ordinary", "v")])
    );
    let key: String =
        wslib_db_sqlite::sqlx::query_scalar("SELECT key FROM config WHERE value = 'now'")
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(key, "here.last_run");

    for name in ["Config", "config; DROP TABLE x", "", "1config"] {
        let refused = Settings::new(&db).table(name);
        assert!(matches!(refused, Err(Error::InvalidName(_))), "{name:?}");
    }
    for prefix in ["", "here", "secret.", "secret.more.", "s"] {
        let refused = Settings::new(&db).local_prefix(prefix);
        assert!(matches!(refused, Err(Error::LocalPrefix(_))), "{prefix:?}");
    }
}
