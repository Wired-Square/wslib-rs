//! The hooks: what they answer, and that they answer nowhere but the hooks
//! socket, to nobody but the console.

use axum::Router;
use axum::http::{StatusCode, header};
use axum::routing::any;
use serde_json::{Value, json};
use wslib_appliance_store::Store;
use wslib_appliance_types::Role;
use wslib_appliance_types::about::Fact;
use wslib_appliance_types::console::{ConsoleIdentity, IDENTITY_HEADER};
use wslib_appliance_types::host::AddressConfig;

use crate::testing::{Harness, HarnessBuilder, Req, body_json, body_text};
use crate::{About, Actor, ApplianceState, BackupHooks, HookCaller, Notes, ProductAbout};

struct Uplink;

impl Notes for Uplink {
    fn note(&self, interface: &str) -> Option<String> {
        (interface == "eth0").then(|| "Discovery listens on this one.".to_string())
    }

    async fn warnings(&self, _: &Store, interface: &str, change: &AddressConfig) -> Vec<String> {
        match change {
            AddressConfig::Static { .. } => {
                vec![format!("Widgets on {interface} lose their lease.")]
            }
            AddressConfig::Dhcp { .. } => Vec::new(),
        }
    }
}

struct Rows;

impl About for Rows {
    async fn about(&self, _: &Store) -> ProductAbout {
        ProductAbout::new(vec![Fact::new("Widgets", "3")], Vec::new())
    }
}

fn who_routes() -> Router<ApplianceState> {
    Router::new().route(
        "/who",
        any(|who: HookCaller| async move { format!("{} {:?}", who.actor(), who.actor_id()) }),
    )
}

fn who() -> BackupHooks {
    BackupHooks::routes(who_routes(), |state: ApplianceState| state)
}

fn hooked() -> HarnessBuilder {
    Harness::builder()
        .about(Rows)
        .notes(Uplink)
        .backup_hooks(who())
}

fn error(text: &str) -> Value {
    json!({ "error": text })
}

#[tokio::test]
async fn the_index_says_which_optional_hooks_are_served_and_an_absent_one_is_a_404() {
    let bare = Harness::new().await;
    let index = bare.hook("GET", "/v1").send().await;
    assert_eq!(index.status(), StatusCode::OK);
    assert_eq!(
        body_json(index).await,
        json!({ "notes": false, "backup": false })
    );
    for path in ["/v1/notes", "/v1/backup/who"] {
        let absent = bare.hook("POST", path).json(json!({})).send().await;
        assert_eq!(absent.status(), StatusCode::NOT_FOUND, "{path}");
        assert_eq!(
            body_json(absent).await,
            error(&format!("no such hook: {path}"))
        );
    }

    let hooked = hooked().build().await;
    let index = body_json(hooked.hook("GET", "/v1").send().await).await;
    assert_eq!(index, json!({ "notes": true, "backup": true }));
}

#[tokio::test]
async fn about_is_the_products_name_version_and_rows_and_nothing_of_the_box() {
    let app = hooked().build().await;
    let about = app.hook("GET", "/v1/about").send().await;
    assert_eq!(about.status(), StatusCode::OK);
    assert_eq!(
        body_json(about).await,
        json!({
            "product": "Widget Monitor",
            "version": Harness::VERSION,
            "facts": [{ "label": "Widgets", "value": "3" }],
            "subsystems": []
        })
    );
}

#[tokio::test]
async fn notes_answer_the_products_sentences_about_an_interface_and_a_change() {
    let app = hooked().build().await;
    let asked = |body: Value| app.hook("POST", "/v1/notes").json(body).send();
    let fixed =
        json!({ "method": "static", "address": "192.0.2.7", "prefix": 24, "gateway": null });

    let answered = asked(json!({ "interface": "eth0", "change": fixed })).await;
    assert_eq!(answered.status(), StatusCode::OK);
    assert_eq!(
        body_json(answered).await,
        json!({
            "note": "Discovery listens on this one.",
            "warnings": ["Widgets on eth0 lose their lease."]
        })
    );
    let bare = body_json(asked(json!({ "interface": "wlan0" })).await).await;
    assert_eq!(bare, json!({ "note": null, "warnings": [] }));

    for interface in [
        "",
        "a-name-sixteen-b",
        "../eth0",
        "eth 0",
        ".",
        "..",
        "eth0:1",
    ] {
        let refused = asked(json!({ "interface": interface })).await;
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST, "{interface:?}");
    }
    let unusable =
        json!({ "method": "static", "address": "192.0.2.7", "prefix": 32, "gateway": null });
    let refused = asked(json!({ "interface": "eth0", "change": unusable })).await;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    let unknown = asked(json!({ "interface": "eth0", "users": [] })).await;
    assert_eq!(unknown.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let large = asked(json!({ "interface": "eth0", "x": "a".repeat(16 * 1024) })).await;
    assert_eq!(large.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn nothing_but_the_hooks_is_on_the_hooks_socket() {
    let bundle = tempfile::tempdir().unwrap();
    std::fs::write(bundle.path().join("index.html"), "<!doctype html>").unwrap();
    let app = hooked().ui(bundle.path()).build().await;
    for path in [
        "/",
        "/index.html",
        "/healthz",
        "/api/about",
        "/api/branding",
        "/v1/../api/about",
        "/apps/x/v1/about",
        "/v2",
    ] {
        let response = app.hook("GET", path).send().await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        assert_eq!(
            body_json(response).await,
            error(&format!("no such hook: {path}")),
            "{path}"
        );
    }
}

#[tokio::test]
async fn without_the_listeners_marker_the_hooks_answer_nothing() {
    let app = hooked().build().await;
    for (method, path) in [
        ("GET", "/v1"),
        ("GET", "/v1/about"),
        ("POST", "/v1/notes"),
        ("POST", "/v1/backup/who"),
        ("GET", "/nowhere"),
    ] {
        let response = app
            .unmarked_hook(method, path)
            .json(json!({ "interface": "eth0" }))
            .send()
            .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        assert_eq!(
            body_json(response).await,
            error(&format!("no such hook: {path}"))
        );
    }
}

#[tokio::test]
async fn the_hooks_are_not_on_the_app_socket_under_any_base() {
    for base in ["/", "/apps/x/"] {
        let app = hooked().base_path(base.parse().unwrap()).build().await;
        for hook in ["/v1", "/v1/about", "/v1/notes", "/v1/backup/who"] {
            let path = format!("{}{hook}", base.trim_end_matches('/'));
            for from_console in [true, false] {
                let request = app
                    .request("POST", &path)
                    .json(json!({ "interface": "eth0" }));
                let request = match from_console {
                    true => request.on_app_socket(),
                    false => request,
                };
                let response = request.send().await;
                assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
                assert_eq!(
                    body_json(response).await,
                    error(&format!("no such path: {hook}")),
                    "{path}"
                );
            }
        }
    }
}

#[tokio::test]
async fn nothing_on_the_hooks_is_compressed() {
    let app = hooked().build().await;
    let about = app
        .hook("GET", "/v1/about")
        .header("accept-encoding", "gzip")
        .send()
        .await;
    assert_eq!(about.status(), StatusCode::OK);
    assert!(about.headers().get(header::CONTENT_ENCODING).is_none());
    assert!(body_json(about).await["product"].is_string());
}

fn console(username: &str) -> String {
    ConsoleIdentity {
        id: "c-17".to_string(),
        username: username.to_string(),
        role: Role::Viewer,
        reauthenticated_at: None,
    }
    .to_string()
}

#[tokio::test]
async fn the_acting_user_is_named_with_its_role_ignored_and_a_bad_header_refused() {
    let app = hooked().build().await;
    let asked = |values: &[&str]| {
        values
            .iter()
            .fold(app.hook("POST", "/v1/backup/who"), |request, value| {
                request.header(IDENTITY_HEADER, value)
            })
            .send()
    };
    assert_eq!(body_text(asked(&[]).await).await, "console:hooks None");
    assert_eq!(
        body_text(asked(&[&console("ops")]).await).await,
        r#"ops Some("console:c-17")"#
    );
    let ops = console("ops");
    for values in [
        &["v1; id=c-17; user=ops"][..],
        &["v2"],
        &[&console("control-socket")],
        &[&console("a:b")],
        &[&ops, &ops],
    ] {
        let refused = asked(values).await;
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST, "{values:?}");
    }
}

#[tokio::test]
async fn the_acting_user_off_the_hooks_socket_is_ignored() {
    let app = Harness::new().await;
    let routes = who_routes().with_state(app.state().clone());
    let asked = Req::new(routes, "POST", "/who")
        .header(IDENTITY_HEADER, &console("ops"))
        .send()
        .await;
    assert_eq!(body_text(asked).await, "console:hooks None");
}

#[cfg(unix)]
mod socket {
    use std::path::Path;
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use wslib_appliance_core::backend;
    use wslib_appliance_store::Store;
    use wslib_appliance_types::Branding;

    use super::super::WITHIN;
    use super::super::proxied::{over, own_uid};
    use super::*;
    use crate::testing::{bootstrap_in, bound};
    use crate::{AppSocket, ServeError, Server, logs};

    #[tokio::test]
    async fn the_consoles_uid_is_answered_and_any_other_hung_up_on_unanswered() {
        let app = hooked().build().await;
        let uid = own_uid(app.dir());
        let socket = app.serve_hooks_socket(uid).await;
        let (status, body) = over(&socket, "/v1", None).await;
        assert_eq!(
            (status, body.as_str()),
            (200, r#"{"notes":true,"backup":true}"#)
        );

        let other = hooked().build().await;
        let socket = other.serve_hooks_socket(uid.wrapping_add(1)).await;
        let answer = tokio::time::timeout(WITHIN, async {
            let mut stream = tokio::net::UnixStream::connect(&socket).await.unwrap();
            stream
                .write_all(b"GET /v1 HTTP/1.1\r\nHost: app\r\nConnection: close\r\n\r\n")
                .await
                .ok();
            let mut answer = Vec::new();
            stream.read_to_end(&mut answer).await.ok();
            answer
        })
        .await
        .expect("hung up on at once");
        assert!(answer.is_empty(), "{}", String::from_utf8_lossy(&answer));
    }

    #[tokio::test]
    async fn a_products_own_backup_routes_are_served_on_the_hooks_socket() {
        let app = hooked().build().await;
        let socket = app.serve_hooks_socket(own_uid(app.dir())).await;
        let ops = console("ops").parse().unwrap();
        let (status, body) = over(&socket, "/v1/backup/who", Some(&ops)).await;
        assert_eq!(
            (status, body.as_str()),
            (200, r#"ops Some("console:c-17")"#)
        );
    }

    #[tokio::test]
    async fn the_overflow_uid_and_an_abstract_or_empty_path_are_refused() {
        let app = hooked().build().await;
        let ok = app.dir().join("hooks.sock");
        for (path, uid, because) in [
            (ok.as_path(), 65534, "userns-remap"),
            (Path::new("\0hidden"), 0, "abstract namespace"),
            (Path::new(""), 0, "abstract namespace"),
        ] {
            let refused = tokio::time::timeout(
                WITHIN,
                backend::serve_hooks_socket(
                    backend::hooks(app.state()),
                    path.to_path_buf(),
                    uid,
                    app.shutdown(),
                ),
            )
            .await
            .expect("refused at once");
            assert!(
                matches!(&refused, Err(ServeError::Socket { because: why, .. }) if why.contains(because)),
                "{path:?}: {refused:?}"
            );
        }
        assert!(!ok.exists());
    }

    /// `serve` until the app socket binds, and what then is in `dir`.
    async fn served(dir: &Path, socket: AppSocket) -> Vec<String> {
        let store = Store::open_in_memory(None).await.expect("store");
        let server =
            Server::new(store, Branding::unbranded(), "0.0.0", logs(&[])).backup_hooks(who());
        let bootstrap = bootstrap_in(dir);
        let serving = tokio::spawn(async move {
            server
                .serve(&bootstrap, socket, std::future::pending())
                .await
        });
        bound(&dir.join("app.sock")).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .filter(|name| name.ends_with(".sock"))
            .collect();
        names.sort();
        if dir.join("hooks.sock").exists() {
            let (status, _) = over(&dir.join("hooks.sock"), "/v1", None).await;
            assert_eq!(status, 200);
        }
        serving.abort();
        names
    }

    #[tokio::test]
    async fn serving_binds_the_hooks_socket_only_where_one_is_named() {
        let dir = tempfile::tempdir().unwrap();
        let dir = dir.path();
        let uid = own_uid(dir);
        let unnamed = served(dir, AppSocket::new(dir.join("app.sock"), uid)).await;
        assert_eq!(unnamed, ["app.sock"]);

        let dir = tempfile::tempdir().unwrap();
        let dir = dir.path();
        let socket = AppSocket::new(dir.join("app.sock"), uid).hooks(dir.join("hooks.sock"));
        assert_eq!(served(dir, socket).await, ["app.sock", "hooks.sock"]);
    }

    #[tokio::test]
    async fn a_hooks_socket_that_cannot_bind_fails_the_start() {
        let dir = tempfile::tempdir().unwrap();
        let dir = dir.path();
        let store = Store::open_in_memory(None).await.expect("store");
        let server = Server::new(store, Branding::unbranded(), "0.0.0", logs(&[]));
        let socket = AppSocket::new(dir.join("app.sock"), own_uid(dir))
            .hooks(dir.join("missing").join("hooks.sock"));
        let bootstrap = bootstrap_in(dir);
        let serving = server.serve(&bootstrap, socket, std::future::pending());
        let failed = tokio::time::timeout(WITHIN, serving)
            .await
            .expect("fails at once");
        assert!(
            matches!(&failed, Err(ServeError::Socket { path, .. }) if path.ends_with("hooks.sock")),
            "{failed:?}"
        );
    }
}
