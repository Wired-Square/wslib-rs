//! `Server::serve`: the app socket, the console's asserted caller, and
//! everything a proxied app does not have.

use std::os::unix::fs::MetadataExt;
use std::path::Path;

use axum::Router;
use axum::http::StatusCode;
use axum::routing::{get, post};
use chrono::{DateTime, Utc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use wslib_appliance_store::Store;
use wslib_appliance_types::console::{ConsoleIdentity, IDENTITY_HEADER};
use wslib_appliance_types::{Branding, Role};

use super::WITHIN;
use crate::testing::{Harness, HarnessBuilder, bootstrap_in};
use crate::{
    Admin, AppSocket, HostAdmin, Operator, Server, SessionAdmin, Unclaimed, Viewer,
    host_admin_only, reauthenticate,
};

fn console(role: Role) -> ConsoleIdentity {
    ConsoleIdentity {
        id: "c-17".to_string(),
        username: "ops".to_string(),
        role,
        reauthenticated_at: None,
    }
}

fn rungs() -> Router<crate::ApplianceState> {
    Router::new()
        .route("/viewer", get(|_: Viewer| async {}))
        .route("/operator", get(|_: Operator| async {}))
        .route("/admin", get(|_: Admin| async {}))
        .route("/session-admin", get(|_: SessionAdmin| async {}))
        .route("/hostadmin", get(|_: HostAdmin| async {}))
        .route(
            "/who",
            get(|Viewer(who): Viewer| async move {
                format!("{} {:?} {}", who.actor(), who.account_id(), who.is_host_admin())
            }),
        )
        .route("/unclaimed", get(|_: Unclaimed| async {}))
        .route(
            "/reauthenticated",
            post(
                |SessionAdmin(who): SessionAdmin,
                 axum::extract::State(app): axum::extract::State<crate::ApplianceState>| async move {
                    let reached = crate::Reached::default();
                    reauthenticate(&app, &who, &reached, Default::default(), "a test")
                        .await
                        .map(drop)
                },
            ),
        )
        .merge(host_admin_only(
            Router::new().route("/raised", get(|_: Viewer| async {})),
        ))
}

fn proxied() -> HarnessBuilder {
    Harness::builder().api(rungs()).route(
        "/outside",
        Router::new().route(
            "/who",
            get(|Viewer(who): Viewer| async move { who.actor().to_owned() }),
        ),
    )
}

const RUNGS: [&str; 5] = [
    "/api/viewer",
    "/api/operator",
    "/api/admin",
    "/api/session-admin",
    "/api/hostadmin",
];

#[tokio::test]
async fn without_the_consoles_marker_the_header_is_ignored() {
    let app = proxied().build().await;
    for path in RUNGS {
        let ignored = app
            .get(path)
            .header(IDENTITY_HEADER, &console(Role::Admin).to_string())
            .send()
            .await;
        assert_eq!(ignored.status(), StatusCode::UNAUTHORIZED, "{path}");
        let bare = app.get(path).on_app_socket().send().await;
        assert_eq!(bare.status(), StatusCode::UNAUTHORIZED, "{path}");
    }
}

#[tokio::test]
async fn an_asserted_caller_meets_the_ladder_and_never_reaches_host_admin() {
    let app = proxied().build().await;
    for (role, allowed) in [
        (Role::Viewer, 1),
        (Role::Operator, 2),
        (Role::Admin, 4),
        (Role::HostAdmin, 4),
    ] {
        for (i, path) in RUNGS.iter().enumerate() {
            let response = app.get(path).from_console(&console(role)).send().await;
            let expected = match i < allowed {
                true => StatusCode::OK,
                false => StatusCode::FORBIDDEN,
            };
            assert_eq!(response.status(), expected, "{role} at {path}");
        }
    }
    let who = app
        .get("/api/who")
        .from_console(&console(Role::HostAdmin))
        .send()
        .await;
    assert_eq!(
        crate::testing::body_text(who).await,
        r#"ops Some("console:c-17") false"#
    );
    let raised = app
        .get("/api/raised")
        .from_console(&console(Role::HostAdmin))
        .send()
        .await;
    assert_eq!(raised.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_proxied_app_never_offers_itself_unclaimed() {
    let app = proxied().build().await;
    assert_eq!(app.store().user_count().await.unwrap(), 0);
    let refused = app.get("/api/unclaimed").send().await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
}

async fn asserting(app: &Harness, value: &str) -> axum::response::Response {
    let request = app.get("/api/viewer").on_app_socket();
    request.header(IDENTITY_HEADER, value).send().await
}

#[tokio::test]
async fn a_malformed_header_is_a_bad_request_and_never_a_panic() {
    let app = proxied().build().await;
    for value in [
        "",
        "v2; id=a; user=a; role=admin",
        "v1; id=a; user=a; role=root",
        "v1; id=a; user=control-socket:root; role=admin",
        "v1; id=a; user=onboarding; role=admin",
        "v1; id=%FF; user=a; role=admin",
        "v1; id=a; user=a; role=admin; reauth=soon",
        "v1; id=a; user=é; role=admin",
    ] {
        let response = asserting(&app, value).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{value:?}");
        let body = crate::testing::body_text(response).await;
        assert!(!body.contains("control-socket"), "{body}");
    }
    let mut seed: u32 = 0x5eed;
    let alphabet: Vec<char> = (' '..='~').chain(['é', '\t', '%', '%', '%', '%']).collect();
    let prefixes = [
        "",
        "v1;",
        "v1; id=a; user=b; role=",
        "v1; role=admin; user=b; id=",
    ];
    for round in 0..800 {
        let mut value = String::from(prefixes[round % prefixes.len()]);
        for _ in 0..(round % 40) {
            seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            value.push(alphabet[(seed >> 16) as usize % alphabet.len()]);
        }
        let value = value.trim_matches([' ', '\t']);
        let response = asserting(&app, value).await;
        assert!(
            [
                StatusCode::OK,
                StatusCode::BAD_REQUEST,
                StatusCode::UNAUTHORIZED
            ]
            .contains(&response.status()),
            "{value:?}: {}",
            response.status()
        );
    }
}

#[tokio::test]
async fn reauth_stands_in_for_the_password_within_the_window_alone() {
    let app = proxied().build().await;
    let at = |minutes: i64| Some(Utc::now() + chrono::Duration::minutes(minutes));
    for (reauthenticated_at, status) in [
        (at(0), StatusCode::OK),
        (at(-4), StatusCode::OK),
        (at(-6), StatusCode::FORBIDDEN),
        (at(10), StatusCode::FORBIDDEN),
        (None::<DateTime<Utc>>, StatusCode::FORBIDDEN),
    ] {
        let who = ConsoleIdentity {
            reauthenticated_at,
            ..console(Role::Admin)
        };
        let response = app
            .post("/api/reauthenticated")
            .from_console(&who)
            .send()
            .await;
        assert_eq!(response.status(), status, "{reauthenticated_at:?}");
    }
}

#[tokio::test]
async fn every_built_in_route_has_its_proxied_stance() {
    let app = proxied().build().await;
    let admin = console(Role::Admin);
    for (method, path, status) in [
        ("GET", "/healthz", StatusCode::OK),
        ("GET", "/api/branding", StatusCode::OK),
        ("GET", "/api/audit", StatusCode::OK),
        ("GET", "/api/about", StatusCode::OK),
        ("GET", "/api/logs", StatusCode::OK),
        ("GET", "/api/tls/pins", StatusCode::OK),
        ("GET", "/api/tls/cas", StatusCode::OK),
        ("GET", "/api/session", StatusCode::OK),
        ("POST", "/api/session", StatusCode::METHOD_NOT_ALLOWED),
        ("DELETE", "/api/session", StatusCode::METHOD_NOT_ALLOWED),
        ("PUT", "/api/session/password", StatusCode::NOT_FOUND),
        ("POST", "/api/onboarding", StatusCode::NOT_FOUND),
        ("GET", "/api/users", StatusCode::NOT_FOUND),
    ] {
        let response = app.request(method, path).from_console(&admin).send().await;
        assert_eq!(response.status(), status, "{method} {path}");
    }
    for public in ["/healthz", "/api/branding"] {
        assert_eq!(app.get(public).send().await.status(), StatusCode::OK);
    }
    for guarded in [
        "/api/audit",
        "/api/about",
        "/api/logs",
        "/api/tls/pins",
        "/api/session",
    ] {
        let response = app.get(guarded).send().await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{guarded}");
    }
}

#[tokio::test]
async fn the_session_answers_the_consoles_account_at_the_role_that_applies() {
    let app = proxied().build().await;
    for (role, held) in [
        (Role::Viewer, "viewer"),
        (Role::Admin, "admin"),
        (Role::HostAdmin, "admin"),
    ] {
        let response = app
            .get("/api/session")
            .from_console(&console(role))
            .send()
            .await;
        assert_eq!(response.status(), StatusCode::OK, "{role}");
        assert_eq!(
            crate::testing::body_json(response).await,
            serde_json::json!({ "id": "c-17", "username": "ops", "role": held })
        );
    }
}

#[tokio::test]
async fn a_resolvers_harness_keeps_host_admin() {
    struct Owner;
    impl crate::ResolveCaller for Owner {
        async fn resolve(
            &self,
            _: &axum::http::request::Parts,
        ) -> Result<Option<crate::Principal>, crate::ApiError> {
            Ok(Some(crate::Principal {
                id: "owner".to_string(),
                username: "owner".to_string(),
                role: Role::HostAdmin,
                reauthenticated_at: None,
            }))
        }
    }
    let app = Harness::builder()
        .resolver(Owner)
        .api(rungs())
        .build()
        .await;
    let response = app.get("/api/hostadmin").send().await;
    assert_eq!(response.status(), StatusCode::OK);
}

pub(super) fn own_uid(dir: &Path) -> u32 {
    std::fs::metadata(dir).expect("the directory").uid()
}

pub(super) async fn over(
    socket: &Path,
    path: &str,
    identity: Option<&ConsoleIdentity>,
) -> (u16, String) {
    tokio::time::timeout(WITHIN, async {
        let mut stream = tokio::net::UnixStream::connect(socket)
            .await
            .expect("connects");
        let header = identity
            .map(|who| format!("{IDENTITY_HEADER}: {who}\r\n"))
            .unwrap_or_default();
        let request =
            format!("GET {path} HTTP/1.1\r\nHost: app\r\n{header}Connection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).await.expect("writes");
        let mut answer = String::new();
        stream.read_to_string(&mut answer).await.expect("reads");
        let status = answer[9..12].parse().expect("a status");
        let body = answer
            .split_once("\r\n\r\n")
            .map(|(_, body)| body.to_string());
        (status, body.unwrap_or_default())
    })
    .await
    .expect("the app socket answers in time")
}

#[tokio::test]
async fn over_the_socket_the_consoles_uid_is_heard_and_any_other_is_nobody() {
    let admin = console(Role::Admin);
    let under = || proxied().base_path("/apps/x/".parse().unwrap()).build();
    let callers = [
        "/apps/x/api/who",
        "/apps/x/outside/who",
        "/apps/x/api/session",
    ];
    let heard = under().await;
    let uid = own_uid(heard.dir());
    let socket = heard.serve_app_socket(uid).await;
    for path in callers {
        let (status, body) = over(&socket, path, Some(&admin)).await;
        assert_eq!(status, 200, "{path}");
        assert!(body.contains("ops"), "{path}: {body}");
    }

    let other = under().await;
    let socket = other.serve_app_socket(uid.wrapping_add(1)).await;
    for path in callers {
        assert_eq!(over(&socket, path, Some(&admin)).await.0, 401, "{path}");
    }
    let (status, body) = over(&socket, "/apps/x/healthz", None).await;
    assert_eq!((status, body.as_str()), (200, r#"{"status":"ok"}"#));
}

#[tokio::test]
async fn serving_binds_no_control_socket() {
    let dir = tempfile::tempdir().unwrap();
    let mut bootstrap = bootstrap_in(dir.path());
    bootstrap.socket = dir.path().join("control.sock");
    let socket = dir.path().join("app.sock");

    let store = Store::open_in_memory(None).await.expect("store");
    let server = Server::new(store, Branding::unbranded(), "0.0.0", crate::logs(&[]));
    let serving = tokio::spawn({
        let (bootstrap, socket) = (bootstrap.clone(), socket.clone());
        let uid = own_uid(dir.path());
        let socket = AppSocket::new(socket, uid);
        async move {
            server
                .serve(&bootstrap, socket, std::future::pending())
                .await
        }
    });
    tokio::time::timeout(WITHIN, async {
        while !socket.exists() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the app socket binds");
    assert_eq!(over(&socket, "/healthz", None).await.0, 200);
    assert!(!bootstrap.socket.exists(), "a control socket was made");
    serving.abort();
}

/// `GET /healthz` on a new connection: its status, or `None` when the
/// connection is closed unanswered.
async fn health(socket: &Path) -> Option<u16> {
    tokio::time::timeout(WITHIN, async {
        let mut stream = tokio::net::UnixStream::connect(socket).await.ok()?;
        let request = "GET /healthz HTTP/1.1\r\nHost: app\r\nConnection: close\r\n\r\n";
        stream.write_all(request.as_bytes()).await.ok()?;
        let mut answer = String::new();
        stream.read_to_string(&mut answer).await.ok()?;
        answer.get(9..12)?.parse().ok()
    })
    .await
    .expect("the app socket answers or closes in time")
}

#[tokio::test]
async fn anybody_but_the_console_holds_at_most_four_connections() {
    let app = proxied().build().await;
    let uid = own_uid(app.dir());
    let socket = app.serve_app_socket(uid.wrapping_add(1)).await;
    let mut held = Vec::new();
    for _ in 0..4 {
        held.push(tokio::net::UnixStream::connect(&socket).await.unwrap());
    }
    assert_eq!(health(&socket).await, None, "a fifth is closed");
    held.pop();
    let served = tokio::time::timeout(WITHIN, async {
        while health(&socket).await != Some(200) {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    });
    served.await.expect("a slot frees when a connection ends");

    let console = proxied().build().await;
    let socket = console.serve_app_socket(uid).await;
    let mut held = Vec::new();
    for _ in 0..8 {
        held.push(tokio::net::UnixStream::connect(&socket).await.unwrap());
    }
    assert_eq!(
        health(&socket).await,
        Some(200),
        "the console is not held to it"
    );
}

#[tokio::test]
async fn the_overflow_uid_is_refused_as_the_console() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open_in_memory(None).await.expect("store");
    let server = Server::new(store, Branding::unbranded(), "0.0.0", crate::logs(&[]));
    let socket = dir.path().join("app.sock");
    let refused = tokio::time::timeout(
        WITHIN,
        server.serve(
            &bootstrap_in(dir.path()),
            AppSocket::new(&socket, 65534),
            std::future::pending(),
        ),
    )
    .await
    .expect("refused at once");
    assert!(
        matches!(&refused, Err(crate::ServeError::Socket { because, .. })
            if because.contains("userns-remap")),
        "{refused:?}"
    );
    assert!(!socket.exists());
}

#[tokio::test]
async fn an_abstract_or_empty_path_is_refused() {
    let store = Store::open_in_memory(None).await.expect("store");
    let dir = tempfile::tempdir().unwrap();
    for path in ["\0hidden", ""] {
        let server = Server::new(
            store.clone(),
            Branding::unbranded(),
            "0.0.0",
            crate::logs(&[]),
        );
        let refused = tokio::time::timeout(
            WITHIN,
            server.serve(
                &bootstrap_in(dir.path()),
                AppSocket::new(path, 0),
                std::future::pending(),
            ),
        )
        .await
        .expect("refused at once");
        assert!(
            matches!(&refused, Err(crate::ServeError::Socket { because, .. })
                if because.contains("abstract namespace")),
            "{path:?}: {refused:?}"
        );
    }
}
