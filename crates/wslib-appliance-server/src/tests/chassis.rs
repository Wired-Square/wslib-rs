//! The assembled surface: the mounts, the fallbacks, the bundle and the
//! compression over it, through the harness.

#[cfg(unix)]
use std::sync::Arc;
#[cfg(unix)]
use std::time::Duration;

use axum::Router;
use axum::extract::{FromRef, State};
use axum::http::{StatusCode, header};
use axum::routing::get;
use tempfile::TempDir;
#[cfg(unix)]
use wslib_appliance_core::backend;
use wslib_appliance_store::Store;
use wslib_appliance_types::Branding;

use crate::testing::{
    ENCODERS, Harness, body_bytes, body_json, console, product as product_of, varies,
};

use crate::{
    Admin, ApplianceState, Identity, Mount, RequestBase, Server, Uncompressed, Viewer, logs,
};

#[cfg(unix)]
#[tokio::test]
async fn a_registered_task_runs_against_the_state_and_ends_when_serving_does() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let dir = TempDir::new().unwrap();
    let socket = crate::serve::unbindable_socket(&dir);

    let store = Store::open_in_memory(None).await.expect("store");
    let stopped = Arc::new(AtomicBool::new(false));
    let seen = stopped.clone();
    let outcome = Server::new(
        store,
        Branding::unbranded(),
        crate::testing::Harness::VERSION,
        logs(&[]),
    )
    .task(move |state, stop| async move {
        assert_eq!(product_of(&state), Branding::unbranded().app_name);
        stop.cancelled().await;
        seen.store(true, Ordering::SeqCst);
    })
    .serve(
        &crate::testing::bootstrap_in(dir.path()),
        socket,
        std::future::pending(),
    )
    .await;

    assert!(outcome.is_err(), "{outcome:?}");
    assert!(
        stopped.load(Ordering::SeqCst),
        "the task saw its stop handle fire and was waited for"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn winding_down_waits_for_work_run_to_completion_before_the_audit_log_closes() {
    let store = Store::open_in_memory(None).await.expect("store");
    let built = Server::new(
        store.clone(),
        Branding::unbranded(),
        Harness::VERSION,
        logs(&[]),
    )
    .build(
        Arc::new(backend::no_tls()),
        wslib_appliance_config::BasePath::default(),
        crate::Front::Console,
    )
    .await
    .expect("built");
    let release = Arc::new(tokio::sync::Notify::new());
    let work = backend::to_completion(&built.state, {
        let (state, release) = (built.state.clone(), release.clone());
        async move {
            release.notified().await;
            crate::audit!(&state, &Identity::Local, "finished after the stop").await;
        }
    });

    let mut winding =
        tokio::spawn(async move { backend::wind_down(&built.state, built.tasks).await });
    let early = tokio::time::timeout(Duration::from_millis(300), &mut winding).await;
    assert!(early.is_err(), "the wind-down waited");
    release.notify_one();
    tokio::time::timeout(Duration::from_secs(5), winding)
        .await
        .expect("wound down once the work ended")
        .unwrap();
    work.await.unwrap();

    let rows = store.audit(10, None).await.unwrap().items;
    assert!(
        rows.iter()
            .any(|row| row.message == "finished after the stop"),
        "{rows:?}"
    );
}

#[tokio::test]
async fn a_products_state_resolves_both_halves_for_the_console_and_a_socket() {
    #[derive(Clone, FromRef)]
    struct Product {
        chassis: ApplianceState,
        poller: Poller,
    }

    #[derive(Clone)]
    struct Poller(&'static str);

    async fn which(
        Admin(who): Admin,
        State(Poller(poller)): State<Poller>,
        State(app): State<ApplianceState>,
    ) -> String {
        format!("{poller} for {} on {}", who.actor(), product_of(&app))
    }

    fn chassis_only<S>() -> Router<S>
    where
        ApplianceState: FromRef<S>,
        S: Clone + Send + Sync + 'static,
    {
        async fn product(Viewer(_): Viewer, State(app): State<ApplianceState>) -> String {
            product_of(&app).to_string()
        }
        Router::new().route("/product", get(product))
    }

    let app = Harness::builder()
        .api(Mount::new(
            Router::new()
                .route("/which", get(which))
                .merge(chassis_only()),
            |chassis| Product {
                chassis,
                poller: Poller("the poller"),
            },
        ))
        .build()
        .await;
    let admin = console("admin", wslib_appliance_types::Role::Admin);

    let response = app.get("/api/which").from_console(&admin).send().await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        String::from_utf8_lossy(&body_bytes(response).await),
        "the poller for admin on Widget Monitor"
    );
    let local = app.get("/api/which").local().send().await;
    assert_eq!(
        String::from_utf8_lossy(&body_bytes(local).await),
        "the poller for control-socket on Widget Monitor",
        "the socket's marker is layered outside the mount's state"
    );
    let response = app.get("/api/product").from_console(&admin).send().await;
    assert_eq!(
        String::from_utf8_lossy(&body_bytes(response).await),
        "Widget Monitor"
    );
}

/// Real files: the `/api` rule has to survive a fallback that answers.
fn bundle() -> TempDir {
    let dir = TempDir::new().unwrap();
    std::fs::write(
        dir.path().join("index.html"),
        "<!doctype html><title>the bundle</title>",
    )
    .expect("write index.html");
    std::fs::create_dir(dir.path().join("assets")).expect("make assets/");
    std::fs::write(dir.path().join("assets/index-abc123.js"), "export {};")
        .expect("write an asset");
    dir
}

#[tokio::test]
async fn a_bundle_with_no_index_html_answers_its_page_404_and_still_serves_its_assets() {
    let bundle = bundle();
    std::fs::remove_file(bundle.path().join("index.html")).expect("remove index.html");
    let app = Harness::builder().ui(bundle.path()).build().await;

    for path in ["/", "/index.html", "/settings"] {
        let response = app.get(path).send().await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            "no-store",
            "{path}"
        );
        let body = body_json(response).await;
        assert_eq!(body["error"], "the bundle has no index.html", "{path}");
    }
    let asset = app.get("/assets/index-abc123.js").send().await;
    assert_eq!(asset.status(), StatusCode::OK);
}

#[tokio::test]
async fn a_mistyped_api_path_answers_json_rather_than_the_browser_bundle() {
    let app = Harness::new().await;
    for path in ["/api/nonsense", "/api/", "/api/users/x/y/z"] {
        let response = app.get(path).send().await;
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "{path} must not be answered by the SPA"
        );

        let body = body_json(response).await;
        assert!(
            body["error"].as_str().is_some_and(|e| e.contains(path)),
            "{path}: {body}"
        );
    }
}

#[tokio::test]
async fn a_route_outside_api_is_served_and_no_miss_under_it_or_apps_is_the_page() {
    let bundle = bundle();
    let app = Harness::builder()
        .ui(bundle.path())
        .route(
            "/console",
            Router::new().route("/ok", get(|_: Viewer| async { "ok" })),
        )
        .build()
        .await;
    let admin = console("admin", wslib_appliance_types::Role::Admin);

    let ok = app.get("/console/ok").from_console(&admin).send().await;
    assert_eq!(ok.status(), StatusCode::OK);
    assert_eq!(body_bytes(ok).await, "ok".as_bytes());
    assert_eq!(
        app.get("/console/ok").send().await.status(),
        StatusCode::UNAUTHORIZED,
        "a route outside /api names its rung like any other"
    );
    assert_eq!(
        app.request("PUT", "/console/ok").send().await.status(),
        StatusCode::METHOD_NOT_ALLOWED
    );
    for path in [
        "/console/nope",
        "/console",
        "/apps",
        "/apps/x",
        "/apps/x/y",
        "/%61pps/x",
    ] {
        let response = app.get(path).send().await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        assert!(body_json(response).await["error"].is_string(), "{path}");
    }
    assert_eq!(
        app.get("/console/ok").local().send().await.status(),
        StatusCode::NOT_FOUND,
        "the socket serves /api alone"
    );
    let page = app.get("/settings").send().await;
    assert_eq!(page.status(), StatusCode::OK);
}

#[tokio::test]
async fn a_route_prefix_is_one_segment_and_never_one_already_served() {
    let store = Store::open_in_memory(None).await.expect("store");
    for prefix in [
        "/api",
        "/assets",
        "/healthz",
        "/index.html",
        "/a/b",
        "console",
        "/",
        "/..",
        "/a b",
    ] {
        let server = Server::new(store.clone(), Branding::unbranded(), "0", logs(&[]));
        let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            server.route(prefix, Router::<ApplianceState>::new())
        }));
        assert!(refused.is_err(), "{prefix:?}");
    }
}

#[tokio::test]
async fn under_a_base_path_everything_the_app_socket_serves_is_beneath_it() {
    let bundle = bundle();
    let app = Harness::builder()
        .ui(bundle.path())
        .base_path("/apps/hello/".parse().unwrap())
        .route(
            "/console",
            Router::new().route("/ok", get(|| async { "ok" })),
        )
        .build()
        .await;

    for path in ["/apps/hello", "/apps/hello/", "/apps/hello/settings"] {
        let page = app.get(path).send().await;
        assert_eq!(page.status(), StatusCode::OK, "{path}");
        let page = String::from_utf8(body_bytes(page).await.to_vec()).unwrap();
        assert!(
            page.contains("<base href=\"/apps/hello/\">"),
            "{path}: {page}"
        );
    }
    for path in [
        "/apps/hello/api/branding",
        "/apps/hello/healthz",
        "/apps/hello/assets/index-abc123.js",
        "/apps/hello/console/ok",
    ] {
        assert_eq!(
            app.get(path).send().await.status(),
            StatusCode::OK,
            "{path}"
        );
    }
    for path in ["/apps/hello/assets", "/apps/hello/assets/"] {
        let response = app.get(path).send().await;
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "{path}: a redirect from a directory drops the base"
        );
        assert!(response.headers().get(header::LOCATION).is_none(), "{path}");
    }
    for path in [
        "/api/branding",
        "/settings",
        "/",
        "/apps/hello/api/nope",
        "/apps/other/",
    ] {
        assert_eq!(
            app.get(path).send().await.status(),
            StatusCode::NOT_FOUND,
            "{path}"
        );
    }
    assert_eq!(
        app.get("/api/branding").local().send().await.status(),
        StatusCode::OK,
        "the socket is not under the base"
    );
}

#[tokio::test]
async fn a_root_page_answers_the_base_alone_on_a_products_state_at_its_rung() {
    #[derive(Clone, FromRef)]
    struct Product {
        chassis: ApplianceState,
        greeting: &'static str,
    }

    async fn page(
        Viewer(who): Viewer,
        State(greeting): State<&'static str>,
        RequestBase(base): RequestBase,
    ) -> String {
        format!("{greeting} {} under {}", who.actor(), base.as_str())
    }

    let app = Harness::builder()
        .base_path("/apps/hello/".parse().unwrap())
        .root(Mount::new(
            Router::new()
                .route("/", get(page))
                .route("/elsewhere", get(|| async { "shadowed" })),
            |chassis| Product {
                chassis,
                greeting: "hello",
            },
        ))
        .build()
        .await;
    let viewer = console("viewer", wslib_appliance_types::Role::Viewer);

    for path in ["/apps/hello", "/apps/hello/"] {
        let response = app.get(path).from_console(&viewer).send().await;
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        assert_eq!(
            body_bytes(response).await,
            "hello viewer under /apps/hello/".as_bytes()
        );
    }
    assert_eq!(
        app.get("/apps/hello/").send().await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        app.request("POST", "/apps/hello/")
            .from_console(&viewer)
            .send()
            .await
            .status(),
        StatusCode::METHOD_NOT_ALLOWED
    );
    for path in [
        "/apps/hello/elsewhere",
        "/apps/hello/api/",
        "/",
        "/apps/hello//",
    ] {
        let response = app.get(path).from_console(&viewer).send().await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        assert!(body_json(response).await["error"].is_string(), "{path}");
    }
    assert_eq!(
        app.get("/apps/hello/api/branding").send().await.status(),
        StatusCode::OK
    );
    assert_eq!(
        app.get("/").local().send().await.status(),
        StatusCode::NOT_FOUND,
        "the socket serves /api alone"
    );
}

#[tokio::test]
async fn a_root_mount_without_a_root_route_answers_the_json_404() {
    let app = Harness::builder()
        .base_path("/apps/hello/".parse().unwrap())
        .root(Router::new().route("/elsewhere", get(|| async { "shadowed" })))
        .build()
        .await;
    let response = app.get("/apps/hello/").send().await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(body_json(response).await["error"].is_string());
}

#[tokio::test]
#[should_panic(expected = "a root page and a UI directory both answer `/`")]
async fn a_root_page_beside_a_ui_directory_is_refused() {
    let bundle = bundle();
    Harness::builder()
        .ui(bundle.path())
        .root(Router::new().route("/", get(|| async { "mine" })))
        .build()
        .await;
}

/// `/healthz` is on the outer router, so it goes red if the fallback moves
/// under the nest.
#[tokio::test]
async fn a_wrong_method_is_the_one_error_body_and_keeps_allow() {
    let app = Harness::new().await;

    for path in ["/api/session", "/api/audit", "/healthz"] {
        let response = app.request("PATCH", path).send().await;
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED, "{path}");

        assert!(
            response
                .headers()
                .get(header::ALLOW)
                .is_some_and(|a| !a.is_empty()),
            "{path} must still say which methods it takes"
        );
        let body = body_json(response).await;
        let error = body["error"].as_str().unwrap_or_default();
        assert!(
            error.contains("PATCH") && error.contains(path),
            "{path} must name the method it refused and where: {body}"
        );
    }
}

const API_SHAPES: [&str; 12] = [
    "/api",
    "/api/",
    "/api/nonsense",
    "//api/nonsense",
    "/api%2Fnonsense",
    "/%61pi/nonsense",
    "/%2Fapi/nonsense",
    "/./api/nonsense",
    "/x/../api/nonsense",
    "/ui/../api/branding",
    "/x/%2e%2e/api/nonsense",
    "/apiary/../api/nonsense",
];

#[tokio::test]
async fn a_hashed_asset_answered_304_keeps_the_cache_control_its_200_carries() {
    let bundle = bundle();
    let app = Harness::builder().ui(bundle.path()).build().await;
    let asset = app.get("/assets/index-abc123.js").send().await;
    let modified = asset.headers()[header::LAST_MODIFIED]
        .to_str()
        .expect("ascii")
        .to_owned();

    let unchanged = app
        .get("/assets/index-abc123.js")
        .header("if-modified-since", &modified)
        .send()
        .await;
    assert_eq!(unchanged.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(
        unchanged
            .headers()
            .get(header::CACHE_CONTROL)
            .map(|v| v.as_bytes()),
        Some(&b"public, max-age=31536000, immutable"[..])
    );
}

#[tokio::test]
async fn the_browser_bundle_answers_a_page_route_and_never_an_api_one() {
    let bundle = bundle();
    let app = Harness::builder().ui(bundle.path()).build().await;

    let page = app.get("/settings").send().await;
    assert_eq!(page.status(), StatusCode::OK);
    assert_eq!(
        page.headers()
            .get(header::CACHE_CONTROL)
            .map(|v| v.as_bytes()),
        Some(&b"no-store"[..])
    );
    assert!(
        String::from_utf8_lossy(&body_bytes(page).await).contains("the bundle"),
        "a page route must be answered by index.html"
    );

    let asset = app.get("/assets/index-abc123.js").send().await;
    assert_eq!(asset.status(), StatusCode::OK);
    assert_eq!(
        asset
            .headers()
            .get(header::CACHE_CONTROL)
            .map(|v| v.as_bytes()),
        Some(&b"public, max-age=31536000, immutable"[..])
    );
    let gone = app.get("/assets/index-old.js").send().await;
    assert_eq!(gone.status(), StatusCode::NOT_FOUND);
    assert_eq!(gone.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(
        body_json(gone).await["error"],
        "no such file: /assets/index-old.js"
    );

    for path in API_SHAPES {
        let response = app.get(path).send().await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        assert!(
            body_json(response).await["error"].is_string(),
            "{path} must answer JSON, not the bundle"
        );
    }

    for path in [
        "/apiary",
        "/api-docs",
        "/x/./settings",
        "/settings/../about",
    ] {
        let response = app.get(path).send().await;
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        assert!(
            String::from_utf8_lossy(&body_bytes(response).await).contains("the bundle"),
            "{path} is a page route and must be answered by index.html"
        );
    }
}

fn gunzip(body: &[u8]) -> Vec<u8> {
    use std::io::Read;
    let mut plain = Vec::new();
    flate2::read::GzDecoder::new(body)
        .read_to_end(&mut plain)
        .expect("a gzip body");
    plain
}

#[tokio::test]
async fn the_surface_is_gzipped_when_the_client_asks_and_reads_back_the_same() {
    let bundle = bundle();
    let app = Harness::builder().ui(bundle.path()).build().await;

    for path in ["/api/branding", "/"] {
        let plain = app.get(path).send().await;
        assert!(
            plain.headers().get(header::CONTENT_ENCODING).is_none(),
            "{path}: nothing asked, nothing encoded"
        );
        let plain = body_bytes(plain).await;
        assert!(plain.len() >= 32, "{path}: under the floor, so not a test");

        let gz = app.get(path).header("accept-encoding", "gzip").send().await;
        assert_eq!(gz.status(), StatusCode::OK, "{path}");
        assert_eq!(gz.headers()[header::CONTENT_ENCODING], "gzip", "{path}");
        assert!(
            gz.headers().get(header::CONTENT_LENGTH).is_none(),
            "{path}: a length the encoder cannot know must not be claimed"
        );
        assert_eq!(
            varies(&gz),
            [b"accept-encoding"],
            "{path}: a cache must key on what was asked for, once"
        );
        let gz = body_bytes(gz).await;
        assert_eq!(gz[8], 4, "{path}: XFL 4, the fastest level");
        assert_eq!(gunzip(&gz), plain, "{path}");
    }
}

fn gzip(plain: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    encoder.write_all(plain).expect("gzip into a Vec");
    encoder.finish().expect("gzip into a Vec")
}

/// Each `.gz` holds text its plain file does not, so a test can tell which was sent.
fn precompressed_bundle() -> TempDir {
    let dir = bundle();
    for (name, text) in [
        (
            "index.html.gz",
            "<!doctype html><title>the stored page</title>",
        ),
        ("assets/index-abc123.js.gz", "export const stored = true;"),
    ] {
        std::fs::write(dir.path().join(name), gzip(text.as_bytes())).expect("write a .gz");
    }
    dir
}

#[tokio::test]
async fn a_stored_gz_is_sent_as_it_is_to_a_client_that_takes_gzip() {
    let bundle = precompressed_bundle();
    let app = Harness::builder().ui(bundle.path()).build().await;

    for (path, file, cache) in [(
        "/assets/index-abc123.js",
        "assets/index-abc123.js",
        "public, max-age=31536000, immutable",
    )] {
        let stored = std::fs::read(bundle.path().join(format!("{file}.gz"))).expect("read the .gz");
        let gz = app.get(path).header("accept-encoding", "gzip").send().await;
        assert_eq!(gz.status(), StatusCode::OK, "{path}");
        assert_eq!(gz.headers()[header::CONTENT_ENCODING], "gzip", "{path}");
        assert_eq!(
            gz.headers()[header::CONTENT_LENGTH],
            stored.len().to_string().as_str(),
            "{path}: the stored copy's own length"
        );
        assert_eq!(gz.headers()[header::CACHE_CONTROL], cache, "{path}");
        assert_eq!(varies(&gz), [b"accept-encoding"], "{path}");
        let content_type = gz.headers()[header::CONTENT_TYPE].clone();
        assert_eq!(
            body_bytes(gz).await,
            stored,
            "{path}: the stored bytes, not the layer encoding them again"
        );

        let plain = app.get(path).send().await;
        assert_eq!(plain.status(), StatusCode::OK, "{path}");
        assert!(plain.headers().get(header::CONTENT_ENCODING).is_none());
        assert_eq!(
            plain.headers()[header::CONTENT_TYPE],
            content_type,
            "{path}"
        );
        assert_eq!(
            varies(&plain),
            [b"accept-encoding"],
            "{path}: a cache must not hand this to a client that takes gzip"
        );
        assert_eq!(
            body_bytes(plain).await,
            std::fs::read(bundle.path().join(file)).expect("read the plain file"),
            "{path}"
        );
    }
}

fn long_page(base: &str) -> String {
    let text = "<p>the bundle</p>".repeat(64);
    format!("<!doctype html>{base}<title>the bundle</title>{text}")
}

fn long_page_bundle() -> TempDir {
    let dir = precompressed_bundle();
    std::fs::write(dir.path().join("index.html"), long_page("")).expect("write index.html");
    dir
}

#[tokio::test]
async fn the_page_carries_the_base_and_its_gzip_is_made_once_not_read_from_disk() {
    let bundle = long_page_bundle();
    let app = Harness::builder().ui(bundle.path()).build().await;
    let page = long_page("<base href=\"/\">");

    for path in ["/", "/index.html", "/settings"] {
        let gz = app.get(path).header("accept-encoding", "gzip").send().await;
        assert_eq!(gz.status(), StatusCode::OK, "{path}");
        assert_eq!(gz.headers()[header::CONTENT_ENCODING], "gzip", "{path}");
        assert_eq!(gz.headers()[header::CACHE_CONTROL], "no-store", "{path}");
        assert_eq!(varies(&gz), [b"accept-encoding"], "{path}");
        let gz = body_bytes(gz).await;
        assert_eq!(gz[8], 2, "{path}: XFL 2, the best level, not the layer's");
        assert_eq!(gunzip(&gz), page.as_bytes(), "{path}");

        let plain = app.get(path).send().await;
        assert!(plain.headers().get(header::CONTENT_ENCODING).is_none());
        assert_eq!(
            plain.headers()[header::CONTENT_TYPE],
            "text/html; charset=utf-8"
        );
        assert_eq!(body_bytes(plain).await, page.as_bytes(), "{path}");
    }
}

#[tokio::test]
async fn x_gzip_or_a_star_takes_the_pages_stored_gzip_and_a_q_of_0_or_nonsense_refuses_it() {
    let bundle = long_page_bundle();
    let app = Harness::builder().ui(bundle.path()).build().await;
    let page = long_page("<base href=\"/\">");

    for accepted in ["x-gzip", "*"] {
        let gz = app
            .get("/")
            .header("accept-encoding", accepted)
            .send()
            .await;
        assert_eq!(gz.headers()[header::CONTENT_ENCODING], "gzip", "{accepted}");
        let gz = body_bytes(gz).await;
        assert_eq!(gz[8], 2, "{accepted}: the stored copy, not the layer's");
        assert_eq!(gunzip(&gz), page.as_bytes(), "{accepted}");
    }
    for refused in ["gzip;q=0, *", "gzip;q=nonsense"] {
        let plain = app.get("/").header("accept-encoding", refused).send().await;
        assert!(
            plain.headers().get(header::CONTENT_ENCODING).is_none(),
            "{refused}"
        );
        assert_eq!(varies(&plain), [b"accept-encoding"], "{refused}");
        assert_eq!(body_bytes(plain).await, page.as_bytes(), "{refused}");
    }
}

#[tokio::test]
async fn a_gz_asked_for_by_name_is_that_file() {
    let bundle = precompressed_bundle();
    let app = Harness::builder().ui(bundle.path()).build().await;

    for name in ["index.html.gz", "assets/index-abc123.js.gz"] {
        let stored = std::fs::read(bundle.path().join(name)).expect("read the .gz");
        for accept in ["identity", "gzip"] {
            let response = app
                .get(&format!("/{name}"))
                .header("accept-encoding", accept)
                .send()
                .await;
            assert_eq!(response.status(), StatusCode::OK, "{name}");
            assert_eq!(
                response.headers()[header::CONTENT_TYPE],
                "application/gzip",
                "{name}"
            );
            assert!(
                response.headers().get(header::CONTENT_ENCODING).is_none(),
                "{name}, {accept}: gzip is not gzipped again"
            );
            assert_eq!(body_bytes(response).await, stored, "{name}");
        }
    }
}

#[tokio::test]
async fn a_stored_copy_answers_head_and_a_range_is_of_the_plain_file() {
    let bundle = precompressed_bundle();
    let app = Harness::builder().ui(bundle.path()).build().await;
    let stored =
        std::fs::read(bundle.path().join("assets/index-abc123.js.gz")).expect("read the .gz");

    let head = app
        .request("HEAD", "/assets/index-abc123.js")
        .header("accept-encoding", "x-gzip")
        .send()
        .await;
    assert_eq!(head.status(), StatusCode::OK);
    assert_eq!(head.headers()[header::CONTENT_ENCODING], "gzip");
    assert_eq!(
        head.headers()[header::CONTENT_LENGTH],
        stored.len().to_string().as_str()
    );

    let plain = std::fs::read(bundle.path().join("assets/index-abc123.js")).expect("read the file");
    let range = app
        .get("/assets/index-abc123.js")
        .header("accept-encoding", "gzip")
        .header("range", "bytes=0-5")
        .send()
        .await;
    assert_eq!(range.status(), StatusCode::PARTIAL_CONTENT);
    assert!(range.headers().get(header::CONTENT_ENCODING).is_none());
    assert_eq!(
        range.headers()[header::CONTENT_RANGE],
        format!("bytes 0-5/{}", plain.len()).as_str(),
        "a range of the plain file"
    );
    assert_eq!(body_bytes(range).await, plain[..6]);
}

#[tokio::test]
async fn a_stored_copy_is_sent_past_the_cap_and_holds_no_encoder() {
    let bundle = precompressed_bundle();
    let app = Harness::builder().ui(bundle.path()).build().await;
    let gzipped = |path: &'static str| app.get(path).header("accept-encoding", "gzip").send();

    let mut encoding = Vec::new();
    for _ in 0..ENCODERS {
        encoding.push(gzipped("/api/branding").await);
    }
    assert!(
        gzipped("/api/branding")
            .await
            .headers()
            .get(header::CONTENT_ENCODING)
            .is_none(),
        "every encoder is held"
    );
    assert_eq!(
        gzipped("/assets/index-abc123.js").await.headers()[header::CONTENT_ENCODING],
        "gzip",
        "a stored copy needs none"
    );
    drop(encoding);

    let mut held = Vec::new();
    for _ in 0..=ENCODERS {
        let asset = app
            .get("/assets/index-abc123.js")
            .header("accept-encoding", "gzip")
            .send()
            .await;
        assert_eq!(asset.headers()[header::CONTENT_ENCODING], "gzip");
        held.push(asset);
    }
    let api = app
        .get("/api/branding")
        .header("accept-encoding", "gzip")
        .send()
        .await;
    assert_eq!(
        api.headers()[header::CONTENT_ENCODING],
        "gzip",
        "past the cap in stored copies, an encoder is still free"
    );
}

#[tokio::test]
async fn a_stored_gz_answers_no_api_path() {
    let bundle = precompressed_bundle();
    let app = Harness::builder().ui(bundle.path()).build().await;

    for path in API_SHAPES {
        let response = app.get(path).header("accept-encoding", "gzip").send().await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "application/json",
            "{path}"
        );
    }
}

/// The cap is a no-op if the two layers are registered the other way round.
#[tokio::test]
async fn the_encoder_cap_holds_on_the_surface_the_product_serves() {
    let app = Harness::new().await;
    let gzipped = || async {
        app.get("/api/branding")
            .header("accept-encoding", "gzip")
            .send()
            .await
    };

    let mut held = Vec::new();
    for _ in 0..ENCODERS {
        let gz = gzipped().await;
        assert_eq!(gz.headers()[header::CONTENT_ENCODING], "gzip");
        held.push(gz);
    }

    let past = gzipped().await;
    assert!(
        past.headers().get(header::CONTENT_ENCODING).is_none(),
        "past the cap the surface has to serve plain, not encode anyway"
    );

    drop(held);
    assert_eq!(
        gzipped().await.headers()[header::CONTENT_ENCODING],
        "gzip",
        "and take the encoders back when the bodies go"
    );
}

#[tokio::test]
async fn a_response_marked_uncompressed_is_sent_plain_and_holds_no_encoder() {
    let archive = || async {
        (
            Uncompressed,
            [(header::CONTENT_TYPE, "application/vnd.example.archive")],
            "an archive already compressed, well over the floor",
        )
    };
    let app = Harness::builder()
        .api(Mount::new(
            Router::new().route("/export", get(archive)),
            |chassis| chassis,
        ))
        .build()
        .await;

    let mut held = Vec::new();
    for _ in 0..=ENCODERS {
        let response = app
            .get("/api/export")
            .header("accept-encoding", "gzip")
            .send()
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get(header::CONTENT_ENCODING).is_none());
        held.push(response);
    }

    let gz = app
        .get("/api/branding")
        .header("accept-encoding", "gzip")
        .send()
        .await;
    assert_eq!(
        gz.headers()[header::CONTENT_ENCODING],
        "gzip",
        "the plain bodies held no encoder"
    );
}

#[tokio::test]
async fn an_event_stream_a_short_body_and_the_socket_are_never_compressed() {
    let app = Harness::new().await;
    let admin = console("admin", wslib_appliance_types::Role::Admin);
    crate::audit!(app.state(), &Identity::Local, "something to read").await;

    let local = app
        .get("/api/audit")
        .local()
        .header("accept-encoding", "gzip")
        .send()
        .await;
    assert_eq!(local.status(), StatusCode::OK);
    assert!(local.headers().get(header::CONTENT_ENCODING).is_none());
    assert!(
        body_bytes(local).await.len() >= 32,
        "under the floor, so not a test"
    );

    let feed = app
        .get("/api/logs/events")
        .from_console(&admin)
        .header("accept-encoding", "gzip")
        .send()
        .await;
    assert_eq!(feed.status(), StatusCode::OK);
    assert_eq!(feed.headers()[header::CONTENT_TYPE], "text/event-stream");
    assert!(feed.headers().get(header::CONTENT_ENCODING).is_none());

    let probe = app
        .get("/healthz")
        .header("accept-encoding", "gzip")
        .send()
        .await;
    assert!(probe.headers().get(header::CONTENT_ENCODING).is_none());
    let body = body_bytes(probe).await;
    assert!(body.len() < 32, "over the floor, so not a test");
    assert_eq!(body, r#"{"status":"ok"}"#);
}

#[tokio::test]
async fn an_unmatched_api_path_is_a_404_before_it_is_an_authorisation_question() {
    let app = Harness::new().await;
    assert_eq!(
        app.get("/api/nonsense").send().await.status(),
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn the_health_check_answers_without_a_credential_and_reads_the_database() {
    let app = Harness::new().await;
    let response = app.get("/healthz").send().await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_json(response).await["status"], "ok");
}

#[tokio::test]
async fn the_health_check_is_reachable_over_the_control_socket_too() {
    let app = Harness::new().await;
    assert_eq!(
        app.get("/healthz").local().send().await.status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn a_consuming_products_routes_are_mounted_under_api_with_the_same_extractors() {
    async fn devices(Admin(who): Admin) -> String {
        who.actor().to_string()
    }

    let app = Harness::builder()
        .api(Router::new().route("/devices", get(devices)))
        .build()
        .await;

    assert_eq!(
        app.get("/api/devices").send().await.status(),
        StatusCode::UNAUTHORIZED,
        "and gated by the extractor it named"
    );
    assert_eq!(
        app.get("/devices").send().await.status(),
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn a_store_handed_to_the_harness_is_the_one_its_routes_run_on() {
    async fn note(Admin(who): Admin, State(app): State<ApplianceState>) {
        crate::audit!(&app, &who, "noted").await;
    }
    let theirs = Store::open_in_memory(None).await.expect("store");
    let app = Harness::builder()
        .store(theirs.clone())
        .api(Router::new().route("/note", axum::routing::post(note)))
        .build()
        .await;

    let noted = app
        .post("/api/note")
        .from_console(&console("admin", wslib_appliance_types::Role::Admin))
        .send()
        .await;
    assert_eq!(noted.status(), StatusCode::OK);

    let page = theirs.audit(10, None).await.expect("audit");
    assert!(
        page.items.iter().any(|row| row.message == "noted"),
        "the route wrote its audit row somewhere else: {:?}",
        page.items
            .iter()
            .map(|row| &row.message)
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn a_consumers_handle_cannot_stop_the_appliance() {
    let app = Harness::new().await;
    let theirs = app.shutdown();
    let another = app.shutdown();

    theirs.cancel();
    assert!(theirs.is_cancelled());
    assert!(!another.is_cancelled(), "a sibling handle was cancelled");

    app.stop();
    assert!(another.is_cancelled());
}
