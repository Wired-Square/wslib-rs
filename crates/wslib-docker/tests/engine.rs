#![cfg(unix)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::{Value, json};
use wslib_docker::testing::FakeEngine;
use wslib_docker::{Docker, DockerError, ImageReference};

fn socket() -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "wslib-docker-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("docker.sock")
}

fn engine(answer: fn(&str, &str) -> (u16, String)) -> FakeEngine {
    FakeEngine::serve(socket(), answer)
}

fn requests(engine: &FakeEngine) -> Vec<(String, String)> {
    engine
        .seen()
        .into_iter()
        .map(|seen| (seen.method, seen.uri))
        .collect()
}

fn pairs<const N: usize>(expected: [(&str, &str); N]) -> Vec<(String, String)> {
    expected
        .map(|(m, u)| (m.to_string(), u.to_string()))
        .to_vec()
}

#[tokio::test]
async fn a_container_is_created_by_its_name_with_the_spec_as_json() {
    let engine = engine(|_, _| (201, r#"{"Id":"c0ffee"}"#.to_string()));
    let spec = json!({"Image": "sha256:0123", "User": "70000:0"});
    engine.docker().create("app-hello", &spec).await.unwrap();
    let seen = &engine.seen()[0];
    assert_eq!(
        (
            seen.method.as_str(),
            seen.uri.as_str(),
            seen.content_type.as_str()
        ),
        (
            "POST",
            "/v1.44/containers/create?name=app-hello",
            "application/json"
        )
    );
    assert_eq!(serde_json::from_slice::<Value>(&seen.body).unwrap(), spec);
}

#[tokio::test]
async fn start_stop_and_remove_name_the_container_and_already_so_succeeds() {
    let engine = engine(|_, uri| (if uri.contains("stop") { 304 } else { 204 }, String::new()));
    let docker = engine.docker();
    docker.start("app-hello").await.unwrap();
    docker.stop("app-hello").await.unwrap();
    docker.remove("app-hello").await.unwrap();
    docker.remove_image("sha256:0123").await.unwrap();
    assert_eq!(
        requests(&engine),
        pairs([
            ("POST", "/v1.44/containers/app-hello/start"),
            ("POST", "/v1.44/containers/app-hello/stop"),
            ("DELETE", "/v1.44/containers/app-hello?force=true"),
            ("DELETE", "/v1.44/images/sha256:0123"),
        ])
    );
}

#[tokio::test]
async fn stopping_for_good_drops_the_restart_policy_first() {
    let engine = engine(|_, _| (200, String::new()));
    engine.docker().stop_for_good("app_hello").await.unwrap();
    assert_eq!(
        requests(&engine),
        pairs([
            ("POST", "/v1.44/containers/app_hello/update"),
            ("POST", "/v1.44/containers/app_hello/stop"),
        ])
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&engine.seen()[0].body).unwrap(),
        json!({"RestartPolicy": {"Name": "no"}})
    );
}

#[tokio::test]
async fn what_the_engine_does_not_have_inspects_as_none() {
    let engine = engine(|_, uri| match uri {
        "/v1.44/images/sha256:0123/json" => (200, r#"{"Id":"sha256:0123"}"#.to_string()),
        _ => (404, r#"{"message":"No such container"}"#.to_string()),
    });
    let docker = engine.docker();
    assert_eq!(
        docker.image("sha256:0123").await.unwrap(),
        Some(json!({"Id": "sha256:0123"}))
    );
    assert_eq!(docker.container("app-hello").await.unwrap(), None);
    assert_eq!(docker.network("apps").await.unwrap(), None);
    docker
        .create_network(&json!({"Name": "apps"}))
        .await
        .unwrap_err();
    assert_eq!(
        requests(&engine)[1..],
        pairs([
            ("GET", "/v1.44/containers/app-hello/json"),
            ("GET", "/v1.44/networks/apps"),
            ("POST", "/v1.44/networks/create"),
        ])
    );
}

#[tokio::test]
async fn a_refusal_is_an_error_with_the_engines_message() {
    let engine = engine(|_, _| (409, r#"{"message":"name in use"}"#.to_string()));
    assert!(matches!(
        engine.docker().create("app-hello", &json!({})).await,
        Err(DockerError::Refused { status: 409, message }) if message == "name in use"
    ));
}

#[tokio::test]
async fn a_name_that_would_change_the_path_is_refused_before_anything_is_sent() {
    let engine = engine(|_, _| (204, String::new()));
    let docker = engine.docker();
    assert!(matches!(
        docker.remove("x?force=false").await,
        Err(DockerError::Name(_))
    ));
    assert!(matches!(
        docker.container("../images/x").await,
        Err(DockerError::Name(_))
    ));
    assert!(engine.seen().is_empty());
}

#[tokio::test]
async fn a_load_streams_the_archive_as_a_tar_and_names_what_it_loaded() {
    let engine = engine(|_, _| {
        (
            200,
            r#"{"stream":"Loaded image: applianceos/hello-app:2\n"}"#.to_string(),
        )
    });
    assert_eq!(
        engine.docker().load(&b"a tar archive"[..]).await.unwrap(),
        ["applianceos/hello-app:2"]
    );
    let seen = &engine.seen()[0];
    assert_eq!(
        (
            seen.method.as_str(),
            seen.uri.as_str(),
            seen.content_type.as_str(),
            seen.body.as_slice()
        ),
        (
            "POST",
            "/v1.44/images/load?quiet=1",
            "application/x-tar",
            b"a tar archive".as_slice()
        )
    );
}

#[tokio::test]
async fn a_pull_asks_for_the_one_image_and_fails_on_an_error_in_its_progress() {
    let reference = format!("10.0.2.2:5443/wired-square/hello@sha256:{}", "a".repeat(64));
    let image = ImageReference::parse(&reference).unwrap();
    let pulling = engine(|_, _| {
        (
            200,
            r#"{"status":"Pulling from wired-square/hello"}"#.to_string(),
        )
    });
    assert_eq!(pulling.docker().pull(&image).await.unwrap(), reference);
    assert_eq!(
        requests(&pulling),
        [(
            "POST".to_string(),
            format!("/v1.44/images/create?fromImage={reference}")
        )]
    );
    let failing = engine(|_, _| {
        (
            200,
            r#"{"status":"Pulling"}
{"errorDetail":{"message":"manifest unknown"},"error":"manifest unknown"}"#
                .to_string(),
        )
    });
    assert!(matches!(
        failing.docker().pull(&image).await,
        Err(DockerError::Refused { status: 200, message }) if message == "manifest unknown"
    ));
}

#[tokio::test]
async fn an_absent_engine_is_unreachable() {
    let docker = Docker::default().with_socket(socket());
    assert!(matches!(
        docker.ping().await,
        Err(DockerError::Unreachable(_))
    ));
}

#[tokio::test]
async fn a_held_request_is_answered_once_released_and_a_slow_one_times_out() {
    let engine = FakeEngine::holding(socket(), |_, _| (200, "OK".to_string()), "/v1.44/_ping");
    let impatient = engine.docker().with_call_timeout(Duration::from_millis(50));
    assert!(matches!(impatient.ping().await, Err(DockerError::Timeout)));
    engine.release();
    engine.release();
    engine.docker().ping().await.unwrap();
    assert_eq!(engine.seen().len(), 2);
}
