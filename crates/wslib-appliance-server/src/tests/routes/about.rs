//! Settings › About, through the harness.

use axum::http::StatusCode;
use wslib_appliance_store::Store;
use wslib_appliance_types::Availability;
use wslib_appliance_types::about::{Fact, Subsystem};

use crate::testing::{Harness, body_json, console};
use crate::tests::admin;
use crate::{About, Mount, ProductAbout};

struct Rows(&'static str);

impl About for Rows {
    async fn about(&self, _store: &Store) -> ProductAbout {
        ProductAbout::new(
            vec![Fact::new(self.0, "2 of 3 answering")],
            vec![Subsystem::new(
                format!("{} bus", self.0),
                Availability::unsupported("no bus on this box"),
            )],
        )
    }
}

#[tokio::test]
async fn each_contributor_follows_in_order() {
    let app = Harness::builder()
        .about(Rows("Widgets"))
        .about(Rows("Gadgets"))
        .build()
        .await;
    let response = app.get("/api/about").from_console(&admin()).send().await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["version"], Harness::VERSION);
    assert_eq!(
        body["facts"],
        serde_json::json!([
            { "label": "Widgets", "value": "2 of 3 answering" },
            { "label": "Gadgets", "value": "2 of 3 answering" },
        ])
    );
    let names: Vec<&str> = body["subsystems"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["Widgets bus", "Gadgets bus"]);
    assert_eq!(
        body["subsystems"][0]["availability"]["state"],
        "unsupported"
    );
}

#[tokio::test]
async fn a_mounts_rows_come_ahead_of_every_server_row_whatever_the_call_order() {
    let mounted = |name| Mount::from(axum::Router::new()).about(Rows(name));
    let app = Harness::builder()
        .about(Rows("Widgets"))
        .api(mounted("Clock"))
        .about(Rows("Gadgets"))
        .api(mounted("Radio"))
        .build()
        .await;

    let body = body_json(app.get("/api/about").from_console(&admin()).send().await).await;
    let labels: Vec<&str> = body["facts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["label"].as_str().unwrap())
        .collect();
    assert_eq!(labels, ["Clock", "Radio", "Widgets", "Gadgets"]);
}

#[tokio::test]
async fn with_no_contributor_there_are_no_rows_and_the_start_matches_the_uptime() {
    let app = Harness::new().await;

    let body = body_json(app.get("/api/about").from_console(&admin()).send().await).await;
    assert_eq!(body["facts"], serde_json::json!([]));
    assert_eq!(body["subsystems"], serde_json::json!([]));

    let uptime = body["daemon_uptime_s"].as_u64().expect("seconds");
    let started: chrono::DateTime<chrono::Utc> =
        serde_json::from_value(body["daemon_started_at"].clone()).expect("a time");
    // Two truncations to the second and a later reading: never negative,
    // at most two seconds apart.
    let since = (wslib_appliance_store::now() - started).num_seconds();
    assert!(
        (0..=2).contains(&(since - uptime as i64)),
        "started {since}s ago by the clock, uptime {uptime}s"
    );
}

#[tokio::test]
async fn about_takes_an_administrator_and_answers_the_socket() {
    let app = Harness::new().await;
    let operator = console("operator", wslib_appliance_types::Role::Operator);

    assert_eq!(
        app.get("/api/about")
            .from_console(&operator)
            .send()
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        app.get("/api/about").send().await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        app.get("/api/about").local().send().await.status(),
        StatusCode::OK
    );
}
