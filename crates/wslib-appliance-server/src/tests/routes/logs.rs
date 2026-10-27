//! The daemon's own log over HTTP, through the harness.

use axum::http::{StatusCode, header};
use futures_util::StreamExt;
use wslib_appliance_core::backend;

use crate::testing::{Harness, body_json, captured};
use crate::tests::admin;

#[tokio::test]
async fn the_snapshot_is_the_ring_and_takes_a_browser_administrator_only() {
    let app = Harness::new().await;
    captured(backend::logs(app.state()), || {
        tracing::warn!(device = "bench", "poll failed")
    });

    let response = app.get("/api/logs").from_console(&admin()).send().await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["records"][0]["message"], "poll failed");
    assert_eq!(body["records"][0]["level"], "warn");
    assert_eq!(
        body["records"][0]["fields"][0],
        serde_json::json!(["device", "bench"])
    );
    assert_eq!(body["log_file"], serde_json::Value::Null, "{body}");

    assert_eq!(
        app.get("/api/logs").send().await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        app.get("/api/logs").local().send().await.status(),
        StatusCode::FORBIDDEN,
        "the socket's group is not the journal's"
    );
    assert_eq!(
        app.get("/api/logs/events").local().send().await.status(),
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn the_feed_is_an_event_stream_carrying_each_record_as_it_arrives() {
    let app = Harness::new().await;

    let response = app
        .get("/api/logs/events")
        .from_console(&admin())
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "text/event-stream"
    );

    captured(backend::logs(app.state()), || {
        tracing::warn!("something happened")
    });
    let mut body = response.into_body().into_data_stream();
    let frame = body.next().await.expect("a frame").expect("bytes");
    assert_eq!(
        frame, "event: heartbeat\ndata: ok\n\n",
        "the head travels with a frame, for a proxy that holds it until one"
    );
    let frame = body.next().await.expect("a frame").expect("bytes");
    let text = String::from_utf8(frame.to_vec()).unwrap();
    assert!(text.starts_with("event: log\ndata: {"), "{text}");
    assert!(
        text.contains("\"message\":\"something happened\""),
        "{text}"
    );

    app.stop();
    assert!(
        body.next().await.is_none(),
        "stopping the appliance ends the feed"
    );
}

/// Over the real app socket: h1 and the compression layer must pass each
/// frame through as it is written rather than buffering the stream.
#[cfg(unix)]
#[tokio::test]
async fn the_feed_reaches_the_console_over_the_app_socket_frame_by_frame() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use wslib_appliance_types::console::IDENTITY_HEADER;

    let app = Harness::new().await;
    let socket = app
        .serve_app_socket(crate::tests::proxied::own_uid(app.dir()))
        .await;
    let mut peer = tokio::net::UnixStream::connect(&socket)
        .await
        .expect("connects");
    peer.write_all(
        format!(
            "GET /api/logs/events HTTP/1.1\r\nHost: app\r\n\
             {IDENTITY_HEADER}: {}\r\nAccept-Encoding: gzip\r\n\r\n",
            admin()
        )
        .as_bytes(),
    )
    .await
    .unwrap();

    let mut seen = String::new();
    let mut read_until = async |wanted: &str| {
        let mut buf = [0u8; 4096];
        while !seen.contains(wanted) {
            let n = tokio::time::timeout(crate::tests::WITHIN, peer.read(&mut buf))
                .await
                .unwrap_or_else(|_| panic!("{wanted:?} did not arrive: {seen}"))
                .expect("read");
            if n == 0 {
                return false;
            }
            seen.push_str(&String::from_utf8_lossy(&buf[..n]));
        }
        true
    };
    assert!(read_until("event: heartbeat\ndata: ok\n\n").await);
    captured(backend::logs(app.state()), || {
        tracing::warn!("over the wire")
    });
    assert!(read_until("\"message\":\"over the wire\"").await);
    app.stop();
    assert!(
        read_until("\r\n0\r\n\r\n").await,
        "stopping the appliance ends the response"
    );
    assert!(!seen.contains("content-encoding"), "{seen}");
}
