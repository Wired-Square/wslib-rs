//! The branding and the logo, through the harness.

use crate::testing::{ENCODERS, Harness, Logo, body_bytes, body_json, varies};
use axum::body::Bytes;
use axum::http::{HeaderValue, StatusCode, header};

#[tokio::test]
async fn the_sign_in_screen_can_brand_itself_before_there_is_a_session() {
    let app = Harness::new().await;
    let response = app.get("/api/branding").send().await;
    assert_eq!(response.status(), StatusCode::OK);

    let body = body_json(response).await;
    assert_eq!(body["app_name"], "Widget Monitor");
    assert_eq!(body["tokens"]["--app-accent"], "#1b3f94");

    let build = body["build"].as_str().expect("a build id");
    assert_eq!(build.len(), 16);
    assert!(build.chars().all(|c| c.is_ascii_hexdigit()));
    assert!(!Harness::VERSION.contains(build));
    assert_eq!(
        body["hostname"],
        serde_json::Value::Null,
        "this server never names the box"
    );
}

async fn tagged(app: &Harness, if_none_match: &str) -> axum::response::Response {
    app.get("/api/branding")
        .header("if-none-match", if_none_match)
        .send()
        .await
}

fn etag(response: &axum::response::Response) -> String {
    response.headers()[header::ETAG]
        .to_str()
        .expect("ascii")
        .to_owned()
}

#[tokio::test]
async fn a_client_holding_the_current_tag_is_answered_304_with_no_body() {
    let app = Harness::new().await;
    let fresh = app.get("/api/branding").send().await;
    assert_eq!(fresh.status(), StatusCode::OK);
    assert_eq!(fresh.headers()[header::CACHE_CONTROL], "no-cache");
    let tag = etag(&fresh);
    let opaque = tag.strip_prefix("W/").expect("a weak tag");
    assert_eq!(opaque.len(), 18, "{tag}");

    for held in [
        tag.clone(),
        opaque.to_owned(),
        format!(r#""elsewhere", {tag}"#),
        "*".to_owned(),
    ] {
        let unchanged = tagged(&app, &held).await;
        assert_eq!(unchanged.status(), StatusCode::NOT_MODIFIED, "{held}");
        assert_eq!(etag(&unchanged), tag, "{held}");
        assert_eq!(unchanged.headers()[header::CACHE_CONTROL], "no-cache");
        assert_eq!(varies(&unchanged), [b"accept-encoding"], "{held}");
        assert!(unchanged.headers().get(header::CONTENT_ENCODING).is_none());
        assert!(body_bytes(unchanged).await.is_empty(), "{held}");
    }

    for stale in [r#""0123456789abcdef""#, r#"W/"0123456789abcdef""#, ""] {
        let changed = tagged(&app, stale).await;
        assert_eq!(changed.status(), StatusCode::OK, "{stale}");
        assert_eq!(etag(&changed), tag, "{stale}");
    }
}

#[tokio::test]
async fn the_tag_is_the_same_for_the_gzipped_body_and_a_304_is_never_gzipped() {
    let app = Harness::new().await;
    let plain = app.get("/api/branding").send().await;
    let tag = etag(&plain);
    let plain = body_bytes(plain).await;

    let gzipped = |tag: &str| {
        let mut request = app.get("/api/branding").header("accept-encoding", "gzip");
        if !tag.is_empty() {
            request = request.header("if-none-match", tag);
        }
        request.send()
    };

    let gz = gzipped("").await;
    assert_eq!(gz.headers()[header::CONTENT_ENCODING], "gzip");
    assert_eq!(etag(&gz), tag);
    let mut unzipped = Vec::new();
    std::io::Read::read_to_end(
        &mut flate2::read::GzDecoder::new(&body_bytes(gz).await[..]),
        &mut unzipped,
    )
    .expect("gzip");
    assert_eq!(unzipped, plain);

    let unchanged = gzipped(&tag).await;
    assert_eq!(unchanged.status(), StatusCode::NOT_MODIFIED);
    assert!(unchanged.headers().get(header::CONTENT_ENCODING).is_none());
    assert!(body_bytes(unchanged).await.is_empty());
}

#[cfg(unix)]
#[tokio::test]
async fn a_304_carries_no_content_length_over_the_app_socket() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let app = Harness::new().await;
    let socket = app
        .serve_app_socket(crate::tests::proxied::own_uid(app.dir()))
        .await;
    let mut answer = Vec::new();
    tokio::time::timeout(crate::tests::WITHIN, async {
        let mut peer = tokio::net::UnixStream::connect(&socket)
            .await
            .expect("connects");
        peer.write_all(
            b"GET /api/branding HTTP/1.1\r\nHost: box\r\nIf-None-Match: *\r\nConnection: close\r\n\r\n",
        )
        .await
        .expect("a request");
        peer.read_to_end(&mut answer).await.expect("an answer");
    })
    .await
    .expect("an answer inside the timeout");
    let answer = String::from_utf8_lossy(&answer).to_ascii_lowercase();
    assert!(answer.starts_with("http/1.1 304"), "{answer}");
    assert!(!answer.contains("content-length"), "{answer}");
}

#[tokio::test]
async fn the_tag_follows_the_branding_where_the_build_does_not() {
    let before = Harness::new().await;
    let after = Harness::builder().app_name("Gadget Monitor").build().await;
    let before = before.get("/api/branding").send().await;
    let tag = etag(&before);

    let changed = tagged(&after, &tag).await;
    assert_eq!(changed.status(), StatusCode::OK);
    assert_ne!(etag(&changed), tag);
    let (before, changed) = (body_json(before).await, body_json(changed).await);
    assert_eq!(before["build"], changed["build"]);
    assert_eq!(changed["app_name"], "Gadget Monitor");
}

#[tokio::test]
async fn the_logo_comes_down_as_bytes_with_its_own_content_type() {
    let app = Harness::new().await;
    let response = app.get("/api/branding/logo").send().await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .unwrap(),
        "image/svg+xml"
    );
}

const SVG: &[u8] = br#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
  <rect x="3" y="4" width="18" height="13" rx="2" />
  <rect x="5" y="6" width="14" height="9" rx="2" />
  <path d="M7 21h10M12 17v4" />
  <path d="M7 12l3 3 3-5 4 4" />
</svg>"#;

#[tokio::test]
async fn a_client_that_takes_gzip_is_sent_the_logo_gzipped_once() {
    let app = Harness::builder().logo(SVG, "image/svg+xml").build().await;
    let stored = Logo::new(
        Bytes::from_static(SVG),
        HeaderValue::from_static("image/svg+xml"),
    )
    .gzipped
    .expect("a copy smaller than the logo");

    // One more than the cap, all held: if a copy took an encoder, the last is plain.
    let mut held = Vec::new();
    for _ in 0..=ENCODERS {
        let gz = app
            .get("/api/branding/logo")
            .header("accept-encoding", "gzip")
            .send()
            .await;
        assert_eq!(gz.status(), StatusCode::OK);
        assert_eq!(gz.headers()[header::CONTENT_ENCODING], "gzip");
        held.push(gz);
    }
    let gz = held.pop().expect("a response");
    assert_eq!(gz.headers()[header::CONTENT_TYPE], "image/svg+xml");
    assert_eq!(varies(&gz), [b"accept-encoding"]);
    assert_eq!(body_bytes(gz).await, stored);

    let mut encoding = Vec::new();
    for _ in 0..ENCODERS {
        let gz = app
            .get("/api/branding")
            .header("accept-encoding", "gzip")
            .send()
            .await;
        assert_eq!(gz.headers()[header::CONTENT_ENCODING], "gzip");
        encoding.push(gz);
    }
    let past = app
        .get("/api/branding/logo")
        .header("accept-encoding", "gzip")
        .send()
        .await;
    assert_eq!(
        past.headers()[header::CONTENT_ENCODING],
        "gzip",
        "sent with every encoder held"
    );
    drop(encoding);

    for accepted in ["x-gzip", "*"] {
        let gz = app
            .get("/api/branding/logo")
            .header("accept-encoding", accepted)
            .send()
            .await;
        assert_eq!(gz.headers()[header::CONTENT_ENCODING], "gzip", "{accepted}");
        assert_eq!(varies(&gz), [b"accept-encoding"], "{accepted}");
        assert_eq!(body_bytes(gz).await, stored, "{accepted}");
    }
    for refused in [None, Some("gzip;q=0"), Some("gzip;q=0, *"), Some("br")] {
        let mut request = app.get("/api/branding/logo");
        if let Some(refused) = refused {
            request = request.header("accept-encoding", refused);
        }
        let plain = request.send().await;
        assert!(
            plain.headers().get(header::CONTENT_ENCODING).is_none(),
            "{refused:?}"
        );
        assert_eq!(varies(&plain), [b"accept-encoding"], "{refused:?}");
        assert_eq!(body_bytes(plain).await, SVG, "{refused:?}");
    }
}

#[test]
fn a_logo_keeps_a_copy_only_where_the_layer_would_have_encoded_it_smaller() {
    let copied = |bytes: &'static [u8], content_type: &'static str| {
        Logo::new(
            Bytes::from_static(bytes),
            HeaderValue::from_static(content_type),
        )
        .gzipped
        .is_some()
    };
    assert!(copied(SVG, "image/svg+xml"));
    assert!(copied(SVG, "text/plain"));
    assert!(!copied(b"<svg/>", "image/svg+xml"), "gzip would grow it");
    assert!(!copied(SVG, "image/png"), "the layer leaves a raster alone");
}

#[tokio::test]
async fn an_appliance_with_no_logo_says_so_in_the_one_error_body() {
    let app = Harness::builder().no_logo().build().await;
    let response = app.get("/api/branding/logo").send().await;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = body_json(response).await;
    assert!(
        body["error"].as_str().unwrap().contains("no logo"),
        "{body}"
    );
}
