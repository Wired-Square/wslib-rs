use std::io::Write;
use std::sync::atomic::Ordering;

use wslib_dns::FakeResolver;

use super::*;
use crate::bimi::SvgRule;
use crate::discover::fetch::testing::{clients, response, serve, serve_with};
use crate::discover::fetch::{DEFAULT_USER_AGENT, HttpClients};

const HOST: &str = "logo.example.com";

const LOGO: &str = r#"<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 1 1"><title>Example</title></svg>"#;

fn loopback() -> FakeResolver {
    FakeResolver::new().with_ip(HOST, ["127.0.0.1".parse().unwrap()])
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

async fn local(raw: Vec<u8>) -> LogoFetch {
    let (port, _) = serve(raw).await;
    fetch(
        &loopback(),
        &clients(),
        &format!("http://{HOST}:{port}/logo.svg"),
        None,
        Reach::Anywhere,
    )
    .await
}

async fn failure(raw: Vec<u8>) -> FetchFailure {
    match local(raw).await {
        LogoFetch::Unreachable { failure, .. } => failure,
        fetched => panic!("expected a failure, got {fetched:?}"),
    }
}

#[tokio::test]
async fn a_logo_is_fetched_and_validated() {
    let LogoFetch::Fetched {
        content_type,
        gzip,
        body,
        validation,
        ..
    } = local(response(
        "200 OK",
        &["Content-Type: image/svg+xml"],
        LOGO.as_bytes(),
    ))
    .await
    else {
        panic!("the logo is served");
    };
    assert_eq!(content_type.as_deref(), Some("image/svg+xml"));
    assert!(!gzip);
    assert_eq!(body, LOGO.as_bytes());
    assert!(validation.is_conformant(), "{:?}", validation.violations);
}

#[tokio::test]
async fn an_svgz_or_gzip_encoded_logo_is_inflated_first() {
    for headers in [
        vec!["Content-Type: image/svg+xml"],
        vec!["Content-Type: image/svg+xml", "Content-Encoding: gzip"],
    ] {
        let LogoFetch::Fetched {
            gzip,
            body,
            validation,
            ..
        } = local(response("200 OK", &headers, &gzip(LOGO.as_bytes()))).await
        else {
            panic!("the logo is served");
        };
        assert!(gzip);
        assert_eq!(body, LOGO.as_bytes());
        assert!(validation.is_conformant());
    }
}

#[tokio::test]
async fn a_compressed_bomb_and_a_corrupt_stream_are_refused() {
    let bomb = gzip(&vec![b' '; 4 * LOGO_INFLATE_LIMIT]);
    assert!(bomb.len() < LOGO_FETCH_LIMIT);
    assert_eq!(
        failure(response("200 OK", &["Content-Type: image/svg+xml"], &bomb)).await,
        FetchFailure::TooLarge {
            limit: LOGO_INFLATE_LIMIT,
            decompressed: true
        }
    );
    assert_eq!(
        failure(response(
            "200 OK",
            &["Content-Encoding: gzip"],
            b"not gzip at all"
        ))
        .await,
        FetchFailure::Undecodable
    );
}

#[tokio::test]
async fn a_logo_over_the_cap_is_cut_off_while_streaming() {
    let huge = vec![b' '; LOGO_FETCH_LIMIT + 1];
    assert_eq!(
        failure(response("200 OK", &["Content-Type: image/svg+xml"], &huge)).await,
        FetchFailure::TooLarge {
            limit: LOGO_FETCH_LIMIT,
            decompressed: false
        }
    );
}

#[tokio::test]
async fn redirects_and_errors_are_refused() {
    assert_eq!(
        failure(response(
            "302 Found",
            &["Location: https://example.com/logo.svg"],
            b""
        ))
        .await,
        FetchFailure::Redirect {
            location: Some("https://example.com/logo.svg".into())
        }
    );
    assert_eq!(
        failure(response("404 Not Found", &[], b"")).await,
        FetchFailure::Status { status: 404 }
    );
}

#[tokio::test]
async fn the_content_type_is_recorded_not_enforced() {
    let LogoFetch::Fetched {
        content_type,
        validation,
        ..
    } = local(response(
        "200 OK",
        &["Content-Type: text/plain"],
        LOGO.as_bytes(),
    ))
    .await
    else {
        panic!("a mislabelled logo is still fetched");
    };
    assert_eq!(content_type.as_deref(), Some("text/plain"));
    assert!(validation.is_conformant());
}

#[tokio::test]
async fn private_hosts_ip_literals_bad_schemes_and_credentials_are_never_contacted() {
    let (port, connections) = serve(response("200 OK", &[], LOGO.as_bytes())).await;
    let dns = loopback().with_ip("ten.example.com", ["10.0.3.7".parse().unwrap()]);
    for (url, expected) in [
        (format!("https://{HOST}:{port}/logo.svg"), "non-global"),
        (
            format!("https://ten.example.com:{port}/logo.svg"),
            "non-global",
        ),
        (format!("https://127.0.0.1:{port}/logo.svg"), "non-global"),
        (format!("https://[::1]:{port}/logo.svg"), "non-global"),
        (
            "https://169.254.169.254/latest/meta-data".to_owned(),
            "non-global",
        ),
        (format!("http://{HOST}:{port}/logo.svg"), "invalid"),
        (
            format!("https://user:secret@{HOST}:{port}/logo.svg"),
            "invalid",
        ),
        ("ftp://logo.example.com/logo.svg".to_owned(), "invalid"),
        ("not a url".to_owned(), "invalid"),
    ] {
        let fetched = bimi_logo(&dns, &clients(), &url, None).await;
        let ok = matches!(
            (&fetched, expected),
            (
                LogoFetch::Unreachable {
                    failure: FetchFailure::NonGlobalAddress { .. },
                    ..
                },
                "non-global"
            ) | (
                LogoFetch::Unreachable {
                    failure: FetchFailure::InvalidUrl,
                    ..
                },
                "invalid"
            )
        );
        assert!(ok, "{url}: {fetched:?}");
    }
    assert_eq!(connections.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn violations_come_through_the_fetch() {
    let svg = LOGO.replace("<title>Example</title>", "<script/>");
    let LogoFetch::Fetched { validation, .. } =
        local(response("200 OK", &[], svg.as_bytes())).await
    else {
        panic!("the logo is served");
    };
    let rules: Vec<SvgRule> = validation.violations.iter().map(|v| v.rule).collect();
    assert_eq!(rules, [SvgRule::ProhibitedElement, SvgRule::Title]);
}

/// As some real hosts do: 406 without a User-Agent.
fn strict(request: &str) -> Vec<u8> {
    let lower = request.to_ascii_lowercase();
    if !lower.contains("\r\nuser-agent: ") || !lower.contains("\r\naccept: image/svg+xml") {
        return response("406 Not Acceptable", &[], b"");
    }
    response("200 OK", &["Content-Type: image/svg+xml"], LOGO.as_bytes())
}

#[tokio::test]
async fn a_user_agent_and_accept_are_always_sent() {
    let (port, _) = serve_with(strict).await;
    let url = format!("http://{HOST}:{port}/logo.svg");
    let fetched = fetch(&loopback(), &clients(), &url, None, Reach::Anywhere).await;
    assert!(matches!(fetched, LogoFetch::Fetched { .. }), "{fetched:?}");
    assert!(DEFAULT_USER_AGENT.starts_with("wslib-dns-mail/"));
}

#[tokio::test]
async fn the_user_agent_can_be_replaced_but_not_dropped() {
    let (port, _) = serve_with(|request| {
        let agent = request
            .lines()
            .find_map(|line| {
                line.strip_prefix("user-agent: ")
                    .or_else(|| line.strip_prefix("User-Agent: "))
            })
            .unwrap_or("")
            .to_owned();
        response("200 OK", &["Content-Type: image/svg+xml"], agent.as_bytes())
    })
    .await;
    let url = format!("http://{HOST}:{port}/logo.svg");
    let clients = HttpClients::new(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
        reqwest::Client::builder().user_agent("caller/9")
    })
    .user_agent("example-checker/1.0");
    let LogoFetch::Fetched { body, .. } =
        fetch(&loopback(), &clients, &url, None, Reach::Anywhere).await
    else {
        panic!("the logo is served");
    };
    assert_eq!(body, b"example-checker/1.0");
}
