mod support;

use std::net::SocketAddr;

use axum::Router;
use support::{BRIEF, PATIENT, Pair, closed, dial, exchange, listener};
use tokio::io::AsyncWriteExt;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use wslib_http_server::{Bounds, Https, Tls, serve_redirect};

async fn redirecting(to: watch::Receiver<u16>) -> SocketAddr {
    let listener = listener(Bounds::REDIRECT).await;
    let address = listener.local_addr();
    tokio::spawn(serve_redirect(listener, to, std::future::pending()));
    address
}

fn location(answer: &str) -> &str {
    answer
        .lines()
        .find_map(|line| line.strip_prefix("location: "))
        .unwrap_or_else(|| panic!("no location: {answer}"))
}

#[tokio::test]
async fn https_reports_the_port_it_bound_and_the_redirect_follows_it() {
    let pair = Pair::new();
    let https = Https::new(
        listener(Bounds::SERVING).await,
        Tls::new(pair.server_config()),
    );
    let redirect = listener(Bounds::REDIRECT).await;
    let from = redirect.local_addr();
    let port = *https.port().borrow();
    assert_ne!(port, 0, "port 0 resolves at bind");
    tokio::spawn(
        https
            .redirect_from(redirect)
            .serve(Router::new(), std::future::pending()),
    );

    let answer = exchange(&mut dial(from).await, "/a/b?c=d")
        .await
        .expect("an answer");
    assert!(answer.starts_with("HTTP/1.1 307"), "{answer}");
    assert_eq!(
        location(&answer),
        format!("https://localhost:{port}/a/b?c=d")
    );
    assert!(
        answer.to_lowercase().contains("connection: close"),
        "{answer}"
    );
}

#[tokio::test]
async fn the_redirect_follows_a_port_that_moves() {
    let (moving, to) = watch::channel(8443);
    let address = redirecting(to).await;
    let before = exchange(&mut dial(address).await, "/")
        .await
        .expect("an answer");
    moving.send_replace(9443);
    let after = exchange(&mut dial(address).await, "/")
        .await
        .expect("an answer");
    assert_eq!(location(&before), "https://localhost:8443/");
    assert_eq!(location(&after), "https://localhost:9443/");
}

#[tokio::test]
async fn the_redirect_does_not_serve_cleartext_h2() {
    let mut peer = dial(redirecting(watch::channel(443).1).await).await;
    peer.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        .await
        .expect("the h2 preface");
    let mut answer = Vec::new();
    tokio::time::timeout(
        PATIENT,
        tokio::io::AsyncReadExt::read_to_end(&mut peer, &mut answer),
    )
    .await
    .expect("closed")
    .expect("read");
    assert!(answer.is_empty(), "{}", String::from_utf8_lossy(&answer));
}

#[tokio::test]
async fn the_stop_drains_both_listeners() {
    let pair = Pair::new();
    let https = Https::new(
        listener(Bounds::SERVING).await,
        Tls::new(pair.server_config()),
    );
    let redirect = listener(Bounds::REDIRECT).await;
    let mut held = dial(redirect.local_addr()).await;
    let stop = CancellationToken::new();
    let serving = tokio::spawn(
        https
            .redirect_from(redirect)
            .serve(Router::new(), stop.clone().cancelled_owned()),
    );
    tokio::time::sleep(BRIEF / 4).await;
    stop.cancel();
    tokio::time::timeout(PATIENT, serving)
        .await
        .expect("both drain")
        .expect("did not panic")
        .expect("served");
    assert!(closed(&mut held, PATIENT).await);
}
