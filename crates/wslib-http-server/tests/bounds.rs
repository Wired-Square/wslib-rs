mod support;

use std::net::SocketAddr;

use axum::Router;
use support::{BRIEF, PATIENT, Pair, answered, closed, dial, dial_tls, listener};
use tokio::io::AsyncWriteExt;
use tokio::sync::watch;
use wslib_http_server::{Bounds, Tls, serve_http, serve_https, serve_redirect};

const TIGHT: Bounds = Bounds {
    connections: 2,
    head: BRIEF,
    grace: BRIEF,
};

async fn http() -> SocketAddr {
    let listener = listener(TIGHT).await;
    let address = listener.local_addr();
    tokio::spawn(serve_http(listener, Router::new(), std::future::pending()));
    address
}

async fn redirect() -> SocketAddr {
    let listener = listener(TIGHT).await;
    let address = listener.local_addr();
    tokio::spawn(serve_redirect(
        listener,
        watch::channel(443).1,
        std::future::pending(),
    ));
    address
}

/// Silent peers hold every slot, so only the head timeout gives one back;
/// hyper's own 30s default would too, but not within this test's patience.
async fn the_cap_holds_until_the_head_timeout_frees_a_slot(address: SocketAddr) {
    let _held = [dial(address).await, dial(address).await];
    let mut past = dial(address).await;
    assert!(!answered(&mut past, BRIEF / 4).await, "served past the cap");
    assert!(
        answered(&mut past, PATIENT).await,
        "the slots were never reclaimed"
    );
}

#[tokio::test]
async fn the_http_listener_caps_connections() {
    the_cap_holds_until_the_head_timeout_frees_a_slot(http().await).await;
}

#[tokio::test]
async fn the_redirect_listener_caps_connections() {
    the_cap_holds_until_the_head_timeout_frees_a_slot(redirect().await).await;
}

/// Hung up on, but not at once: an instant close is also what a connection
/// task panicking on a missing timer looks like.
async fn hung_up_at_the_head_timeout(peer: &mut (impl tokio::io::AsyncRead + Unpin)) {
    assert!(!closed(peer, BRIEF / 4).await, "hung up before the timeout");
    assert!(closed(peer, PATIENT).await, "never hung up");
}

#[tokio::test]
async fn a_peer_part_way_through_the_h2_preface_is_hung_up_on() {
    let mut peer = dial(http().await).await;
    peer.write_all(b"PRI * HTTP")
        .await
        .expect("a partial preface");
    hung_up_at_the_head_timeout(&mut peer).await;
}

#[tokio::test]
async fn a_peer_dribbling_its_head_is_hung_up_on() {
    let mut peer = dial(http().await).await;
    peer.write_all(b"GET / HTTP/1.1\r\n")
        .await
        .expect("a request line");
    hung_up_at_the_head_timeout(&mut peer).await;
}

#[tokio::test]
async fn the_redirect_hangs_up_on_a_silent_peer() {
    hung_up_at_the_head_timeout(&mut dial(redirect().await).await).await;
}

#[tokio::test]
async fn a_tls_peer_silent_after_its_handshake_is_hung_up_on() {
    let pair = Pair::new();
    let listener = listener(TIGHT).await;
    let address = listener.local_addr();
    tokio::spawn(serve_https(
        listener,
        Router::new(),
        Tls::new(pair.server_config()),
        std::future::pending(),
    ));
    hung_up_at_the_head_timeout(&mut dial_tls(address, &pair.cert, &[b"h2", b"http/1.1"]).await)
        .await;
}
