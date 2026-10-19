mod support;

use std::net::SocketAddr;
use std::time::Duration;

use axum::Router;
use axum::extract::ConnectInfo;
use axum::routing::get;
use support::{BRIEF, PATIENT, closed, dial, exchange, listener};
use tokio::io::AsyncWriteExt;
use tokio_util::sync::CancellationToken;
use wslib_http_server::{Bounds, Listener, serve_http};

fn app() -> Router {
    Router::new()
        .route(
            "/peer",
            get(|ConnectInfo(peer): ConnectInfo<SocketAddr>| async move { peer.ip().to_string() }),
        )
        .route(
            "/slow",
            get(|| async {
                tokio::time::sleep(BRIEF).await;
                "done"
            }),
        )
        .route("/stalled", get(std::future::pending::<()>))
}

async fn serving(
    bounds: Bounds,
) -> (
    SocketAddr,
    CancellationToken,
    tokio::task::JoinHandle<std::io::Result<()>>,
) {
    let listener = listener(bounds).await;
    let address = listener.local_addr();
    let stop = CancellationToken::new();
    let served = tokio::spawn(serve_http(listener, app(), stop.clone().cancelled_owned()));
    (address, stop, served)
}

#[tokio::test]
async fn a_request_is_answered_and_sees_its_peer() {
    let (address, _stop, _served) = serving(Bounds::SERVING).await;
    let answer = exchange(&mut dial(address).await, "/peer")
        .await
        .expect("an answer");
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    assert!(answer.ends_with("127.0.0.1"), "{answer}");
}

#[tokio::test]
async fn a_request_in_flight_at_the_stop_is_finished() {
    let (address, stop, served) = serving(Bounds::SERVING).await;
    let asking = tokio::spawn(async move { exchange(&mut dial(address).await, "/slow").await });
    tokio::time::sleep(BRIEF / 4).await;
    stop.cancel();

    let answer = asking.await.expect("did not panic").expect("an answer");
    assert!(answer.ends_with("done"), "{answer}");
    tokio::time::timeout(PATIENT, served)
        .await
        .expect("stops once drained")
        .expect("did not panic")
        .expect("served");
}

#[tokio::test]
async fn a_stalled_request_is_closed_at_the_grace_period() {
    let (address, stop, served) = serving(Bounds {
        grace: BRIEF,
        ..Bounds::SERVING
    })
    .await;
    let mut peer = dial(address).await;
    peer.write_all(b"GET /stalled HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("a request");
    tokio::time::sleep(BRIEF / 4).await;

    let stopped = tokio::time::Instant::now();
    stop.cancel();
    tokio::time::timeout(PATIENT, served)
        .await
        .expect("stops at the grace period")
        .expect("did not panic")
        .expect("served");
    assert!(stopped.elapsed() >= BRIEF, "{:?}", stopped.elapsed());
    assert!(closed(&mut peer, PATIENT).await);
}

#[tokio::test]
async fn nothing_is_accepted_after_the_stop() {
    let (address, stop, served) = serving(Bounds::SERVING).await;
    stop.cancel();
    served.await.expect("did not panic").expect("served");
    assert!(
        tokio::time::timeout(
            Duration::from_secs(1),
            tokio::net::TcpStream::connect(address)
        )
        .await
        .expect("refused, not left hanging")
        .is_err()
    );
}

#[tokio::test]
async fn a_listener_bound_by_the_caller_is_served() {
    let tcp = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind");
    let listener = Listener::from_tcp(tcp, Bounds::SERVING).expect("held");
    let address = listener.local_addr();
    tokio::spawn(serve_http(listener, app(), std::future::pending()));
    let answer = exchange(&mut dial(address).await, "/peer")
        .await
        .expect("an answer");
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
}

#[tokio::test]
async fn a_port_taken_is_the_bare_bind_error() {
    let holding = listener(Bounds::SERVING).await;
    let refused = Listener::bind(holding.local_addr(), Bounds::SERVING)
        .await
        .err()
        .expect("taken");
    assert_eq!(refused.kind(), std::io::ErrorKind::AddrInUse);
    assert!(!refused.to_string().contains("binding"), "{refused}");
}
