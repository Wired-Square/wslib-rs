#![cfg(unix)]

mod support;

use std::io::ErrorKind;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use axum::extract::ConnectInfo;
use axum::routing::get;
use axum::{Extension, Router};
use support::{BRIEF, PATIENT, answered, closed, exchange};
use tempfile::TempDir;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use wslib_http_server::{Bounds, LocalSocket, PeerCredentials, serve_http, serve_local};

fn app() -> Router {
    Router::new()
        .route(
            "/peer",
            get(|ConnectInfo(peer): ConnectInfo<PeerCredentials>| async move { peer.uid.to_string() }),
        )
        .route(
            "/extension",
            get(|peer: Option<Extension<PeerCredentials>>| async move {
                peer.map_or("none".to_owned(), |Extension(peer)| peer.uid.to_string())
            }),
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

fn socket_in() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("a tempdir");
    let path = dir.path().join("app.sock");
    (dir, path)
}

struct Serving {
    stop: CancellationToken,
    served: JoinHandle<std::io::Result<()>>,
}

impl Serving {
    fn on(socket: LocalSocket) -> Self {
        let stop = CancellationToken::new();
        let served = tokio::spawn(serve_local(socket, app(), stop.clone().cancelled_owned()));
        Self { stop, served }
    }

    async fn stopped(self) {
        self.stop.cancel();
        tokio::time::timeout(PATIENT, self.served)
            .await
            .expect("stops once drained")
            .expect("did not panic")
            .expect("served");
    }
}

fn bind(path: &Path, bounds: Bounds) -> LocalSocket {
    LocalSocket::bind(path, 0o600, bounds).expect("bind")
}

async fn dial(path: &Path) -> UnixStream {
    UnixStream::connect(path).await.expect("connect")
}

async fn asked(path: &Path, route: &str) -> String {
    exchange(&mut dial(path).await, route)
        .await
        .expect("an answer")
}

#[tokio::test]
async fn a_request_is_answered_and_sees_the_peers_uid() {
    let (dir, path) = socket_in();
    let _serving = Serving::on(bind(&path, Bounds::SERVING));

    let answer = asked(&path, "/peer").await;
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    let own_uid = std::fs::metadata(dir.path()).expect("the tempdir").uid();
    assert!(answer.ends_with(&format!("\r\n\r\n{own_uid}")), "{answer}");
}

#[tokio::test]
async fn the_credentials_are_an_extension_over_the_socket_and_absent_over_tcp() {
    let (dir, path) = socket_in();
    let _serving = Serving::on(bind(&path, Bounds::SERVING));
    let own_uid = std::fs::metadata(dir.path()).expect("the tempdir").uid();
    let answer = asked(&path, "/extension").await;
    assert!(answer.ends_with(&format!("\r\n\r\n{own_uid}")), "{answer}");

    let tcp = support::listener(Bounds::SERVING).await;
    let address = tcp.local_addr();
    tokio::spawn(serve_http(tcp, app(), std::future::pending()));
    let answer = exchange(&mut support::dial(address).await, "/extension")
        .await
        .expect("an answer");
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    assert!(answer.ends_with("\r\n\r\nnone"), "{answer}");
}

#[tokio::test]
async fn the_socket_has_the_mode_asked_for() {
    let (_dir, path) = socket_in();
    for mode in [0o600, 0o660] {
        let _socket = LocalSocket::bind(&path, mode, Bounds::SERVING).expect("bind");
        let found = std::fs::metadata(&path).expect("the socket");
        assert_eq!(found.permissions().mode() & 0o7777, mode, "{mode:o}");
    }
}

#[tokio::test]
async fn a_socket_nobody_answers_on_is_replaced() {
    let (_dir, path) = socket_in();
    drop(std::os::unix::net::UnixListener::bind(&path).expect("a stale socket"));

    let _serving = Serving::on(bind(&path, Bounds::SERVING));
    assert!(asked(&path, "/peer").await.starts_with("HTTP/1.1 200"));
}

#[tokio::test]
async fn a_live_servers_socket_is_refused() {
    let (_dir, path) = socket_in();
    let _live = std::os::unix::net::UnixListener::bind(&path).expect("a live socket");

    let refused = LocalSocket::bind(&path, 0o600, Bounds::SERVING)
        .err()
        .expect("in use");
    assert_eq!(refused.kind(), ErrorKind::AddrInUse);
    assert!(std::os::unix::net::UnixStream::connect(&path).is_ok());
}

#[tokio::test]
async fn a_regular_file_at_the_path_is_refused_and_kept() {
    let (_dir, path) = socket_in();
    std::fs::write(&path, "kept").expect("a file");

    let refused = LocalSocket::bind(&path, 0o600, Bounds::SERVING)
        .err()
        .expect("not a socket");
    assert_eq!(refused.kind(), ErrorKind::AlreadyExists);
    assert_eq!(std::fs::read_to_string(&path).expect("the file"), "kept");
}

#[tokio::test]
async fn an_empty_or_abstract_path_is_refused() {
    for path in ["", "\0abstract"] {
        let refused = LocalSocket::bind(path, 0o600, Bounds::SERVING)
            .err()
            .expect("refused");
        assert_eq!(refused.kind(), ErrorKind::InvalidInput, "{path:?}");
    }
}

/// 103 bytes fits `sun_path` on macOS (104) and Linux (108); staged as
/// `.<pid>.<n>/s` in place of the one-byte name, it fits neither.
#[tokio::test]
async fn a_path_too_long_once_staged_is_refused_by_name() {
    let dir = tempfile::tempdir().expect("a tempdir");
    let padding = 103 - dir.path().as_os_str().len() - "/".len() - "/s".len();
    let parent = dir.path().join("p".repeat(padding));
    std::fs::create_dir(&parent).expect("the parent");
    let path = parent.join("s");
    assert_eq!(path.as_os_str().len(), 103);

    let refused = LocalSocket::bind(&path, 0o600, Bounds::SERVING)
        .err()
        .expect("too long");
    assert_eq!(refused.kind(), ErrorKind::InvalidInput);
    assert!(
        refused.to_string().contains("sun_path holds at most"),
        "{refused}"
    );
    assert_eq!(std::fs::read_dir(&parent).expect("the parent").count(), 0);
}

#[tokio::test]
async fn binding_leaves_only_the_socket_in_its_directory() {
    let (dir, path) = socket_in();
    let _socket = bind(&path, Bounds::SERVING);
    let entries: Vec<_> = std::fs::read_dir(dir.path())
        .expect("the tempdir")
        .map(|entry| entry.expect("an entry").path())
        .collect();
    assert_eq!(entries, [path]);
}

#[tokio::test]
async fn the_socket_is_unlinked_once_serving_stops() {
    let (_dir, path) = socket_in();
    let serving = Serving::on(bind(&path, Bounds::SERVING));
    assert!(asked(&path, "/peer").await.starts_with("HTTP/1.1 200"));

    serving.stopped().await;
    assert!(!path.exists());
}

#[tokio::test]
async fn a_successors_socket_is_not_unlinked() {
    let (_dir, path) = socket_in();
    let serving = Serving::on(bind(&path, Bounds::SERVING));
    std::fs::remove_file(&path).expect("unlinked by a successor");
    let _successor = std::os::unix::net::UnixListener::bind(&path).expect("the successor");

    serving.stopped().await;
    assert!(std::os::unix::net::UnixStream::connect(&path).is_ok());
}

#[tokio::test]
async fn a_socket_the_caller_bound_is_served_and_not_unlinked() {
    let (_dir, path) = socket_in();
    let listener = tokio::net::UnixListener::bind(&path).expect("bind");
    let socket = LocalSocket::from_listener(listener, Bounds::SERVING).expect("held");
    assert_eq!(socket.path(), path);
    let serving = Serving::on(socket);
    assert!(asked(&path, "/peer").await.starts_with("HTTP/1.1 200"));

    serving.stopped().await;
    assert!(path.exists());
}

#[tokio::test]
async fn a_request_in_flight_at_the_stop_is_finished() {
    let (_dir, path) = socket_in();
    let serving = Serving::on(bind(&path, Bounds::SERVING));
    let asking = tokio::spawn({
        let path = path.clone();
        async move { asked(&path, "/slow").await }
    });
    tokio::time::sleep(BRIEF / 4).await;

    serving.stopped().await;
    assert!(asking.await.expect("did not panic").ends_with("done"));
}

#[tokio::test]
async fn a_stalled_request_is_closed_at_the_grace_period() {
    let (_dir, path) = socket_in();
    let serving = Serving::on(bind(
        &path,
        Bounds {
            grace: BRIEF,
            ..Bounds::SERVING
        },
    ));
    let mut peer = dial(&path).await;
    peer.write_all(b"GET /stalled HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("a request");
    tokio::time::sleep(BRIEF / 4).await;

    let stopping = tokio::time::Instant::now();
    serving.stopped().await;
    assert!(stopping.elapsed() >= BRIEF, "{:?}", stopping.elapsed());
    assert!(closed(&mut peer, PATIENT).await);
}

#[tokio::test]
async fn the_cap_holds_until_the_head_timeout_frees_a_slot() {
    let (_dir, path) = socket_in();
    let _serving = Serving::on(bind(
        &path,
        Bounds {
            connections: 2,
            head: BRIEF,
            grace: BRIEF,
        },
    ));
    let _held = [dial(&path).await, dial(&path).await];
    let mut past = dial(&path).await;
    assert!(!answered(&mut past, BRIEF / 4).await, "served past the cap");
    assert!(
        answered(&mut past, PATIENT).await,
        "the slots were never reclaimed"
    );
}
