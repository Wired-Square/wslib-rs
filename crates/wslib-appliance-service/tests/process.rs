//! Which sockets a serving process holds: a binary of its own, so no other
//! test's listener is in the scan, and so it may install the global subscriber.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use wslib_appliance_core::testing::group_of;
use wslib_appliance_service::{LocalBootstrap, LocalEndpoint, Service, install_logs};
use wslib_appliance_store::Store;
use wslib_appliance_types::{Branding, Role};

fn inet_sockets() -> Vec<i32> {
    (0..4096)
        .filter(|&fd| {
            // SAFETY: `address` and `length` are live locals and `length` is
            // `address`'s size; an fd that is not a socket fails and is skipped.
            let mut address: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let mut length = std::mem::size_of_val(&address) as libc::socklen_t;
            let named =
                unsafe { libc::getsockname(fd, (&raw mut address).cast(), &mut length) == 0 };
            named && matches!(i32::from(address.ss_family), libc::AF_INET | libc::AF_INET6)
        })
        .collect()
}

async fn until_bound(socket: &Path) {
    tokio::time::timeout(Duration::from_secs(30), async {
        while !socket.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the socket bound");
}

async fn get_json(socket: &Path, path: &str) -> serde_json::Value {
    let answer = tokio::time::timeout(Duration::from_secs(15), async {
        let mut stream = tokio::net::UnixStream::connect(socket).await.unwrap();
        let request =
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut answer = String::new();
        stream.read_to_string(&mut answer).await.unwrap();
        answer
    })
    .await
    .expect("answered");
    let (head, body) = answer.split_once("\r\n\r\n").expect("a head and a body");
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    serde_json::from_str(body).unwrap_or_else(|e| panic!("{e}: {body}"))
}

#[tokio::test]
async fn serving_locally_holds_no_network_socket_and_names_its_log_file() {
    let planted = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
    assert!(!inet_sockets().is_empty(), "the scan sees a TCP listener");
    drop(planted);

    let _ = rustls::crypto::ring::default_provider().install_default();
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path();
    let state_dir = dir.join("state");
    std::fs::create_dir(&state_dir).unwrap();
    std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let admin = dir.join("admin");
    std::fs::create_dir(&admin).unwrap();
    std::fs::set_permissions(&admin, std::fs::Permissions::from_mode(0o750)).unwrap();
    let socket = admin.join("test.sock");
    let bootstrap = LocalBootstrap {
        db: state_dir.join("test.db"),
        state_dir,
        endpoints: vec![LocalEndpoint {
            path: socket.clone(),
            ceiling: Role::Admin,
            group: group_of(&admin),
        }],
        ui: None,
        log_file: dir.join("test.log"),
    };
    let logs = install_logs(&bootstrap.log_file, &[]).expect("installs");
    let store: Store = bootstrap.open_store(None).await.expect("store");
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let serving = tokio::spawn(async move {
        Service::new(store, Branding::unbranded(), "0.0.0", logs)
            .serve_local(&bootstrap, async {
                stopped.await.ok();
            })
            .await
    });
    until_bound(&socket).await;

    assert_eq!(inet_sockets(), Vec::<i32>::new());

    let snapshot = get_json(&socket, "/api/logs").await;
    assert_eq!(
        snapshot["log_file"],
        dir.join("test.log").display().to_string(),
        "the file install_logs was given: {snapshot}"
    );

    stop.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(15), serving)
        .await
        .expect("stops")
        .expect("did not panic")
        .expect("served");
    assert!(!socket.exists(), "unlinked");
}
