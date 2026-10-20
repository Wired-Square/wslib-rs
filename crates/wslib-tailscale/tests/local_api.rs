#![cfg(unix)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::UnixListener;
use wslib_tailscale::testing::{self, Answering, FakeNode, FakeTailscaled};
use wslib_tailscale::{BackendState, Error, LocalApi};

fn socket() -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!("wslib-ts-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let socket = dir.join(NEXT.fetch_add(1, Ordering::Relaxed).to_string());
    drop(std::fs::remove_file(&socket));
    socket
}

fn running(node: FakeNode) -> (FakeTailscaled, LocalApi) {
    let fake = FakeTailscaled::new(socket(), node);
    fake.start().unwrap();
    let api = LocalApi::default().with_socket(fake.socket());
    (fake, api)
}

/// Answers every connection with `raw` and closes.
fn answering_raw(raw: Vec<u8>) -> LocalApi {
    let socket = socket();
    let listener = UnixListener::bind(&socket).unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            drop(stream.write_all(&raw).await);
        }
    });
    LocalApi::default().with_socket(socket)
}

#[tokio::test]
async fn an_enrolled_node_reports_its_name_addresses_and_control_server() {
    let (_fake, api) = running(FakeNode::Enrolled);
    let status = api.status().await.unwrap();
    assert_eq!(status.backend_state, BackendState::Running);
    assert_eq!(status.enrolled(), Some(testing::NAME));
    assert_eq!(status.addresses[0].to_string(), testing::ADDRESSES[0]);
    assert!(status.health.is_empty());
    let prefs = api.prefs().await.unwrap();
    assert_eq!(prefs.control_url.as_deref(), Some(testing::CONTROL_URL));
}

#[tokio::test]
async fn a_logout_leaves_the_node_needing_a_login_and_every_request_is_heard() {
    let (fake, api) = running(FakeNode::Enrolled);
    api.logout().await.unwrap();
    api.reset_auth().await.unwrap();
    let status = api.status().await.unwrap();
    assert_eq!(fake.node(), FakeNode::LoggedOut);
    assert_eq!(status.backend_state, BackendState::NeedsLogin);
    assert_eq!(status.enrolled(), None);
    assert_eq!(
        fake.heard(),
        [
            "POST /localapi/v0/logout",
            "POST /localapi/v0/reset-auth",
            "GET /localapi/v0/status?peers=false",
        ]
    );
}

#[tokio::test]
async fn no_socket_or_one_left_behind_is_absent() {
    let api = LocalApi::default().with_socket(socket());
    assert!(matches!(api.status().await, Err(Error::Absent)));

    let stale = socket();
    drop(std::os::unix::net::UnixListener::bind(&stale).unwrap());
    let api = LocalApi::default().with_socket(stale);
    assert!(matches!(api.status().await, Err(Error::Absent)));
}

#[tokio::test]
async fn a_stopped_fake_is_absent_until_it_starts_again_with_its_node_kept() {
    let (fake, api) = running(FakeNode::Enrolled);
    fake.set_node(FakeNode::LoggedOut);
    fake.stop();
    assert!(matches!(api.status().await, Err(Error::Absent)));
    fake.start().unwrap();
    assert_eq!(api.status().await.unwrap().enrolled(), None);
}

#[tokio::test]
async fn a_tailscaled_that_never_answers_is_silent() {
    let (fake, api) = running(FakeNode::Enrolled);
    fake.set_answering(Answering::Silently);
    let quick = Duration::from_millis(100);
    let api = api.with_read_timeout(quick).with_change_timeout(quick);
    assert!(matches!(api.status().await, Err(Error::Silent)));
    assert!(matches!(api.logout().await, Err(Error::Silent)));
    assert!(matches!(api.status_within(quick).await, Err(Error::Silent)));
    assert_eq!(fake.node(), FakeNode::Enrolled);
    assert_eq!(fake.heard().len(), 3);
}

#[tokio::test]
async fn a_refusal_keeps_its_status_and_the_first_line_of_its_body_capped() {
    let (fake, api) = running(FakeNode::Enrolled);
    fake.set_answering(Answering::Refusing {
        status: 503,
        body: format!("{}\nsecond line", "x".repeat(300)),
    });
    let Err(Error::Refused { status, said }) = api.status().await else {
        panic!("not refused");
    };
    assert_eq!((status, said), (503, "x".repeat(200)));
}

#[tokio::test]
async fn an_unknown_path_is_refused_as_not_found() {
    let (_fake, api) = running(FakeNode::Enrolled);
    let refused = api.request("GET", "/localapi/v0/nothing").await;
    assert!(matches!(refused, Err(Error::Refused { status: 404, .. })));
}

#[tokio::test]
async fn an_answer_that_is_not_http_or_not_the_json_expected_or_over_1_mib_is_malformed() {
    let header = b"HTTP/1.0 200 OK\r\n\r\n".to_vec();
    let fine = br#"{"BackendState": "Running"}"#.to_vec();
    assert!(
        answering_raw([&header[..], &fine].concat())
            .status()
            .await
            .is_ok()
    );
    let oversized = [&header[..], &fine, &vec![b' '; 1 << 20]].concat();
    for raw in [
        b"nonsense".to_vec(),
        [header, b"{".to_vec()].concat(),
        oversized,
    ] {
        let api = answering_raw(raw);
        assert!(matches!(api.status().await, Err(Error::Malformed(_))));
    }
}
