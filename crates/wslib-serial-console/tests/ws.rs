use std::{
    future::Future,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    body::Body,
    extract::{FromRef, FromRequestParts, State},
    http::{Method, StatusCode, request::Parts},
    response::{IntoResponse, Response},
};
use futures_util::{SinkExt, StreamExt};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, connect_async,
    tungstenite::{Message, client::IntoClientRequest, protocol::Role},
};
use wslib_serial_console::{
    ConsoleEvent, EndReason, Finished, MonitorOptions, MonitorState, Monitors, Participant,
    PortKey, RefusalReason, Span, Update,
    test_support::{FakeDevice, FakePorts, StopReaders, Wired},
    ws::{Attendee, Audit, ConsoleHooks, console, frames, text_frame},
};

const PATH: &str = "/dev/ttyACM0";
const HELD: &str = "/dev/held";
/// Where the USB serial [`HELD_SERIAL`] resolves, a path the host holds.
const HELD_USB: &str = "/dev/ttyUSB-held";
const HELD_SERIAL: &str = "0042";
const WAIT: Duration = Duration::from_secs(5);

type Browser = WebSocketStream<MaybeTlsStream<TcpStream>>;

#[derive(Clone)]
struct Desk {
    via: Via,
    held: &'static str,
}

/// Where the router's consoles are attached from, taken by an extractor.
#[derive(Clone)]
struct Via(&'static str);

impl FromRef<Desk> for Via {
    fn from_ref(desk: &Desk) -> Self {
        desk.via.clone()
    }
}

/// The attendee is named by `x-name`, writes unless `x-watch` is sent, and is
/// refused with `x-deny`. Each audit is logged as `name what`.
#[derive(Clone, Default)]
struct Hooks(Arc<Mutex<Vec<String>>>);

impl Hooks {
    fn audited(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }
}

impl ConsoleHooks<Desk> for Hooks {
    async fn attendee(&self, desk: &Desk, request: &mut Parts) -> Result<Attendee, Response> {
        let Ok(State(Via(via))) = State::<Via>::from_request_parts(request, desk).await;
        let header = |name| request.headers.get(name).and_then(|v| v.to_str().ok());
        if header("x-deny").is_some() {
            return Err(StatusCode::UNAUTHORIZED.into_response());
        }
        Ok(Attendee {
            name: header("x-name").unwrap_or("anonymous").to_owned(),
            writes: header("x-watch").is_none(),
            via: via.into(),
        })
    }

    async fn may_open(&self, desk: &Desk, key: &PortKey) -> Result<(), String> {
        match key {
            PortKey::Path(path) if path == desk.held => Err("an app holds the port".into()),
            _ => Ok(()),
        }
    }

    async fn may_open_path(
        &self,
        desk: &Desk,
        key: &PortKey,
        path: Option<&str>,
    ) -> Result<(), String> {
        match path {
            Some(HELD_USB) => Err(format!("{key} is {HELD_USB}, which an app holds")),
            _ => self.may_open(desk, key).await,
        }
    }

    fn audit(&self, _: &Desk, key: &PortKey, who: &Attendee, what: Audit<'_>) {
        let what = match what {
            Audit::Wrote(bytes) => format!("wrote {}", String::from_utf8_lossy(bytes)),
            other => format!("{other:?}").to_lowercase(),
        };
        self.0
            .lock()
            .unwrap()
            .push(format!("{} {what} {key}", who.name));
    }
}

struct Bench {
    at: SocketAddr,
    ports: FakePorts,
    monitors: Monitors,
    hooks: Hooks,
    _stop: StopReaders,
}

impl Bench {
    async fn new() -> Self {
        let ports = FakePorts::default();
        let monitors = ports.monitors(MonitorOptions {
            reopen: Duration::from_millis(10),
            ..MonitorOptions::default()
        });
        let desk = Desk {
            via: Via("local"),
            held: HELD,
        };
        let hooks = Hooks::default();
        let app = axum::Router::new()
            .route("/ws/serial", console(monitors.clone(), hooks.clone()))
            .with_state(desk);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let at = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self {
            at,
            ports,
            _stop: StopReaders(monitors.clone()),
            monitors,
            hooks,
        }
    }

    /// The status of a request that doesn't ask to upgrade.
    async fn plain(&self, method: &str, headers: &str) -> String {
        let mut stream = TcpStream::connect(self.at).await.unwrap();
        let request = format!(
            "{method} /ws/serial?address={PATH} HTTP/1.1\r\nhost: {}\r\n{headers}connection: close\r\n\r\n",
            self.at
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = String::new();
        within(stream.read_to_string(&mut response)).await.unwrap();
        response.lines().next().unwrap_or_default().to_owned()
    }

    fn plug(&self) -> FakeDevice {
        self.ports.plug(PATH)
    }

    async fn open(&self, query: &str, headers: &[(&'static str, &str)]) -> Browser {
        let mut request = format!("ws://{}/ws/serial?{query}", self.at)
            .into_client_request()
            .unwrap();
        for (name, value) in headers {
            request.headers_mut().insert(*name, value.parse().unwrap());
        }
        within(connect_async(request)).await.expect("upgrade").0
    }

    /// A console in the session, once it shows the port read.
    async fn console(&self, name: &str) -> Browser {
        let mut browser = self
            .open(&format!("address={PATH}"), &[("x-name", name)])
            .await;
        assert!(matches!(
            event(&mut browser).await,
            ConsoleEvent::Attached { .. }
        ));
        reading(&mut browser).await;
        browser
    }
}

async fn within<F: Future>(test: F) -> F::Output {
    timeout(WAIT, test).await.expect("timed out")
}

async fn frame(browser: &mut Browser) -> Message {
    within(browser.next())
        .await
        .expect("the socket closed")
        .expect("a frame")
}

async fn event(browser: &mut Browser) -> ConsoleEvent {
    match frame(browser).await {
        Message::Text(text) => serde_json::from_str(&text).expect("a console event"),
        other => panic!("not an event: {other:?}"),
    }
}

/// The next event that is not a state or a roster.
async fn next_event(browser: &mut Browser) -> ConsoleEvent {
    loop {
        match event(browser).await {
            ConsoleEvent::State { .. } | ConsoleEvent::Participants { .. } => {}
            other => return other,
        }
    }
}

async fn reading(browser: &mut Browser) {
    while !matches!(
        event(browser).await,
        ConsoleEvent::State {
            state: MonitorState::Reading,
            ..
        }
    ) {}
}

async fn paused(browser: &mut Browser) {
    while !matches!(
        event(browser).await,
        ConsoleEvent::State {
            state: MonitorState::Paused,
            ..
        }
    ) {}
}

async fn quiet(browser: &mut Browser, wanted: impl Fn(&ConsoleEvent) -> bool) -> bool {
    timeout(Duration::from_millis(500), async {
        loop {
            if let Message::Text(text) = frame(browser).await
                && wanted(&serde_json::from_str(&text).unwrap())
            {
                return;
            }
        }
    })
    .await
    .is_err()
}

#[tokio::test]
async fn a_console_is_attached_first_and_its_input_is_written_as_theirs_and_their_echo_marked() {
    let bench = Bench::new().await;
    let mut device = bench.plug();
    let mut browser = bench
        .open(&format!("address={PATH}&baud=74880"), &[("x-name", "alex")])
        .await;
    assert_eq!(
        event(&mut browser).await,
        ConsoleEvent::Attached {
            name: "alex".into(),
            writes: true,
            baud: Some(74880)
        }
    );
    reading(&mut browser).await;

    browser
        .send(Message::Binary(b"ls".to_vec().into()))
        .await
        .unwrap();
    assert_eq!(within(device.read(2)).await, b"ls");
    device.send(b"ls");
    assert_eq!(
        next_event(&mut browser).await,
        ConsoleEvent::Spans {
            spans: vec![Span {
                start: 0,
                len: 2,
                by: "alex".into(),
                colour: 0
            }]
        }
    );
    assert_eq!(
        frame(&mut browser).await,
        Message::Binary(b"ls".to_vec().into())
    );
}

#[tokio::test]
async fn the_roster_reaches_every_console() {
    let bench = Bench::new().await;
    let _device = bench.plug();
    let mut olive = bench.console("olive").await;
    let _alex = bench.console("alex").await;
    let person = |name: &str, colour| Participant {
        name: name.into(),
        via: "local".into(),
        colour,
    };
    loop {
        if let ConsoleEvent::Participants { participants } = event(&mut olive).await
            && participants.len() == 2
        {
            assert_eq!(participants, [person("alex", 1), person("olive", 0)]);
            break;
        }
    }
}

#[tokio::test]
async fn a_console_that_may_only_watch_is_refused_and_nothing_reaches_the_port() {
    let bench = Bench::new().await;
    let mut device = bench.plug();
    let mut browser = bench
        .open(
            &format!("address={PATH}"),
            &[("x-name", "guest"), ("x-watch", "1")],
        )
        .await;
    assert_eq!(
        event(&mut browser).await,
        ConsoleEvent::Attached {
            name: "guest".into(),
            writes: false,
            baud: Some(115200)
        }
    );
    reading(&mut browser).await;

    browser
        .send(Message::Binary(b"x".to_vec().into()))
        .await
        .unwrap();
    browser
        .send(Message::Text(r#"{"action":"reset"}"#.into()))
        .await
        .unwrap();
    let not_permitted = ConsoleEvent::Refused {
        reason: RefusalReason::NotPermitted,
        detail: None,
    };
    assert_eq!(next_event(&mut browser).await, not_permitted);
    assert_eq!(next_event(&mut browser).await, not_permitted);
    assert!(
        timeout(Duration::from_millis(300), device.next())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn a_reset_resets_the_board() {
    let bench = Bench::new().await;
    let mut device = bench.plug();
    let mut browser = bench.console("alex").await;
    browser
        .send(Message::Text(r#"{"action":"reset"}"#.into()))
        .await
        .unwrap();
    assert_eq!(within(device.next()).await, Some(Wired::Dtr(false)));
    assert_eq!(within(device.next()).await, Some(Wired::Dtr(true)));
}

#[tokio::test]
async fn a_reset_refused_during_a_flash_reaches_only_the_console_that_sent_it() {
    let bench = Bench::new().await;
    let _device = bench.plug();
    let mut alex = bench.console("alex").await;
    let mut olive = bench.console("olive").await;
    let key = PortKey::Path(PATH.into());

    within(bench.monitors.pause(&key)).await;
    paused(&mut alex).await;
    paused(&mut olive).await;
    alex.send(Message::Text(r#"{"action":"reset"}"#.into()))
        .await
        .unwrap();
    assert_eq!(
        next_event(&mut alex).await,
        ConsoleEvent::Refused {
            reason: RefusalReason::Paused,
            detail: Some(format!("{PATH} is paused for a flash"))
        }
    );
    assert!(quiet(&mut olive, |e| matches!(e, ConsoleEvent::Refused { .. })).await);

    alex.send(Message::Binary(b"x".to_vec().into()))
        .await
        .unwrap();
    assert!(matches!(
        next_event(&mut alex).await,
        ConsoleEvent::Refused {
            reason: RefusalReason::Paused,
            ..
        }
    ));
    assert!(quiet(&mut olive, |e| matches!(e, ConsoleEvent::Refused { .. })).await);
}

#[tokio::test]
async fn a_port_the_host_holds_is_refused_with_its_reason() {
    let bench = Bench::new().await;
    let mut browser = bench
        .open(&format!("address={HELD}"), &[("x-name", "alex")])
        .await;
    assert_eq!(
        event(&mut browser).await,
        ConsoleEvent::Error {
            message: "an app holds the port".into()
        }
    );
    assert!(matches!(frame(&mut browser).await, Message::Close(_)));
}

#[tokio::test]
async fn a_bounded_console_streams_until_its_bound_and_says_why_it_ended() {
    let bench = Bench::new().await;
    let device = bench.plug();
    let mut logs = bench.open(&format!("address={PATH}&lines=1"), &[]).await;
    reading(&mut logs).await;

    device.send(b"boot\r\nmore");
    assert_eq!(
        frame(&mut logs).await,
        Message::Binary(b"boot\r\nmore".to_vec().into())
    );
    let finished = match frame(&mut logs).await {
        Message::Text(text) => serde_json::from_str::<Finished>(&text).unwrap(),
        other => panic!("{other:?}"),
    };
    assert_eq!(
        finished,
        Finished {
            reason: EndReason::Lines
        }
    );
    assert!(matches!(frame(&mut logs).await, Message::Close(_)));
}

#[tokio::test]
async fn a_console_naming_no_port_is_upgraded_then_told_why_and_closed() {
    let bench = Bench::new().await;
    let mut browser = bench.open("baud=9600", &[]).await;
    assert_eq!(
        event(&mut browser).await,
        ConsoleEvent::Error {
            message: "missing address and usb_serial".into()
        }
    );
    assert!(matches!(frame(&mut browser).await, Message::Close(_)));
}

#[test]
fn an_update_relayed_elsewhere_is_the_frames_a_console_gets() {
    use axum::extract::ws::Message;

    let span = Span {
        start: 0,
        len: 2,
        by: "alex".into(),
        colour: 0,
    };
    let output = Update::Output {
        bytes: b"ls".as_slice().into(),
        spans: vec![span.clone()],
    };
    assert_eq!(
        frames(output),
        [
            text_frame(&ConsoleEvent::Spans { spans: vec![span] }),
            Message::Binary(b"ls".to_vec().into())
        ]
    );
    assert_eq!(
        frames(Update::End(EndReason::Lines)),
        [Message::Text(r#"{"reason":"lines"}"#.into())]
    );
}

#[tokio::test]
async fn a_request_the_host_refuses_gets_its_answer_with_or_without_an_upgrade() {
    let bench = Bench::new().await;
    assert_eq!(
        bench.plain("GET", "x-deny: 1\r\n").await,
        "HTTP/1.1 401 Unauthorized"
    );
    assert_eq!(
        bench.plain("CONNECT", "x-deny: 1\r\n").await,
        "HTTP/1.1 401 Unauthorized"
    );
    assert_eq!(bench.plain("GET", "").await, "HTTP/1.1 400 Bad Request");
    assert_eq!(
        bench.plain("PUT", "").await,
        "HTTP/1.1 405 Method Not Allowed"
    );
    let mut request = format!("ws://{}/ws/serial?address={PATH}", bench.at)
        .into_client_request()
        .unwrap();
    request.headers_mut().insert("x-deny", "1".parse().unwrap());
    assert!(connect_async(request).await.is_err());
}

#[tokio::test]
async fn a_console_opens_over_http2_extended_connect() {
    let bench = Bench::new().await;
    let _device = bench.plug();
    let io = TokioIo::new(TcpStream::connect(bench.at).await.unwrap());
    let (mut send, connection) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .handshake(io)
        .await
        .unwrap();
    tokio::spawn(connection);
    let request = axum::http::Request::builder()
        .method(Method::CONNECT)
        .extension(hyper::ext::Protocol::from_static("websocket"))
        .uri(format!("http://{}/ws/serial?address={PATH}", bench.at))
        .header("sec-websocket-version", "13")
        .header("x-name", "alex")
        .body(Body::empty())
        .unwrap();
    let mut response = within(send.send_request(request)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let upgraded = TokioIo::new(hyper::upgrade::on(&mut response).await.unwrap());
    let mut browser = WebSocketStream::from_raw_socket(upgraded, Role::Client, None).await;
    assert_eq!(
        within(browser.next()).await.unwrap().unwrap(),
        Message::Text(r#"{"type":"attached","name":"alex","writes":true,"baud":115200}"#.into())
    );
}

#[tokio::test]
async fn may_open_is_told_the_path_a_usb_serial_resolves_to() {
    let bench = Bench::new().await;
    let _device = bench.ports.plug_usb(HELD_USB, HELD_SERIAL);
    let mut browser = bench
        .open(&format!("usb_serial={HELD_SERIAL}"), &[("x-name", "alex")])
        .await;
    assert_eq!(
        event(&mut browser).await,
        ConsoleEvent::Error {
            message: format!("usb:{HELD_SERIAL} is {HELD_USB}, which an app holds")
        }
    );
    assert!(matches!(frame(&mut browser).await, Message::Close(_)));
    assert!(
        !bench
            .monitors
            .is_monitored(&PortKey::UsbSerial(HELD_SERIAL.into()))
    );
}

#[tokio::test]
async fn a_revoked_port_tells_each_console_why_then_closes_it() {
    let bench = Bench::new().await;
    let device = bench.plug();
    let mut alex = bench.console("alex").await;
    let mut logs = bench.open(&format!("address={PATH}&lines=5"), &[]).await;
    reading(&mut logs).await;

    let key = PortKey::Path(PATH.into());
    assert!(within(bench.monitors.revoke(&key, "handed to the flasher")).await);
    let revoked = ConsoleEvent::Error {
        message: "handed to the flasher".into(),
    };
    for browser in [&mut alex, &mut logs] {
        assert_eq!(next_event(browser).await, revoked);
        assert!(matches!(frame(browser).await, Message::Close(_)));
    }
    assert!(device.is_closed());
    assert!(!bench.monitors.is_monitored(&key));
}

#[tokio::test]
async fn the_host_audits_attaching_writes_resets_and_detaching() {
    let bench = Bench::new().await;
    let mut device = bench.plug();
    let mut alex = bench.console("alex").await;
    let mut guest = bench
        .open(
            &format!("address={PATH}"),
            &[("x-name", "guest"), ("x-watch", "1")],
        )
        .await;
    reading(&mut guest).await;
    guest
        .send(Message::Binary(b"x".to_vec().into()))
        .await
        .unwrap();
    next_event(&mut guest).await;

    alex.send(Message::Binary(b"ls".to_vec().into()))
        .await
        .unwrap();
    assert_eq!(within(device.read(2)).await, b"ls");
    alex.send(Message::Text(r#"{"action":"reset"}"#.into()))
        .await
        .unwrap();
    assert_eq!(within(device.next()).await, Some(Wired::Dtr(false)));
    alex.close(None).await.unwrap();
    within(async {
        while bench.hooks.audited().len() < 5 {
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert_eq!(
        bench.hooks.audited(),
        [
            format!("alex attached {PATH}"),
            format!("guest attached {PATH}"),
            format!("alex wrote ls {PATH}"),
            format!("alex reset {PATH}"),
            format!("alex detached {PATH}"),
        ]
    );
}
