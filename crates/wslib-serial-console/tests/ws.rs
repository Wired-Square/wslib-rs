use std::{future::Future, net::SocketAddr, time::Duration};

use axum::{
    extract::{FromRef, FromRequestParts, State},
    http::request::Parts,
    response::Response,
};
use futures_util::{SinkExt, StreamExt};
use tokio::{net::TcpStream, time::timeout};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, connect_async,
    tungstenite::{Message, client::IntoClientRequest},
};
use wslib_serial_console::{
    ConsoleEvent, EndReason, Finished, MonitorOptions, MonitorState, Monitors, Participant,
    PortKey, RefusalReason, Span, Update,
    test_support::{FakeDevice, FakePorts, StopReaders, Wired},
    ws::{Attendee, ConsoleHooks, console, frames, text_frame},
};

const PATH: &str = "/dev/ttyACM0";
const HELD: &str = "/dev/held";
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

/// The attendee is named by `x-name`, and writes unless `x-watch` is sent.
struct Hooks;

impl ConsoleHooks<Desk> for Hooks {
    async fn attendee(&self, desk: &Desk, request: &mut Parts) -> Result<Attendee, Response> {
        let Ok(State(Via(via))) = State::<Via>::from_request_parts(request, desk).await;
        let header = |name| request.headers.get(name).and_then(|v| v.to_str().ok());
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
}

struct Bench {
    at: SocketAddr,
    ports: FakePorts,
    monitors: Monitors,
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
        let app = axum::Router::new()
            .route("/ws/serial", console(monitors.clone(), Hooks))
            .with_state(desk);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let at = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self {
            at,
            ports,
            _stop: StopReaders(monitors.clone()),
            monitors,
        }
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
