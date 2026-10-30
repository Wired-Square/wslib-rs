//! What a session makes of the bytes a device sends: frames the link drops,
//! and a device identified from its replies. The device is a loopback fake.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use wslib_framelink::{
    DEFAULT_TX_QUEUE_DEPTH, Error, FrameLinkSession, FramingStats, SessionConfig,
};
use wslib_framelink_protocol::frame::{Frame, HEADER_SIZE, build_frame, parse_unstuffed};
use wslib_framelink_protocol::stream::{FrameMetadata, build_frame_rx_entry};
use wslib_framelink_protocol::types::*;
use wslib_framing::cobs::{self, CobsDecoder};

/// A device that writes `reply(request)` for each frame it reads.
async fn device(reply: impl Fn(&Frame) -> Vec<u8> + Send + 'static) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut decoder = CobsDecoder::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = match socket.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => n,
            };
            for block in decoder.feed(&buf[..n]) {
                let request = parse_unstuffed(&block.bytes).unwrap();
                if socket.write_all(&reply(&request)).await.is_err() {
                    return;
                }
            }
        }
    });
    addr
}

fn reply(request: &Frame, msg_type: u8, payload: &[u8]) -> Vec<u8> {
    build_frame(msg_type, FLAG_RESPONSE, request.seq, payload)
}

#[tokio::test]
async fn an_oversized_and_a_malformed_block_are_counted_and_the_link_carries_on() {
    let longest_payload = vec![0x11; u16::MAX.into()];
    let expected = longest_payload.clone();
    let addr = device(move |request| {
        let mut wire = vec![0x11; cobs::max_stuffed_len(HEADER_SIZE + u16::MAX as usize) + 1];
        wire.push(0x00);
        wire.extend([0x03, 0x11, 0x00]);
        wire.extend(reply(request, MSG_PONG, &longest_payload));
        wire
    })
    .await;
    let session = FrameLinkSession::connect(addr).await.unwrap();
    assert_eq!(session.framing_stats(), FramingStats::default());

    let pong = session.request(MSG_PING, FLAG_ACK_REQ, &[]).await.unwrap();

    assert_eq!(pong.msg_type, MSG_PONG);
    assert_eq!(pong.payload, expected, "the longest frame fits the cap");
    assert_eq!(
        session.framing_stats(),
        FramingStats {
            abandoned_frames: 1,
            malformed_frames: 1,
            stream_dropped: 0,
        }
    );
}

fn string_meta(id: u8, value: &str) -> Vec<u8> {
    let mut meta = vec![id, QTY_STRING, value.len() as u8];
    meta.extend_from_slice(value.as_bytes());
    meta
}

fn capabilities(metas: &[Vec<u8>]) -> Vec<u8> {
    let mut payload = vec![metas.len() as u8];
    metas.iter().for_each(|m| payload.extend(m));
    payload.extend([0, 0]);
    payload
}

/// One signal, the first interface's bitrate.
fn signal_list() -> Vec<u8> {
    let mut payload = Vec::new();
    for half in [1u16, 0, 1] {
        payload.extend(half.to_le_bytes());
    }
    payload.extend(0x0100u16.to_le_bytes());
    payload.extend([
        SIGNAL_TARGET_INTERFACE,
        0,
        ROLE_CONFIG,
        QTY_DATARATE,
        ASPECT_DEFAULT,
        SIGNAL_CHANNEL_NONE,
        0,
        0,
        4,
    ]);
    payload.extend(1.0f32.to_le_bytes());
    payload.extend(0.0f32.to_le_bytes());
    payload.extend([0; 16]);
    payload
}

fn identifying_device(caps: Vec<u8>) -> impl Fn(&Frame) -> Vec<u8> + Send + 'static {
    move |request| match request.msg_type {
        MSG_CAPABILITIES_REQ => reply(request, MSG_CAPABILITIES_RESP, &caps),
        MSG_DSIG_LIST => reply(request, MSG_DSIG_LIST_RESP, &signal_list()),
        _ => reply(request, MSG_NACK, &[ERR_UNKNOWN_TYPE]),
    }
}

#[tokio::test]
async fn identify_names_the_board_and_reads_the_signals() {
    let caps = capabilities(&[
        string_meta(META_BOARD_NAME, "wiredflexlink"),
        string_meta(META_BOARD_REVISION, "esp32c6-v0.0.2"),
    ]);
    let addr = device(identifying_device(caps)).await;
    let session = FrameLinkSession::connect(addr).await.unwrap();

    let identity = session.identify().await.unwrap();

    assert_eq!(identity.board_name, "wiredflexlink");
    assert_eq!(identity.board_revision, "esp32c6-v0.0.2");
    assert_eq!(identity.device_id, None);
    assert_eq!(identity.tx_queue_depth, DEFAULT_TX_QUEUE_DEPTH);
    let board = identity.board_def.expect("an embedded board");
    assert_eq!(board.revision, "esp32c6-v0.0.2");
    assert_eq!(identity.signals.len(), 1);
    assert_eq!(
        board.signal_name(&identity.signals[0].key()),
        Some("CAN0 Bitrate")
    );
}

#[tokio::test]
async fn identify_reads_the_reported_queue_depth_and_device_id() {
    let caps = capabilities(&[
        string_meta(META_BOARD_NAME, "unknown-board"),
        string_meta(META_BOARD_REVISION, "a"),
        string_meta(META_DEVICE_ID, "9C1C"),
        vec![META_TX_QUEUE_DEPTH, QTY_COUNT, 2, 16, 0],
    ]);
    let addr = device(identifying_device(caps)).await;
    let session = FrameLinkSession::connect(addr).await.unwrap();

    let identity = session.identify().await.unwrap();

    assert_eq!(identity.device_id.as_deref(), Some("9C1C"));
    assert_eq!(identity.tx_queue_depth, 16);
    assert!(identity.board_def.is_none());
}

#[tokio::test]
async fn a_device_that_names_no_board_is_not_identified() {
    let caps = capabilities(&[string_meta(META_BOARD_REVISION, "a")]);
    let addr = device(identifying_device(caps)).await;
    let session = FrameLinkSession::connect(addr).await.unwrap();

    let err = session.identify().await.unwrap_err();

    assert!(matches!(err, Error::MissingIdentity("board name")), "{err}");
}

/// Well inside any timeout a session would otherwise wait out.
const PROMPTLY: Duration = Duration::from_secs(1);

/// A FRAME_RX of `count` CAN frames, ids counting up from `first_id`.
fn frame_rx(first_id: u32, count: u16) -> Vec<u8> {
    let mut payload = count.to_le_bytes().to_vec();
    for id in first_id..first_id + u32::from(count) {
        let meta = FrameMetadata::Can {
            can_id: id,
            dlc: 1,
            flags: 0,
        };
        build_frame_rx_entry(&mut payload, 0, 0, &meta, &[0xAA]);
    }
    build_frame(MSG_FRAME_RX, FLAG_NONE, 0, &payload)
}

fn can_id(frame: &wslib_framelink_protocol::stream::StreamFrame) -> u32 {
    match frame.metadata {
        FrameMetadata::Can { can_id, .. } => can_id,
        _ => panic!("not CAN: {frame:?}"),
    }
}

#[tokio::test]
async fn a_connect_that_never_completes_times_out() {
    let config = SessionConfig {
        connect_timeout: Duration::from_millis(200),
        ..SessionConfig::default()
    };
    let started = Instant::now();
    // TEST-NET-1: routed nowhere, so a connect either hangs or is refused.
    let result =
        FrameLinkSession::connect_with_config("192.0.2.1:120".parse().unwrap(), config).await;
    assert!(started.elapsed() < PROMPTLY, "{:?}", started.elapsed());
    assert!(
        matches!(result, Err(Error::Timeout(_) | Error::Io(_))),
        "{:?}",
        result.err()
    );
}

#[tokio::test]
async fn a_peer_that_hangs_up_ends_the_session() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 64];
        let _ = socket.read(&mut buf).await;
    });
    let session = FrameLinkSession::connect(addr).await.unwrap();

    let pending = tokio::time::timeout(PROMPTLY, session.request(MSG_PING, FLAG_ACK_REQ, &[]))
        .await
        .expect("a pending request fails promptly");
    assert!(
        matches!(pending, Err(Error::ConnectionClosed)),
        "{pending:?}"
    );

    let stream = tokio::time::timeout(PROMPTLY, session.recv_stream_frame())
        .await
        .expect("the stream ends promptly");
    assert!(stream.is_none());

    tokio::time::timeout(PROMPTLY, async {
        while session.is_alive() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the session task exits");

    let later = tokio::time::timeout(PROMPTLY, session.request(MSG_PING, FLAG_ACK_REQ, &[]))
        .await
        .expect("a later request fails promptly");
    assert!(matches!(later, Err(Error::ConnectionClosed)), "{later:?}");
}

#[tokio::test]
async fn frames_streamed_ahead_of_a_reply_reach_the_stream() {
    let addr = device(|request| {
        let mut wire = frame_rx(0x100, 1);
        wire.extend(reply(request, MSG_PONG, &[]));
        wire
    })
    .await;
    let session = FrameLinkSession::connect(addr).await.unwrap();

    let pong = session.request(MSG_PING, FLAG_ACK_REQ, &[]).await.unwrap();

    assert_eq!(pong.msg_type, MSG_PONG);
    let streamed = tokio::time::timeout(PROMPTLY, session.recv_stream_frame())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(can_id(&streamed), 0x100);
}

#[tokio::test]
async fn a_request_dropped_mid_flight_leaves_the_session_usable() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut decoder = CobsDecoder::new();
        let mut buf = [0u8; 4096];
        let mut answered = 0;
        loop {
            let n = match socket.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => n,
            };
            for block in decoder.feed(&buf[..n]) {
                let request = parse_unstuffed(&block.bytes).unwrap();
                if answered == 0 {
                    tokio::time::sleep(Duration::from_millis(150)).await;
                }
                answered += 1;
                let payload = [answered];
                socket
                    .write_all(&reply(&request, MSG_PONG, &payload))
                    .await
                    .unwrap();
            }
        }
    });
    let session = FrameLinkSession::connect(addr).await.unwrap();

    let abandoned = tokio::time::timeout(
        Duration::from_millis(30),
        session.request(MSG_PING, FLAG_ACK_REQ, &[]),
    )
    .await;
    assert!(abandoned.is_err(), "the first reply is held back");

    let pong = tokio::time::timeout(PROMPTLY, session.request(MSG_PING, FLAG_ACK_REQ, &[]))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pong.payload, [2], "the second request gets its own reply");
}

#[tokio::test]
async fn frames_the_stream_has_no_room_for_are_counted() {
    const STREAMED: u32 = 5000;
    const CHANNEL: u32 = 4096;
    let addr = device(|request| {
        let mut wire = Vec::new();
        for first in (0..STREAMED).step_by(100) {
            wire.extend(frame_rx(first, 100));
        }
        wire.extend(reply(request, MSG_PONG, &[]));
        wire
    })
    .await;
    let session = FrameLinkSession::connect(addr).await.unwrap();

    session.request(MSG_PING, FLAG_ACK_REQ, &[]).await.unwrap();

    assert_eq!(
        session.framing_stats().stream_dropped,
        u64::from(STREAMED - CHANNEL)
    );
    let first = session.recv_stream_frame().await.unwrap();
    assert_eq!(can_id(&first), 0, "the oldest frames are kept");
}

#[tokio::test]
async fn a_nack_to_a_typed_request_is_the_devices_error() {
    let addr = device(|request| reply(request, MSG_NACK, &[ERR_UNKNOWN_TYPE])).await;
    let session = FrameLinkSession::connect(addr).await.unwrap();

    let err = session.list_all_signals().await.unwrap_err();

    assert!(
        matches!(
            err,
            Error::Nack {
                request: MSG_DSIG_LIST,
                code: ERR_UNKNOWN_TYPE
            }
        ),
        "{err}"
    );
}

#[tokio::test]
async fn a_reply_of_the_wrong_type_is_named() {
    let addr = device(|request| reply(request, MSG_PONG, &[])).await;
    let session = FrameLinkSession::connect(addr).await.unwrap();

    let err = session.capabilities().await.unwrap_err();

    assert!(
        matches!(
            err,
            Error::UnexpectedReply {
                request: MSG_CAPABILITIES_REQ,
                reply: MSG_PONG
            }
        ),
        "{err}"
    );
}
