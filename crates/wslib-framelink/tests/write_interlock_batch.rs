use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::net::tcp::OwnedWriteHalf;
use wslib_framelink::{FrameLinkSession, SessionConfig};
use wslib_framelink_protocol::frame::{build_frame, parse_frame};
use wslib_framelink_protocol::types::*;

const COMMAND_TIMEOUT: Duration = Duration::from_millis(300);

const TEST_DEADLINE: Duration = Duration::from_secs(5);

const GATED: [u8; 4] = [
    MSG_FRAME_DEF_ADD,
    MSG_XFORM_ADD,
    MSG_GEN_ADD,
    MSG_BRIDGE_ADD,
];

#[derive(Default)]
struct DeviceState {
    locked: bool,
    nonce: u32,
    accepted: Vec<u8>,
    unlocks: usize,
    refuse_unlock: bool,
    stale_unlocks: usize,
    challenges: usize,
    reject_type: Option<u8>,
    challenge_replies: VecDeque<ChallengeReply>,
    held: Option<Vec<u8>>,
    hold_reply_for: Option<u8>,
    held_after_next: Option<Vec<u8>>,
    drop_reply_for: Option<u8>,
    flood_stream: bool,
}

#[derive(Clone, Copy)]
enum ChallengeReply {
    Dropped,
    After(Duration),
    HeldUntilNextFrame,
}

struct Reply {
    bytes: Vec<u8>,
    delay: Option<Duration>,
}

impl Reply {
    fn now(bytes: Vec<u8>) -> Self {
        Self { bytes, delay: None }
    }
}

async fn spawn_device(state: Arc<Mutex<DeviceState>>) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let (mut reader, writer) = socket.into_split();
        let writer = Arc::new(tokio::sync::Mutex::new(writer));
        if state.lock().unwrap().flood_stream {
            let writer = Arc::clone(&writer);
            tokio::spawn(async move {
                let frame = build_frame(MSG_FRAME_RX, FLAG_NONE, 0, &[]);
                loop {
                    if writer.lock().await.write_all(&frame).await.is_err() {
                        return;
                    }
                    tokio::task::yield_now().await;
                }
            });
        }
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let n = match reader.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(n) => n,
            };
            buf.extend_from_slice(&chunk[..n]);
            while let Some(bytes) = take_frame(&mut buf) {
                let frame = parse_frame(&bytes).expect("device: undecodable frame");
                let held = state.lock().unwrap().held.take();
                if let Some(held) = held {
                    write(&writer, &held).await;
                }
                let Some(reply) = handle(&state, &frame) else {
                    continue;
                };
                match reply.delay {
                    None => {
                        write(&writer, &reply.bytes).await;
                        let after = state.lock().unwrap().held_after_next.take();
                        if let Some(after) = after {
                            write(&writer, &after).await;
                        }
                    }
                    Some(delay) => {
                        let writer = Arc::clone(&writer);
                        tokio::spawn(async move {
                            tokio::time::sleep(delay).await;
                            write(&writer, &reply.bytes).await;
                        });
                    }
                }
            }
        }
    });

    addr
}

async fn write(writer: &tokio::sync::Mutex<OwnedWriteHalf>, bytes: &[u8]) {
    let _ = writer.lock().await.write_all(bytes).await;
}

fn handle(
    state: &Arc<Mutex<DeviceState>>,
    frame: &wslib_framelink_protocol::frame::Frame,
) -> Option<Reply> {
    let seq = frame.seq;
    let ack = || Reply::now(build_frame(MSG_ACK, FLAG_RESPONSE, seq, &[]));
    let nack = |code: u8| {
        Reply::now(build_frame(
            MSG_NACK,
            FLAG_RESPONSE | FLAG_ERROR,
            seq,
            &[code],
        ))
    };

    let mut state = state.lock().unwrap();
    match frame.msg_type {
        MSG_WRITE_CHALLENGE => {
            state.challenges += 1;
            state.nonce = state.nonce.wrapping_add(0x1234_5678).max(1);
            let bytes = build_frame(
                MSG_WRITE_CHALLENGE_RESP,
                FLAG_RESPONSE,
                seq,
                &state.nonce.to_le_bytes(),
            );
            match state.challenge_replies.pop_front() {
                None => Some(Reply::now(bytes)),
                Some(ChallengeReply::Dropped) => None,
                Some(ChallengeReply::After(delay)) => Some(Reply {
                    bytes,
                    delay: Some(delay),
                }),
                Some(ChallengeReply::HeldUntilNextFrame) => {
                    state.held = Some(bytes);
                    None
                }
            }
        }
        MSG_WRITE_UNLOCK => {
            let current = std::mem::take(&mut state.nonce);
            if state.stale_unlocks > 0 {
                state.stale_unlocks -= 1;
                return Some(nack(ERR_WRITE_LOCKED));
            }
            if state.refuse_unlock {
                return Some(nack(ERR_INVALID_PAYLOAD));
            }
            if current == 0 || frame.payload != current.to_le_bytes() {
                return Some(nack(ERR_WRITE_LOCKED));
            }
            state.locked = false;
            state.unlocks += 1;
            Some(ack())
        }
        msg_type => {
            let reply = if state.locked && GATED.contains(&msg_type) {
                nack(ERR_WRITE_LOCKED)
            } else if state.reject_type == Some(msg_type) {
                nack(ERR_NOT_FOUND)
            } else {
                state.accepted.push(msg_type);
                ack()
            };
            if state.drop_reply_for == Some(msg_type) {
                return None;
            }
            if state.hold_reply_for == Some(msg_type) {
                state.hold_reply_for = None;
                state.held_after_next = Some(reply.bytes);
                return None;
            }
            Some(reply)
        }
    }
}

fn take_frame(buf: &mut Vec<u8>) -> Option<Vec<u8>> {
    let start = buf.iter().position(|&b| b == 0x00)?;
    let end = buf[start + 1..].iter().position(|&b| b == 0x00)? + start + 1;
    let frame = buf[start + 1..end].to_vec();
    buf.drain(..=end);
    Some(frame)
}

async fn session_for(addr: std::net::SocketAddr) -> Arc<FrameLinkSession> {
    FrameLinkSession::connect_with_config(
        addr,
        SessionConfig {
            command_timeout: COMMAND_TIMEOUT,
            ..SessionConfig::default()
        },
    )
    .await
    .unwrap()
}

fn rule_batch() -> Vec<(u8, u8, Vec<u8>)> {
    vec![
        (MSG_FRAME_TX, FLAG_ACK_REQ, vec![0x01]),
        (MSG_XFORM_ADD, FLAG_ACK_REQ, vec![0x02]),
        (MSG_GEN_ADD, FLAG_ACK_REQ, vec![0x03]),
    ]
}

#[tokio::test]
async fn a_locked_device_unlocks_once_and_only_refused_messages_are_resent() {
    let state = Arc::new(Mutex::new(DeviceState {
        locked: true,
        ..DeviceState::default()
    }));
    let addr = spawn_device(Arc::clone(&state)).await;
    let session = session_for(addr).await;

    let responses = session.send_batch(&rule_batch()).await.unwrap();

    assert!(
        responses.iter().all(|f| f.msg_type == MSG_ACK),
        "every message should end up accepted: {:?}",
        responses.iter().map(|f| f.msg_type).collect::<Vec<_>>()
    );
    let state = state.lock().unwrap();
    assert_eq!(state.unlocks, 1, "one unlock should cover the whole batch");
    assert_eq!(
        state.accepted,
        vec![MSG_FRAME_TX, MSG_XFORM_ADD, MSG_GEN_ADD],
        "the ungated message must not be sent again"
    );
}

#[tokio::test]
async fn replies_line_up_with_the_messages_that_produced_them() {
    let state = Arc::new(Mutex::new(DeviceState {
        locked: true,
        reject_type: Some(MSG_GEN_ADD),
        ..DeviceState::default()
    }));
    let addr = spawn_device(Arc::clone(&state)).await;
    let session = session_for(addr).await;

    let responses = session.send_batch(&rule_batch()).await.unwrap();

    assert_eq!(responses[0].msg_type, MSG_ACK);
    assert_eq!(responses[1].msg_type, MSG_ACK);
    assert_eq!(
        responses[2].msg_type, MSG_NACK,
        "the rejected message's own reply must land in its own slot"
    );
    assert_eq!(nack_code(&responses[2].payload), ERR_NOT_FOUND);
}

#[tokio::test]
async fn replies_that_arrive_out_of_order_still_land_in_their_own_slots() {
    let state = Arc::new(Mutex::new(DeviceState {
        hold_reply_for: Some(MSG_XFORM_ADD),
        reject_type: Some(MSG_GEN_ADD),
        ..DeviceState::default()
    }));
    let addr = spawn_device(Arc::clone(&state)).await;
    let session = session_for(addr).await;

    let responses = session.send_batch(&rule_batch()).await.unwrap();

    let kinds: Vec<u8> = responses.iter().map(|f| f.msg_type).collect();
    assert_eq!(
        kinds,
        vec![MSG_ACK, MSG_ACK, MSG_NACK],
        "the NACK arrived second but belongs to the third request"
    );
    assert_eq!(nack_code(&responses[2].payload), ERR_NOT_FOUND);
}

#[tokio::test]
async fn a_device_that_will_not_unlock_fails_the_batch() {
    let state = Arc::new(Mutex::new(DeviceState {
        locked: true,
        refuse_unlock: true,
        ..DeviceState::default()
    }));
    let addr = spawn_device(Arc::clone(&state)).await;
    let session = session_for(addr).await;

    let result = session.send_batch(&rule_batch()).await;

    let rendered = result
        .expect_err("a batch that cannot be unlocked must fail")
        .to_string();
    assert!(
        rendered.contains("unlock"),
        "the failure must name the unlock: {rendered}"
    );
}

#[tokio::test]
async fn a_stale_nonce_is_answered_with_a_fresh_challenge() {
    let state = Arc::new(Mutex::new(DeviceState {
        locked: true,
        stale_unlocks: 1,
        ..DeviceState::default()
    }));
    let addr = spawn_device(Arc::clone(&state)).await;
    let session = session_for(addr).await;

    let responses = session.send_batch(&rule_batch()).await.unwrap();

    assert!(
        responses.iter().all(|f| f.msg_type == MSG_ACK),
        "a stale nonce is not a failure — challenge again and carry on"
    );
    let state = state.lock().unwrap();
    assert_eq!(
        state.challenges, 2,
        "the second attempt must ask for a new nonce, never re-send the old challenge"
    );
    assert_eq!(state.unlocks, 1);
}

#[tokio::test]
async fn endless_stale_nonces_end_the_attempt() {
    let state = Arc::new(Mutex::new(DeviceState {
        locked: true,
        stale_unlocks: usize::MAX,
        ..DeviceState::default()
    }));
    let addr = spawn_device(Arc::clone(&state)).await;
    let session = session_for(addr).await;

    let result = session.send_batch(&rule_batch()).await;

    assert!(
        result.is_err(),
        "retrying a stale nonce forever is not a plan"
    );
    let challenges = state.lock().unwrap().challenges;
    assert!(
        (2..=4).contains(&challenges),
        "attempts must be bounded and more than one, saw {challenges}"
    );
}

#[tokio::test]
async fn an_unlocked_device_needs_no_unlock_exchange() {
    let state = Arc::new(Mutex::new(DeviceState::default()));
    let addr = spawn_device(Arc::clone(&state)).await;
    let session = session_for(addr).await;

    session.send_batch(&rule_batch()).await.unwrap();

    assert_eq!(state.lock().unwrap().unlocks, 0);
}

#[tokio::test]
async fn a_late_challenge_reply_is_never_taken_as_the_unlock_verdict() {
    let state = Arc::new(Mutex::new(DeviceState {
        locked: true,
        challenge_replies: VecDeque::from([
            ChallengeReply::After(COMMAND_TIMEOUT + COMMAND_TIMEOUT / 6),
            ChallengeReply::HeldUntilNextFrame,
        ]),
        ..DeviceState::default()
    }));
    let addr = spawn_device(Arc::clone(&state)).await;
    let session = session_for(addr).await;

    let responses = session.send_batch(&rule_batch()).await.unwrap();

    assert!(
        responses.iter().all(|f| f.msg_type == MSG_ACK),
        "a stray challenge reply must not shift the batch's replies: {:?}",
        responses.iter().map(|f| f.msg_type).collect::<Vec<_>>()
    );
    let state = state.lock().unwrap();
    assert_eq!(state.unlocks, 1);
    assert_eq!(
        state.accepted,
        vec![MSG_FRAME_TX, MSG_XFORM_ADD, MSG_GEN_ADD]
    );
}

#[tokio::test]
async fn a_refused_unlock_is_reported_as_refused_even_after_a_silent_challenge() {
    let state = Arc::new(Mutex::new(DeviceState {
        locked: true,
        stale_unlocks: usize::MAX,
        challenge_replies: VecDeque::from([ChallengeReply::Dropped]),
        ..DeviceState::default()
    }));
    let addr = spawn_device(Arc::clone(&state)).await;
    let session = session_for(addr).await;

    let error = session.send_batch(&rule_batch()).await.unwrap_err();

    assert!(
        matches!(error, wslib_framelink::Error::WriteLocked(_)),
        "the last attempt was refused, so the error must not blame silence: {error}"
    );
}

#[tokio::test]
async fn a_lost_reply_still_times_out_under_a_gapless_stream() {
    let state = Arc::new(Mutex::new(DeviceState {
        flood_stream: true,
        drop_reply_for: Some(MSG_GEN_ADD),
        ..DeviceState::default()
    }));
    let addr = spawn_device(Arc::clone(&state)).await;
    let session = session_for(addr).await;

    let result = tokio::time::timeout(TEST_DEADLINE, session.send_batch(&rule_batch()))
        .await
        .expect("the reply deadline must fire even when frames never stop arriving");

    assert!(
        matches!(result, Err(wslib_framelink::Error::Timeout(_))),
        "got {result:?}"
    );
}
