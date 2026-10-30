use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::net::tcp::OwnedWriteHalf;
use wslib_framelink::{FileUploadOutcome, FrameLinkSession, SessionConfig};
use wslib_framelink_protocol::file_xfer::{FileAction, parse_begin, parse_data, parse_end};
use wslib_framelink_protocol::frame::{build_frame, parse_frame};
use wslib_framelink_protocol::types::*;

const DEVICE_CHUNK: u32 = 64;

const COMMAND_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(300);

const STREAM_INTERVAL: std::time::Duration = std::time::Duration::from_millis(50);

const TEST_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    None,
    DropFirstDataAck,
    DropFirstDataAckWhileStreaming,
    SilentOnAbort,
    DropFinalDataAck,
    DropFirstEndAck,
    RebootOnCommit,
    LinkDropsOnCommit,
    UnknownTarget,
    UnlockRefused,
    RelocksAtCommitThenIgnoresChallenges,
    NackThirdChunk,
    SessionExpiresOnce,
    RelocksOnce,
    SessionAlwaysExpires,
}

#[derive(Default)]
struct DeviceState {
    file: Vec<u8>,
    declared_size: u32,
    declared_crc: u32,
    target: u8,
    receiving: bool,
    committed: bool,
    committed_file: Vec<u8>,
    last_chunk: Option<(u32, usize)>,
    data_writes: usize,
    commits: usize,
    largest_chunk: usize,
    hang_up: bool,
    begins: usize,
    locked: bool,
    nonce: u32,
    relocked: bool,
    expired: bool,
    data_frames: Vec<Vec<u8>>,
}

struct FakeDevice {
    state: Arc<Mutex<DeviceState>>,
}

impl FakeDevice {
    async fn spawn(fault: Fault) -> (std::net::SocketAddr, Arc<Mutex<DeviceState>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(DeviceState::default()));
        let device = FakeDevice {
            state: Arc::clone(&state),
        };

        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let (mut socket, writer) = socket.into_split();
            let writer = Arc::new(tokio::sync::Mutex::new(writer));
            if fault == Fault::DropFirstDataAckWhileStreaming {
                tokio::spawn(stream_frames(Arc::clone(&writer)));
            }
            let mut dropped_data_ack = false;
            let mut dropped_end_ack = false;
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                let n = match socket.read(&mut chunk).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => n,
                };
                buf.extend_from_slice(&chunk[..n]);
                while let Some(frame_bytes) = take_frame(&mut buf) {
                    let frame = parse_frame(&frame_bytes).expect("device: undecodable frame");
                    if frame.msg_type == MSG_FILE_DATA {
                        device
                            .state
                            .lock()
                            .unwrap()
                            .data_frames
                            .push(frame_bytes.clone());
                    }
                    let reply =
                        device.handle(&frame, fault, &mut dropped_data_ack, &mut dropped_end_ack);
                    if let Some(bytes) = reply
                        && writer.lock().await.write_all(&bytes).await.is_err()
                    {
                        return;
                    }
                    if device.state.lock().unwrap().hang_up {
                        let _ = writer.lock().await.shutdown().await;
                        return;
                    }
                }
            }
        });

        (addr, state)
    }

    fn handle(
        &self,
        frame: &wslib_framelink_protocol::frame::Frame,
        fault: Fault,
        dropped_data_ack: &mut bool,
        dropped_end_ack: &mut bool,
    ) -> Option<Vec<u8>> {
        let seq = frame.seq;
        let ack = || Some(build_frame(MSG_ACK, FLAG_RESPONSE, seq, &[]));
        let nack = |code: u8| {
            Some(build_frame(
                MSG_NACK,
                FLAG_RESPONSE | FLAG_ERROR,
                seq,
                &[code],
            ))
        };

        if frame.msg_type == MSG_CAPABILITIES_REQ {
            return Some(build_frame(
                MSG_CAPABILITIES_RESP,
                FLAG_RESPONSE,
                seq,
                &capabilities_payload(),
            ));
        }
        if fault == Fault::UnknownTarget && frame.msg_type == MSG_FILE_BEGIN {
            return nack(ERR_NOT_FOUND);
        }

        let mut state = self.state.lock().unwrap();

        if frame.msg_type == MSG_WRITE_CHALLENGE {
            if fault == Fault::RelocksAtCommitThenIgnoresChallenges && state.relocked {
                return None;
            }
            state.nonce = state.nonce.wrapping_add(0x5EED_1234).max(1);
            let nonce = state.nonce;
            return Some(build_frame(
                MSG_WRITE_CHALLENGE_RESP,
                FLAG_RESPONSE,
                seq,
                &nonce.to_le_bytes(),
            ));
        }
        if frame.msg_type == MSG_WRITE_UNLOCK {
            if fault == Fault::UnlockRefused {
                return nack(ERR_INVALID_PAYLOAD);
            }
            if frame.payload != state.nonce.to_le_bytes() {
                return nack(ERR_WRITE_LOCKED);
            }
            state.locked = false;
            return ack();
        }
        if state.locked
            && matches!(
                frame.msg_type,
                MSG_FILE_BEGIN | MSG_FILE_DATA | MSG_FILE_END
            )
        {
            return nack(ERR_WRITE_LOCKED);
        }
        match frame.msg_type {
            MSG_FILE_BEGIN => {
                let begin = match parse_begin(&frame.payload) {
                    Ok(b) => b,
                    Err(_) => return nack(ERR_INVALID_PAYLOAD),
                };
                if begin.size == 0 {
                    return nack(ERR_INVALID_PAYLOAD);
                }
                let carried = (state.begins + 1, state.nonce, state.relocked, state.expired);
                *state = DeviceState {
                    declared_size: begin.size,
                    declared_crc: begin.crc32,
                    target: begin.target,
                    receiving: true,
                    begins: carried.0,
                    nonce: carried.1,
                    relocked: carried.2,
                    expired: carried.3,
                    ..DeviceState::default()
                };
                ack()
            }
            MSG_FILE_DATA => {
                let data = match parse_data(&frame.payload) {
                    Ok(d) => d,
                    Err(_) => return nack(ERR_INVALID_PAYLOAD),
                };
                if fault == Fault::SessionAlwaysExpires {
                    state.receiving = false;
                    return nack(ERR_INVALID_STATE);
                }
                if fault == Fault::SessionExpiresOnce && !state.expired && state.data_writes == 2 {
                    state.expired = true;
                    state.receiving = false;
                    return nack(ERR_INVALID_STATE);
                }
                if fault == Fault::RelocksOnce && !state.relocked && state.data_writes == 2 {
                    state.relocked = true;
                    state.locked = true;
                    state.receiving = false;
                    return nack(ERR_WRITE_LOCKED);
                }
                if !state.receiving {
                    return nack(ERR_INVALID_STATE);
                }
                if fault == Fault::NackThirdChunk && state.data_writes == 2 {
                    return nack(ERR_RESOURCE_FULL);
                }
                state.largest_chunk = state.largest_chunk.max(data.data.len());
                if state.last_chunk == Some((data.offset, data.data.len())) {
                    return ack();
                }
                if data.offset as usize != state.file.len() {
                    return nack(ERR_INVALID_STATE);
                }
                if data.offset as usize + data.data.len() > state.declared_size as usize {
                    state.receiving = false;
                    return nack(ERR_OUT_OF_RANGE);
                }
                state.file.extend_from_slice(&data.data);
                state.last_chunk = Some((data.offset, data.data.len()));
                state.data_writes += 1;
                if matches!(
                    fault,
                    Fault::DropFirstDataAck | Fault::DropFirstDataAckWhileStreaming
                ) && !*dropped_data_ack
                {
                    *dropped_data_ack = true;
                    return None;
                }
                if fault == Fault::DropFinalDataAck
                    && !*dropped_data_ack
                    && state.file.len() == state.declared_size as usize
                {
                    *dropped_data_ack = true;
                    return None;
                }
                ack()
            }
            MSG_FILE_END => {
                let action = match parse_end(&frame.payload) {
                    Ok(a) => a,
                    Err(_) => return nack(ERR_INVALID_PAYLOAD),
                };
                match action {
                    FileAction::Abort => {
                        if fault == Fault::SilentOnAbort {
                            return None;
                        }
                        state.receiving = false;
                        ack()
                    }
                    FileAction::Commit => {
                        if fault == Fault::RelocksAtCommitThenIgnoresChallenges && !state.relocked {
                            state.relocked = true;
                            state.locked = true;
                            return nack(ERR_WRITE_LOCKED);
                        }
                        if state.committed {
                            return ack();
                        }
                        if !state.receiving {
                            return nack(ERR_INVALID_STATE);
                        }
                        if state.file.len() != state.declared_size as usize {
                            state.receiving = false;
                            return nack(ERR_INVALID_STATE);
                        }
                        let crc = wslib_framelink_protocol::file_xfer::file_crc32(&state.file);
                        if crc != state.declared_crc {
                            state.receiving = false;
                            return nack(ERR_CRC_FAIL);
                        }
                        state.receiving = false;
                        state.committed = true;
                        state.commits += 1;
                        state.committed_file = state.file.clone();
                        if fault == Fault::RebootOnCommit {
                            state.committed = false;
                            state.last_chunk = None;
                            state.file.clear();
                            return None;
                        }
                        if fault == Fault::LinkDropsOnCommit {
                            state.hang_up = true;
                            return None;
                        }
                        if fault == Fault::DropFirstEndAck && !*dropped_end_ack {
                            *dropped_end_ack = true;
                            return None;
                        }
                        ack()
                    }
                    _ => nack(ERR_INVALID_PAYLOAD),
                }
            }
            _ => nack(ERR_UNKNOWN_TYPE),
        }
    }
}

async fn stream_frames(writer: Arc<tokio::sync::Mutex<OwnedWriteHalf>>) {
    let frame = build_frame(MSG_FRAME_RX, FLAG_NONE, 0, &[]);
    loop {
        tokio::time::sleep(STREAM_INTERVAL).await;
        if writer.lock().await.write_all(&frame).await.is_err() {
            return;
        }
    }
}

fn capabilities_payload() -> Vec<u8> {
    let mut payload = vec![1];
    payload.push(META_MAX_FILE_CHUNK);
    payload.push(QTY_COUNT);
    payload.push(4);
    payload.extend_from_slice(&DEVICE_CHUNK.to_le_bytes());
    payload.push(0);
    payload.push(0);
    payload
}

fn take_frame(buf: &mut Vec<u8>) -> Option<Vec<u8>> {
    let start = buf.iter().position(|&b| b == 0x00)?;
    let end = buf[start + 1..].iter().position(|&b| b == 0x00)? + start + 1;
    let frame = buf[start + 1..end].to_vec();
    buf.drain(..=end);
    Some(frame)
}

async fn locked_device(fault: Fault) -> (std::net::SocketAddr, Arc<Mutex<DeviceState>>) {
    let (addr, state) = FakeDevice::spawn(fault).await;
    state.lock().unwrap().locked = true;
    (addr, state)
}

async fn session_for(addr: std::net::SocketAddr) -> Arc<FrameLinkSession> {
    let config = SessionConfig {
        command_timeout: COMMAND_TIMEOUT,
        ..SessionConfig::default()
    };
    FrameLinkSession::connect_with_config(addr, config)
        .await
        .unwrap()
}

fn test_file(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

#[tokio::test]
async fn upload_puts_every_byte_on_the_device_and_commits() {
    let (addr, state) = FakeDevice::spawn(Fault::None).await;
    let session = session_for(addr).await;
    let file = test_file(1000);

    let outcome = session.upload_file(3, &file, None).await.unwrap();

    assert_eq!(outcome, FileUploadOutcome::Committed);
    let state = state.lock().unwrap();
    assert_eq!(state.committed_file, file);
    assert_eq!(state.target, 3);
    assert_eq!(state.commits, 1);
    assert!(
        state.data_writes >= 3,
        "DEVICE_CHUNK must stay small enough for a test file to span the three chunks the mid-transfer faults need, got {} writes",
        state.data_writes
    );
}

#[tokio::test]
async fn upload_never_exceeds_the_advertised_chunk_size() {
    let (addr, state) = FakeDevice::spawn(Fault::None).await;
    let session = session_for(addr).await;

    session
        .upload_file(0, &test_file(1000), None)
        .await
        .unwrap();

    let largest = state.lock().unwrap().largest_chunk;
    assert!(
        largest <= DEVICE_CHUNK as usize,
        "sent a {largest}-byte chunk to a device advertising {DEVICE_CHUNK}"
    );
}

#[tokio::test]
async fn upload_resends_the_same_chunk_when_an_ack_goes_missing() {
    let (addr, state) = FakeDevice::spawn(Fault::DropFirstDataAck).await;
    let session = session_for(addr).await;
    let file = test_file(500);

    let outcome = session.upload_file(0, &file, None).await.unwrap();

    assert_eq!(outcome, FileUploadOutcome::Committed);
    let state = state.lock().unwrap();
    assert_eq!(
        state.committed_file, file,
        "the resent chunk must not be written twice"
    );
}

#[tokio::test]
async fn an_unacked_chunk_holds_back_the_next_and_is_resent_byte_for_byte() {
    let (addr, state) = FakeDevice::spawn(Fault::DropFirstDataAck).await;
    let session = session_for(addr).await;

    session.upload_file(0, &test_file(500), None).await.unwrap();

    let state = state.lock().unwrap();
    assert_eq!(
        state.data_frames[0], state.data_frames[1],
        "the frame after an unacked chunk must be that chunk again, same sequence number: never the next chunk"
    );
}

#[tokio::test]
async fn upload_resends_a_complete_final_chunk_and_still_commits_once() {
    let (addr, state) = FakeDevice::spawn(Fault::DropFinalDataAck).await;
    let session = session_for(addr).await;
    let file = test_file(500);

    let outcome = session.upload_file(0, &file, None).await.unwrap();

    assert_eq!(outcome, FileUploadOutcome::Committed);
    let state = state.lock().unwrap();
    assert_eq!(
        state.committed_file, file,
        "a resend of the last chunk must not append past the declared size"
    );
    assert_eq!(state.commits, 1);
}

#[tokio::test]
async fn upload_resends_file_end_when_the_final_ack_goes_missing() {
    let (addr, state) = FakeDevice::spawn(Fault::DropFirstEndAck).await;
    let session = session_for(addr).await;
    let file = test_file(300);

    let outcome = session.upload_file(0, &file, None).await.unwrap();

    assert_eq!(outcome, FileUploadOutcome::Committed);
    assert_eq!(
        state.lock().unwrap().commits,
        1,
        "a resent FILE_END must not commit a second time"
    );
}

#[tokio::test]
async fn upload_to_a_target_that_reboots_reports_an_unknown_outcome() {
    let (addr, state) = FakeDevice::spawn(Fault::RebootOnCommit).await;
    let session = session_for(addr).await;
    let file = test_file(300);

    let outcome = session.upload_file(0, &file, None).await.unwrap();

    assert_eq!(
        outcome,
        FileUploadOutcome::Unknown,
        "a silent device after commit is not a failure — the caller checks the running build"
    );
    assert_eq!(state.lock().unwrap().committed_file, file);
}

#[tokio::test]
async fn upload_reports_unknown_when_the_link_drops_on_commit() {
    let (addr, state) = FakeDevice::spawn(Fault::LinkDropsOnCommit).await;
    let session = session_for(addr).await;
    let file = test_file(300);

    let outcome = session.upload_file(0, &file, None).await.unwrap();

    assert_eq!(outcome, FileUploadOutcome::Unknown);
    assert_eq!(state.lock().unwrap().committed_file, file);
}

#[tokio::test]
async fn upload_begins_again_when_the_device_has_dropped_the_session() {
    let (addr, state) = FakeDevice::spawn(Fault::SessionExpiresOnce).await;
    let session = session_for(addr).await;
    let file = test_file(1000);
    let (tx, mut rx) = tokio::sync::mpsc::channel(file.len());

    let outcome = session.upload_file(0, &file, Some(tx)).await.unwrap();

    let mut reported = Vec::new();
    while let Ok(progress) = rx.try_recv() {
        reported.push(progress.bytes_done);
    }
    let first_progress = reported.iter().position(|&done| done > 0);
    assert!(
        first_progress.is_some_and(|i| reported[i..].contains(&0)),
        "a restart must report progress back at zero: {reported:?}"
    );

    assert_eq!(outcome, FileUploadOutcome::Committed);
    let state = state.lock().unwrap();
    assert_eq!(state.committed_file, file);
    assert_eq!(
        state.begins, 2,
        "a dropped session must be restarted with FILE_BEGIN, not resumed"
    );
    assert_eq!(state.commits, 1);
}

#[tokio::test]
async fn upload_unlocks_a_locked_device_and_recovers_from_a_relock() {
    let (addr, state) = locked_device(Fault::RelocksOnce).await;
    let session = session_for(addr).await;
    let file = test_file(1000);

    let outcome = session.upload_file(0, &file, None).await.unwrap();

    assert_eq!(outcome, FileUploadOutcome::Committed);
    let state = state.lock().unwrap();
    assert_eq!(state.committed_file, file);
    assert!(
        state.begins >= 2,
        "a relock drops the session, so the transfer restarts: {} begins",
        state.begins
    );
}

#[tokio::test]
async fn upload_gives_up_when_the_device_keeps_dropping_the_session() {
    let (addr, state) = FakeDevice::spawn(Fault::SessionAlwaysExpires).await;
    let session = session_for(addr).await;

    let result = session.upload_file(0, &test_file(1000), None).await;

    assert!(result.is_err(), "endless restarts are not a recovery");
    let begins = state.lock().unwrap().begins;
    assert!(
        begins <= 4,
        "restarts must be bounded, the device saw {begins} begins"
    );
}

#[tokio::test]
async fn abort_is_accepted_when_there_is_no_session_to_abort() {
    let (addr, _state) = FakeDevice::spawn(Fault::None).await;
    let session = session_for(addr).await;

    session.abort_file().await.unwrap();
}

#[tokio::test]
async fn abort_after_a_commit_leaves_the_commit_in_place() {
    let (addr, state) = FakeDevice::spawn(Fault::None).await;
    let session = session_for(addr).await;
    session.upload_file(0, &test_file(300), None).await.unwrap();

    session.abort_file().await.unwrap();

    assert_eq!(
        state.lock().unwrap().commits,
        1,
        "aborting after a commit must not undo or repeat it"
    );
}

#[tokio::test]
async fn upload_surfaces_a_nack_to_file_begin() {
    let (addr, _state) = FakeDevice::spawn(Fault::UnknownTarget).await;
    let session = session_for(addr).await;

    let result = session.upload_file(9, &test_file(300), None).await;

    let rendered = result
        .expect_err("an unknown target must fail the upload")
        .to_string();
    assert!(
        rendered.contains("Not found"),
        "the NACK reason must reach the caller: {rendered}"
    );
}

#[tokio::test]
async fn upload_surfaces_a_nack_that_arrives_mid_transfer() {
    let (addr, _state) = FakeDevice::spawn(Fault::NackThirdChunk).await;
    let session = session_for(addr).await;

    let result = session.upload_file(0, &test_file(1000), None).await;

    let rendered = result
        .expect_err("a rejection mid-transfer must fail the upload")
        .to_string();
    assert!(
        rendered.contains("Resource full"),
        "the NACK reason must reach the caller: {rendered}"
    );
}

#[tokio::test]
async fn abort_ends_a_session_that_is_part_way_through() {
    use wslib_framelink_protocol::file_xfer::{FileBegin, FileData, pack_begin, pack_data};

    let (addr, state) = FakeDevice::spawn(Fault::None).await;
    let session = session_for(addr).await;
    let file = test_file(300);
    let begin = pack_begin(&FileBegin {
        target: 0,
        size: file.len() as u32,
        crc32: wslib_framelink_protocol::file_xfer::file_crc32(&file),
    });
    let first_chunk = pack_data(&FileData {
        offset: 0,
        data: file[..DEVICE_CHUNK as usize].to_vec(),
    });
    session
        .request(MSG_FILE_BEGIN, FLAG_ACK_REQ, &begin)
        .await
        .unwrap();
    session
        .request(MSG_FILE_DATA, FLAG_ACK_REQ, &first_chunk)
        .await
        .unwrap();
    assert!(state.lock().unwrap().receiving);

    session.abort_file().await.unwrap();

    let state = state.lock().unwrap();
    assert!(
        !state.receiving,
        "the device must no longer hold the session"
    );
    assert_eq!(state.commits, 0);
}

#[tokio::test]
async fn an_abort_the_device_never_answers_is_an_error() {
    let (addr, _state) = FakeDevice::spawn(Fault::SilentOnAbort).await;
    let session = session_for(addr).await;

    let result = session.abort_file().await;

    assert!(
        result.is_err(),
        "an unanswered abort may have left the device holding the session"
    );
}

#[tokio::test]
async fn a_lost_ack_is_resent_while_the_device_streams_frames() {
    let (addr, state) = FakeDevice::spawn(Fault::DropFirstDataAckWhileStreaming).await;
    let session = session_for(addr).await;
    let file = test_file(500);

    let outcome = tokio::time::timeout(TEST_DEADLINE, session.upload_file(0, &file, None))
        .await
        .expect("streamed frames must not keep extending the wait for a lost ACK")
        .unwrap();

    assert_eq!(outcome, FileUploadOutcome::Committed);
    assert_eq!(state.lock().unwrap().committed_file, file);
}

#[tokio::test]
async fn upload_to_a_device_that_will_not_unlock_fails_as_write_locked() {
    let (addr, state) = locked_device(Fault::UnlockRefused).await;
    let session = session_for(addr).await;

    let result = session.upload_file(0, &test_file(300), None).await;

    assert!(
        matches!(result, Err(wslib_framelink::Error::WriteLocked(_))),
        "a refused unlock is a write-lock failure, not an unanswered commit: {result:?}"
    );
    assert_eq!(state.lock().unwrap().commits, 0);
}

#[tokio::test]
async fn a_commit_refused_as_locked_is_never_reported_as_unknown() {
    let (addr, state) = FakeDevice::spawn(Fault::RelocksAtCommitThenIgnoresChallenges).await;
    let session = session_for(addr).await;

    let result = tokio::time::timeout(TEST_DEADLINE, session.upload_file(0, &test_file(300), None))
        .await
        .expect("a bounded number of unlock attempts must end the upload");

    assert!(
        matches!(result, Err(wslib_framelink::Error::WriteLocked(_))),
        "the device refused the commit, so a dead unlock must not read as an unanswered commit: {result:?}"
    );
    assert_eq!(state.lock().unwrap().commits, 0);
}
