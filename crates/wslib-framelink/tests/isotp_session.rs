use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::time::{Instant, sleep, timeout};
use wslib_can::{
    CanFrame, CanOptions, CanRead, Direction,
    loopback::{LoopbackBus, LoopbackPort},
};
use wslib_can_bus::OpenError;
use wslib_framelink::{
    BusConfig, CanBus, CanDeviceId, Error, FileProgress, FileUploadOutcome, FrameLinkSession,
    FramingStats, Peer, SessionConfig, can_link_config,
};
use wslib_framelink_protocol::file_xfer::{
    FileAction, file_crc32, parse_begin, parse_data, parse_end,
};
use wslib_framelink_protocol::frame::{Frame, build_frame, parse_unstuffed};
use wslib_framelink_protocol::types::*;
use wslib_framing::cobs::{self, CobsDecoder, DELIMITER};
use wslib_isotp::{IsoTpLink, LinkConfig, Messages, PciKind, Segmenter};

const DEVICE_ID: u32 = 0x02_8F08;
const OVERFILL: usize = 3;
const H2D_ID: u32 = 0x128F_0840;
const D2H_ID: u32 = 0x028F_0841;
const BUS: &str = "slcan=ttyACM0";
const PEER: &str = "can:slcan=ttyACM0@028F08";
const UNOPENABLE_BUS: &str = "slcan=wslib-no-such-port";
const BITRATE: u32 = 500_000;
const V3_NACK: [u8; 7] = [0x36, 0x06, 0x0E, 0x02, 0x00, 0x00, 0x0C];
const PEER_V3: u8 = 3;
const PEER_ON_SLCAN: &str = "can:slcan=wslib-no-such-port@028F08";
const ABSENT_GSUSB_BUS: &str = "gsusb=wslib-no-such-serial";
const DEVICE_CHUNK: u32 = 1428;
const FILE_LEN: usize = 64 * 1024;
const TARGET: u8 = 1;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(3);
const PATIENCE: Duration = Duration::from_secs(600);
const TICK: Duration = Duration::from_millis(10);
const META_COUNT: u8 = 1;
const CHUNK_FIELD_LEN: u8 = size_of::<u32>() as u8;
const NO_INTERFACES: u8 = 0;
const NO_PERIPHERALS: u8 = 0;
const SHORT_CONNECT: Duration = Duration::from_millis(200);
const GVRET_PROBE_TIMEOUT: Duration = Duration::from_millis(1500);
const BATCHED: usize = 2;
const NONCE_STEP: u32 = 0x5EED_1234;
const SMALL_FILE: usize = 300;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    None,
    LoseFlowControlOnSecondData,
    OtherProtocolVersion,
    RebootsLockedOnCommit,
}

#[derive(Default)]
struct DeviceState {
    declared: Option<(u32, u32)>,
    file: Vec<u8>,
    data_messages: usize,
    committed: Option<Vec<u8>>,
}

#[derive(Default)]
struct Wire {
    requests: usize,
    misframed: usize,
    data_arrivals: Vec<Instant>,
    begins: usize,
}

#[derive(Default)]
struct Device {
    state: DeviceState,
    wire: Wire,
    locked: bool,
    nonce: u32,
    rebooted: bool,
    flashed: Option<Vec<u8>>,
}

impl Device {
    fn answer(&mut self, request: &Frame, fault: Fault) -> Option<Vec<u8>> {
        let seq = request.seq;
        let ack = build_frame(MSG_ACK, FLAG_RESPONSE, seq, &[]);
        let locked = build_frame(
            MSG_NACK,
            FLAG_RESPONSE | FLAG_ERROR,
            seq,
            &[ERR_WRITE_LOCKED],
        );
        match request.msg_type {
            MSG_WRITE_CHALLENGE => {
                self.nonce = self.nonce.wrapping_add(NONCE_STEP);
                let nonce = self.nonce.to_le_bytes();
                return Some(build_frame(
                    MSG_WRITE_CHALLENGE_RESP,
                    FLAG_RESPONSE,
                    seq,
                    &nonce,
                ));
            }
            MSG_WRITE_UNLOCK if request.payload == self.nonce.to_le_bytes() => {
                self.locked = false;
                return Some(ack);
            }
            MSG_WRITE_UNLOCK => return Some(locked),
            MSG_FILE_BEGIN | MSG_FILE_DATA | MSG_FILE_END if self.locked => return Some(locked),
            MSG_FILE_BEGIN => self.wire.begins += 1,
            _ => {}
        }
        let reply = self.state.answer(request);
        let commits = request.msg_type == MSG_FILE_END && self.state.committed.is_some();
        if fault == Fault::RebootsLockedOnCommit && commits && !self.rebooted {
            self.flashed = self.state.committed.take();
            self.state = DeviceState::default();
            self.locked = true;
            self.rebooted = true;
            return None;
        }
        Some(reply)
    }
}

impl DeviceState {
    fn answer(&mut self, request: &Frame) -> Vec<u8> {
        let seq = request.seq;
        let ack = build_frame(MSG_ACK, FLAG_RESPONSE, seq, &[]);
        let nack = |code: u8| build_frame(MSG_NACK, FLAG_RESPONSE | FLAG_ERROR, seq, &[code]);
        match request.msg_type {
            MSG_CAPABILITIES_REQ => {
                build_frame(MSG_CAPABILITIES_RESP, FLAG_RESPONSE, seq, &capabilities())
            }
            MSG_FILE_BEGIN => {
                let begin = parse_begin(&request.payload).unwrap();
                *self = DeviceState {
                    declared: Some((begin.size, begin.crc32)),
                    ..DeviceState::default()
                };
                ack
            }
            MSG_FILE_DATA | MSG_FILE_END if self.declared.is_none() => nack(ERR_INVALID_STATE),
            MSG_FILE_DATA => {
                let data = parse_data(&request.payload).unwrap();
                self.data_messages += 1;
                let offset = data.offset as usize;
                if offset + data.data.len() == self.file.len() {
                    return ack;
                }
                if offset != self.file.len() {
                    return nack(ERR_INVALID_STATE);
                }
                self.file.extend_from_slice(&data.data);
                ack
            }
            MSG_FILE_END => {
                assert_eq!(parse_end(&request.payload).unwrap(), FileAction::Commit);
                let whole = Some((self.file.len() as u32, file_crc32(&self.file)));
                if whole != self.declared {
                    return nack(ERR_CRC_FAIL);
                }
                self.committed = Some(self.file.clone());
                ack
            }
            _ => nack(ERR_UNKNOWN_TYPE),
        }
    }
}

fn capabilities() -> Vec<u8> {
    let mut payload = vec![META_COUNT, META_MAX_FILE_CHUNK, QTY_COUNT, CHUNK_FIELD_LEN];
    payload.extend_from_slice(&DEVICE_CHUNK.to_le_bytes());
    payload.extend([NO_INTERFACES, NO_PERIPHERALS]);
    payload
}

fn device_id() -> CanDeviceId {
    CanDeviceId::new(DEVICE_ID).unwrap()
}

fn is_flow_control(frame: &CanFrame) -> bool {
    PciKind::classify(&frame.data) == Some(PciKind::FlowControl)
}

fn device_config() -> LinkConfig {
    let host = can_link_config(device_id());
    LinkConfig::new(host.bus, host.rx_id, host.tx_id)
}

fn one_frame(message: &[u8]) -> bool {
    message.first() == Some(&DELIMITER)
        && message.last() == Some(&DELIMITER)
        && CobsDecoder::new().feed(message).len() == 1
}

async fn respond(
    link: IsoTpLink,
    mut messages: Messages,
    port: LoopbackPort,
    device: Arc<Mutex<Device>>,
    fault: Fault,
) {
    while let Some(message) = messages.recv().await {
        if !one_frame(&message) {
            device.lock().unwrap().wire.misframed += 1;
        }
        for block in CobsDecoder::new().feed(&message) {
            let request = parse_unstuffed(&block.bytes).unwrap();
            let (reply, first_data) = {
                let mut device = device.lock().unwrap();
                device.wire.requests += 1;
                if request.msg_type == MSG_FILE_DATA {
                    device.wire.data_arrivals.push(Instant::now());
                }
                let reply = device.answer(&request, fault);
                let first_data =
                    request.msg_type == MSG_FILE_DATA && device.state.data_messages == 1;
                (reply, first_data)
            };
            let Some(reply) = reply else {
                continue;
            };
            if fault == Fault::LoseFlowControlOnSecondData && first_data {
                port.lose_next_write(is_flow_control);
            }
            let reply = if fault == Fault::OtherProtocolVersion {
                cobs::encode(&V3_NACK)
            } else {
                reply
            };
            link.send(&reply).await.unwrap();
        }
    }
}

struct Rig {
    session: Arc<FrameLinkSession>,
    host_port: LoopbackPort,
    device_port: LoopbackPort,
    device_link: IsoTpLink,
    device: Arc<Mutex<Device>>,
}

impl Rig {
    fn assert_one_frame_per_message(&self) {
        assert_eq!(self.device.lock().unwrap().wire.misframed, 0);
    }
}

fn host_options() -> CanOptions {
    let mut options = CanOptions::default();
    options.reopen = None;
    options
}

async fn rig(fault: Fault) -> Rig {
    let bus = LoopbackBus::default();
    let device_port = bus.port();
    let device_task = device_port.open(CanOptions::default()).await.unwrap();
    let (device_link, device_messages) = IsoTpLink::over(device_task, device_config());
    let device = Arc::new(Mutex::new(Device::default()));
    tokio::spawn(respond(
        device_link.clone(),
        device_messages,
        device_port.clone(),
        device.clone(),
        fault,
    ));

    let host_port = bus.port();
    let host_task = host_port.open(host_options()).await.unwrap();
    let (link, messages) = IsoTpLink::over(host_task, can_link_config(device_id()));
    let config = SessionConfig {
        command_timeout: COMMAND_TIMEOUT,
        ..SessionConfig::default()
    };
    let session =
        FrameLinkSession::connect_isotp(link, messages, BUS.parse().unwrap(), device_id(), config);
    Rig {
        session,
        host_port,
        device_port,
        device_link,
        device,
    }
}

fn test_file() -> Vec<u8> {
    (0..FILE_LEN).map(|i| (i % 251) as u8).collect()
}

async fn upload(rig: &Rig, data: &[u8]) -> (FileUploadOutcome, Vec<FileProgress>) {
    let (progress_tx, mut progress_rx) = mpsc::channel(1);
    let seen = tokio::spawn(async move {
        let mut seen = Vec::new();
        while let Some(progress) = progress_rx.recv().await {
            seen.push(progress);
        }
        seen
    });
    let outcome = timeout(
        PATIENCE,
        rig.session.upload_file(TARGET, data, Some(progress_tx)),
    )
    .await
    .expect("in time")
    .unwrap();
    (outcome, seen.await.unwrap())
}

fn assert_progress_runs_to_the_end(progress: &[FileProgress]) {
    let total = FILE_LEN;
    assert_eq!(
        progress.first(),
        Some(&FileProgress {
            bytes_done: 0,
            total_bytes: total
        })
    );
    assert_eq!(
        progress.last(),
        Some(&FileProgress {
            bytes_done: total,
            total_bytes: total
        })
    );
    assert!(
        progress
            .windows(2)
            .all(|pair| pair[0].bytes_done < pair[1].bytes_done)
    );
    assert_eq!(progress.len(), 1 + FILE_LEN.div_ceil(DEVICE_CHUNK as usize));
}

#[tokio::test(start_paused = true)]
async fn capabilities_cross_iso_tp() {
    let rig = rig(Fault::None).await;
    let capabilities = rig.session.capabilities().await.unwrap();
    assert_eq!(capabilities.max_file_chunk(), Some(DEVICE_CHUNK));
    assert_eq!(rig.session.framing_stats(), FramingStats::default());
    rig.assert_one_frame_per_message();
}

#[tokio::test(start_paused = true)]
async fn capabilities_with_a_lost_flow_control_time_out_with_no_resend() {
    let rig = rig(Fault::None).await;
    rig.device_port.lose_next_write(is_flow_control);
    let asked = Instant::now();
    let refused = rig.session.capabilities().await;
    assert!(
        matches!(refused, Err(Error::Timeout(waited)) if waited == COMMAND_TIMEOUT),
        "{refused:?}"
    );
    assert!(asked.elapsed() >= COMMAND_TIMEOUT);
    assert!(asked.elapsed() < COMMAND_TIMEOUT + TICK);
    assert_eq!(rig.session.framing_stats().send_failures, 1);
    assert_eq!(rig.device.lock().unwrap().wire.requests, 0);
}

#[tokio::test(start_paused = true)]
async fn frames_queued_together_go_as_one_message_each() {
    let rig = rig(Fault::None).await;
    let request = (MSG_CAPABILITIES_REQ, FLAG_ACK_REQ, Vec::new());
    let batch = vec![request; BATCHED];
    let replies = rig.session.send_batch(&batch).await.unwrap();
    assert_eq!(replies.len(), BATCHED);
    assert!(
        replies
            .iter()
            .all(|reply| reply.msg_type == MSG_CAPABILITIES_RESP)
    );
    assert_eq!(rig.device.lock().unwrap().wire.requests, BATCHED);
    rig.assert_one_frame_per_message();
}

#[tokio::test(start_paused = true)]
async fn a_64_kb_upload_reports_its_progress_and_commits() {
    let rig = rig(Fault::None).await;
    let data = test_file();
    let (outcome, progress) = upload(&rig, &data).await;
    assert_eq!(outcome, FileUploadOutcome::Committed);
    assert_progress_runs_to_the_end(&progress);
    {
        let device = rig.device.lock().unwrap();
        assert_eq!(device.state.committed.as_deref(), Some(&data[..]));
        assert_eq!(
            device.state.data_messages,
            FILE_LEN.div_ceil(DEVICE_CHUNK as usize)
        );
    }
    assert_eq!(rig.session.framing_stats().send_failures, 0);
    rig.assert_one_frame_per_message();
}

#[tokio::test(start_paused = true)]
async fn a_lost_flow_control_on_file_data_is_answered_by_the_steps_resend() {
    let rig = rig(Fault::LoseFlowControlOnSecondData).await;
    let data = test_file();
    let (outcome, progress) = upload(&rig, &data).await;
    assert_eq!(outcome, FileUploadOutcome::Committed);
    assert_progress_runs_to_the_end(&progress);
    {
        let device = rig.device.lock().unwrap();
        assert_eq!(device.state.committed.as_deref(), Some(&data[..]));
        let gaps: Vec<Duration> = device
            .wire
            .data_arrivals
            .windows(2)
            .map(|pair| pair[1] - pair[0])
            .collect();
        assert!(gaps[0] >= COMMAND_TIMEOUT, "{gaps:?}");
        assert!(gaps[0] < COMMAND_TIMEOUT * 2, "{gaps:?}");
        assert!(
            gaps[1..].iter().all(|gap| *gap < COMMAND_TIMEOUT),
            "{gaps:?}"
        );
    }
    assert_eq!(rig.session.framing_stats().send_failures, 1);
    assert_eq!(rig.device_link.stats().aborts, 1);
    rig.assert_one_frame_per_message();
}

#[tokio::test(start_paused = true)]
async fn the_session_ends_when_its_link_does() {
    let rig = rig(Fault::None).await;
    rig.session.capabilities().await.unwrap();
    rig.host_port.unplug();
    timeout(PATIENCE, async {
        while rig.session.is_alive() {
            sleep(TICK).await;
        }
    })
    .await
    .expect("the session ends");
    assert!(matches!(
        rig.session.capabilities().await,
        Err(Error::ConnectionClosed)
    ));
}

#[tokio::test(start_paused = true)]
async fn the_peer_is_the_bus_and_device_id() {
    let rig = rig(Fault::None).await;
    let peer = rig.session.addr();
    assert_eq!(
        peer,
        Peer::Can {
            bus: BUS.parse().unwrap(),
            device: device_id(),
        }
    );
    assert_eq!(peer.to_string(), PEER);
    assert_eq!(PEER.parse::<Peer>().unwrap(), peer);
}

#[test]
fn the_link_config_follows_framelinks_can_id_scheme() {
    let config = can_link_config(device_id());
    assert_eq!((config.tx_id, config.rx_id), (H2D_ID, D2H_ID));
    assert_eq!(config.bus, 0);
    assert!(config.extended);
}

#[tokio::test]
async fn a_gsusb_bus_that_is_refused_or_absent_is_can_open() {
    let bus: CanBus = ABSENT_GSUSB_BUS.parse().unwrap();
    let config = SessionConfig {
        can_bus: BusConfig::classic(Some(BITRATE)),
        ..SessionConfig::default()
    };
    let refused = FrameLinkSession::connect_can(&bus, device_id(), config).await;
    assert!(
        matches!(
            &refused,
            Err(Error::CanOpen(
                OpenError::FeatureOff(_) | OpenError::Unreachable(_) | OpenError::Open { .. }
            ))
        ),
        "{:?}",
        refused.err()
    );
}

#[tokio::test]
async fn an_adapter_that_fails_to_open_is_can_open() {
    let closed = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = closed.local_addr().unwrap().port();
    drop(closed);
    let bus: CanBus = format!("gvret={}:{port}", Ipv4Addr::LOCALHOST)
        .parse()
        .unwrap();
    let refused = FrameLinkSession::connect_can(&bus, device_id(), SessionConfig::default()).await;
    assert!(
        matches!(refused, Err(Error::CanOpen(OpenError::Open { .. }))),
        "{:?}",
        refused.err()
    );
}

#[tokio::test]
async fn connect_timeout_bounds_an_adapter_that_never_answers() {
    let silent = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = silent.local_addr().unwrap().port();
    tokio::spawn(async move {
        let held = silent.accept().await;
        std::future::pending::<()>().await;
        drop(held);
    });
    let bus: CanBus = format!("gvret={}:{port}", Ipv4Addr::LOCALHOST)
        .parse()
        .unwrap();
    let config = SessionConfig {
        connect_timeout: SHORT_CONNECT,
        ..SessionConfig::default()
    };
    let asked = std::time::Instant::now();
    let refused = FrameLinkSession::connect_can(&bus, device_id(), config).await;
    assert!(
        matches!(refused, Err(Error::Timeout(waited)) if waited == SHORT_CONNECT),
        "{:?}",
        refused.err()
    );
    assert!(asked.elapsed() < GVRET_PROBE_TIMEOUT);
}

#[tokio::test(start_paused = true)]
async fn messages_the_session_had_no_room_for_are_counted() {
    let task = LoopbackBus::default()
        .port()
        .open(host_options())
        .await
        .unwrap();
    let config = can_link_config(device_id());
    let (link, messages) = IsoTpLink::new(task.writer(), config.clone());
    let single = Segmenter::new(&[DELIMITER]).unwrap().first();
    for _ in 0..Messages::CAPACITY + OVERFILL {
        let frame = CanFrame::data(config.bus, config.rx_id, true, false, false, single.clone());
        link.feed(&CanRead::new(frame, Direction::Rx, SystemTime::UNIX_EPOCH));
    }
    sleep(TICK).await;
    let session = FrameLinkSession::connect_isotp(
        link,
        messages,
        BUS.parse().unwrap(),
        device_id(),
        SessionConfig::default(),
    );
    let stats = session.framing_stats();
    assert_eq!(stats.messages_dropped, OVERFILL as u64);
    assert_eq!(stats.send_failures, 0);
    drop(task);
}

#[tokio::test]
async fn connect_peer_opens_a_can_peer_as_connect_can_does() {
    let closed = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = closed.local_addr().unwrap().port();
    drop(closed);
    let peer: Peer = format!("can:gvret={}:{port}@028F08", Ipv4Addr::LOCALHOST)
        .parse()
        .unwrap();
    let refused = FrameLinkSession::connect_peer(&peer, SessionConfig::default()).await;
    assert!(
        matches!(refused, Err(Error::CanOpen(OpenError::Open { .. }))),
        "{:?}",
        refused.err()
    );
}

#[tokio::test]
async fn connect_can_opens_at_the_configured_bitrate() {
    let bus: CanBus = UNOPENABLE_BUS.parse().unwrap();
    let refused = FrameLinkSession::connect_can(&bus, device_id(), SessionConfig::default()).await;
    assert!(
        matches!(&refused, Err(Error::CanOpen(OpenError::NoBitrate(refused))) if *refused == bus),
        "{:?}",
        refused.err()
    );
    let config = SessionConfig {
        can_bus: BusConfig::classic(Some(BITRATE)),
        ..SessionConfig::default()
    };
    let refused = FrameLinkSession::connect_can(&bus, device_id(), config).await;
    assert!(
        matches!(refused, Err(Error::CanOpen(OpenError::Open { .. }))),
        "{:?}",
        refused.err()
    );
}

#[tokio::test(start_paused = true)]
async fn a_peer_on_another_protocol_version_fails_capabilities_at_once() {
    let rig = rig(Fault::OtherProtocolVersion).await;
    let asked = Instant::now();
    let refused = rig.session.capabilities().await;
    assert!(
        matches!(refused, Err(Error::PeerVersion(PEER_V3))),
        "{:?}",
        refused.err()
    );
    assert!(
        asked.elapsed() < COMMAND_TIMEOUT / 10,
        "{:?}",
        asked.elapsed()
    );
    let stats = rig.session.framing_stats();
    assert_eq!(
        (
            stats.other_version_frames,
            stats.last_other_version,
            stats.unparsed_frames
        ),
        (1, Some(PEER_V3), 0)
    );
}

#[tokio::test]
async fn connect_peer_passes_its_can_bus_config_on() {
    let peer: Peer = PEER_ON_SLCAN.parse().unwrap();
    let refused = FrameLinkSession::connect_peer(&peer, SessionConfig::default()).await;
    assert!(
        matches!(refused, Err(Error::CanOpen(OpenError::NoBitrate(_)))),
        "{:?}",
        refused.err()
    );
    let config = SessionConfig {
        can_bus: BusConfig::fd(Some(BITRATE), None),
        ..SessionConfig::default()
    };
    let refused = FrameLinkSession::connect_peer(&peer, config).await;
    assert!(
        matches!(refused, Err(Error::CanOpen(OpenError::NoDataBitrate(_)))),
        "{:?}",
        refused.err()
    );
    let config = SessionConfig {
        can_bus: BusConfig::classic(Some(BITRATE)),
        ..SessionConfig::default()
    };
    let refused = FrameLinkSession::connect_peer(&peer, config).await;
    assert!(
        matches!(refused, Err(Error::CanOpen(OpenError::Open { .. }))),
        "{:?}",
        refused.err()
    );
}

#[tokio::test(start_paused = true)]
async fn a_resent_commit_to_a_device_that_reboots_locked_is_unknown() {
    let rig = rig(Fault::RebootsLockedOnCommit).await;
    let data: Vec<u8> = test_file().into_iter().take(SMALL_FILE).collect();
    let outcome = timeout(PATIENCE, rig.session.upload_file(TARGET, &data, None))
        .await
        .expect("in time")
        .unwrap();
    assert_eq!(outcome, FileUploadOutcome::Unknown);
    let device = rig.device.lock().unwrap();
    assert_eq!(device.flashed.as_deref(), Some(&data[..]));
    assert_eq!(device.wire.begins, 1);
    assert!(!device.locked);
}
