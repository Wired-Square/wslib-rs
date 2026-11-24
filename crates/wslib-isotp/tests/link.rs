use std::{
    collections::VecDeque,
    future::Future,
    time::{Duration, SystemTime},
};

use tokio::time::{Instant, sleep, timeout};
use wslib_can::{
    CanEvent, CanFrame, CanOptions, CanRead, CanTask, CanWriter, Direction, SendRefused,
    WriteFailed,
    loopback::{LoopbackBus, LoopbackPort},
};
use wslib_isotp::{
    FlowControl, FlowStatus, IsoTpLink, LinkConfig, MAX_MESSAGE, Messages, Reassembler, Segmenter,
    SendFailed, StMin, Step,
};

const BUS: u8 = 0;
const OTHER_BUS: u8 = 1;
const H2D: u32 = 0x1012_3440;
const D2H: u32 = 0x0012_3441;
const OTHER_ID: u32 = 0x0012_3442;
const SIZES: [usize; 6] = [1, 7, 8, 62, 1200, MAX_MESSAGE];
const CROSSING: usize = 1200;
const SHORT_MULTI: usize = 20;
const SLOW: usize = 62;
const PAYLOAD: [u8; 1] = [0x5A];
const ALL: u8 = 0;
const NO_GAP: StMin = StMin(0);
const ROUNDS: usize = 2;
const PATIENCE: Duration = Duration::from_secs(60);
const FF_DATA: usize = 6;
const CF_DATA: usize = 7;
const BLOCK: u8 = 2;
const BLOCKS_OF_TWO: usize = 2;
const ENDS_AT_A_BLOCK: usize = FF_DATA + CF_DATA * BLOCK as usize * BLOCKS_OF_TWO;
const MARGIN: Duration = Duration::from_millis(100);
const N_AS: Duration = Duration::from_millis(200);
const N_BS: Duration = Duration::from_millis(700);
const N_CR: Duration = Duration::from_millis(1300);
const MIDWAY: Duration = Duration::from_millis(650);
const TICK: Duration = Duration::from_millis(1);
const EXTRA: usize = 3;
const ISO_TIMEOUT: Duration = Duration::from_secs(1);
const ONE_MS: Duration = Duration::from_millis(1);
const WAIT_LIMIT: u32 = 10;
const RX_QUEUE: usize = 1024;
const SETTLE: Duration = Duration::from_millis(50);
const REOPEN: Duration = Duration::from_millis(10);
const ST_MIN_MS: StMin = StMin(0x0A);
const ST_MIN_US: StMin = StMin(0xF5);
const STALL: Duration = Duration::from_millis(50);
const MID_STALL: Duration = Duration::from_millis(25);
const PART_OF_N_AS: Duration = Duration::from_millis(150);
const ST_MIN_MAX: StMin = StMin(0x7F);
const BLOCKED: [u8; 1] = [0x2A];
const SPINS: usize = 10_000;
const STALLED_CF: usize = 1;
const SMALL_QUEUE: usize = 2;
const FED: usize = 5;
const RESERVED_STATUS: u8 = 0x3;
const RESERVED_FC: [u8; 3] = [0x30 | RESERVED_STATUS, 0x00, 0x00];
const SHORT_FC: [u8; 2] = [0x30, 0x00];
const STRAY_CF: [u8; 2] = [0x21, 0x00];
const OVERFLOW_FC: FlowControl = FlowControl {
    status: FlowStatus::Overflow,
    block_size: ALL,
    st_min: NO_GAP,
};
const WAIT_FC: FlowControl = FlowControl {
    status: FlowStatus::Wait,
    block_size: ALL,
    st_min: NO_GAP,
};

#[derive(Default)]
struct Rig {
    bus: LoopbackBus,
}

impl Rig {
    fn port(&self) -> LoopbackPort {
        self.bus.port()
    }

    async fn task(&self, port: &LoopbackPort) -> CanTask {
        self.task_with(port, options()).await
    }

    async fn task_with(&self, port: &LoopbackPort, options: CanOptions) -> CanTask {
        port.open(options).await.unwrap()
    }

    async fn link(&self, config: LinkConfig) -> (IsoTpLink, Messages, LoopbackPort) {
        let port = self.port();
        let (link, messages) = IsoTpLink::over(self.task(&port).await, config);
        (link, messages, port)
    }

    async fn host(&self) -> (IsoTpLink, Messages, LoopbackPort) {
        self.link(host()).await
    }

    async fn device(&self) -> (IsoTpLink, Messages, LoopbackPort) {
        self.link(device()).await
    }

    async fn peer(&self, listen: u32, talk: u32) -> Peer {
        let task = self.task(&self.port()).await;
        let writer = task.writer();
        Peer {
            task,
            writer,
            listen,
            talk,
            pending: VecDeque::new(),
        }
    }

    async fn host_peer(&self) -> Peer {
        self.peer(H2D, D2H).await
    }

    async fn device_peer(&self) -> Peer {
        self.peer(D2H, H2D).await
    }
}

struct Peer {
    task: CanTask,
    writer: CanWriter,
    listen: u32,
    talk: u32,
    pending: VecDeque<Vec<u8>>,
}

impl Peer {
    async fn next(&mut self) -> Vec<u8> {
        loop {
            if let Some(frame) = self.pending.pop_front() {
                return frame;
            }
            let Some(CanEvent::Read(reads)) = self.task.next_event().await else {
                continue;
            };
            let listen = self.listen;
            self.pending.extend(
                reads
                    .into_iter()
                    .filter(|read| read.direction == Direction::Rx && read.frame.arb_id == listen)
                    .map(|read| read.frame.data),
            );
        }
    }

    async fn next_at(&mut self) -> (Vec<u8>, Instant) {
        let frame = self.next().await;
        (frame, Instant::now())
    }

    async fn silent_for(&mut self, quiet: Duration) -> bool {
        timeout(quiet, self.next()).await.is_err()
    }

    async fn send(&self, data: &[u8]) {
        let frame = CanFrame::data(BUS, self.talk, true, false, false, data.to_vec());
        self.writer.send(frame).await.unwrap().unwrap();
    }

    async fn flow(&self, flow: FlowControl) {
        self.send(&flow.encode()).await;
    }

    async fn finish(&mut self, reassembler: &mut Reassembler) -> Vec<u8> {
        loop {
            let frame = self.next().await;
            match reassembler.on_frame(&frame).step {
                Step::Message(message) => return message,
                Step::SendFlowControl(flow) => self.flow(flow).await,
                Step::Accepted | Step::Nothing => {}
            }
        }
    }

    async fn first_frame(&mut self) -> Reassembler {
        let mut reassembler = Reassembler::new(ALL, NO_GAP);
        let first = self.next().await;
        assert!(matches!(
            reassembler.on_frame(&first).step,
            Step::SendFlowControl(_)
        ));
        reassembler
    }
}

fn options() -> CanOptions {
    let mut options = CanOptions::default();
    options.own_frames = true;
    options.reopen = Some(REOPEN);
    options
}

fn timed(mut config: LinkConfig) -> LinkConfig {
    config.n_as = N_AS;
    config.n_bs = N_BS;
    config.n_cr = N_CR;
    config
}

fn host() -> LinkConfig {
    timed(LinkConfig::new(BUS, H2D, D2H))
}

fn device() -> LinkConfig {
    timed(LinkConfig::new(BUS, D2H, H2D))
}

fn fed(data: Vec<u8>) -> CanRead {
    read(
        CanFrame::data(BUS, D2H, true, false, false, data),
        Direction::Rx,
    )
}

async fn until(done: impl Fn() -> bool) {
    soon(async {
        while !done() {
            sleep(TICK).await;
        }
    })
    .await;
}

fn message(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i + len) as u8).collect()
}

fn cts(block_size: u8, st_min: StMin) -> FlowControl {
    FlowControl {
        status: FlowStatus::ContinueToSend,
        block_size,
        st_min,
    }
}

fn consecutive_frames(len: usize) -> usize {
    (len - FF_DATA).div_ceil(CF_DATA)
}

async fn soon<F: Future>(future: F) -> F::Output {
    timeout(PATIENCE, future).await.expect("in time")
}

async fn both<A: Future, B: Future>(a: A, b: B) -> (A::Output, B::Output) {
    soon(async { tokio::join!(a, b) }).await
}

async fn nothing(messages: &mut Messages) -> bool {
    timeout(SETTLE, messages.recv()).await.is_err()
}

fn read(frame: CanFrame, direction: Direction) -> CanRead {
    CanRead::new(frame, direction, SystemTime::UNIX_EPOCH)
}

fn single(arb_id: u32) -> CanFrame {
    let data = Segmenter::new(&PAYLOAD).unwrap().first();
    CanFrame::data(BUS, arb_id, true, false, false, data)
}

#[tokio::test(start_paused = true)]
async fn messages_of_every_size_cross_both_ways() {
    let rig = Rig::default();
    let (host, mut to_host, _) = rig.host().await;
    let (device, mut to_device, _) = rig.device().await;
    for len in SIZES {
        let data = message(len);
        soon(host.send(&data)).await.unwrap();
        assert_eq!(soon(to_device.recv()).await, Some(data.clone()), "{len}");
        soon(device.send(&data)).await.unwrap();
        assert_eq!(soon(to_host.recv()).await, Some(data), "{len}");
    }
    let host = host.stats();
    let device = device.stats();
    let each = SIZES.len() as u64;
    assert_eq!((host.messages_out, host.messages_in), (each, each));
    assert_eq!((device.messages_out, device.messages_in), (each, each));
    assert_eq!(host.frames_out, device.frames_in);
    assert_eq!(device.frames_out, host.frames_in);
    assert_eq!(host.flow_controls_dropped + device.flow_controls_dropped, 0);
    assert_eq!(host.aborts + device.aborts, 0);
}

#[tokio::test(start_paused = true)]
async fn a_request_crosses_a_reply() {
    let rig = Rig::default();
    let (host, mut to_host, _) = rig.host().await;
    let (device, mut to_device, _) = rig.device().await;
    let request = message(CROSSING);
    let reply = message(CROSSING - 1);
    let (sent, answered) = both(host.send(&request), device.send(&reply)).await;
    sent.unwrap();
    answered.unwrap();
    assert_eq!(soon(to_device.recv()).await, Some(request));
    assert_eq!(soon(to_host.recv()).await, Some(reply));
}

#[tokio::test(start_paused = true)]
async fn a_block_size_of_2_asks_for_flow_control_after_every_block_but_the_last() {
    let rig = Rig::default();
    let (host, _, _) = rig.host().await;
    let mut config = device();
    config.block_size = BLOCK;
    let (device, mut to_device, _) = rig.link(config).await;
    for len in [CROSSING, ENDS_AT_A_BLOCK] {
        let before = device.stats().frames_out;
        let data = message(len);
        soon(host.send(&data)).await.unwrap();
        assert_eq!(soon(to_device.recv()).await, Some(data), "{len}");
        let flow_controls = 1 + (consecutive_frames(len) - 1) / usize::from(BLOCK);
        assert_eq!(
            device.stats().frames_out - before,
            flow_controls as u64,
            "{len}"
        );
    }
    assert_eq!(host.stats().flow_controls_dropped, 0);
}

#[tokio::test(start_paused = true)]
async fn a_message_ending_at_a_block_waits_for_no_more_flow_control() {
    let rig = Rig::default();
    let (host, _, _) = rig.host().await;
    let mut peer = rig.host_peer().await;
    let data = message(ENDS_AT_A_BLOCK);
    let (sent, received) = both(host.send(&data), async {
        let mut reassembler = peer.first_frame().await;
        let mut received = None;
        for _ in 0..BLOCKS_OF_TWO {
            peer.flow(cts(BLOCK, NO_GAP)).await;
            for _ in 0..BLOCK {
                if let Step::Message(message) = reassembler.on_frame(&peer.next().await).step {
                    received = Some(message);
                }
            }
        }
        received
    })
    .await;
    sent.unwrap();
    assert_eq!(received, Some(data));
    assert!(peer.silent_for(SETTLE).await);
}

async fn consecutive_frame_times(st_min: StMin, stall: bool) -> Vec<Instant> {
    let rig = Rig::default();
    let (host, _, port) = rig.host().await;
    let mut peer = rig.host_peer().await;
    let data = message(CROSSING);
    let (sent, times) = both(host.send(&data), async {
        peer.first_frame().await;
        peer.flow(cts(ALL, st_min)).await;
        let mut times = Vec::new();
        for index in 0..consecutive_frames(CROSSING) {
            let (_, at) = peer.next_at().await;
            if stall && index == STALLED_CF {
                port.stall_next_write(STALL);
            }
            times.push(at);
        }
        times
    })
    .await;
    sent.unwrap();
    times
}

#[tokio::test(start_paused = true)]
async fn st_min_spaces_every_consecutive_frame_from_the_last_send_and_never_bursts() {
    let times = consecutive_frame_times(ST_MIN_MS, true).await;
    let gaps: Vec<Duration> = times.windows(2).map(|pair| pair[1] - pair[0]).collect();
    assert!(
        gaps.iter().all(|gap| *gap >= ST_MIN_MS.duration()),
        "{gaps:?}"
    );
    assert!(gaps[STALLED_CF] >= ST_MIN_MS.duration() + STALL);
    assert!(gaps[STALLED_CF + 1] >= ST_MIN_MS.duration());
}

#[tokio::test(start_paused = true)]
async fn a_sub_millisecond_st_min_is_still_a_lower_bound() {
    let times = consecutive_frame_times(ST_MIN_US, false).await;
    assert!(
        times
            .windows(2)
            .all(|pair| pair[1] - pair[0] >= ST_MIN_US.duration())
    );
}

#[tokio::test(start_paused = true)]
async fn a_wait_restarts_n_bs_and_a_cts_then_sends() {
    let rig = Rig::default();
    let (host, _, _) = rig.host().await;
    let mut peer = rig.host_peer().await;
    let data = message(SHORT_MULTI);
    let asked = Instant::now();
    let (sent, received) = both(host.send(&data), async {
        let mut reassembler = peer.first_frame().await;
        sleep(N_BS - MARGIN).await;
        peer.flow(WAIT_FC).await;
        sleep(N_BS - MARGIN).await;
        peer.flow(cts(ALL, NO_GAP)).await;
        peer.finish(&mut reassembler).await
    })
    .await;
    sent.unwrap();
    assert_eq!(received, data);
    assert!(asked.elapsed() > N_BS);
}

async fn waits_then_cts(waits: u32) -> (Result<(), SendFailed>, Option<Vec<u8>>, IsoTpLink) {
    let rig = Rig::default();
    let (host, _, _) = rig.host().await;
    let mut peer = rig.host_peer().await;
    let data = message(SHORT_MULTI);
    let (sent, received) = both(host.send(&data), async {
        let mut reassembler = peer.first_frame().await;
        for _ in 0..waits {
            peer.flow(WAIT_FC).await;
        }
        if waits > LinkConfig::DEFAULT_WAIT_LIMIT {
            return peer.silent_for(N_BS).await.then_some(Vec::new());
        }
        peer.flow(cts(ALL, NO_GAP)).await;
        Some(peer.finish(&mut reassembler).await)
    })
    .await;
    (sent, received, host)
}

#[tokio::test(start_paused = true)]
async fn ten_waits_then_cts_succeeds() {
    let (sent, received, host) = waits_then_cts(LinkConfig::DEFAULT_WAIT_LIMIT).await;
    sent.unwrap();
    assert_eq!(received, Some(message(SHORT_MULTI)));
    assert_eq!(host.stats().flow_controls_dropped, 0);
}

#[tokio::test(start_paused = true)]
async fn the_eleventh_wait_in_a_row_fails_the_send() {
    let (sent, received, host) = waits_then_cts(LinkConfig::DEFAULT_WAIT_LIMIT + 1).await;
    assert!(matches!(sent, Err(SendFailed::TooManyWaits)), "{sent:?}");
    assert_eq!(received, Some(Vec::new()), "no consecutive frame followed");
    assert_eq!(host.stats().send_failures.too_many_waits, 1);
}

#[tokio::test(start_paused = true)]
async fn a_cts_resets_the_wait_count() {
    let rig = Rig::default();
    let (host, _, _) = rig.host().await;
    let mut peer = rig.host_peer().await;
    let data = message(ENDS_AT_A_BLOCK);
    let (sent, received) = both(host.send(&data), async {
        let mut reassembler = peer.first_frame().await;
        let mut received = None;
        for _ in 0..BLOCKS_OF_TWO {
            for _ in 0..LinkConfig::DEFAULT_WAIT_LIMIT {
                peer.flow(WAIT_FC).await;
            }
            peer.flow(cts(BLOCK, NO_GAP)).await;
            for _ in 0..BLOCK {
                if let Step::Message(message) = reassembler.on_frame(&peer.next().await).step {
                    received = Some(message);
                }
            }
        }
        received
    })
    .await;
    sent.unwrap();
    assert_eq!(received, Some(data));
}

#[tokio::test(start_paused = true)]
async fn overflow_fails_the_send() {
    let rig = Rig::default();
    let (host, _, _) = rig.host().await;
    let mut peer = rig.host_peer().await;
    let data = message(SHORT_MULTI);
    let (sent, ()) = both(host.send(&data), async {
        peer.first_frame().await;
        peer.flow(OVERFLOW_FC).await;
    })
    .await;
    assert!(matches!(sent, Err(SendFailed::Overflow)), "{sent:?}");
    assert!(peer.silent_for(SETTLE).await);
    assert_eq!(host.stats().send_failures.overflow, 1);
}

#[tokio::test(start_paused = true)]
async fn a_reserved_flow_status_fails_at_once_and_a_malformed_frame_is_ignored() {
    let rig = Rig::default();
    let (host, _, _) = rig.host().await;
    let mut peer = rig.host_peer().await;
    let mut answered = None;
    let data = message(SHORT_MULTI);
    let (sent, ()) = both(host.send(&data), async {
        peer.first_frame().await;
        peer.send(&SHORT_FC).await;
        peer.send(&STRAY_CF).await;
        peer.send(&RESERVED_FC).await;
        answered = Some(Instant::now());
    })
    .await;
    let failed = Instant::now();
    assert!(
        matches!(sent, Err(SendFailed::ReservedStatus(RESERVED_STATUS))),
        "{sent:?}"
    );
    assert_eq!(failed - answered.unwrap(), Duration::ZERO);
    assert_eq!(host.stats().send_failures.reserved_status, 1);
}

#[tokio::test(start_paused = true)]
async fn no_flow_control_within_n_bs_fails() {
    let rig = Rig::default();
    let (host, _, _) = rig.host().await;
    let mut peer = rig.host_peer().await;
    let asked = Instant::now();
    let data = message(SHORT_MULTI);
    let (sent, ()) = both(host.send(&data), async {
        peer.first_frame().await;
    })
    .await;
    assert!(matches!(sent, Err(SendFailed::NoFlowControl)), "{sent:?}");
    assert!(asked.elapsed() >= N_BS);
    assert!(asked.elapsed() < N_BS + MARGIN);
    assert_eq!(host.stats().send_failures.no_flow_control, 1);
}

#[tokio::test(start_paused = true)]
async fn a_late_flow_control_is_dropped_and_never_starts_the_next_send() {
    let rig = Rig::default();
    let (host, _, _) = rig.host().await;
    let mut peer = rig.host_peer().await;
    for _ in 0..ROUNDS {
        let data = message(SHORT_MULTI);
        let (sent, ()) = both(host.send(&data), async {
            peer.first_frame().await;
        })
        .await;
        assert!(matches!(sent, Err(SendFailed::NoFlowControl)), "{sent:?}");
        peer.flow(cts(ALL, NO_GAP)).await;
        sleep(SETTLE).await;
        assert!(peer.silent_for(SETTLE).await);
    }
    let stats = host.stats();
    assert_eq!(stats.flow_controls_dropped, ROUNDS as u64);
    assert_eq!(stats.send_failures.no_flow_control, ROUNDS as u64);
}

fn segments(len: usize) -> (Vec<u8>, Vec<Vec<u8>>) {
    let data = message(len);
    let segmenter = Segmenter::new(&data).unwrap();
    (segmenter.first(), segmenter.collect())
}

#[tokio::test(start_paused = true)]
async fn a_gap_over_n_cr_aborts_the_message() {
    let rig = Rig::default();
    let (device, mut to_device, _) = rig.device().await;
    let mut peer = rig.device_peer().await;
    let (first, rest) = segments(SHORT_MULTI);
    peer.send(&first).await;
    peer.next().await;
    peer.send(&rest[0]).await;
    sleep(N_CR + MARGIN).await;
    peer.send(&rest[1]).await;
    assert!(nothing(&mut to_device).await);
    assert_eq!(device.stats().aborts, 1);
}

#[tokio::test(start_paused = true)]
async fn a_slow_message_with_every_gap_under_n_cr_completes() {
    let rig = Rig::default();
    let (device, mut to_device, _) = rig.device().await;
    let mut peer = rig.device_peer().await;
    let len = SLOW;
    let (first, rest) = segments(len);
    let started = Instant::now();
    peer.send(&first).await;
    peer.next().await;
    for frame in &rest {
        sleep(N_CR - MARGIN).await;
        peer.send(frame).await;
    }
    assert_eq!(soon(to_device.recv()).await, Some(message(len)));
    assert!(started.elapsed() > N_CR);
    assert_eq!(device.stats().aborts, 0);
}

#[tokio::test(start_paused = true)]
async fn echoes_other_ids_and_other_frames_are_ignored() {
    let rig = Rig::default();
    let task = rig.task(&rig.port()).await;
    let (link, mut messages) = IsoTpLink::new(task.writer(), device());
    let mut fd = single(H2D);
    fd.fd = true;
    let mut standard = single(H2D);
    standard.extended = false;
    let mut other_bus = single(H2D);
    other_bus.bus = OTHER_BUS;
    let ignored = [
        read(single(H2D), Direction::Tx),
        read(single(OTHER_ID), Direction::Rx),
        read(other_bus, Direction::Rx),
        read(standard, Direction::Rx),
        read(fd, Direction::Rx),
        read(
            CanFrame::remote(BUS, H2D, true, PAYLOAD.len() as u8),
            Direction::Rx,
        ),
    ];
    for read in &ignored {
        link.feed(read);
    }
    assert!(nothing(&mut messages).await);
    assert_eq!(link.stats().frames_in, 0);
    link.feed(&read(single(H2D), Direction::Rx));
    assert_eq!(soon(messages.recv()).await, Some(PAYLOAD.to_vec()));
    assert_eq!(link.stats().frames_in, 1);
}

#[tokio::test(start_paused = true)]
async fn a_frame_fed_to_a_full_queue_is_dropped_and_counted() {
    let rig = Rig::default();
    let task = rig.task(&rig.port()).await;
    let mut config = device();
    config.rx_queue = SMALL_QUEUE;
    let (link, mut messages) = IsoTpLink::new(task.writer(), config);
    for _ in 0..FED {
        link.feed(&read(single(H2D), Direction::Rx));
    }
    let stats = link.stats();
    assert_eq!(stats.frames_in, SMALL_QUEUE as u64);
    assert_eq!(stats.frames_dropped, (FED - SMALL_QUEUE) as u64);
    for _ in 0..SMALL_QUEUE {
        assert_eq!(soon(messages.recv()).await, Some(PAYLOAD.to_vec()));
    }
    assert!(nothing(&mut messages).await);
}

#[tokio::test(start_paused = true)]
async fn reset_drops_the_message_being_received() {
    let rig = Rig::default();
    let (device, mut to_device, _) = rig.device().await;
    let mut peer = rig.device_peer().await;
    let (first, rest) = segments(SHORT_MULTI);
    peer.send(&first).await;
    peer.next().await;
    peer.send(&rest[0]).await;
    sleep(SETTLE).await;
    device.reset();
    peer.send(&rest[1]).await;
    assert!(nothing(&mut to_device).await);
    peer.send(&first).await;
    peer.next().await;
    for frame in &rest {
        peer.send(frame).await;
    }
    assert_eq!(soon(to_device.recv()).await, Some(message(SHORT_MULTI)));
    assert_eq!(device.stats().aborts, 0);
}

#[tokio::test(start_paused = true)]
async fn reset_fails_the_send_under_way_and_the_next_succeeds() {
    let rig = Rig::default();
    let (host, _, _) = rig.host().await;
    let mut peer = rig.host_peer().await;
    let asked = Instant::now();
    let data = message(SHORT_MULTI);
    let (sent, ()) = both(host.send(&data), async {
        peer.first_frame().await;
        host.reset();
    })
    .await;
    assert!(matches!(sent, Err(SendFailed::Reset)), "{sent:?}");
    assert!(asked.elapsed() < N_BS);
    peer.flow(cts(ALL, NO_GAP)).await;
    assert!(peer.silent_for(SETTLE).await);
    let data = message(SHORT_MULTI);
    let (sent, received) = both(host.send(&data), async {
        let mut reassembler = peer.first_frame().await;
        peer.flow(cts(ALL, NO_GAP)).await;
        peer.finish(&mut reassembler).await
    })
    .await;
    sent.unwrap();
    assert_eq!(received, data);
    assert_eq!(host.stats().send_failures.reset, 1);
}

#[tokio::test(start_paused = true)]
async fn a_disconnect_resets_a_link_over_its_task() {
    let rig = Rig::default();
    let (_device, mut to_device, port) = rig.device().await;
    let mut peer = rig.device_peer().await;
    let (first, rest) = segments(SHORT_MULTI);
    peer.send(&first).await;
    peer.next().await;
    peer.send(&rest[0]).await;
    sleep(SETTLE).await;
    port.unplug();
    sleep(SETTLE).await;
    peer.send(&rest[1]).await;
    assert!(nothing(&mut to_device).await);
    peer.send(&first).await;
    peer.next().await;
    for frame in &rest {
        peer.send(frame).await;
    }
    assert_eq!(soon(to_device.recv()).await, Some(message(SHORT_MULTI)));
}

#[tokio::test(start_paused = true)]
async fn a_message_iso_tp_cannot_carry_fails_with_its_length() {
    let rig = Rig::default();
    let (host, _, _) = rig.host().await;
    assert!(matches!(host.send(&[]).await, Err(SendFailed::Length(_))));
    let long = message(MAX_MESSAGE + 1);
    assert!(matches!(host.send(&long).await, Err(SendFailed::Length(_))));
    let stats = host.stats();
    assert_eq!(stats.send_failures.length, ROUNDS as u64);
    assert_eq!(stats.frames_out, 0);
}

#[tokio::test(start_paused = true)]
async fn the_link_ends_when_its_last_handle_is_dropped() {
    let rig = Rig::default();
    let (host, mut to_host, _) = rig.host().await;
    let clone = host.clone();
    drop(host);
    soon(clone.send(&PAYLOAD)).await.unwrap();
    drop(clone);
    assert_eq!(soon(to_host.recv()).await, None);
}

#[tokio::test(start_paused = true)]
async fn reset_drops_the_frames_queued_before_it() {
    let rig = Rig::default();
    let task = rig.task(&rig.port()).await;
    let (link, mut messages) = IsoTpLink::new(task.writer(), device());
    let (first, rest) = segments(SHORT_MULTI);
    let frame = |data: &[u8]| {
        read(
            CanFrame::data(BUS, H2D, true, false, false, data.to_vec()),
            Direction::Rx,
        )
    };
    link.feed(&frame(&first));
    link.feed(&frame(&rest[0]));
    link.reset();
    link.feed(&frame(&rest[1]));
    assert!(nothing(&mut messages).await);
    assert_eq!(link.stats().frames_out, 0);
}

#[test]
fn the_defaults_are_iso_tp_s() {
    let config = LinkConfig::new(BUS, H2D, D2H);
    assert!(config.extended);
    assert_eq!(
        (config.n_as, config.n_bs, config.n_cr),
        (ISO_TIMEOUT, ISO_TIMEOUT, ISO_TIMEOUT)
    );
    assert_eq!((config.block_size, config.st_min), (ALL, ONE_MS));
    assert_eq!((config.wait_limit, config.rx_queue), (WAIT_LIMIT, RX_QUEUE));
}

#[tokio::test(start_paused = true)]
async fn a_link_over_a_task_that_ends_ends_too() {
    let rig = Rig::default();
    let port = rig.port();
    let mut once = options();
    once.reopen = None;
    let (host, mut to_host) = IsoTpLink::over(rig.task_with(&port, once).await, host());
    let mut peer = rig.host_peer().await;
    let asked = Instant::now();
    let data = message(SHORT_MULTI);
    let (sent, ()) = both(host.send(&data), async {
        peer.first_frame().await;
        port.unplug();
    })
    .await;
    assert!(
        matches!(
            sent,
            Err(SendFailed::Reset | SendFailed::Refused(SendRefused::Stopped))
        ),
        "{sent:?}"
    );
    assert!(asked.elapsed() < N_BS);
    assert_eq!(soon(to_host.recv()).await, None);
    let asked = Instant::now();
    let sent = soon(host.send(&data)).await;
    assert!(
        matches!(sent, Err(SendFailed::Refused(SendRefused::Stopped))),
        "{sent:?}"
    );
    assert_eq!(asked.elapsed(), Duration::ZERO);
}

#[tokio::test(start_paused = true)]
async fn a_wait_and_a_cts_fed_back_to_back_both_reach_the_send() {
    let rig = Rig::default();
    let task = rig.task(&rig.port()).await;
    let (host, _to_host) = IsoTpLink::new(task.writer(), host());
    let mut peer = rig.host_peer().await;
    let data = message(SHORT_MULTI);
    let (sent, ()) = both(host.send(&data), async {
        peer.next().await;
        host.feed(&fed(WAIT_FC.encode()));
        host.feed(&fed(cts(ALL, NO_GAP).encode()));
    })
    .await;
    sent.unwrap();
    assert_eq!(host.stats().flow_controls_dropped, 0);
}

async fn aborts_after_n_cr(device: &IsoTpLink) {
    sleep(N_CR - MARGIN).await;
    assert_eq!(device.stats().aborts, 0);
    sleep(MARGIN + MARGIN).await;
    assert_eq!(device.stats().aborts, 1);
}

#[tokio::test(start_paused = true)]
async fn n_cr_runs_from_the_flow_control_after_a_first_frame() {
    let rig = Rig::default();
    let (device, _to_device, _) = rig.device().await;
    let mut peer = rig.device_peer().await;
    let (first, _) = segments(SHORT_MULTI);
    peer.send(&first).await;
    peer.next().await;
    aborts_after_n_cr(&device).await;
}

#[tokio::test(start_paused = true)]
async fn n_cr_runs_from_the_flow_control_after_a_block() {
    let rig = Rig::default();
    let mut config = device();
    config.block_size = BLOCK;
    let (device, _to_device, _) = rig.link(config).await;
    let mut peer = rig.device_peer().await;
    let (first, rest) = segments(ENDS_AT_A_BLOCK);
    peer.send(&first).await;
    peer.next().await;
    peer.send(&rest[0]).await;
    sleep(MIDWAY).await;
    peer.send(&rest[1]).await;
    peer.next().await;
    aborts_after_n_cr(&device).await;
}

#[tokio::test(start_paused = true)]
async fn a_full_message_queue_drops_and_counts_while_flow_control_still_routes() {
    let rig = Rig::default();
    let (host, mut to_host, _) = rig.host().await;
    let (device, mut to_device, _) = rig.device().await;
    for _ in 0..Messages::CAPACITY + EXTRA {
        soon(host.send(&PAYLOAD)).await.unwrap();
    }
    sleep(SETTLE).await;
    let stats = device.stats();
    assert_eq!(stats.messages_in, Messages::CAPACITY as u64);
    assert_eq!(stats.messages_dropped, EXTRA as u64);
    let data = message(SHORT_MULTI);
    soon(device.send(&data)).await.unwrap();
    assert_eq!(soon(to_host.recv()).await, Some(data));
    for _ in 0..Messages::CAPACITY {
        assert_eq!(soon(to_device.recv()).await, Some(PAYLOAD.to_vec()));
    }
    assert!(nothing(&mut to_device).await);
}

#[tokio::test(start_paused = true)]
async fn a_write_stalled_past_n_as_fails_the_send() {
    let rig = Rig::default();
    let (host, _, port) = rig.host().await;
    let mut peer = rig.host_peer().await;
    port.stall_next_write(N_AS + MARGIN);
    let asked = Instant::now();
    let sent = host.send(&PAYLOAD).await;
    assert!(matches!(sent, Err(SendFailed::Unconfirmed)), "{sent:?}");
    assert_eq!(asked.elapsed(), N_AS);
    let (frame, at) = soon(peer.next_at()).await;
    assert_eq!(frame, single_frame());
    assert_eq!(at - asked, N_AS + MARGIN);
    let failures = host.stats().send_failures;
    assert_eq!((failures.unconfirmed, failures.adapter_timeout), (1, 0));
}

#[tokio::test(start_paused = true)]
async fn a_write_that_failed_or_panicked_fails_the_send_with_its_typed_cause() {
    let rig = Rig::default();
    let (host, _, port) = rig.host().await;
    port.fail_next_write(WriteFailed::Io(std::io::ErrorKind::BrokenPipe.into()));
    let failed = host.send(&PAYLOAD).await;
    assert!(
        matches!(&failed, Err(SendFailed::Write(WriteFailed::Io(e))) if e.kind() == std::io::ErrorKind::BrokenPipe),
        "{failed:?}"
    );
    port.fail_next_write(WriteFailed::Panicked);
    let panicked = host.send(&PAYLOAD).await.unwrap_err();
    assert!(
        matches!(
            std::error::Error::source(&panicked).and_then(|e| e.downcast_ref::<WriteFailed>()),
            Some(WriteFailed::Panicked)
        ),
        "{panicked:?}"
    );
    assert_eq!(host.stats().send_failures.write, 2);
}

fn single_frame() -> Vec<u8> {
    Segmenter::new(&PAYLOAD).unwrap().first()
}

async fn narrow(rig: &Rig) -> (IsoTpLink, CanWriter, LoopbackPort) {
    let port = rig.port();
    let mut narrow = options();
    narrow.writes = 1;
    let task = rig.task_with(&port, narrow).await;
    let writer = task.writer();
    let (host, _) = IsoTpLink::over(task, host());
    (host, writer, port)
}

fn raw() -> CanFrame {
    CanFrame::data(BUS, OTHER_ID, true, false, false, PAYLOAD.to_vec())
}

#[tokio::test(start_paused = true)]
async fn a_writer_queue_full_past_n_as_fails_the_send_with_nothing_sent() {
    let rig = Rig::default();
    let (host, writer, port) = narrow(&rig).await;
    let mut peer = rig.host_peer().await;
    port.stall_next_write(N_AS + MARGIN);
    let taken = writer.submit(raw()).unwrap();
    until(|| writer.queued() == 0).await;
    let queued = writer.submit(raw()).unwrap();
    let asked = Instant::now();
    let sent = host.send(&PAYLOAD).await;
    assert!(matches!(sent, Err(SendFailed::AdapterTimeout)), "{sent:?}");
    assert_eq!(asked.elapsed(), N_AS);
    taken.await.unwrap().unwrap();
    queued.await.unwrap().unwrap();
    assert!(peer.silent_for(N_AS).await);
    let failures = host.stats().send_failures;
    assert_eq!((failures.adapter_timeout, failures.unconfirmed), (1, 0));
}

#[tokio::test(start_paused = true)]
async fn one_n_as_bounds_the_wait_for_room_and_for_the_answer_together() {
    let rig = Rig::default();
    let (host, writer, port) = narrow(&rig).await;
    let mut peer = rig.host_peer().await;
    port.stall_next_write(PART_OF_N_AS);
    let taken = writer.submit(raw()).unwrap();
    until(|| writer.queued() == 0).await;
    port.stall_next_write(PART_OF_N_AS);
    let queued = writer.submit(raw()).unwrap();
    let asked = Instant::now();
    let sent = host.send(&PAYLOAD).await;
    assert!(matches!(sent, Err(SendFailed::Unconfirmed)), "{sent:?}");
    assert_eq!(asked.elapsed(), N_AS);
    taken.await.unwrap().unwrap();
    queued.await.unwrap().unwrap();
    assert_eq!(soon(peer.next()).await, single_frame());
}

#[tokio::test(start_paused = true)]
async fn a_briefly_full_writer_queue_delays_the_send_without_failing_it() {
    let rig = Rig::default();
    let port = rig.port();
    let mut narrow = options();
    narrow.writes = 1;
    let task = rig.task_with(&port, narrow).await;
    let writer = task.writer();
    let (host, _) = IsoTpLink::over(task, host());
    port.stall_next_write(STALL);
    let asked = Instant::now();
    let taken = writer.submit(raw()).unwrap();
    until(|| writer.queued() == 0).await;
    let queued = writer.submit(raw()).unwrap();
    assert!(matches!(writer.submit(raw()), Err(SendRefused::QueueFull)));
    soon(host.send(&PAYLOAD)).await.unwrap();
    assert!(asked.elapsed() >= STALL);
    taken.await.unwrap().unwrap();
    queued.await.unwrap().unwrap();
}

#[tokio::test(start_paused = true)]
async fn dropping_the_last_handle_stops_the_can_task() {
    let rig = Rig::default();
    let (host, _to_host, port) = rig.host().await;
    let clone = host.clone();
    drop(host);
    sleep(SETTLE).await;
    assert_eq!(port.closes(), 0);
    drop(clone);
    until(|| port.closes() == 1).await;
}

#[tokio::test(start_paused = true)]
async fn a_cancelled_send_is_counted_and_frees_the_link() {
    let rig = Rig::default();
    let (host, _, _) = rig.host().await;
    let mut peer = rig.host_peer().await;
    let data = message(SHORT_MULTI);
    let (cut, ()) = both(timeout(N_BS - MARGIN, host.send(&data)), async {
        peer.first_frame().await;
    })
    .await;
    assert!(cut.is_err());
    peer.flow(cts(ALL, NO_GAP)).await;
    sleep(SETTLE).await;
    let stats = host.stats();
    assert_eq!(stats.send_failures.cancelled, 1);
    assert_eq!(stats.flow_controls_dropped, 1);
    assert!(peer.silent_for(SETTLE).await);
    soon(host.send(&PAYLOAD)).await.unwrap();
    assert_eq!(host.stats().messages_out, 1);
}

#[tokio::test(start_paused = true)]
async fn close_ends_a_fed_link_for_every_handle() {
    let rig = Rig::default();
    let task = rig.task(&rig.port()).await;
    let (link, mut messages) = IsoTpLink::new(task.writer(), device());
    let mut peer = rig.device_peer().await;
    let data = message(SHORT_MULTI);
    let clone = link.clone();
    let (sent, ()) = both(link.send(&data), async {
        peer.first_frame().await;
        clone.close();
    })
    .await;
    assert!(
        matches!(sent, Err(SendFailed::Refused(SendRefused::Stopped))),
        "{sent:?}"
    );
    assert_eq!(soon(messages.recv()).await, None);
    let refused = soon(link.send(&PAYLOAD)).await;
    assert!(
        matches!(refused, Err(SendFailed::Refused(SendRefused::Stopped))),
        "{refused:?}"
    );
}

async fn interrupted_in_the_gap(interrupt: impl FnOnce(&IsoTpLink)) -> Result<(), SendFailed> {
    let rig = Rig::default();
    let (host, _, _) = rig.host().await;
    let mut peer = rig.host_peer().await;
    let data = message(SHORT_MULTI);
    let mut interrupted = None;
    let (sent, ()) = both(host.send(&data), async {
        peer.first_frame().await;
        peer.flow(cts(ALL, ST_MIN_MAX)).await;
        peer.next().await;
        sleep(SETTLE).await;
        interrupt(&host);
        interrupted = Some(Instant::now());
    })
    .await;
    assert_eq!(Instant::now(), interrupted.unwrap());
    assert!(peer.silent_for(ST_MIN_MAX.duration() + SETTLE).await);
    sent
}

#[tokio::test(start_paused = true)]
async fn a_reset_during_st_min_fails_the_send_at_once() {
    let sent = interrupted_in_the_gap(IsoTpLink::reset).await;
    assert!(matches!(sent, Err(SendFailed::Reset)), "{sent:?}");
}

#[tokio::test(start_paused = true)]
async fn a_close_during_st_min_fails_the_send_at_once() {
    let sent = interrupted_in_the_gap(IsoTpLink::close).await;
    assert!(
        matches!(sent, Err(SendFailed::Refused(SendRefused::Stopped))),
        "{sent:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn a_reset_while_the_adapter_takes_the_last_frame_leaves_the_send_ok() {
    let rig = Rig::default();
    let (host, _, port) = rig.host().await;
    let mut peer = rig.host_peer().await;
    let data = message(SHORT_MULTI);
    let (sent, received) = both(host.send(&data), async {
        let mut reassembler = peer.first_frame().await;
        peer.flow(cts(ALL, ST_MIN_MS)).await;
        let first = peer.next().await;
        assert_eq!(reassembler.on_frame(&first).step, Step::Accepted);
        port.stall_next_write(STALL);
        sleep(ST_MIN_MS.duration() + MID_STALL).await;
        host.reset();
        peer.finish(&mut reassembler).await
    })
    .await;
    sent.unwrap();
    assert_eq!(received, data);
}

async fn interrupted_waiting_for_room(
    rig: &Rig,
    host: &IsoTpLink,
    writer: &CanWriter,
    port: &LoopbackPort,
    interrupt: impl FnOnce(&IsoTpLink),
) -> Result<(), SendFailed> {
    let mut peer = rig.host_peer().await;
    port.stall_next_write(STALL);
    let taken = writer.submit(raw()).unwrap();
    until(|| writer.queued() == 0).await;
    let queued = writer.submit(raw()).unwrap();
    let mut interrupted = None;
    let (sent, ()) = both(host.send(&BLOCKED), async {
        interrupt(host);
        interrupted = Some(Instant::now());
    })
    .await;
    assert_eq!(Instant::now(), interrupted.unwrap());
    taken.await.unwrap().unwrap();
    queued.await.unwrap().unwrap();
    assert!(peer.silent_for(N_AS).await);
    assert_eq!(host.stats().frames_out, 0);
    sent
}

#[tokio::test(start_paused = true)]
async fn a_reset_while_waiting_for_writer_room_fails_the_send_with_nothing_sent() {
    let rig = Rig::default();
    let (host, writer, port) = narrow(&rig).await;
    let sent = interrupted_waiting_for_room(&rig, &host, &writer, &port, IsoTpLink::reset).await;
    assert!(matches!(sent, Err(SendFailed::Reset)), "{sent:?}");
}

#[tokio::test(start_paused = true)]
async fn a_close_while_waiting_for_writer_room_fails_a_fed_links_send_with_nothing_sent() {
    let rig = Rig::default();
    let port = rig.port();
    let mut narrow = options();
    narrow.writes = 1;
    let task = rig.task_with(&port, narrow).await;
    let writer = task.writer();
    let (host, _to_host) = IsoTpLink::new(task.writer(), host());
    let sent = interrupted_waiting_for_room(&rig, &host, &writer, &port, IsoTpLink::close).await;
    assert!(
        matches!(sent, Err(SendFailed::Refused(SendRefused::Stopped))),
        "{sent:?}"
    );
}

async fn settled(done: impl Fn() -> bool) {
    for _ in 0..SPINS {
        if done() {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("never settled");
}

fn toward_device(data: &[u8]) -> CanRead {
    read(
        CanFrame::data(BUS, H2D, true, false, false, data.to_vec()),
        Direction::Rx,
    )
}

#[tokio::test(start_paused = true)]
async fn a_consecutive_frame_at_the_n_cr_deadline_aborts_and_is_a_stray() {
    let rig = Rig::default();
    let task = rig.task(&rig.port()).await;
    let (device, mut to_device) = IsoTpLink::new(task.writer(), device());
    let (first, rest) = segments(SHORT_MULTI);
    device.feed(&toward_device(&first));
    settled(|| device.stats().frames_out == 1).await;
    sleep(N_CR).await;
    for frame in &rest {
        device.feed(&toward_device(frame));
    }
    assert!(nothing(&mut to_device).await);
    assert_eq!(device.stats().aborts, 1);
}

#[tokio::test(start_paused = true)]
async fn a_flow_control_after_the_send_gave_up_is_dropped_and_counted() {
    let rig = Rig::default();
    let task = rig.task(&rig.port()).await;
    let (host, _to_host) = IsoTpLink::new(task.writer(), host());
    let mut peer = rig.host_peer().await;
    let data = message(SHORT_MULTI);
    let (sent, ()) = both(host.send(&data), async {
        peer.next().await;
        sleep(N_BS).await;
        host.feed(&fed(cts(ALL, NO_GAP).encode()));
    })
    .await;
    assert!(matches!(sent, Err(SendFailed::NoFlowControl)), "{sent:?}");
    assert!(peer.silent_for(SETTLE).await);
    assert_eq!(host.stats().flow_controls_dropped, 1);
}
