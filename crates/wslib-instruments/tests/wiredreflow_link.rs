use std::{
    collections::VecDeque,
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use wslib_instruments::{
    probe::{Probe, ProbeError},
    wiredreflow::{
        bus::{Bus, BusError, CanBus, PortDirectory, SerialPort},
        frame::{CJ1, CJ2, RawFrame, TC1, TC1_FAULT, TC2, TC2_FAULT},
        link::{Opener, Timing, WiredReflowProbe, discover},
    },
};

const BENCH_DEVICE: u32 = 0x02_8F08;
const OTHER_DEVICE_THERMOCOUPLE_ID: u32 = 0x0312_0021;
const THERMOCOUPLE_ID: u32 = 0x028F_0821;
const FAULT_ID: u32 = 0x028F_0825;
const ROOM: [u8; 8] = [0xE8, 0x00, 0xE3, 0x00, 0xFC, 0x00, 0xFA, 0x00];
const CLEAR: [u8; 2] = [0x00, 0x00];
const FAST: Timing = Timing {
    poll: Duration::from_millis(10),
    silence: Duration::from_millis(200),
};
const WINDOW: Duration = Duration::from_millis(100);
const SETTLE: Duration = Duration::from_millis(100);
const DEADLINE: Duration = Duration::from_secs(1);
const WITHIN_SILENCE: Duration = Duration::from_millis(100);
const STOP_WITHIN_POLLS: u32 = 5;
const STOP_CHECK: Duration = Duration::from_millis(1);

type Step = Result<Option<RawFrame>, BusError>;
type Script = Arc<Mutex<VecDeque<Step>>>;

struct Scripted(Script);

impl Bus for Scripted {
    fn read(&mut self, timeout: Duration) -> Step {
        let next = self.0.lock().unwrap().pop_front();
        next.unwrap_or_else(|| {
            thread::sleep(timeout);
            Ok(None)
        })
    }
}

struct Watched(Arc<AtomicBool>);

impl Bus for Watched {
    fn read(&mut self, timeout: Duration) -> Step {
        thread::sleep(timeout);
        Ok(None)
    }
}

impl Drop for Watched {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

fn broadcast(id: u32, data: &[u8]) -> Step {
    Ok(Some(RawFrame {
        id,
        extended: true,
        data: data.to_vec(),
    }))
}

fn script(steps: Vec<Step>) -> Script {
    Arc::new(Mutex::new(steps.into()))
}

fn probe(steps: Vec<Step>) -> (WiredReflowProbe, Script) {
    let shared = script(steps);
    let probe =
        WiredReflowProbe::with_bus(BENCH_DEVICE, Box::new(Scripted(Arc::clone(&shared))), FAST)
            .unwrap();
    (probe, shared)
}

fn deadline_in(wait: Duration) -> Instant {
    Instant::now().checked_add(wait).unwrap()
}

fn deadline() -> Instant {
    deadline_in(DEADLINE)
}

#[test]
fn a_bus_is_a_socketcan_interface_or_an_slcan_port_and_round_trips() {
    assert_eq!(
        "can0".parse::<CanBus>().unwrap(),
        CanBus::SocketCan {
            interface: "can0".into()
        }
    );
    let slcan: CanBus = "slcan=cu.usbmodem2101".parse().unwrap();
    assert_eq!(
        slcan,
        CanBus::Slcan {
            port: SerialPort {
                directory: PortDirectory::Devices,
                name: "cu.usbmodem2101".into()
            }
        }
    );
    assert_eq!(slcan.to_string(), "slcan=cu.usbmodem2101");
    assert!("slcan=".parse::<CanBus>().is_err());
    let path = "slcan=/dev/cu.usbmodem2101".parse::<CanBus>().unwrap_err();
    assert!(
        path.contains("write slcan=cu.usbmodem2101") && path.contains("under /dev/"),
        "{path}"
    );
    assert!("".parse::<CanBus>().is_err());
}

fn can0() -> CanBus {
    CanBus::SocketCan {
        interface: "can0".into(),
    }
}

#[test]
fn one_board_on_the_bus_is_found() {
    let mut bus = Scripted(script(vec![broadcast(THERMOCOUPLE_ID, &ROOM)]));
    assert_eq!(discover(&mut bus, &can0(), WINDOW).unwrap(), BENCH_DEVICE);
}

#[test]
fn no_board_on_the_bus_is_not_found_naming_the_bus() {
    let mut bus = Scripted(script(vec![]));
    let error = discover(&mut bus, &can0(), WINDOW).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::NotFound);
    let text = error.to_string();
    assert!(
        text.contains("on can0") && text.contains("is can0 up?"),
        "{text}"
    );
}

#[test]
fn an_adapter_lost_while_listening_is_named_as_the_reason_nothing_was_found() {
    let mut bus = Scripted(script(vec![Err(BusError::Lost("device closed".into()))]));
    let error = discover(&mut bus, &can0(), WINDOW).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::NotFound);
    let text = error.to_string();
    assert!(
        text.contains("can0") && text.contains("device closed"),
        "{text}"
    );
}

#[test]
fn a_thermocouple_slot_frame_of_the_wrong_length_does_not_bind_a_board() {
    let (short, _) = ROOM.split_at(ROOM.len() / 2);
    let mut bus = Scripted(script(vec![broadcast(THERMOCOUPLE_ID, short)]));
    assert_eq!(
        discover(&mut bus, &can0(), WINDOW).unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
}

#[test]
fn two_boards_on_the_bus_are_refused_naming_both() {
    let mut bus = Scripted(script(vec![
        broadcast(THERMOCOUPLE_ID, &ROOM),
        broadcast(OTHER_DEVICE_THERMOCOUPLE_ID, &ROOM),
    ]));
    let error = discover(&mut bus, &can0(), WINDOW).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    let text = error.to_string();
    assert!(
        text.contains("028F08") && text.contains("031200") && text.contains("@<device-id>"),
        "{text}"
    );
    assert!(text.contains("on can0"), "{text}");
}

#[test]
fn the_probe_is_named_by_its_device() {
    let (probe, _) = probe(vec![]);
    assert_eq!(probe.name(), "WiredReflow 028F08");
    assert_eq!(probe.display_name(&TC1), Some("TC1"));
}

#[test]
fn the_thermocouple_and_fault_batches_queued_together_both_reach_the_consumer() {
    let (mut probe, _) = probe(vec![
        broadcast(THERMOCOUPLE_ID, &ROOM),
        broadcast(FAULT_ID, &CLEAR),
    ]);
    thread::sleep(SETTLE);
    let keys: Vec<_> = probe
        .next(deadline())
        .unwrap()
        .iter()
        .map(|s| s.key)
        .collect();
    assert!(keys.contains(&TC1) && keys.contains(&TC1_FAULT), "{keys:?}");
}

#[test]
fn silence_is_reported_once_and_the_next_frame_clears_it() {
    let (mut probe, shared) = probe(vec![broadcast(THERMOCOUPLE_ID, &ROOM)]);
    assert!(probe.next(deadline()).is_ok());
    assert!(
        matches!(probe.next(deadline()), Err(ProbeError::Disconnected(why)) if why.contains("no WiredReflow frames"))
    );
    assert!(
        matches!(
            probe.next(deadline_in(WITHIN_SILENCE)),
            Err(ProbeError::Timeout)
        ),
        "silence is reported once"
    );
    shared
        .lock()
        .unwrap()
        .push_back(broadcast(THERMOCOUPLE_ID, &ROOM));
    assert!(probe.next(deadline()).is_ok(), "the board came back");
}

#[test]
fn a_batch_queued_before_a_lost_adapter_is_delivered_and_the_loss_follows() {
    let (mut probe, _) = probe(vec![
        broadcast(THERMOCOUPLE_ID, &ROOM),
        broadcast(FAULT_ID, &CLEAR),
        Err(BusError::Lost("device closed".into())),
    ]);
    thread::sleep(SETTLE);
    let keys: Vec<_> = probe
        .next(deadline())
        .unwrap()
        .iter()
        .map(|s| s.key)
        .collect();
    assert!(keys.contains(&TC1), "{keys:?}");
    assert!(
        matches!(probe.next(deadline()), Err(ProbeError::Disconnected(why)) if why.contains("device closed"))
    );
}

#[test]
fn a_lost_adapter_is_reported_and_reading_carries_on_when_it_returns() {
    let (mut probe, shared) = probe(vec![Err(BusError::Lost("device closed".into()))]);
    assert!(
        matches!(probe.next(deadline()), Err(ProbeError::Disconnected(why)) if why.contains("device closed"))
    );
    shared
        .lock()
        .unwrap()
        .push_back(broadcast(THERMOCOUPLE_ID, &ROOM));
    assert!(probe.next(deadline()).is_ok());
}

#[test]
fn an_ended_bus_is_reported_and_the_probe_says_its_link_stopped() {
    let (mut probe, _) = probe(vec![Err(BusError::Ended(
        "the device refused 500 kbit/s".into(),
    ))]);
    assert!(
        matches!(probe.next(deadline()), Err(ProbeError::Disconnected(why)) if why.contains("refused"))
    );
    assert!(
        matches!(probe.next(deadline()), Err(ProbeError::Disconnected(why)) if why.contains("link thread stopped"))
    );
}

#[test]
fn frames_from_another_board_never_reach_a_bound_probe() {
    let (mut probe, _) = probe(vec![broadcast(OTHER_DEVICE_THERMOCOUPLE_ID, &ROOM)]);
    assert!(!matches!(probe.next(deadline()), Ok(samples) if !samples.is_empty()));
}

#[test]
fn dropping_the_probe_stops_its_link_and_releases_the_bus_within_a_few_polls() {
    let released = Arc::new(AtomicBool::new(false));
    let probe =
        WiredReflowProbe::with_bus(BENCH_DEVICE, Box::new(Watched(Arc::clone(&released))), FAST)
            .unwrap();
    drop(probe);
    let dropped = Instant::now();
    let within = FAST.poll * STOP_WITHIN_POLLS;
    while !released.load(Ordering::Relaxed) && dropped.elapsed() < within {
        thread::sleep(STOP_CHECK);
    }
    assert!(
        released.load(Ordering::Relaxed),
        "the bus is still held {within:?} after the probe was dropped"
    );
}

fn started(steps: Vec<Step>, device: Option<u32>) -> (io::Result<WiredReflowProbe>, Script) {
    let shared = script(steps);
    let bus = Scripted(Arc::clone(&shared));
    let opener: Opener = Box::new(move || Ok(Box::new(bus) as Box<dyn Bus>));
    (
        WiredReflowProbe::start_with(opener, &can0(), device, WINDOW, FAST),
        shared,
    )
}

#[test]
fn discovery_on_the_link_thread_binds_the_one_board_names_the_probe_at_once_and_reads_on() {
    let (started, shared) = started(vec![broadcast(THERMOCOUPLE_ID, &ROOM)], None);
    let mut probe = started.unwrap();
    assert_eq!(probe.name(), "WiredReflow 028F08");
    shared
        .lock()
        .unwrap()
        .push_back(broadcast(THERMOCOUPLE_ID, &ROOM));
    let keys: Vec<_> = probe
        .next(deadline())
        .unwrap()
        .iter()
        .map(|s| s.key)
        .collect();
    assert!(keys.contains(&CJ1), "{keys:?}");
}

#[test]
fn discovery_on_the_link_thread_that_finds_no_board_fails_the_start() {
    let error = started(vec![], None).0.err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::NotFound);
    assert!(error.to_string().contains("on can0"), "{error}");
}

#[test]
fn discovery_on_the_link_thread_that_finds_two_boards_fails_the_start_naming_both() {
    let steps = vec![
        broadcast(THERMOCOUPLE_ID, &ROOM),
        broadcast(OTHER_DEVICE_THERMOCOUPLE_ID, &ROOM),
    ];
    let error = started(steps, None).0.err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    let text = error.to_string();
    assert!(text.contains("028F08") && text.contains("031200"), "{text}");
}

#[test]
fn a_named_device_skips_discovery_and_the_probe_starts_at_once() {
    let probe = started(vec![], Some(BENCH_DEVICE)).0.unwrap();
    assert_eq!(probe.name(), "WiredReflow 028F08");
}

#[test]
fn a_bus_that_fails_to_open_on_the_link_thread_fails_the_start_with_its_error() {
    let opener: Opener = Box::new(|| {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "slcan=ttyACM0: busy",
        ))
    });
    let error = WiredReflowProbe::start_with(opener, &can0(), None, WINDOW, FAST)
        .err()
        .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert!(error.to_string().contains("busy"), "{error}");
}

fn lost() -> Step {
    Err(BusError::Lost("device closed".into()))
}

#[test]
fn a_lost_adapter_is_reported_once_per_episode_and_a_frame_ends_the_episode() {
    let (mut probe, shared) = probe(vec![lost(), lost(), broadcast(THERMOCOUPLE_ID, &ROOM)]);
    thread::sleep(SETTLE);
    assert!(
        matches!(probe.next(deadline()), Err(ProbeError::Disconnected(why)) if why.contains("device closed"))
    );
    assert!(
        probe.next(deadline()).is_ok(),
        "the second loss of the episode is not reported"
    );
    shared.lock().unwrap().push_back(lost());
    assert!(
        matches!(probe.next(deadline()), Err(ProbeError::Disconnected(why)) if why.contains("device closed")),
        "a loss after the board came back starts a new episode"
    );
}

#[test]
fn a_period_reaches_the_consumer_in_signal_order() {
    let period = || {
        vec![
            broadcast(THERMOCOUPLE_ID, &ROOM),
            broadcast(FAULT_ID, &CLEAR),
        ]
    };
    let (mut probe, shared) = probe(period());
    thread::sleep(SETTLE);
    probe.next(deadline()).unwrap();
    shared.lock().unwrap().extend(period());
    thread::sleep(SETTLE);
    let keys: Vec<_> = probe
        .next(deadline())
        .unwrap()
        .iter()
        .map(|s| s.key)
        .collect();
    assert_eq!(keys, [TC1, TC2, CJ1, CJ2, TC1_FAULT, TC2_FAULT]);
}
