use std::future::Future;

use tokio::time::{Duration, timeout};

use super::*;
use crate::test_support::{FakeDevice, FakePorts, StopReaders, Wired};

const PATH: &str = "/dev/ttyACM0";
const WAIT: Duration = Duration::from_secs(5);

fn quick() -> MonitorOptions {
    MonitorOptions {
        reopen: Duration::from_millis(10),
        reopen_max: Duration::from_millis(40),
        ..MonitorOptions::default()
    }
}

fn path() -> PortKey {
    PortKey::Path(PATH.into())
}

async fn within<F: Future>(test: F) -> F::Output {
    timeout(WAIT, test).await.expect("timed out")
}

async fn until(subscription: &mut Subscription, wanted: impl Fn(&Update) -> bool) -> Update {
    within(async {
        loop {
            let update = subscription.next().await.expect("the subscription ended");
            if wanted(&update) {
                return update;
            }
        }
    })
    .await
}

async fn reaches(subscription: &mut Subscription, wanted: MonitorState) {
    until(
        subscription,
        |u| matches!(u, Update::State { state, .. } if *state == wanted),
    )
    .await;
}

/// Nothing `wanted` within twice the echo wait.
async fn quiet(subscription: &mut Subscription, wanted: impl Fn(&Update) -> bool) -> bool {
    timeout(echo::ECHO_WAIT * 2, async {
        while let Some(update) = subscription.next().await {
            if wanted(&update) {
                return;
            }
        }
        std::future::pending().await
    })
    .await
    .is_err()
}

fn bytes(update: Update) -> Vec<u8> {
    match update {
        Update::Output { bytes, .. } => bytes.to_vec(),
        other => panic!("{other:?}"),
    }
}

struct Bench {
    ports: FakePorts,
    monitors: Monitors,
    _stop: StopReaders,
}

impl Bench {
    fn new() -> Self {
        let ports = FakePorts::default();
        let monitors = ports.monitors(quick());
        Self {
            _stop: StopReaders(monitors.clone()),
            ports,
            monitors,
        }
    }

    async fn console(&self, name: &str) -> Subscription {
        let mut console = self.monitors.subscribe(path(), None, Bounds::default());
        console.join("local", vec![name.into()]);
        reaches(&mut console, MonitorState::Reading).await;
        console
    }

    fn plug(&self) -> FakeDevice {
        self.ports.plug(PATH)
    }
}

/// Who each echoed byte was attributed to, and in what colour, however the
/// reads were cut.
async fn echoed_by(console: &mut Subscription, len: usize) -> Vec<(String, u8)> {
    let mut by = Vec::new();
    while by.len() < len {
        if let Update::Output { spans, .. } = until(
            console,
            |u| matches!(u, Update::Output { spans, .. } if !spans.is_empty()),
        )
        .await
        {
            by.extend(
                spans
                    .iter()
                    .flat_map(|s| std::iter::repeat_n((s.by.clone(), s.colour), s.len as usize)),
            );
        }
    }
    by
}

#[test]
fn a_port_key_reads_back_from_its_display() {
    for key in [
        PortKey::Path(PATH.into()),
        PortKey::Path("COM3".into()),
        PortKey::UsbSerial("0042".into()),
    ] {
        assert_eq!(key.to_string().parse(), Ok(key));
    }
    assert_eq!("usb:0042".parse(), Ok(PortKey::UsbSerial("0042".into())));
}

#[tokio::test]
async fn a_subscriber_is_told_the_monitors_state_before_anything_else() {
    let bench = Bench::new();
    let mut console = bench.monitors.subscribe(path(), None, Bounds::default());
    let first = within(console.next()).await;
    assert!(matches!(first, Some(Update::State { .. })), "{first:?}");
    reaches(&mut console, MonitorState::Backoff).await;

    let late = bench.monitors.subscribe(path(), None, Bounds::default());
    let mut late = late;
    let first = within(late.next()).await;
    assert!(
        matches!(
            &first,
            Some(Update::State {
                state: MonitorState::Backoff | MonitorState::Resolving | MonitorState::Opening,
                ..
            })
        ),
        "{first:?}"
    );
}

#[tokio::test]
async fn a_writers_echo_reaches_every_console_marked_theirs_in_their_colour() {
    let bench = Bench::new();
    let mut device = bench.plug();
    let mut alex = bench.console("alex").await;
    let mut olive = bench.console("olive").await;

    bench
        .monitors
        .write(&path(), b"ls\r".to_vec(), Some("alex"))
        .expect("write");
    let typed = within(device.read(3)).await;
    assert_eq!(typed, b"ls\r");
    device.send(&typed);

    let theirs = vec![("alex".to_string(), 0); 3];
    assert_eq!(echoed_by(&mut alex, 3).await, theirs);
    assert_eq!(echoed_by(&mut olive, 3).await, theirs);
}

#[tokio::test]
async fn input_the_device_never_echoes_is_a_count_naming_the_writer_without_its_bytes() {
    let bench = Bench::new();
    let mut device = bench.plug();
    let mut olive = bench.console("olive").await;

    bench
        .monitors
        .write(&path(), b"s3cret\r".to_vec(), Some("alex"))
        .expect("write");
    assert_eq!(within(device.read(7)).await, b"s3cret\r");

    let unechoed = until(&mut olive, |u| matches!(u, Update::Unechoed { .. })).await;
    assert_eq!(
        unechoed,
        Update::Unechoed {
            by: "alex".into(),
            colour: 1,
            count: 7,
            controls: "^M".into()
        }
    );
}

#[tokio::test]
async fn a_subscriber_outside_the_session_sees_output_but_not_whose_it_is() {
    let bench = Bench::new();
    let mut device = bench.plug();
    let mut alex = bench.console("alex").await;
    let mut logs = bench.monitors.subscribe(path(), None, Bounds::default());
    reaches(&mut logs, MonitorState::Reading).await;

    bench
        .monitors
        .write(&path(), b"s3cret\r".to_vec(), Some("alex"))
        .expect("write");
    within(device.read(7)).await;
    device.send(b"s3");
    until(&mut alex, |u| matches!(u, Update::Unechoed { .. })).await;

    let output = until(&mut logs, |u| matches!(u, Update::Output { .. })).await;
    assert_eq!(
        output,
        Update::Output {
            bytes: b"s3".as_slice().into(),
            spans: Vec::new()
        }
    );
    assert!(
        quiet(&mut logs, |u| matches!(
            u,
            Update::Unechoed { .. } | Update::Participants(_)
        ))
        .await
    );
}

#[tokio::test]
async fn joining_and_leaving_reaches_the_others_with_a_colour_each() {
    let bench = Bench::new();
    let _device = bench.plug();
    let mut olive = bench.console("olive").await;
    let person = |name: &str, via: &str, colour| Participant {
        name: name.into(),
        via: via.into(),
        colour,
    };
    let roster = |n: usize| move |u: &Update| matches!(u, Update::Participants(p) if p.len() == n);

    let mut alex = bench.monitors.subscribe(path(), None, Bounds::default());
    alex.join("controller", vec!["alex".into()]);
    assert_eq!(
        until(&mut olive, roster(2)).await,
        Update::Participants(vec![
            person("alex", "controller", 1),
            person("olive", "local", 0)
        ])
    );

    drop(alex);
    assert_eq!(
        until(&mut olive, roster(1)).await,
        Update::Participants(vec![person("olive", "local", 0)])
    );
}

#[tokio::test]
async fn a_join_that_changes_nobody_still_tells_the_joiner_who_is_there() {
    let bench = Bench::new();
    let _device = bench.plug();
    let _olive = bench.console("olive").await;

    let mut again = bench.monitors.subscribe(path(), None, Bounds::default());
    again.join("local", vec!["olive".into()]);
    let roster = until(&mut again, |u| matches!(u, Update::Participants(_))).await;
    assert!(matches!(roster, Update::Participants(p) if p.len() == 1));
}

#[tokio::test]
async fn a_seat_joins_from_another_task_and_does_nothing_once_its_subscription_is_gone() {
    let bench = Bench::new();
    let _device = bench.plug();
    let mut olive = bench.console("olive").await;
    let roster = |n: usize| move |u: &Update| matches!(u, Update::Participants(p) if p.len() == n);

    let mut relayed = bench.monitors.subscribe(path(), None, Bounds::default());
    let seat = relayed.seat();
    let relay = tokio::spawn(async move { seat.join("relay", vec!["alex".into(), "kim".into()]) });
    within(relay).await.unwrap();
    until(&mut olive, roster(3)).await;
    until(&mut relayed, roster(3)).await;
    relayed.seat().join("relay", vec!["alex".into()]);
    until(&mut olive, roster(2)).await;

    let seat = relayed.seat();
    drop(relayed);
    until(&mut olive, roster(1)).await;
    seat.join("relay", vec!["alex".into()]);
    assert!(quiet(&mut olive, |u| matches!(u, Update::Participants(_))).await);
}

#[tokio::test]
async fn a_seat_whose_join_changes_nobody_still_tells_its_subscriber_who_is_there() {
    let bench = Bench::new();
    let _device = bench.plug();
    let _olive = bench.console("olive").await;

    let mut again = bench.monitors.subscribe(path(), None, Bounds::default());
    again.seat().join("local", vec!["olive".into()]);
    let roster = until(&mut again, |u| matches!(u, Update::Participants(_))).await;
    assert!(matches!(roster, Update::Participants(p) if p.len() == 1));
}

#[tokio::test]
async fn a_flash_pauses_every_console_refuses_input_and_resumes_them_on_the_ports_new_path() {
    let ports = FakePorts::default();
    let monitors = ports.monitors(quick());
    let _stop = StopReaders(monitors.clone());
    let key = PortKey::UsbSerial("0042".into());
    let first = ports.plug_usb("/dev/ttyACM0", "0042");
    let console = |name: &'static str| {
        let monitors = monitors.clone();
        let key = key.clone();
        async move {
            let mut console = monitors.subscribe(key, None, Bounds::default());
            console.join("local", vec![name.into()]);
            reaches(&mut console, MonitorState::Reading).await;
            console
        }
    };
    let mut alex = console("alex").await;
    let mut olive = console("olive").await;

    within(monitors.pause(&key)).await;
    assert!(first.is_closed(), "the port is closed once pause returns");
    reaches(&mut alex, MonitorState::Paused).await;
    reaches(&mut olive, MonitorState::Paused).await;
    assert_eq!(
        monitors.write(&key, b"x".to_vec(), Some("alex")),
        Err(Refusal::Paused(key.clone()))
    );
    assert_eq!(monitors.reset(&key), Err(Refusal::Paused(key.clone())));
    monitors.progress(&key, "Writing 40%");
    let progress = until(&mut olive, |u| {
        matches!(
            u,
            Update::State {
                message: Some(_),
                ..
            }
        )
    })
    .await;
    assert_eq!(
        progress,
        Update::State {
            state: MonitorState::Paused,
            message: Some("Writing 40%".into())
        }
    );

    drop(first);
    let mut replugged = ports.plug_usb("/dev/ttyACM1", "0042");
    monitors.resume(&key);
    let reading = until(&mut alex, |u| {
        matches!(
            u,
            Update::State {
                state: MonitorState::Reading,
                ..
            }
        )
    })
    .await;
    assert_eq!(
        reading,
        Update::State {
            state: MonitorState::Reading,
            message: Some("/dev/ttyACM1".into())
        }
    );
    reaches(&mut olive, MonitorState::Reading).await;
    monitors
        .write(&key, b"y".to_vec(), Some("alex"))
        .expect("input is taken again");
    assert_eq!(within(replugged.read(1)).await, b"y");
}

#[tokio::test]
async fn a_port_stays_paused_until_every_flash_on_it_is_done() {
    let bench = Bench::new();
    let _first = bench.plug();
    let mut console = bench.console("alex").await;

    within(bench.monitors.pause(&path())).await;
    within(bench.monitors.pause(&path())).await;
    let _second = bench.plug();
    bench.monitors.resume(&path());
    assert!(matches!(
        bench.monitors.write(&path(), b"x".to_vec(), None),
        Err(Refusal::Paused(_))
    ));
    bench.monitors.resume(&path());
    reaches(&mut console, MonitorState::Reading).await;
}

#[tokio::test]
async fn a_port_first_subscribed_during_a_flash_opens_when_it_ends() {
    let bench = Bench::new();
    within(bench.monitors.pause(&path())).await;
    let mut console = bench.monitors.subscribe(path(), None, Bounds::default());
    let first = within(console.next()).await;
    assert_eq!(
        first,
        Some(Update::State {
            state: MonitorState::Paused,
            message: None
        })
    );

    let _device = bench.plug();
    bench.monitors.resume(&path());
    reaches(&mut console, MonitorState::Reading).await;
}

#[tokio::test]
async fn a_lost_line_is_reopened_and_its_ring_kept() {
    let bench = Bench::new();
    let first = bench.plug();
    let mut console = bench.console("alex").await;
    first.send(b"before");
    assert_eq!(
        bytes(until(&mut console, |u| matches!(u, Update::Output { .. })).await),
        b"before"
    );

    drop(first);
    reaches(&mut console, MonitorState::Backoff).await;
    assert!(matches!(
        bench.monitors.write(&path(), b"x".to_vec(), None),
        Err(Refusal::NotOpen(_))
    ));
    let second = bench.plug();
    reaches(&mut console, MonitorState::Reading).await;
    second.send(b"after");
    assert_eq!(
        bytes(until(&mut console, |u| matches!(u, Update::Output { .. })).await),
        b"after"
    );

    let mut replay = bench.monitors.subscribe(
        path(),
        None,
        Bounds {
            tail: Some(1024),
            follow: false,
            ..Bounds::default()
        },
    );
    assert_eq!(
        bytes(until(&mut replay, |u| matches!(u, Update::Output { .. })).await),
        b"beforeafter"
    );
    assert_eq!(
        within(replay.next()).await,
        Some(Update::End(EndReason::Closed))
    );
    assert_eq!(within(replay.next()).await, None);
}

#[tokio::test]
async fn a_usb_serial_not_attached_is_shown_missing_until_it_is() {
    let ports = FakePorts::default();
    let monitors = ports.monitors(quick());
    let _stop = StopReaders(monitors.clone());
    let key = PortKey::UsbSerial("0042".into());
    let mut console = monitors.subscribe(key, None, Bounds::default());
    reaches(&mut console, MonitorState::TtyMissing).await;

    let _device = ports.plug_usb("/dev/cu.usbmodem1", "0042");
    reaches(&mut console, MonitorState::Reading).await;
}

#[tokio::test]
async fn input_queued_before_a_loss_never_reaches_the_reopened_line() {
    let bench = Bench::new();
    let first = bench.plug();
    let _console = bench.console("alex").await;
    let mut second = bench.plug();

    bench
        .monitors
        .write(&path(), b"stale".to_vec(), None)
        .expect("queued");
    drop(first);
    assert!(
        timeout(Duration::from_millis(300), second.next())
            .await
            .is_err(),
        "the reopened line received input written to the last one"
    );
}

#[tokio::test]
async fn input_with_nobody_watching_is_refused() {
    let bench = Bench::new();
    let _device = bench.plug();
    drop(bench.console("alex").await);
    assert_eq!(
        bench.monitors.write(&path(), b"x".to_vec(), None),
        Err(Refusal::NotOpen(path()))
    );
    let other = PortKey::Path("/dev/none".into());
    assert_eq!(bench.monitors.reset(&other), Err(Refusal::NotOpen(other)));
}

#[tokio::test]
async fn a_reset_pulses_dtr_low_then_high() {
    let bench = Bench::new();
    let mut device = bench.plug();
    let _console = bench.console("alex").await;

    bench.monitors.reset(&path()).expect("reset");
    assert_eq!(within(device.next()).await, Some(Wired::Dtr(false)));
    assert_eq!(within(device.next()).await, Some(Wired::Dtr(true)));
}

#[tokio::test]
async fn the_first_subscriber_chooses_the_rate() {
    let bench = Bench::new();
    let first = bench
        .monitors
        .subscribe(path(), Some(74880), Bounds::default());
    let second = bench
        .monitors
        .subscribe(path(), Some(9600), Bounds::default());
    assert_eq!((first.baud(), second.baud()), (74880, 74880));
    let other =
        bench
            .monitors
            .subscribe(PortKey::Path("/dev/other".into()), None, Bounds::default());
    assert_eq!(other.baud(), 115200);
}

#[tokio::test]
async fn release_closes_the_port_ends_its_subscriptions_and_a_later_subscribe_reopens_it() {
    let bench = Bench::new();
    let device = bench.plug();
    let mut console = bench.console("alex").await;

    assert_eq!(within(bench.monitors.release(&path())).await, Ok(true));
    assert!(device.is_closed());
    until(&mut console, |u| *u == Update::End(EndReason::Released)).await;
    assert_eq!(within(console.next()).await, None);
    assert_eq!(within(bench.monitors.release(&path())).await, Ok(false));

    let _again = bench.plug();
    bench.console("alex").await;
}

#[tokio::test]
async fn release_is_refused_while_a_flash_has_the_port() {
    let bench = Bench::new();
    let _device = bench.plug();
    let _console = bench.console("alex").await;
    within(bench.monitors.pause(&path())).await;
    assert_eq!(
        within(bench.monitors.release(&path())).await,
        Err(Refusal::Paused(path()))
    );
}

mod bounds {
    use super::*;

    async fn bounded(bench: &Bench, bounds: Bounds) -> Subscription {
        let mut subscription = bench.monitors.subscribe(path(), None, bounds);
        reaches(&mut subscription, MonitorState::Reading).await;
        subscription
    }

    async fn end(subscription: &mut Subscription) -> EndReason {
        match until(subscription, |u| matches!(u, Update::End(_))).await {
            Update::End(reason) => reason,
            _ => unreachable!(),
        }
    }

    #[tokio::test]
    async fn wait_for_ends_once_the_pattern_arrives_across_reads() {
        let bench = Bench::new();
        let device = bench.plug();
        let mut logs = bounded(
            &bench,
            Bounds {
                wait_for: Some("READY".into()),
                ..Bounds::default()
            },
        )
        .await;
        device.send(b"boot REA");
        device.send(b"DY\r\n");
        assert_eq!(end(&mut logs).await, EndReason::Pattern);
    }

    #[tokio::test]
    async fn lines_ends_after_that_many() {
        let bench = Bench::new();
        let device = bench.plug();
        let mut logs = bounded(
            &bench,
            Bounds {
                lines: Some(2),
                ..Bounds::default()
            },
        )
        .await;
        device.send(b"one\ntwo");
        device.send(b"\nthree\n");
        let mut got = Vec::new();
        while let Some(update) = within(logs.next()).await {
            match update {
                Update::Output { bytes, .. } => got.extend_from_slice(&bytes),
                Update::End(reason) => {
                    assert_eq!(reason, EndReason::Lines);
                    break;
                }
                _ => {}
            }
        }
        assert_eq!(
            got, b"one\ntwo\nthree\n",
            "the read that ends it is still delivered"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn duration_and_timeout_end_on_the_clock() {
        let bench = Bench::new();
        let _device = bench.plug();
        let mut timed = bounded(
            &bench,
            Bounds {
                duration_ms: Some(50),
                ..Bounds::default()
            },
        )
        .await;
        assert_eq!(end(&mut timed).await, EndReason::Duration);
        let mut waited = bounded(
            &bench,
            Bounds {
                wait_for: Some("never".into()),
                timeout_ms: Some(50),
                ..Bounds::default()
            },
        )
        .await;
        assert_eq!(end(&mut waited).await, EndReason::Timeout);
    }

    #[tokio::test]
    async fn a_pattern_already_in_the_replay_ends_it_at_once() {
        let bench = Bench::new();
        let device = bench.plug();
        let mut console = bench.console("alex").await;
        device.send(b"READY\r\n");
        until(&mut console, |u| matches!(u, Update::Output { .. })).await;

        let mut logs = bench.monitors.subscribe(
            path(),
            None,
            Bounds {
                tail: Some(64),
                wait_for: Some("READY".into()),
                ..Bounds::default()
            },
        );
        assert_eq!(end(&mut logs).await, EndReason::Pattern);
    }
}
