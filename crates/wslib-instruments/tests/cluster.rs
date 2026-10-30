use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver},
    },
    thread,
    time::{Duration, Instant},
};

use wslib_instruments::{
    cluster::{Cluster, Latest},
    probe::{Probe, ProbeError},
    sample::{Sample, Stamp},
    signal::{self, ASPECT_DC, ASPECT_DEFAULT, QTY_TEMPERATURE, QTY_VOLTAGE, SignalKey},
    value::Value,
};

const SETTLE: Duration = Duration::from_millis(200);
const LATEST_BOUND: Duration = Duration::from_millis(50);
const STEADY_PERIOD: Duration = Duration::from_millis(10);
const QUIET_WAIT: Duration = Duration::from_millis(1_500);
const MIN_AGE: Duration = Duration::from_secs(1);
const TEST_MAX_INTERVAL: Duration = Duration::from_secs(2);
const SHORT_MAX_INTERVAL: Duration = Duration::from_millis(300);
const SWITCH_WAIT: Duration = Duration::from_millis(600);
const FRESH_AGE: Duration = Duration::from_millis(500);
const STALE_AGE: Duration = Duration::from_millis(2_001);
const TENTHS: i8 = -1;
const ROOM_TENTHS: i64 = 210;
const HOT_TENTHS: i64 = 2_500;
const RAIL_MILLIVOLTS: i64 = 3_300;
const MILLI: i8 = -3;
const FIRST_PROBE: usize = 0;
const SECOND_PROBE: usize = 1;
const CHANNEL_0: u8 = 0;
const TEMPERATURE: SignalKey = signal::measurement(QTY_TEMPERATURE, ASPECT_DEFAULT, CHANNEL_0);
const DC_VOLTAGE: SignalKey = signal::measurement(QTY_VOLTAGE, ASPECT_DC, CHANNEL_0);

fn sample_at(key: SignalKey, value: Value, at: Instant) -> Sample {
    Sample::new(key, value, Stamp::at(at))
}

fn taken_ago(age: Duration) -> Instant {
    Instant::now()
        .checked_sub(age)
        .expect("the test clock cannot reach back that far")
}

fn latest(age: Option<Duration>, error: Option<ProbeError>) -> Latest {
    Latest {
        sample: age
            .map(|ago| sample_at(TEMPERATURE, Value::new(ROOM_TENTHS, TENTHS), taken_ago(ago))),
        error,
        max_interval: TEST_MAX_INTERVAL,
    }
}

fn tenths(latest: &Latest) -> Option<i64> {
    latest.sample.map(|s| s.value.mantissa)
}

struct Steady(i64);

impl Probe for Steady {
    fn name(&self) -> String {
        "steady".into()
    }

    fn signals(&self) -> Vec<SignalKey> {
        vec![TEMPERATURE]
    }

    fn next(&mut self, _: Instant) -> Result<Vec<Sample>, ProbeError> {
        thread::sleep(STEADY_PERIOD);
        Ok(vec![sample_at(
            TEMPERATURE,
            Value::new(self.0, TENTHS),
            Instant::now(),
        )])
    }

    fn max_interval(&self) -> Duration {
        TEST_MAX_INTERVAL
    }
}

struct Stuck(Receiver<()>);

impl Probe for Stuck {
    fn name(&self) -> String {
        "stuck".into()
    }

    fn signals(&self) -> Vec<SignalKey> {
        vec![TEMPERATURE]
    }

    fn next(&mut self, _: Instant) -> Result<Vec<Sample>, ProbeError> {
        let _ = self.0.recv();
        Err(ProbeError::Timeout)
    }

    fn max_interval(&self) -> Duration {
        TEST_MAX_INTERVAL
    }
}

struct GoesQuiet(Arc<AtomicBool>);

impl Probe for GoesQuiet {
    fn name(&self) -> String {
        "quiet".into()
    }

    fn signals(&self) -> Vec<SignalKey> {
        vec![TEMPERATURE]
    }

    fn next(&mut self, deadline: Instant) -> Result<Vec<Sample>, ProbeError> {
        if self.0.load(Ordering::Relaxed) {
            thread::sleep(deadline.saturating_duration_since(Instant::now()));
            return Err(ProbeError::Disconnected("no frames for 5 s".into()));
        }
        Steady(HOT_TENTHS).next(deadline)
    }

    fn max_interval(&self) -> Duration {
        TEST_MAX_INTERVAL
    }
}

struct DialTurns(Arc<AtomicBool>);

impl Probe for DialTurns {
    fn name(&self) -> String {
        "dial".into()
    }

    fn signals(&self) -> Vec<SignalKey> {
        vec![TEMPERATURE, DC_VOLTAGE]
    }

    fn next(&mut self, _: Instant) -> Result<Vec<Sample>, ProbeError> {
        thread::sleep(STEADY_PERIOD);
        let now = Instant::now();
        Ok(vec![if self.0.load(Ordering::Relaxed) {
            sample_at(DC_VOLTAGE, Value::new(RAIL_MILLIVOLTS, MILLI), now)
        } else {
            sample_at(TEMPERATURE, Value::new(ROOM_TENTHS, TENTHS), now)
        }])
    }

    fn max_interval(&self) -> Duration {
        SHORT_MAX_INTERVAL
    }
}

#[test]
fn a_blocked_probe_never_stalls_the_cluster() {
    let (unblock, blocked) = mpsc::channel();
    let cluster = Cluster::start(vec![
        Box::new(Stuck(blocked)),
        Box::new(Steady(ROOM_TENTHS)),
    ])
    .unwrap();
    thread::sleep(SETTLE);
    let asked = Instant::now();
    let stuck = cluster.latest(FIRST_PROBE, &TEMPERATURE).unwrap();
    let steady = cluster.latest(SECOND_PROBE, &TEMPERATURE).unwrap();
    assert!(
        asked.elapsed() < LATEST_BOUND,
        "latest() took {:?}",
        asked.elapsed()
    );
    assert!(stuck.sample.is_none());
    assert_eq!(tenths(&steady), Some(ROOM_TENTHS));
    drop(unblock);
}

#[test]
fn a_silent_probe_ages_and_reports_its_error() {
    let quiet = Arc::new(AtomicBool::new(false));
    let cluster = Cluster::start(vec![Box::new(GoesQuiet(Arc::clone(&quiet)))]).unwrap();
    thread::sleep(SETTLE);
    quiet.store(true, Ordering::Relaxed);
    thread::sleep(QUIET_WAIT);
    let latest = cluster.latest(FIRST_PROBE, &TEMPERATURE).unwrap();
    assert_eq!(tenths(&latest), Some(HOT_TENTHS), "the last value is kept");
    assert!(
        latest.age().unwrap() >= MIN_AGE,
        "and its age grows: {:?}",
        latest.age()
    );
    assert!(
        matches!(latest.error, Some(ProbeError::Disconnected(_))),
        "{:?}",
        latest.error
    );
}

#[test]
fn a_link_error_applies_to_every_signal_of_the_probe() {
    let quiet = Arc::new(AtomicBool::new(true));
    let cluster = Cluster::start(vec![Box::new(GoesQuiet(quiet))]).unwrap();
    thread::sleep(QUIET_WAIT);
    let never_sent = cluster.latest(FIRST_PROBE, &DC_VOLTAGE).unwrap();
    assert!(
        matches!(never_sent.current(), Err(ProbeError::Disconnected(_))),
        "{:?}",
        never_sent.current()
    );
}

#[test]
fn a_signal_the_probe_stops_sending_goes_stale_while_the_new_one_is_current() {
    let turned = Arc::new(AtomicBool::new(false));
    let cluster = Cluster::start(vec![Box::new(DialTurns(Arc::clone(&turned)))]).unwrap();
    thread::sleep(SETTLE);
    assert!(
        cluster
            .latest(FIRST_PROBE, &TEMPERATURE)
            .unwrap()
            .current()
            .is_ok()
    );
    turned.store(true, Ordering::Relaxed);
    thread::sleep(SWITCH_WAIT);
    let old = cluster.latest(FIRST_PROBE, &TEMPERATURE).unwrap();
    let new = cluster.latest(FIRST_PROBE, &DC_VOLTAGE).unwrap();
    assert!(
        matches!(old.current(), Err(ProbeError::Stale(_))),
        "{:?}",
        old.current()
    );
    assert_eq!(
        new.current().map(|s| s.value),
        Ok(Value::new(RAIL_MILLIVOLTS, MILLI))
    );
}

#[test]
fn a_fresh_sample_is_current() {
    assert_eq!(
        latest(Some(FRESH_AGE), None)
            .current()
            .map(|s| s.value.mantissa),
        Ok(ROOM_TENTHS)
    );
}

#[test]
fn an_error_makes_the_held_sample_not_current() {
    let failed = latest(
        Some(STALE_AGE),
        Some(ProbeError::Disconnected("no frames for 5 s".into())),
    );
    assert!(
        matches!(failed.current(), Err(ProbeError::Disconnected(_))),
        "{:?}",
        failed.current()
    );
}

#[test]
fn no_sample_yet_is_not_current() {
    assert_eq!(latest(None, None).current(), Err(ProbeError::Timeout));
}

#[test]
fn a_sample_older_than_the_declared_maximum_interval_is_stale() {
    let old = latest(Some(STALE_AGE), None);
    assert!(
        matches!(old.current(), Err(ProbeError::Stale(age)) if age >= STALE_AGE),
        "{:?}",
        old.current()
    );
}

#[test]
fn staleness_reads_in_tenths_of_a_second() {
    assert_eq!(
        ProbeError::Stale(STALE_AGE).to_string(),
        "no reading for 2.0 s"
    );
}

#[test]
fn the_cluster_carries_each_probe_declared_maximum_interval_and_name() {
    let cluster = Cluster::start(vec![Box::new(Steady(ROOM_TENTHS))]).unwrap();
    assert_eq!(
        cluster
            .latest(FIRST_PROBE, &TEMPERATURE)
            .unwrap()
            .max_interval,
        TEST_MAX_INTERVAL
    );
    assert_eq!(cluster.names(), ["steady"]);
}

#[test]
fn a_probe_index_the_cluster_does_not_have_has_no_latest() {
    let cluster = Cluster::start(vec![Box::new(Steady(ROOM_TENTHS))]).unwrap();
    assert_eq!(cluster.latest(SECOND_PROBE, &TEMPERATURE), None);
}

#[test]
fn a_sample_stamped_in_the_future_is_current_with_no_age() {
    let ahead = Instant::now()
        .checked_add(STALE_AGE)
        .expect("the test clock reaches that far ahead");
    let early = Latest {
        sample: Some(sample_at(
            TEMPERATURE,
            Value::new(ROOM_TENTHS, TENTHS),
            ahead,
        )),
        error: None,
        max_interval: TEST_MAX_INTERVAL,
    };
    assert_eq!(early.age(), Some(Duration::ZERO));
    assert_eq!(early.current().map(|s| s.value.mantissa), Ok(ROOM_TENTHS));
}

struct Named(&'static str);

impl Probe for Named {
    fn name(&self) -> String {
        self.0.into()
    }

    fn signals(&self) -> Vec<SignalKey> {
        vec![]
    }

    fn next(&mut self, _: Instant) -> Result<Vec<Sample>, ProbeError> {
        thread::sleep(STEADY_PERIOD);
        Err(ProbeError::Timeout)
    }

    fn max_interval(&self) -> Duration {
        TEST_MAX_INTERVAL
    }
}

#[test]
fn a_probe_named_with_a_control_character_still_starts() {
    let cluster = Cluster::start(vec![Box::new(Named("odd\u{0}name"))]).unwrap();
    assert_eq!(cluster.names(), ["odd\u{0}name"]);
}

struct Holds(Arc<AtomicBool>);

impl Probe for Holds {
    fn name(&self) -> String {
        "holds".into()
    }

    fn signals(&self) -> Vec<SignalKey> {
        vec![]
    }

    fn next(&mut self, deadline: Instant) -> Result<Vec<Sample>, ProbeError> {
        thread::sleep(deadline.saturating_duration_since(Instant::now()));
        Err(ProbeError::Timeout)
    }

    fn max_interval(&self) -> Duration {
        TEST_MAX_INTERVAL
    }
}

impl Drop for Holds {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

#[test]
fn dropping_the_cluster_drops_its_probes_before_it_returns() {
    let released = Arc::new(AtomicBool::new(false));
    let cluster = Cluster::start(vec![Box::new(Holds(Arc::clone(&released)))]).unwrap();
    thread::sleep(STEADY_PERIOD);
    drop(cluster);
    assert!(released.load(Ordering::Relaxed));
}
