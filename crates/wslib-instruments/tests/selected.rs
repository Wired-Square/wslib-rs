use std::time::{Duration, Instant};

use wslib_instruments::{
    gw121::decode::{METER_TEMPERATURE, STATUS, THERMOCOUPLE},
    probe::{Probe, ProbeError},
    sample::{Sample, Stamp},
    signal::SignalKey,
    uri::narrowed,
    value::Value,
};

const TENTHS: i8 = -1;
const ROOM_TENTHS: i64 = 210;
const MAX_INTERVAL: Duration = Duration::from_secs(2);
const ALL: [SignalKey; 3] = [STATUS, THERMOCOUPLE, METER_TEMPERATURE];

struct Everything;

impl Probe for Everything {
    fn name(&self) -> String {
        "everything".into()
    }

    fn signals(&self) -> Vec<SignalKey> {
        ALL.to_vec()
    }

    fn display_name(&self, _: &SignalKey) -> Option<&'static str> {
        None
    }

    fn next(&mut self, _: Instant) -> Result<Vec<Sample>, ProbeError> {
        let at = Stamp::now();
        Ok(ALL
            .iter()
            .map(|key| Sample::new(*key, Value::new(ROOM_TENTHS, TENTHS), at))
            .collect())
    }

    fn max_interval(&self) -> Duration {
        MAX_INTERVAL
    }
}

#[test]
fn a_selection_narrows_the_signals_and_the_samples_to_the_selected_keys() {
    let mut probe = narrowed(Box::new(Everything), &[THERMOCOUPLE]);
    assert_eq!(probe.signals(), [THERMOCOUPLE]);
    let keys: Vec<SignalKey> = probe
        .next(Instant::now())
        .unwrap()
        .iter()
        .map(|s| s.key)
        .collect();
    assert_eq!(keys, [THERMOCOUPLE]);
    assert_eq!(probe.name(), "everything");
    assert_eq!(probe.max_interval(), MAX_INTERVAL);
}

#[test]
fn no_selection_passes_everything_through() {
    let mut probe = narrowed(Box::new(Everything), &[]);
    assert_eq!(probe.signals(), ALL);
    assert_eq!(probe.next(Instant::now()).unwrap().len(), ALL.len());
}
