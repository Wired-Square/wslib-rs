use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::json;
use wslib_instruments::{
    gw121::decode::THERMOCOUPLE,
    sample::{Sample, Stamp},
    uri::ProbeUri,
    value::Value,
};

const TENTHS: i8 = -1;
const ROOM_TENTHS: i64 = 210;
const THERMOCOUPLE_SLUG: &str = "device.0.measurement.temperature.ch0";
const TAKEN_US: i64 = 1_792_018_701_572_083;
const CLOCK_SLACK: Duration = Duration::from_secs(1);

fn taken_at(wall_clock: SystemTime) -> Sample {
    Sample::new(
        THERMOCOUPLE,
        Value::new(ROOM_TENTHS, TENTHS),
        Stamp {
            wall_clock,
            ..Stamp::now()
        },
    )
}

#[test]
fn a_sample_serialises_its_slug_value_and_wall_clock_but_not_its_instant() {
    let wall_clock = UNIX_EPOCH + Duration::from_micros(TAKEN_US.unsigned_abs());
    assert_eq!(
        serde_json::to_value(taken_at(wall_clock)).unwrap(),
        json!({
            "key": THERMOCOUPLE_SLUG,
            "value": { "mantissa": ROOM_TENTHS, "exponent": TENTHS },
            "wall_clock": TAKEN_US,
        })
    );
}

#[test]
fn a_deserialised_sample_keeps_its_wall_clock_and_ages_on_this_clock() {
    let sample = taken_at(SystemTime::now());
    let text = serde_json::to_string(&sample).unwrap();
    let back: Sample = serde_json::from_str(&text).unwrap();
    assert_eq!((back.key, back.value), (sample.key, sample.value));
    assert!(sample.wall_clock.duration_since(back.wall_clock).unwrap() < Duration::from_micros(1));
    assert!(
        back.at.saturating_duration_since(sample.at) < CLOCK_SLACK,
        "{back:?} against {sample:?}"
    );
    assert!(
        sample.at.saturating_duration_since(back.at) < CLOCK_SLACK,
        "{back:?} against {sample:?}"
    );
}

#[test]
fn a_sample_with_an_unknown_key_is_refused() {
    let refused = serde_json::from_value::<Sample>(json!({
        "key": "voltage",
        "value": { "mantissa": 1, "exponent": 0 },
        "wall_clock": 0,
    }));
    assert!(refused.is_err());
}

#[test]
fn a_probe_uri_serialises_as_its_text_and_parses_back() {
    let uri: ProbeUri = "wiredreflow:slcan=by-id:usb-Foo-if00@028F08/TC1"
        .parse()
        .unwrap();
    let text = serde_json::to_value(&uri).unwrap();
    assert_eq!(
        text,
        json!(format!(
            "wiredreflow:slcan=by-id:usb-Foo-if00@028F08/{THERMOCOUPLE_SLUG}"
        ))
    );
    assert_eq!(serde_json::from_value::<ProbeUri>(text).unwrap(), uri);
    assert!(serde_json::from_value::<ProbeUri>(json!("wiredreflow:can0@zz")).is_err());
}
