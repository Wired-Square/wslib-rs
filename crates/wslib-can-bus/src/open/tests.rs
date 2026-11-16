use std::{
    pin::pin,
    task::{Context, Poll, Waker},
};

use wslib_can::CanOptions;

use super::open;
use crate::{
    bus::{BusKind, CanBus},
    config::BusConfig,
    error::{OpenError, refusal},
};

const BITRATE: u32 = 500_000;
const DATA_BITRATE: u32 = 2_000_000;

fn one_of_each_kind() -> [CanBus; 5] {
    [
        "can0".parse().unwrap(),
        "slcan=wslib-no-such-port".parse().unwrap(),
        "gsusb=wslib-no-such-serial".parse().unwrap(),
        "pcan=wslib-no-such-serial".parse().unwrap(),
        "gvret=127.0.0.1".parse().unwrap(),
    ]
}

#[test]
fn open_refuses_a_bus_exactly_when_refusal_names_why() {
    for bus in one_of_each_kind() {
        let polled = first_poll(&bus, BusConfig::classic(Some(BITRATE)));
        let refused = match &polled {
            Poll::Ready(Err(why @ (OpenError::FeatureOff(_) | OpenError::Unreachable(_)))) => {
                Some(why.to_string())
            }
            _ => None,
        };
        assert_eq!(refused, refusal(&bus).map(|why| why.to_string()), "{bus}");
    }
}

#[test]
fn an_adapter_that_sets_the_bus_rate_needs_a_bitrate_and_the_others_ignore_it() {
    for bus in one_of_each_kind() {
        let polled = first_poll(&bus, BusConfig::default());
        let no_bitrate =
            matches!(&polled, Poll::Ready(Err(OpenError::NoBitrate(refused))) if *refused == bus);
        let opens = refusal(&bus).is_none();
        assert_eq!(no_bitrate, opens && bus.kind().sets_bitrate(), "{bus}");
    }
}

fn first_poll(bus: &CanBus, config: BusConfig) -> Poll<Result<wslib_can::CanTask, OpenError>> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let _entered = runtime.enter();
    let mut opening = pin!(open(bus, config, CanOptions::default()));
    opening
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
}

#[test]
fn fd_on_an_adapter_that_sets_the_bus_rate_needs_a_data_bitrate() {
    for bus in one_of_each_kind() {
        let polled = first_poll(&bus, BusConfig::fd(Some(BITRATE), None));
        let no_data_bitrate = matches!(
            &polled,
            Poll::Ready(Err(OpenError::NoDataBitrate(refused))) if *refused == bus
        );
        let opens = refusal(&bus).is_none();
        assert_eq!(no_data_bitrate, opens && bus.kind().sets_bitrate(), "{bus}");
    }
}

#[test]
fn a_missing_nominal_rate_is_named_before_a_missing_data_rate() {
    for bus in one_of_each_kind() {
        let polled = first_poll(&bus, BusConfig::fd(None, None));
        let no_bitrate =
            matches!(&polled, Poll::Ready(Err(OpenError::NoBitrate(refused))) if *refused == bus);
        let opens = refusal(&bus).is_none();
        assert_eq!(no_bitrate, opens && bus.kind().sets_bitrate(), "{bus}");
    }
}

#[test]
fn gvret_refuses_fd_and_no_other_kind_does() {
    for bus in one_of_each_kind() {
        let polled = first_poll(&bus, BusConfig::fd(Some(BITRATE), Some(DATA_BITRATE)));
        let no_fd =
            matches!(&polled, Poll::Ready(Err(OpenError::NoFd(refused))) if *refused == bus);
        let opens = refusal(&bus).is_none();
        assert_eq!(no_fd, opens && bus.kind() == BusKind::Gvret, "{bus}");
    }
}
