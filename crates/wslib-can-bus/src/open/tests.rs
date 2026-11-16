use std::{
    pin::pin,
    task::{Context, Poll, Waker},
};

use wslib_can::CanOptions;

use super::open;
use crate::{
    bus::CanBus,
    error::{OpenError, refusal},
};

const BITRATE: u32 = 500_000;

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
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let _entered = runtime.enter();
    for bus in one_of_each_kind() {
        let mut opening = pin!(open(&bus, Some(BITRATE), CanOptions::default()));
        let polled = opening
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()));
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
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let _entered = runtime.enter();
    for bus in one_of_each_kind() {
        let mut opening = pin!(open(&bus, None, CanOptions::default()));
        let polled = opening
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()));
        let no_bitrate =
            matches!(&polled, Poll::Ready(Err(OpenError::NoBitrate(refused))) if *refused == bus);
        let opens = refusal(&bus).is_none();
        assert_eq!(no_bitrate, opens && bus.kind().sets_bitrate(), "{bus}");
    }
}
