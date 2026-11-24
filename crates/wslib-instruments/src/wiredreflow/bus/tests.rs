use std::{error::Error, io};

use wslib_can_bus::{BusKind, CanBus, OpenCause, OpenError};

use super::{failed, feature};
use crate::uri::CAN_KINDS;

#[test]
fn the_kinds_offered_are_those_whose_feature_is_on() {
    let enabled: Vec<BusKind> = BusKind::ALL
        .into_iter()
        .filter(|kind| feature(*kind).1)
        .collect();
    assert_eq!(CAN_KINDS, enabled.as_slice());
}

#[test]
fn a_bus_that_did_not_open_says_so_and_keeps_its_cause() {
    let error = failed(OpenError::Open {
        bus: CanBus::SocketCan {
            interface: "can0".into(),
        },
        source: OpenCause::Io(io::Error::new(io::ErrorKind::NotFound, "no such device")),
    });
    assert_eq!(error.kind(), io::ErrorKind::NotFound);
    assert_eq!(error.to_string(), "can0 did not open");
    let cause = error.source().unwrap().downcast_ref::<io::Error>().unwrap();
    assert_eq!(cause.to_string(), "no such device");
}
