use std::{error::Error, io};

use super::only_adapter;
use crate::{
    bus::CanBus,
    error::{OpenCause, OpenError},
};

fn cause(error: &OpenError) -> String {
    let source = error.source().unwrap();
    assert!(source.downcast_ref::<io::Error>().is_some(), "{source:?}");
    source.to_string()
}

fn adapter(
    wanted: Option<&str>,
    found: &[Option<&'static str>],
) -> Result<Option<&'static str>, OpenError> {
    let bus = CanBus::GsUsb {
        serial: wanted.map(str::to_owned),
    };
    only_adapter(&bus, Ok(found.to_vec()), wanted, |device| *device)
}

#[test]
fn a_lone_usb_adapter_is_taken_without_naming_its_serial() {
    assert_eq!(adapter(None, &[Some("A1")]).unwrap(), Some("A1"));
    assert_eq!(adapter(None, &[None]).unwrap(), None);
}

#[test]
fn a_serial_picks_its_adapter_among_several() {
    assert_eq!(
        adapter(Some("B2"), &[Some("A1"), Some("B2")]).unwrap(),
        Some("B2")
    );
}

#[test]
fn several_usb_adapters_without_a_serial_are_refused_listing_their_serials() {
    let error = adapter(None, &[Some("A1"), None]).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(error.to_string(), "gsusb did not open");
    let why = cause(&error);
    assert!(why.contains("A1, (no serial)"), "{why}");
    assert!(why.contains("gsusb=<serial>"), "{why}");
}

#[test]
fn a_serial_no_adapter_has_is_refused_listing_those_found() {
    let error = adapter(Some("C3"), &[Some("A1")]).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::NotFound);
    assert_eq!(error.to_string(), "gsusb=C3 did not open");
    assert_eq!(cause(&error), "no adapter has that serial; found A1");
    let none = adapter(None, &[]).unwrap_err();
    assert_eq!(none.to_string(), "gsusb did not open");
    assert_eq!(cause(&none), "no adapter found");
}

#[test]
fn a_failed_listing_is_refused_naming_the_bus() {
    let bus = CanBus::Pcan { serial: None };
    let listing: io::Result<Vec<Option<&str>>> = Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "access denied",
    ));
    let error = only_adapter(&bus, listing, None, |device| *device).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(error.to_string(), "pcan did not open");
    assert!(matches!(
        &error,
        OpenError::Open {
            source: OpenCause::Io(e),
            ..
        } if e.kind() == io::ErrorKind::PermissionDenied && e.get_ref().is_some()
    ));
    assert_eq!(cause(&error), "access denied");
}

#[test]
fn several_peak_adapters_are_refused_asking_for_a_pcan_serial() {
    let bus = CanBus::Pcan { serial: None };
    let found: io::Result<Vec<Option<&str>>> = Ok(vec![Some("0000002A"), Some("0000002B")]);
    let error = only_adapter(&bus, found, None, |device| *device).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(error.to_string(), "pcan did not open");
    assert_eq!(
        cause(&error),
        "several adapters found (0000002A, 0000002B); name one as pcan=<serial>"
    );
}
