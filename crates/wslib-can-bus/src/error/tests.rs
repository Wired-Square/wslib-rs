use std::{error::Error, io};

use super::{OpenError, refusal};
use crate::bus::{BUS_FORMS, CanBus, name_the_bus};

fn can0() -> CanBus {
    CanBus::SocketCan {
        interface: "can0".into(),
    }
}

fn every_kind() -> [CanBus; 5] {
    [
        can0(),
        "slcan=ttyACM0".parse().unwrap(),
        CanBus::GsUsb { serial: None },
        CanBus::Pcan { serial: None },
        "gvret=127.0.0.1".parse().unwrap(),
    ]
}

#[test]
fn a_feature_left_out_is_named_as_this_crate_names_it() {
    for (bus, feature) in
        every_kind()
            .into_iter()
            .zip(["socketcan", "slcan", "gsusb", "pcan", "gvret"])
    {
        assert_eq!(bus.kind().feature(), feature, "{bus}");
        let error = OpenError::FeatureOff(bus.clone());
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert_eq!(
            error.to_string(),
            format!("{bus}: this build leaves it out; enable wslib-can-bus' `{feature}` feature")
        );
    }
}

#[test]
fn a_usb_adapter_unreachable_this_way_says_to_name_its_socketcan_interface() {
    for bus in [
        CanBus::GsUsb { serial: None },
        CanBus::Pcan {
            serial: Some("0000002A".into()),
        },
    ] {
        let error = OpenError::Unreachable(bus.clone());
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert_eq!(
            error.to_string(),
            format!(
                "{bus}: on Linux a gs_usb or PEAK adapter is a SocketCAN interface; name that \
                 interface, e.g. can0"
            )
        );
    }
}

#[test]
fn socketcan_off_linux_says_it_needs_linux_and_names_the_buses_this_build_opens() {
    let error = OpenError::Unreachable(can0());
    assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    assert_eq!(
        error.to_string(),
        format!(
            "can0: SocketCAN needs Linux; {}",
            name_the_bus("the adapter", BUS_FORMS)
        )
    );
}

#[test]
fn a_failed_open_names_the_bus_and_keeps_its_cause() {
    let error = OpenError::Open {
        bus: can0(),
        source: io::Error::new(io::ErrorKind::NotFound, "no such device"),
    };
    assert_eq!(error.kind(), io::ErrorKind::NotFound);
    assert_eq!(error.to_string(), "can0: no such device");
    assert_eq!(
        error.source().map(ToString::to_string).as_deref(),
        Some("no such device")
    );
}

#[test]
fn a_bus_is_refused_for_its_feature_first_then_for_its_platform() {
    let linux = cfg!(target_os = "linux");
    let usb = cfg!(any(target_os = "macos", target_os = "windows"));
    for (bus, (built, reachable)) in every_kind().into_iter().zip([
        (cfg!(feature = "socketcan"), linux),
        (cfg!(feature = "slcan"), true),
        (cfg!(feature = "gsusb"), usb),
        (cfg!(feature = "pcan"), usb),
        (cfg!(feature = "gvret"), true),
    ]) {
        let refused = refusal(&bus);
        match (built, reachable) {
            (false, _) => assert!(
                matches!(&refused, Some(OpenError::FeatureOff(off)) if *off == bus),
                "{bus}: {refused:?}"
            ),
            (true, false) => assert!(
                matches!(&refused, Some(OpenError::Unreachable(on)) if *on == bus),
                "{bus}: {refused:?}"
            ),
            (true, true) => assert!(refused.is_none(), "{bus}: {refused:?}"),
        }
    }
}

#[test]
fn an_explanation_offers_the_forms_it_is_given() {
    let error = OpenError::Unreachable(can0());
    assert_eq!(error.explain(BUS_FORMS), error.to_string());
    assert_eq!(
        error.explain(&["slcan=<name>"]),
        "can0: SocketCAN needs Linux; name the adapter as slcan=<name>"
    );
    assert!(error.explain(&[]).contains("opens no CAN bus"));
}

#[test]
fn a_missing_bitrate_asks_for_the_buses_rate() {
    let bus: CanBus = "slcan=ttyACM0".parse().unwrap();
    let error = OpenError::NoBitrate(bus.clone());
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(
        error.to_string(),
        format!("{bus}: this adapter sets the bus's rate; give the bus's bitrate")
    );
    assert!(error.source().is_none());
}

#[test]
fn a_missing_data_bitrate_asks_for_can_fds_data_rate() {
    let bus = CanBus::GsUsb { serial: None };
    let error = OpenError::NoDataBitrate(bus.clone());
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(
        error.to_string(),
        format!("{bus}: this adapter sets the bus's rates; give CAN FD's data bitrate")
    );
    assert!(error.source().is_none());
}

#[test]
fn fd_on_gvret_says_it_has_none() {
    let bus: CanBus = "gvret=127.0.0.1".parse().unwrap();
    let error = OpenError::NoFd(bus.clone());
    assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    assert_eq!(
        error.to_string(),
        format!("{bus}: a GVRET device has no CAN FD")
    );
    assert!(error.source().is_none());
}
