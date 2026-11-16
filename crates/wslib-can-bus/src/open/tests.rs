use std::{
    pin::pin,
    task::{Context, Poll, Waker},
};

use wslib_can::CanOptions;

use super::{Rates, open, rates};
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
fn gvret_refuses_every_fd_request_and_no_other_kind_does() {
    for config in [
        BusConfig::fd(Some(BITRATE), Some(DATA_BITRATE)),
        BusConfig::fd(Some(BITRATE), None),
        BusConfig::fd(None, None),
    ] {
        for bus in one_of_each_kind() {
            let polled = first_poll(&bus, config);
            let no_fd =
                matches!(&polled, Poll::Ready(Err(OpenError::NoFd(refused))) if *refused == bus);
            let opens = refusal(&bus).is_none();
            assert_eq!(
                no_fd,
                opens && bus.kind() == BusKind::Gvret,
                "{bus} {config:?}"
            );
        }
    }
}

#[test]
fn classic_is_never_refused_as_fd() {
    for config in [BusConfig::default(), BusConfig::classic(Some(BITRATE))] {
        for bus in one_of_each_kind() {
            let polled = first_poll(&bus, config);
            assert!(
                !matches!(
                    &polled,
                    Poll::Ready(Err(OpenError::NoFd(_) | OpenError::NoDataBitrate(_)))
                ),
                "{bus} {config:?}"
            );
        }
    }
}

fn slcan_bus() -> CanBus {
    "slcan=ttyACM0".parse().unwrap()
}

#[test]
fn rates_carry_the_nominal_rate_and_fds_data_rate() {
    let bus = slcan_bus();
    assert_eq!(
        rates(&bus, BusConfig::classic(Some(BITRATE))).unwrap(),
        Rates {
            bitrate: BITRATE,
            data_bitrate: None
        }
    );
    assert_eq!(
        rates(&bus, BusConfig::fd(Some(BITRATE), Some(DATA_BITRATE))).unwrap(),
        Rates {
            bitrate: BITRATE,
            data_bitrate: Some(DATA_BITRATE)
        }
    );
}

#[test]
fn rates_need_a_nominal_rate_first_and_a_data_rate_in_fd() {
    let bus = slcan_bus();
    assert!(matches!(
        rates(&bus, BusConfig::classic(None)),
        Err(OpenError::NoBitrate(refused)) if refused == bus
    ));
    assert!(matches!(
        rates(&bus, BusConfig::fd(None, None)),
        Err(OpenError::NoBitrate(refused)) if refused == bus
    ));
    assert!(matches!(
        rates(&bus, BusConfig::fd(Some(BITRATE), None)),
        Err(OpenError::NoDataBitrate(refused)) if refused == bus
    ));
}

#[cfg(feature = "slcan")]
#[test]
fn slcan_is_given_both_rates() {
    let CanBus::Slcan { port } = slcan_bus() else {
        panic!("an SLCAN bus");
    };
    let fd = super::slcan_options(
        &port,
        Rates {
            bitrate: BITRATE,
            data_bitrate: Some(DATA_BITRATE),
        },
    );
    assert_eq!(fd.path, port.path());
    assert_eq!(fd.line, super::SLCAN_LINE);
    assert_eq!((fd.bitrate, fd.data_bitrate), (BITRATE, Some(DATA_BITRATE)));
    let classic = super::slcan_options(
        &port,
        Rates {
            bitrate: BITRATE,
            data_bitrate: None,
        },
    );
    assert_eq!((classic.bitrate, classic.data_bitrate), (BITRATE, None));
}

#[cfg(all(feature = "socketcan", target_os = "linux"))]
#[test]
fn socketcan_opens_an_fd_socket_exactly_in_fd() {
    let classic = super::socketcan_options("can0", crate::config::CanMode::Classic);
    assert_eq!((classic.interface.as_str(), classic.fd), ("can0", false));
    let fd = super::socketcan_options("can0", BusConfig::fd(None, None).mode);
    assert_eq!((fd.interface.as_str(), fd.fd), ("can0", true));
}

#[cfg(all(feature = "gsusb", any(target_os = "macos", target_os = "windows")))]
#[test]
fn gsusb_is_given_fds_data_rate_at_its_default_sample_point() {
    let device = wslib_can_gsusb::GsUsbDevice {
        serial: None,
        bus: 1,
        address: 2,
        product: "candleLight".into(),
    };
    let fd = super::gsusb_options(
        device.clone(),
        Rates {
            bitrate: BITRATE,
            data_bitrate: Some(DATA_BITRATE),
        },
    );
    assert_eq!(fd.device, device);
    assert_eq!((fd.bitrate, fd.data), (BITRATE, Some((DATA_BITRATE, None))));
    let classic = super::gsusb_options(
        device,
        Rates {
            bitrate: BITRATE,
            data_bitrate: None,
        },
    );
    assert_eq!((classic.bitrate, classic.data), (BITRATE, None));
}

#[cfg(all(feature = "pcan", any(target_os = "macos", target_os = "windows")))]
#[test]
fn pcan_is_given_fds_data_rate_at_its_default_sample_point() {
    let device = wslib_can_pcan::PcanDevice {
        serial: None,
        bus: 1,
        address: 2,
        product: "PCAN-USB FD".into(),
        model: wslib_can_pcan::PcanModel::UsbFd,
    };
    let fd = super::pcan_options(
        device.clone(),
        Rates {
            bitrate: BITRATE,
            data_bitrate: Some(DATA_BITRATE),
        },
    );
    assert_eq!(fd.device, device);
    assert_eq!((fd.bitrate, fd.data), (BITRATE, Some((DATA_BITRATE, None))));
    let classic = super::pcan_options(
        device,
        Rates {
            bitrate: BITRATE,
            data_bitrate: None,
        },
    );
    assert_eq!((classic.bitrate, classic.data), (BITRATE, None));
}
