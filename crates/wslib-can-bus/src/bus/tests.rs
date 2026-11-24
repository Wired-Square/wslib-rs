use std::error::Error;

use super::{
    BUILT, BUS_FORMS, BusKind, BusParseError, CanBus, PortDirectory, PortParseError, SerialPort,
    form_count, forms_of, name_the_bus,
};

const CANABLE2_BY_ID: &str =
    "usb-Openlight_Labs_CANable2_b158aa7_github.com_normaldotcom_canable2.git_206F33893845-if00";

fn parsed(text: &str) -> CanBus {
    text.parse().unwrap_or_else(|e| panic!("{text}: {e}"))
}

#[test]
fn a_bus_is_a_socketcan_interface_or_an_slcan_port_and_round_trips() {
    assert_eq!(
        "can0".parse::<CanBus>().unwrap(),
        CanBus::SocketCan {
            interface: "can0".into()
        }
    );
    let slcan: CanBus = "slcan=cu.usbmodem2101".parse().unwrap();
    assert_eq!(
        slcan,
        CanBus::Slcan {
            port: SerialPort {
                directory: PortDirectory::Devices,
                name: "cu.usbmodem2101".into()
            }
        }
    );
    assert_eq!(slcan.to_string(), "slcan=cu.usbmodem2101");
    assert!("slcan=".parse::<CanBus>().is_err());
    let path = "slcan=/dev/cu.usbmodem2101".parse::<CanBus>().unwrap_err();
    assert_eq!(
        path.to_string(),
        "slcan=/dev/cu.usbmodem2101 names no serial port"
    );
    let why = path
        .source()
        .unwrap()
        .downcast_ref::<PortParseError>()
        .unwrap();
    assert_eq!(
        why,
        &PortParseError::Path(Some(SerialPort {
            directory: PortDirectory::Devices,
            name: "cu.usbmodem2101".into()
        }))
    );
    let why = why.to_string();
    assert!(
        why.contains("write slcan=cu.usbmodem2101") && why.contains("under /dev/"),
        "{why}"
    );
    assert!("".parse::<CanBus>().is_err());
}

#[test]
fn an_interface_merely_starting_with_an_adapter_name_stays_socketcan() {
    assert_eq!(
        "gsusb0".parse::<CanBus>(),
        Ok(CanBus::SocketCan {
            interface: "gsusb0".into()
        })
    );
}

#[test]
fn every_form_writes_as_it_parses() {
    let by_id = format!("slcan=by-id:{CANABLE2_BY_ID}");
    for text in [
        "can0",
        "slcan=ttyACM0",
        &by_id,
        "gsusb",
        "gsusb=206F33893845",
        "pcan",
        "pcan=0000002A",
        "gvret=esp32ret.local:2323",
        "gvret=[fe80::1]:23",
    ] {
        assert_eq!(parsed(text).to_string(), text);
    }
}

#[test]
fn a_gvret_bus_takes_port_23_unless_it_names_one_and_brackets_an_ipv6_host() {
    for (text, host, port, shown) in [
        (
            "gvret=192.168.4.1",
            "192.168.4.1",
            23,
            "gvret=192.168.4.1:23",
        ),
        ("gvret=fe80::1", "fe80::1", 23, "gvret=[fe80::1]:23"),
        (
            "gvret=[fe80::1]:2323",
            "fe80::1",
            2323,
            "gvret=[fe80::1]:2323",
        ),
    ] {
        let bus = parsed(text);
        assert_eq!(
            bus,
            CanBus::Gvret {
                host: host.into(),
                port
            },
            "{text}"
        );
        assert_eq!(bus.to_string(), shown);
    }
}

#[test]
fn a_port_named_by_id_opens_under_dev_serial_by_id() {
    let CanBus::Slcan { port } = parsed(&format!("slcan=by-id:{CANABLE2_BY_ID}")) else {
        panic!("not an SLCAN bus");
    };
    assert_eq!(port.directory, PortDirectory::ById);
    assert_eq!(port.path(), format!("/dev/serial/by-id/{CANABLE2_BY_ID}"));
}

#[cfg(not(windows))]
#[test]
fn a_path_names_the_port_it_opens_only_if_that_port_parses_back() {
    assert_eq!(
        SerialPort::at("/dev/ttyACM0"),
        Some(SerialPort {
            directory: PortDirectory::Devices,
            name: "ttyACM0".into()
        })
    );
    assert_eq!(
        SerialPort::at(&format!("/dev/serial/by-id/{CANABLE2_BY_ID}")),
        Some(SerialPort {
            directory: PortDirectory::ById,
            name: CANABLE2_BY_ID.into()
        })
    );
    for path in [
        "/dev/",
        "/dev/serial/by-path/pci-0",
        "/dev/tty@0",
        "/dev/by-id:usb-Foo",
    ] {
        assert_eq!(SerialPort::at(path), None, "{path}");
    }
}

#[test]
fn an_adapter_serial_must_be_named_after_its_equals_and_hold_no_separator() {
    for (bad, wanted) in [
        ("gsusb=", "or write gsusb alone"),
        ("pcan=", "or write pcan alone"),
        ("gsusb=A/B", "can't contain '/' or '@'"),
        ("pcan=A@B", "can't contain '/' or '@'"),
    ] {
        let why = bad.parse::<CanBus>().unwrap_err().to_string();
        assert!(why.contains(wanted), "{bad}: {why}");
    }
}

#[test]
fn a_gvret_bus_without_a_usable_endpoint_is_refused_naming_its_form() {
    for bad in [
        "gvret=",
        "gvret=host:port",
        "gvret=:23",
        "gvret=[fe80::1",
        "gvret=[fe80::1]x",
        "gvret=host/x",
    ] {
        let why = bad.parse::<CanBus>().unwrap_err().to_string();
        assert!(why.contains("gvret=<host>[:<port>]"), "{bad}: {why}");
    }
}

#[test]
fn a_port_name_containing_an_at_sign_is_refused_because_at_starts_the_device_id() {
    let refused = "slcan=by-id:usb-Foo@Bar_X-if00"
        .parse::<CanBus>()
        .unwrap_err();
    assert_eq!(
        refused,
        BusParseError::Port {
            bus: "slcan=by-id:usb-Foo@Bar_X-if00".into(),
            source: PortParseError::DeviceSeparator("usb-Foo@Bar_X-if00".into()),
        }
    );
    let why = refused.source().unwrap().to_string();
    assert!(why.contains("can't contain '@'"), "{why}");
}

#[test]
fn an_interface_name_containing_an_at_sign_is_refused_because_at_starts_the_device_id() {
    for bad in ["can0@1", "@can0", "vcan@"] {
        let why = bad.parse::<CanBus>().unwrap_err().to_string();
        assert!(why.contains("can't contain '@'"), "{bad}: {why}");
    }
    assert_eq!(
        "can0".parse::<CanBus>(),
        Ok(CanBus::SocketCan {
            interface: "can0".into()
        })
    );
}

#[test]
fn an_interface_name_containing_a_slash_is_refused_because_linux_forbids_it() {
    for bad in ["can0/1", "/can0", "vcan/"] {
        let why = bad.parse::<CanBus>().unwrap_err().to_string();
        assert!(why.contains("can't contain '/'"), "{bad}: {why}");
    }
}

#[test]
fn a_bus_that_names_no_form_is_invalid_with_its_reason() {
    assert!(matches!(
        "gvret=".parse::<CanBus>(),
        Err(BusParseError::Invalid(why)) if why.contains("gvret=<host>")
    ));
}

#[test]
fn a_control_character_is_refused() {
    for bad in ["can\u{0}x", "slcan=tty\u{0}ACM0", "gvret=host\u{1b}:23"] {
        let why = bad.parse::<CanBus>().unwrap_err().to_string();
        assert!(why.contains("control character"), "{bad:?}: {why}");
    }
}

#[test]
fn the_forms_offered_are_the_adapters_built_in_here() {
    let usb = cfg!(any(target_os = "macos", target_os = "windows"));
    assert_eq!(BUS_FORMS.contains(&"slcan=<name>"), cfg!(feature = "slcan"));
    assert_eq!(
        BUS_FORMS.contains(&"slcan=by-id:<name>"),
        cfg!(feature = "slcan") && cfg!(target_os = "linux")
    );
    assert_eq!(
        BUS_FORMS.iter().any(|form| form.contains("can0")),
        cfg!(feature = "socketcan") && cfg!(target_os = "linux")
    );
    assert_eq!(
        BUS_FORMS.contains(&"gsusb[=<serial>]"),
        cfg!(feature = "gsusb") && usb
    );
    assert_eq!(
        BUS_FORMS.contains(&"pcan[=<serial>]"),
        cfg!(feature = "pcan") && usb
    );
    assert_eq!(
        BUS_FORMS.contains(&"gvret=<host>[:<port>]"),
        cfg!(feature = "gvret")
    );
}

#[test]
fn an_empty_bus_is_refused_naming_the_forms_this_build_opens() {
    let refused = "".parse::<CanBus>().unwrap_err();
    assert_eq!(refused, BusParseError::Empty);
    let why = refused.to_string();
    assert_eq!(why, name_the_bus("the CAN bus", BUS_FORMS));
    for form in BUS_FORMS {
        assert!(why.contains(form), "{form}: {why}");
    }
    assert_eq!(
        BUS_FORMS.is_empty(),
        why.contains("opens no CAN bus"),
        "{why}"
    );
}

#[test]
fn every_bus_has_its_kind_and_every_kind_its_forms() {
    for (text, kind) in [
        ("can0", BusKind::SocketCan),
        ("slcan=ttyACM0", BusKind::Slcan),
        ("gsusb", BusKind::GsUsb),
        ("pcan", BusKind::Pcan),
        ("gvret=127.0.0.1", BusKind::Gvret),
    ] {
        assert_eq!(parsed(text).kind(), kind, "{text}");
    }
    let every: Vec<&str> = BusKind::ALL
        .into_iter()
        .flat_map(BusKind::forms)
        .copied()
        .collect();
    let mut expected = vec![
        "a SocketCAN interface such as can0",
        "slcan=<name>",
        "gsusb[=<serial>]",
        "pcan[=<serial>]",
        "gvret=<host>[:<port>]",
    ];
    if cfg!(target_os = "linux") {
        expected.insert(2, "slcan=by-id:<name>");
    }
    assert_eq!(every, expected);
}

#[test]
fn the_forms_of_some_kinds_are_those_this_platform_reaches_in_order() {
    const KINDS: &[BusKind] = &[BusKind::Gvret, BusKind::SocketCan, BusKind::GsUsb];
    const FORMS: [&str; form_count(KINDS)] = forms_of(KINDS);
    let expected: Vec<&str> = KINDS
        .iter()
        .filter(|kind| kind.reachable())
        .flat_map(|kind| kind.forms())
        .copied()
        .collect();
    assert_eq!(FORMS.to_vec(), expected);
    assert_eq!(forms_of::<0>(&[]), [""; 0]);
}

#[test]
fn the_kinds_built_are_those_whose_feature_is_on() {
    let built: Vec<BusKind> = BusKind::ALL
        .into_iter()
        .filter(|kind| kind.built())
        .collect();
    assert_eq!(BUILT, built.as_slice());
}

#[test]
fn slcan_gs_usb_and_peak_set_the_bus_rate() {
    let setting: Vec<BusKind> = BusKind::ALL
        .into_iter()
        .filter(|kind| kind.sets_bitrate())
        .collect();
    assert_eq!(setting, [BusKind::Slcan, BusKind::GsUsb, BusKind::Pcan]);
}
