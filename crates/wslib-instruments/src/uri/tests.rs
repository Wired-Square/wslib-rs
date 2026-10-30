use crate::{
    gw121::{
        Target,
        decode::{STATUS, STATUS_AUTO_POWER_OFF, STATUS_OVERLOAD, THERMOCOUPLE},
    },
    sample::{Sample, Stamp},
    uri::{ProbeUri, ProbeUriError, value_text},
    value::Value,
    wiredreflow::{
        bus::{CanBus, PortDirectory, SerialPort},
        frame::{CJ1, DEVICE_ID_MAX, TC1, device_text},
    },
};

const TENTHS: i8 = -1;
const ROOM_TENTHS: i64 = 210;
const STATUS_EXPONENT: i8 = 0;
const THERMOCOUPLE_SLUG: &str = "device.0.measurement.temperature.ch0";
const CANABLE2_BY_ID: &str =
    "usb-Openlight_Labs_CANable2_b158aa7_github.com_normaldotcom_canable2.git_206F33893845-if00";

fn parsed(text: &str) -> ProbeUri {
    text.parse().unwrap_or_else(|e| panic!("{text}: {e}"))
}

#[test]
fn bare_121gw_is_the_meter_by_its_default_name() {
    assert_eq!(
        parsed("121gw"),
        ProbeUri::Gw121 {
            target: Target::Name("121GW".into()),
            selected: vec![]
        }
    );
    assert_eq!(parsed("121gw").to_string(), "121gw:121GW");
}

#[test]
fn an_address_target_keeps_its_colons_and_round_trips() {
    let uri = parsed("121gw:88:6B:0F:81:A9:53");
    assert_eq!(
        uri,
        ProbeUri::Gw121 {
            target: Target::Address("88:6B:0F:81:A9:53".into()),
            selected: vec![]
        }
    );
    assert_eq!(uri.to_string(), "121gw:88:6B:0F:81:A9:53");
}

#[test]
fn a_display_name_and_its_slug_select_the_same_signal_and_display_as_the_slug() {
    let by_name = parsed("121gw:121GW/Thermocouple");
    let by_slug = parsed(&format!("121gw:121GW/{THERMOCOUPLE_SLUG}"));
    assert_eq!(by_name, by_slug);
    assert_eq!(by_name.selected(), [THERMOCOUPLE]);
    assert_eq!(
        by_name.to_string(),
        format!("121gw:121GW/{THERMOCOUPLE_SLUG}")
    );
}

#[test]
fn a_signal_the_meter_cannot_produce_is_refused_naming_it() {
    let error = "121gw:121GW/device.0.measurement.pressure.ch0"
        .parse::<ProbeUri>()
        .unwrap_err()
        .to_string();
    assert_eq!(
        error,
        "121gw:121GW can't produce device.0.measurement.pressure.ch0"
    );
}

#[test]
fn an_unknown_selector_names_the_signals_the_scheme_offers() {
    let error = "121gw:121GW/voltage"
        .parse::<ProbeUri>()
        .unwrap_err()
        .to_string();
    assert!(error.contains("Thermocouple"), "{error}");
    assert!(
        error.contains("expected 4-6 dot-separated segments"),
        "{error}"
    );
}

#[test]
fn the_status_reads_ok_or_lists_its_flags_and_a_value_reads_as_its_decimal() {
    let uri = parsed("121gw");
    let at = Stamp::now();
    assert_eq!(
        value_text(
            &uri,
            &Sample::new(STATUS, Value::new(0, STATUS_EXPONENT), at)
        ),
        "ok"
    );
    let flagged = Value::new(STATUS_AUTO_POWER_OFF | STATUS_OVERLOAD, STATUS_EXPONENT);
    assert_eq!(
        value_text(&uri, &Sample::new(STATUS, flagged, at)),
        "APO on, OL"
    );
    assert_eq!(
        value_text(
            &uri,
            &Sample::new(THERMOCOUPLE, Value::new(ROOM_TENTHS, TENTHS), at)
        ),
        "21.0"
    );
}

const BENCH_DEVICE: u32 = 0x02_8F08;

fn can0() -> CanBus {
    CanBus::SocketCan {
        interface: "can0".into(),
    }
}

#[test]
fn a_wiredreflow_uri_names_its_bus_and_optionally_its_device() {
    assert_eq!(
        parsed("wiredreflow:can0"),
        ProbeUri::WiredReflow {
            bus: can0(),
            device: None,
            selected: vec![]
        }
    );
    let pinned = parsed("wiredreflow:can0@028F08/TC1/CJ1");
    assert_eq!(
        pinned,
        ProbeUri::WiredReflow {
            bus: can0(),
            device: Some(BENCH_DEVICE),
            selected: vec![TC1, CJ1]
        }
    );
    assert_eq!(
        pinned.to_string(),
        "wiredreflow:can0@028F08/device.0.measurement.temperature.ch0/device.0.measurement.temperature.reference.ch0"
    );
}

#[test]
fn an_slcan_port_is_a_bus_too() {
    let uri = parsed("wiredreflow:slcan=cu.usbmodem2101@028F08");
    assert_eq!(
        uri,
        ProbeUri::WiredReflow {
            bus: CanBus::Slcan {
                port: SerialPort {
                    directory: PortDirectory::Devices,
                    name: "cu.usbmodem2101".into()
                }
            },
            device: Some(BENCH_DEVICE),
            selected: vec![]
        }
    );
    assert_eq!(uri.to_string(), "wiredreflow:slcan=cu.usbmodem2101@028F08");
}

#[test]
fn a_gs_usb_or_peak_adapter_is_a_bus_named_by_its_serial_or_alone() {
    for (text, bus) in [
        ("wiredreflow:gsusb@028F08", CanBus::GsUsb { serial: None }),
        (
            "wiredreflow:gsusb=206F33893845@028F08",
            CanBus::GsUsb {
                serial: Some("206F33893845".into()),
            },
        ),
        ("wiredreflow:pcan@028F08", CanBus::Pcan { serial: None }),
        (
            "wiredreflow:pcan=0000002A@028F08",
            CanBus::Pcan {
                serial: Some("0000002A".into()),
            },
        ),
    ] {
        let uri = parsed(text);
        assert_eq!(
            uri,
            ProbeUri::WiredReflow {
                bus,
                device: Some(BENCH_DEVICE),
                selected: vec![]
            },
            "{text}"
        );
        assert_eq!(uri.to_string(), text);
    }
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
fn a_device_id_may_carry_0x_and_must_fit_twenty_bits() {
    assert_eq!(
        parsed("wiredreflow:can0@0x28f08"),
        parsed("wiredreflow:can0@028F08")
    );
    for bad in [
        "wiredreflow:can0@1000000",
        "wiredreflow:can0@zz",
        "wiredreflow:can0@",
        "wiredreflow:",
        "wiredreflow:slcan=",
        "wiredreflow:slcan=by-id:",
        "wiredreflow:gsusb=",
        "wiredreflow:pcan=",
    ] {
        assert!(bad.parse::<ProbeUri>().is_err(), "{bad}");
    }
}

#[test]
fn a_wiredreflow_selector_outside_its_signals_is_refused() {
    let error = "wiredreflow:can0/Thermocouple"
        .parse::<ProbeUri>()
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("TC1"),
        "the refusal names the board's signals: {error}"
    );
}

#[test]
fn only_an_unknown_scheme_is_unrecognised_so_a_consumer_can_try_its_own() {
    for unknown in ["sim:25", "siglent:10.0.0.5"] {
        assert!(
            matches!(
                unknown.parse::<ProbeUri>(),
                Err(ProbeUriError::Unrecognised(_))
            ),
            "{unknown}"
        );
    }
    for known in [
        "121gw:",
        "wiredreflow",
        "wiredreflow:",
        "wiredreflow:can0@zz",
        "121gw:121GW/voltage",
    ] {
        let error = known.parse::<ProbeUri>().unwrap_err();
        assert!(
            !matches!(error, ProbeUriError::Unrecognised(_)),
            "{known}: {error}"
        );
    }
}

#[test]
fn bare_wiredreflow_is_refused_for_want_of_a_bus_with_an_example_for_this_platform() {
    let error = "wiredreflow".parse::<ProbeUri>().unwrap_err();
    let example = if cfg!(target_os = "linux") {
        "wiredreflow:can0"
    } else {
        "wiredreflow:slcan="
    };
    assert!(
        matches!(&error, ProbeUriError::Target(why) if why.contains(example)),
        "{error}"
    );
}

#[test]
fn an_empty_signal_after_a_slash_is_refused() {
    for bad in [
        "121gw:121GW/",
        "wiredreflow:can0/",
        "wiredreflow:can0/TC1//TC2",
    ] {
        let error = bad.parse::<ProbeUri>().unwrap_err();
        assert!(
            matches!(&error, ProbeUriError::Signal(why) if why.contains("empty signal after '/'")),
            "{bad}: {error}"
        );
    }
}

#[test]
fn a_repeated_signal_is_selected_once_in_first_seen_order() {
    assert_eq!(
        parsed("wiredreflow:can0/TC1/CJ1/TC1/CJ1").selected(),
        [TC1, CJ1]
    );
    assert_eq!(
        parsed("121gw:121GW/Thermocouple/Thermocouple").selected(),
        [THERMOCOUPLE]
    );
}

#[test]
fn a_device_id_is_hex_digits_only_and_a_refusal_states_the_limit() {
    for bad in [
        "wiredreflow:can0@+28F08",
        "wiredreflow:can0@0x+28F08",
        "wiredreflow:can0@-1",
    ] {
        assert!(
            matches!(bad.parse::<ProbeUri>(), Err(ProbeUriError::Target(_))),
            "{bad}"
        );
    }
    let error = "wiredreflow:can0@1000000"
        .parse::<ProbeUri>()
        .unwrap_err()
        .to_string();
    assert!(error.contains(&format!("{DEVICE_ID_MAX:X}")), "{error}");
}

#[test]
fn a_device_id_reads_as_six_hex_digits_everywhere() {
    assert_eq!(device_text(BENCH_DEVICE), "028F08");
    assert_eq!(
        parsed("wiredreflow:can0@28f08").to_string(),
        format!("wiredreflow:can0@{}", device_text(BENCH_DEVICE))
    );
}

fn refusal(bad: &str) -> String {
    match bad.parse::<ProbeUri>() {
        Err(ProbeUriError::Target(why)) => why,
        other => panic!("{bad}: {other:?}"),
    }
}

#[test]
fn an_slcan_port_written_as_a_dev_path_is_refused_quoting_the_corrected_uri() {
    for (bad, wanted) in [
        (
            "wiredreflow:slcan=/dev/ttyACM0",
            "write wiredreflow:slcan=ttyACM0",
        ),
        (
            "wiredreflow:slcan=/dev/ttyACM0@028F08/TC1",
            "write wiredreflow:slcan=ttyACM0@028F08/TC1",
        ),
        (
            "wiredreflow:slcan=/dev/ttyACM0/TC1/CJ1",
            "write wiredreflow:slcan=ttyACM0/TC1/CJ1",
        ),
    ] {
        let why = refusal(bad);
        assert!(why.ends_with(wanted), "{bad}: {why}");
    }
}

#[test]
fn an_slcan_port_named_by_id_opens_under_dev_serial_by_id_and_round_trips() {
    let text = format!("wiredreflow:slcan=by-id:{CANABLE2_BY_ID}@028F08/TC1");
    let uri = parsed(&text);
    let port = SerialPort {
        directory: PortDirectory::ById,
        name: CANABLE2_BY_ID.into(),
    };
    assert_eq!(port.path(), format!("/dev/serial/by-id/{CANABLE2_BY_ID}"));
    assert_eq!(
        uri,
        ProbeUri::WiredReflow {
            bus: CanBus::Slcan { port },
            device: Some(BENCH_DEVICE),
            selected: vec![TC1]
        }
    );
    assert_eq!(parsed(&uri.to_string()), uri);
    assert!(
        uri.to_string()
            .starts_with(&format!("wiredreflow:slcan=by-id:{CANABLE2_BY_ID}@028F08/")),
        "{uri}"
    );
    let bare = format!("wiredreflow:slcan=by-id:{CANABLE2_BY_ID}");
    assert_eq!(parsed(&bare).to_string(), bare);
}

#[test]
fn a_port_name_containing_an_at_sign_is_refused_because_at_starts_the_device_id() {
    let why = "slcan=by-id:usb-Foo@Bar_X-if00"
        .parse::<CanBus>()
        .unwrap_err();
    assert!(why.contains("can't contain '@'"), "{why}");
    let why = refusal("wiredreflow:slcan=by-id:usb-Foo@Bar_X-if00@028F08");
    assert!(
        why.contains("is not a WiredReflow device id") && why.contains("after the first '@'"),
        "{why}"
    );
}

#[test]
fn an_slcan_port_written_as_a_by_id_path_is_refused_quoting_its_by_id_uri() {
    for suffix in ["", "@028F08/TC1", "/TC1"] {
        let bad = format!("wiredreflow:slcan=/dev/serial/by-id/{CANABLE2_BY_ID}{suffix}");
        let why = refusal(&bad);
        assert!(
            why.ends_with(&format!(
                "write wiredreflow:slcan=by-id:{CANABLE2_BY_ID}{suffix}"
            )),
            "{bad}: {why}"
        );
    }
}

#[test]
fn an_slcan_path_naming_no_port_this_probe_can_open_is_refused_naming_the_forms_this_platform_has()
{
    for bad in [
        "wiredreflow:slcan=/dev/serial/by-path/pci-0000:00:14.0-usb-0:1:1.0",
        "wiredreflow:slcan=/dev/serial/by-id/usb-Foo@Bar_X-if00",
        "wiredreflow:slcan=/dev/ttyACM0/Thermocouple",
        "wiredreflow:slcan=/dev/by-id:usb-Foo",
    ] {
        let why = refusal(bad);
        assert!(why.contains("slcan=<name>"), "{bad}: {why}");
        assert_eq!(
            why.contains("slcan=by-id:<name>"),
            cfg!(target_os = "linux"),
            "{bad}: {why}"
        );
    }
}

#[test]
fn a_device_id_0x_prefix_is_read_in_either_case() {
    assert_eq!(
        parsed("wiredreflow:can0@0X28F08"),
        parsed("wiredreflow:can0@028F08")
    );
    assert!(matches!(
        "wiredreflow:can0@0X+28F08".parse::<ProbeUri>(),
        Err(ProbeUriError::Target(_))
    ));
}

#[test]
fn a_gvret_device_is_a_bus_named_by_its_host_and_port_which_defaults_to_23() {
    for (text, host, port, shown) in [
        (
            "wiredreflow:gvret=192.168.4.1@028F08",
            "192.168.4.1",
            23,
            "wiredreflow:gvret=192.168.4.1:23@028F08",
        ),
        (
            "wiredreflow:gvret=esp32ret.local:2323/TC1",
            "esp32ret.local",
            2323,
            "",
        ),
        ("wiredreflow:gvret=[fe80::1]:23", "fe80::1", 23, ""),
        (
            "wiredreflow:gvret=fe80::1",
            "fe80::1",
            23,
            "wiredreflow:gvret=[fe80::1]:23",
        ),
    ] {
        let uri = parsed(text);
        let ProbeUri::WiredReflow { bus, .. } = &uri else {
            panic!("{text}: {uri:?}")
        };
        assert_eq!(
            bus,
            &CanBus::Gvret {
                host: host.into(),
                port
            },
            "{text}"
        );
        let shown = if shown.is_empty() {
            text.to_owned()
        } else {
            shown.to_owned()
        };
        assert_eq!(
            uri.to_string()
                .replace("/device.0.measurement.temperature.ch0", "/TC1"),
            shown
        );
        assert_eq!(parsed(&uri.to_string()), uri);
    }
}

#[test]
fn a_gvret_bus_without_a_usable_endpoint_is_refused_naming_its_form() {
    for bad in [
        "wiredreflow:gvret=",
        "wiredreflow:gvret=host:port",
        "wiredreflow:gvret=:23",
        "wiredreflow:gvret=[fe80::1",
    ] {
        let why = refusal(bad);
        assert!(why.contains("gvret=<host>[:<port>]"), "{bad}: {why}");
    }
}

#[test]
fn a_control_character_in_a_target_or_bus_is_refused_before_anything_opens() {
    for bad in [
        "wiredreflow:can\u{0}x",
        "wiredreflow:slcan=tty\u{0}ACM0@028F08",
        "wiredreflow:gvret=host\u{1b}:23",
        "121gw:a\u{0}b",
        "121gw:121GW\u{7f}",
    ] {
        let why = refusal(bad);
        assert!(why.contains("control character"), "{bad:?}: {why}");
    }
    assert!("a\u{0}b".parse::<Target>().is_err());
    assert!("can\u{0}x".parse::<CanBus>().is_err());
}

#[test]
fn the_121gw_scheme_is_read_in_any_case_and_written_in_lower_case() {
    assert_eq!(parsed("121GW"), parsed("121gw"));
    let uri = parsed("121GW:88:6B:0F:81:A9:53");
    assert_eq!(uri, parsed("121gw:88:6B:0F:81:A9:53"));
    assert_eq!(uri.to_string(), "121gw:88:6B:0F:81:A9:53");
}
