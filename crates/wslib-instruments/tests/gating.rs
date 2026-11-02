use std::io;

use wslib_instruments::{
    probe::ProbeError,
    uri::{BUS_FORMS, ProbeUri, URI_FORMS, open},
};

fn parsed(text: &str) -> ProbeUri {
    text.parse().unwrap_or_else(|e| panic!("{text}: {e}"))
}

fn open_error(text: &str) -> io::Error {
    open(&parsed(text))
        .err()
        .unwrap_or_else(|| panic!("{text} opened"))
}

#[test]
fn the_forms_offered_are_the_backends_built_in_here() {
    let usb = cfg!(any(target_os = "macos", target_os = "windows"));
    assert_eq!(URI_FORMS.contains(&"121gw"), cfg!(feature = "ble"));
    assert_eq!(
        BUS_FORMS.contains(&"slcan=<name>"),
        cfg!(feature = "can-slcan")
    );
    assert_eq!(
        BUS_FORMS.iter().any(|form| form.contains("can0")),
        cfg!(feature = "can-socketcan") && cfg!(target_os = "linux")
    );
    assert_eq!(
        BUS_FORMS.contains(&"gsusb[=<serial>]"),
        cfg!(feature = "can-gsusb") && usb
    );
    assert_eq!(
        BUS_FORMS.contains(&"pcan[=<serial>]"),
        cfg!(feature = "can-pcan") && usb
    );
    assert_eq!(
        BUS_FORMS.contains(&"gvret=<host>[:<port>]"),
        cfg!(feature = "can-gvret")
    );
    assert_eq!(
        URI_FORMS
            .iter()
            .any(|form| form.starts_with("wiredreflow:")),
        !BUS_FORMS.is_empty()
    );
}

#[test]
fn a_probe_whose_backend_is_left_out_parses_and_opening_it_names_the_feature() {
    for (text, feature, built) in [
        ("121gw", "ble", cfg!(feature = "ble")),
        (
            "wiredreflow:slcan=ttyACM0@028F08",
            "can-slcan",
            cfg!(feature = "can-slcan"),
        ),
        (
            "wiredreflow:can0@028F08",
            "can-socketcan",
            cfg!(feature = "can-socketcan"),
        ),
        (
            "wiredreflow:gsusb@028F08",
            "can-gsusb",
            cfg!(feature = "can-gsusb"),
        ),
        (
            "wiredreflow:pcan@028F08",
            "can-pcan",
            cfg!(feature = "can-pcan"),
        ),
        (
            "wiredreflow:gvret=127.0.0.1@028F08",
            "can-gvret",
            cfg!(feature = "can-gvret"),
        ),
    ] {
        if built {
            continue;
        }
        let error = open_error(text);
        assert_eq!(error.kind(), io::ErrorKind::Unsupported, "{text}");
        let inner = error
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<ProbeError>());
        assert_eq!(inner, Some(&ProbeError::FeatureDisabled(feature)), "{text}");
        assert!(error.to_string().contains(feature), "{text}: {error}");
    }
}

#[cfg(not(any(
    feature = "ble",
    feature = "can-slcan",
    feature = "can-socketcan",
    feature = "can-gsusb",
    feature = "can-pcan",
    feature = "can-gvret"
)))]
#[test]
fn a_build_with_no_backend_says_so_when_a_probe_is_unrecognised() {
    let error = "siglent:10.0.0.5"
        .parse::<ProbeUri>()
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("opens no probe") && error.contains("`ble`"),
        "{error}"
    );
}

#[cfg(feature = "ble")]
#[test]
fn every_refusal_of_a_malformed_or_unknown_uri_names_the_accepted_forms() {
    for bad in ["", "siglent:10.0.0.5", "121gwx", "121gw:"] {
        let error = bad.parse::<ProbeUri>().unwrap_err().to_string();
        assert!(
            error.contains("121gw:<address-or-name>"),
            "{bad:?}: {error}"
        );
    }
}

#[cfg(feature = "can-slcan")]
#[test]
fn an_unrecognised_probe_lists_the_wiredreflow_form_and_its_buses() {
    let error = "siglent:10.0.0.5"
        .parse::<ProbeUri>()
        .unwrap_err()
        .to_string();
    assert!(error.contains("wiredreflow:<bus>[@<device-id>]"), "{error}");
    assert!(error.contains("slcan=<name>"), "{error}");
    assert_eq!(
        error.contains("by-id"),
        cfg!(target_os = "linux"),
        "/dev/serial/by-id is Linux's: {error}"
    );
}

#[cfg(feature = "can-slcan")]
#[test]
fn opening_a_wiredreflow_from_inside_a_tokio_runtime_returns_the_error_rather_than_panicking() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let uri = parsed("wiredreflow:slcan=wslib-no-such-port@028F08");
    let error = runtime.block_on(async { open(&uri).err().unwrap() });
    assert!(error.to_string().contains("wslib-no-such-port"), "{error}");
}

#[cfg(all(feature = "can-socketcan", not(target_os = "linux")))]
#[test]
fn a_socketcan_bus_off_linux_names_only_the_buses_this_build_opens() {
    let error = open_error("wiredreflow:can0@028F08");
    assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    let error = error.to_string();
    for form in BUS_FORMS {
        assert!(error.contains(form), "{form}: {error}");
    }
    assert_eq!(
        BUS_FORMS.is_empty(),
        error.contains("opens no CAN bus"),
        "{error}"
    );
    assert!(!error.contains("by-id"), "{error}");
}

#[cfg(all(feature = "can-gsusb", target_os = "linux"))]
#[test]
fn a_usb_adapter_on_linux_says_to_name_its_socketcan_interface() {
    let error = open_error("wiredreflow:gsusb@028F08");
    assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    assert!(error.to_string().contains("can0"), "{error}");
}

#[cfg(all(
    feature = "can-gsusb",
    feature = "can-pcan",
    any(target_os = "macos", target_os = "windows")
))]
#[test]
fn a_usb_adapter_serial_nothing_answers_to_is_not_found() {
    for text in [
        "wiredreflow:gsusb=wslib-no-such-serial@028F08",
        "wiredreflow:pcan=wslib-no-such-serial@028F08",
    ] {
        assert_eq!(open_error(text).kind(), io::ErrorKind::NotFound, "{text}");
    }
}
