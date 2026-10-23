//! Which host-side endpoint a (chip family, USB access, transport) triple
//! flashes through, resolved over a snapshot of the host's serial ports.

use std::str::FromStr;

use crate::chip::{ChipFamily, ESPRESSIF_VID};
use crate::error::{FlashError, Result};
use crate::ports::{SerialPort, describe_ports, describe_serials, ports_for_serial};

/// How the chip reaches USB from the board, if at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum UsbAccess {
    Native,
    CdcInterface { interface: u8 },
    None,
}

/// Whether the host reaches the chip directly or through a programmer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum Transport {
    Direct,
    ViaProgrammer,
}

impl Transport {
    pub fn as_str(self) -> &'static str {
        match self {
            Transport::Direct => "direct",
            Transport::ViaProgrammer => "via_programmer",
        }
    }
}

impl FromStr for Transport {
    type Err = FlashError;

    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "direct" => Ok(Transport::Direct),
            "via_programmer" => Ok(Transport::ViaProgrammer),
            _ => Err(FlashError::Message(format!(
                "unknown transport {s:?}: expected \"direct\" or \"via_programmer\""
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlashEndpoint {
    Tty {
        path: String,
        usb_serial: Option<String>,
    },
    UsbSerial(String),
}

pub fn tty(path: &str, usb_serial: Option<&str>) -> FlashEndpoint {
    FlashEndpoint::Tty {
        path: path.to_string(),
        usb_serial: usb_serial.map(str::to_string),
    }
}

fn describe_access(usb: UsbAccess) -> String {
    match usb {
        UsbAccess::Native => "its native USB interface".into(),
        UsbAccess::CdcInterface { interface } => format!("CDC interface {interface}"),
        UsbAccess::None => "no USB path from the board".into(),
    }
}

pub fn pairing_error(family: ChipFamily, usb: UsbAccess, transport: Transport) -> Option<String> {
    let supported = match transport {
        Transport::ViaProgrammer => family.flashes_over_serial(),
        Transport::Direct => match usb {
            UsbAccess::Native => true,
            UsbAccess::CdcInterface { .. } => family.flashes_over_serial(),
            UsbAccess::None => false,
        },
    };
    if supported {
        None
    } else {
        Some(format!(
            "no flash backend for {} over {} ({})",
            family.as_str(),
            describe_access(usb),
            transport.as_str()
        ))
    }
}

fn single_tty(serial: &str, ports: &[SerialPort]) -> Result<String> {
    let matched = ports_for_serial(ports, serial);
    match matched.as_slice() {
        [] => Err(FlashError::NotAttached(serial.to_string())),
        [only] => Ok(only.path.clone()),
        many => Err(FlashError::Message(format!(
            "USB device {serial} exposes several ttys; declare a cdc_interface on the board's MCU: [{}]",
            describe_ports(many)
        ))),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedDirectDevice {
    pub path: String,
    pub serial_number: Option<String>,
    pub vid: u16,
    pub pid: u16,
}

fn is_native_usb(family: ChipFamily, port: &SerialPort) -> bool {
    match family {
        ChipFamily::Esp32 => port.vid == ESPRESSIF_VID,
        ChipFamily::Stm32 => false,
    }
}

/// The one native-USB device of `family` among `ports`; an error names the
/// fix when there are none or several.
pub fn auto_detect_direct_device(
    family: ChipFamily,
    ports: &[SerialPort],
) -> Result<DetectedDirectDevice> {
    let candidates: Vec<&SerialPort> = ports.iter().filter(|p| is_native_usb(family, p)).collect();
    match candidates.as_slice() {
        [] => Err(FlashError::Message(format!(
            "no native-USB {} device attached — plug the board in or switch the \
             fixture to 'via_programmer' if a programmer is in use",
            family.as_str()
        ))),
        [only] => Ok(DetectedDirectDevice {
            path: only.path.clone(),
            serial_number: only.serial_number.clone(),
            vid: only.vid,
            pid: only.pid,
        }),
        many => Err(FlashError::Message(format!(
            "multiple native-USB {} devices attached — pin a usb_serial on \
             the fixture target to disambiguate: [{}]",
            family.as_str(),
            describe_serials(many.iter().copied()),
        ))),
    }
}

pub fn resolve_endpoint(
    family: ChipFamily,
    usb: UsbAccess,
    transport: Transport,
    usb_serial: Option<&str>,
    ports: &[SerialPort],
) -> Result<FlashEndpoint> {
    if let Some(e) = pairing_error(family, usb, transport) {
        return Err(FlashError::Message(e));
    }
    match (transport, usb, usb_serial) {
        (Transport::ViaProgrammer, _, None) => Err(FlashError::Message(
            "via_programmer flash request missing usb_serial — programmer USB serials must be \
             pinned on the fixture target"
                .into(),
        )),
        (Transport::ViaProgrammer, _, Some(serial)) => {
            single_tty(serial, ports).map(|p| tty(&p, Some(serial)))
        }
        (Transport::Direct, UsbAccess::Native, None) => match family {
            ChipFamily::Esp32 => {
                let detected = auto_detect_direct_device(family, ports)?;
                Ok(tty(&detected.path, detected.serial_number.as_deref()))
            }
            ChipFamily::Stm32 => Err(FlashError::Message(
                "DFU flashing needs the board's USB serial pinned on the fixture target".into(),
            )),
        },
        (Transport::Direct, UsbAccess::Native, Some(serial)) => match family {
            ChipFamily::Esp32 => single_tty(serial, ports).map(|p| tty(&p, Some(serial))),
            ChipFamily::Stm32 => Ok(FlashEndpoint::UsbSerial(serial.to_string())),
        },
        (Transport::Direct, UsbAccess::CdcInterface { .. }, None) => Err(FlashError::Message(
            "a CDC-bridged MCU needs the board's USB serial pinned on the fixture target".into(),
        )),
        (Transport::Direct, UsbAccess::CdcInterface { interface }, Some(serial)) => {
            let matched = ports_for_serial(ports, serial);
            if matched.is_empty() {
                return Err(FlashError::NotAttached(serial.to_string()));
            }
            if matched.iter().all(|p| p.interface.is_none()) {
                return Err(FlashError::Message(format!(
                    "the host's USB enumeration reports no interface numbers for {serial}, so \
                     CDC interface {interface} cannot be located: [{}]",
                    describe_ports(&matched)
                )));
            }
            matched
                .iter()
                .find(|p| p.interface == Some(interface))
                .map(|p| tty(&p.path, Some(serial)))
                .ok_or_else(|| {
                    FlashError::Message(format!(
                        "no CDC interface {interface} on USB device {serial}; present: [{}]",
                        describe_ports(&matched)
                    ))
                })
        }
        (Transport::Direct, UsbAccess::None, _) => Err(FlashError::Message(format!(
            "{} has no USB path from the board; use a programmer target",
            family.as_str()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn port(path: &str, serial: &str, interface: u8) -> SerialPort {
        SerialPort::new(path, Some(serial), Some(interface))
    }

    const COMPOSITE: &str = "4B305017002A0042";

    fn composite() -> Vec<SerialPort> {
        vec![
            port("/dev/ttyACM1", COMPOSITE, 1),
            port("/dev/ttyACM2", COMPOSITE, 3),
        ]
    }

    #[test]
    fn cdc_interface_resolves_to_the_matching_tty() {
        let endpoint = resolve_endpoint(
            ChipFamily::Esp32,
            UsbAccess::CdcInterface { interface: 3 },
            Transport::Direct,
            Some(COMPOSITE),
            &composite(),
        )
        .unwrap();
        assert_eq!(endpoint, tty("/dev/ttyACM2", Some(COMPOSITE)));
    }

    #[test]
    fn enumeration_without_interface_numbers_is_named_as_the_cause() {
        let ports = vec![SerialPort::new("/dev/ttyACM1", Some(COMPOSITE), None)];
        let err = resolve_endpoint(
            ChipFamily::Esp32,
            UsbAccess::CdcInterface { interface: 3 },
            Transport::Direct,
            Some(COMPOSITE),
            &ports,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("no interface numbers"), "{err}");
    }

    #[test]
    fn missing_cdc_interface_lists_what_is_present() {
        let err = resolve_endpoint(
            ChipFamily::Esp32,
            UsbAccess::CdcInterface { interface: 5 },
            Transport::Direct,
            Some(COMPOSITE),
            &composite(),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("if01 → /dev/ttyACM1"), "{err}");
        assert!(err.contains("if03 → /dev/ttyACM2"), "{err}");
    }

    #[test]
    fn native_stm32_resolves_to_the_usb_serial_without_a_tty() {
        let endpoint = resolve_endpoint(
            ChipFamily::Stm32,
            UsbAccess::Native,
            Transport::Direct,
            Some(COMPOSITE),
            &composite(),
        )
        .unwrap();
        assert_eq!(endpoint, FlashEndpoint::UsbSerial(COMPOSITE.into()));
    }

    #[test]
    fn native_esp32_with_several_ttys_asks_for_a_cdc_interface() {
        let err = resolve_endpoint(
            ChipFamily::Esp32,
            UsbAccess::Native,
            Transport::Direct,
            Some(COMPOSITE),
            &composite(),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("cdc_interface"), "{err}");
    }

    #[test]
    fn native_esp32_with_one_tty_resolves_to_it() {
        let ports = vec![port("/dev/ttyACM0", "58:8C", 0)];
        let endpoint = resolve_endpoint(
            ChipFamily::Esp32,
            UsbAccess::Native,
            Transport::Direct,
            Some("58:8C"),
            &ports,
        )
        .unwrap();
        assert_eq!(endpoint, tty("/dev/ttyACM0", Some("58:8C")));
    }

    #[test]
    fn unpaired_family_and_access_are_refused_before_enumeration() {
        let err = pairing_error(
            ChipFamily::Stm32,
            UsbAccess::CdcInterface { interface: 1 },
            Transport::Direct,
        )
        .unwrap();
        assert!(err.contains("no flash backend for stm32"), "{err}");
        assert!(
            pairing_error(ChipFamily::Esp32, UsbAccess::None, Transport::ViaProgrammer).is_none()
        );
        assert!(pairing_error(ChipFamily::Esp32, UsbAccess::None, Transport::Direct).is_some());
        assert!(
            pairing_error(ChipFamily::Stm32, UsbAccess::None, Transport::ViaProgrammer).is_some()
        );
    }

    #[test]
    fn programmer_transport_needs_a_pinned_serial() {
        let err = resolve_endpoint(
            ChipFamily::Esp32,
            UsbAccess::None,
            Transport::ViaProgrammer,
            None,
            &[],
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("usb_serial"), "{err}");
    }

    fn espressif(path: &str, serial: &str) -> SerialPort {
        SerialPort {
            vid: ESPRESSIF_VID,
            ..SerialPort::new(path, Some(serial), Some(0))
        }
    }

    #[test]
    fn native_esp32_without_a_serial_auto_detects_the_only_espressif_port() {
        let ports = vec![
            SerialPort::new("/dev/ttyUSB0", Some("BRIDGE"), Some(0)),
            espressif("/dev/ttyACM0", "58:8C"),
        ];
        let endpoint = resolve_endpoint(
            ChipFamily::Esp32,
            UsbAccess::Native,
            Transport::Direct,
            None,
            &ports,
        )
        .unwrap();
        assert_eq!(endpoint, tty("/dev/ttyACM0", Some("58:8C")));
    }

    #[test]
    fn missing_serial_is_a_typed_not_attached_error() {
        for usb in [UsbAccess::Native, UsbAccess::CdcInterface { interface: 1 }] {
            let err =
                resolve_endpoint(ChipFamily::Esp32, usb, Transport::Direct, Some("GONE"), &[])
                    .unwrap_err();
            assert_eq!(err, FlashError::NotAttached("GONE".into()));
            assert_eq!(
                err.to_string(),
                "USB device with serial \"GONE\" not attached"
            );
        }
    }

    #[test]
    fn transport_round_trips_through_its_text_form() {
        for t in [Transport::Direct, Transport::ViaProgrammer] {
            assert_eq!(t.as_str().parse::<Transport>().unwrap(), t);
        }
        assert_eq!(
            " Via_Programmer ".parse::<Transport>().unwrap(),
            Transport::ViaProgrammer
        );
        let err = "usb".parse::<Transport>().unwrap_err().to_string();
        assert!(err.contains("\"usb\""), "{err}");
    }

    #[test]
    fn auto_detect_refuses_none_or_several() {
        let none = auto_detect_direct_device(ChipFamily::Esp32, &[])
            .unwrap_err()
            .to_string();
        assert!(none.contains("no native-USB esp32"), "{none}");
        let ports = vec![
            espressif("/dev/ttyACM0", "A"),
            espressif("/dev/ttyACM1", "B"),
        ];
        let many = auto_detect_direct_device(ChipFamily::Esp32, &ports)
            .unwrap_err()
            .to_string();
        assert!(
            many.contains("/dev/ttyACM0 (A), /dev/ttyACM1 (B)"),
            "{many}"
        );
    }
}
