//! Which host-side endpoint a (chip family, USB access, transport) triple
//! flashes through, resolved over a snapshot of the host's serial ports.

use std::str::FromStr;

use crate::chip::{ChipFamily, ESPRESSIF_VID};
use crate::error::{FlashError, Result};
use crate::identity::PortIdentity;
use crate::ports::{
    SerialPort, describe_ports, describe_serials, not_attached, ports_for_identity,
};

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
        identity: Option<PortIdentity>,
    },
    UsbSerial(String),
}

pub fn tty(path: &str, identity: Option<&PortIdentity>) -> FlashEndpoint {
    FlashEndpoint::Tty {
        path: path.to_string(),
        identity: identity.cloned(),
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

fn single_tty(id: &PortIdentity, ports: &[SerialPort]) -> Result<String> {
    let matched = ports_for_identity(ports, id);
    match matched.as_slice() {
        [] => Err(not_attached(id)),
        [only] => Ok(only.path.clone()),
        many => Err(FlashError::Message(format!(
            "USB device {id} exposes several ttys; declare a cdc_interface on the board's MCU: [{}]",
            describe_ports(many)
        ))),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedDirectDevice {
    pub path: String,
    pub serial_number: Option<String>,
    pub identity: Option<PortIdentity>,
    pub vid: u16,
    pub pid: u16,
}

fn is_native_usb(family: ChipFamily, port: &SerialPort) -> bool {
    match family {
        ChipFamily::Esp32 => port.vid == ESPRESSIF_VID,
        ChipFamily::Stm32 => false,
    }
}

fn stable_identity(port: &SerialPort) -> Option<PortIdentity> {
    port.serial_number
        .clone()
        .map(PortIdentity::UsbSerial)
        .or_else(|| port.topology.first().cloned().map(PortIdentity::UsbPath))
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
            identity: stable_identity(only),
            vid: only.vid,
            pid: only.pid,
        }),
        many => Err(FlashError::Message(format!(
            "multiple native-USB {} devices attached — pin a port identity on \
             the fixture target to disambiguate: [{}]",
            family.as_str(),
            describe_serials(many.iter().copied()),
        ))),
    }
}

fn cdc_tty(id: &PortIdentity, interface: u8, ports: &[SerialPort]) -> Result<FlashEndpoint> {
    let matched = ports_for_identity(ports, id);
    if matched.is_empty() {
        return Err(not_attached(id));
    }
    if matched.iter().all(|p| p.interface.is_none()) {
        return Err(FlashError::Message(format!(
            "the host's USB enumeration reports no interface numbers for {id}, so \
             CDC interface {interface} cannot be located: [{}]",
            describe_ports(&matched)
        )));
    }
    matched
        .iter()
        .find(|p| p.interface == Some(interface))
        .map(|p| tty(&p.path, Some(id)))
        .ok_or_else(|| {
            FlashError::Message(format!(
                "no CDC interface {interface} on USB device {id}; present: [{}]",
                describe_ports(&matched)
            ))
        })
}

pub fn resolve_endpoint(
    family: ChipFamily,
    usb: UsbAccess,
    transport: Transport,
    identity: Option<&PortIdentity>,
    ports: &[SerialPort],
) -> Result<FlashEndpoint> {
    if let Some(e) = pairing_error(family, usb, transport) {
        return Err(FlashError::Message(e));
    }
    match (transport, usb, identity) {
        (Transport::ViaProgrammer, _, None) => Err(FlashError::Message(
            "via_programmer flash request missing a port identity — the programmer's port must \
             be pinned on the fixture target"
                .into(),
        )),
        (Transport::ViaProgrammer, _, Some(id)) => single_tty(id, ports).map(|p| tty(&p, Some(id))),
        (Transport::Direct, UsbAccess::Native, None) => match family {
            ChipFamily::Esp32 => {
                let detected = auto_detect_direct_device(family, ports)?;
                Ok(tty(&detected.path, detected.identity.as_ref()))
            }
            ChipFamily::Stm32 => Err(FlashError::Message(
                "DFU flashing needs the board's USB serial pinned on the fixture target".into(),
            )),
        },
        (Transport::Direct, UsbAccess::Native, Some(id)) => match (family, id) {
            (ChipFamily::Esp32, _) => single_tty(id, ports).map(|p| tty(&p, Some(id))),
            (ChipFamily::Stm32, PortIdentity::UsbSerial(serial)) => {
                Ok(FlashEndpoint::UsbSerial(serial.clone()))
            }
            (ChipFamily::Stm32, _) => Err(FlashError::Message(
                "DFU needs the board's USB serial; a topology path or tty cannot address a DFU \
                 device"
                    .into(),
            )),
        },
        (Transport::Direct, UsbAccess::CdcInterface { .. }, None) => Err(FlashError::Message(
            "a CDC-bridged MCU needs the board's port identity pinned on the fixture target".into(),
        )),
        (Transport::Direct, UsbAccess::CdcInterface { interface }, Some(id)) => {
            cdc_tty(id, interface, ports)
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

    const COMPOSITE: &str = "4B305017002A0042";
    const CH340_PATH: &str = "platform-xhci-hcd.0-usb-0:1.4:1.0-port0";

    fn port(path: &str, serial: &str, interface: u8) -> SerialPort {
        SerialPort::new(path, Some(serial), Some(interface))
    }

    fn serial(s: &str) -> PortIdentity {
        PortIdentity::UsbSerial(s.into())
    }

    fn usb_path(s: &str) -> PortIdentity {
        PortIdentity::UsbPath(s.into())
    }

    fn tty_id(s: &str) -> PortIdentity {
        PortIdentity::Tty(s.into())
    }

    fn composite() -> Vec<SerialPort> {
        vec![
            port("/dev/ttyACM1", COMPOSITE, 1).with_topology(&["platform-x-usb-0:3:1.1"]),
            port("/dev/ttyACM2", COMPOSITE, 3).with_topology(&["platform-x-usb-0:3:1.3"]),
        ]
    }

    fn ch340() -> Vec<SerialPort> {
        vec![SerialPort::new("/dev/ttyUSB1", None, Some(0)).with_topology(&[CH340_PATH])]
    }

    fn resolve(
        family: ChipFamily,
        usb: UsbAccess,
        id: Option<&PortIdentity>,
        ports: &[SerialPort],
    ) -> Result<FlashEndpoint> {
        resolve_endpoint(family, usb, Transport::Direct, id, ports)
    }

    fn espressif(path: &str, serial: Option<&str>) -> SerialPort {
        SerialPort {
            vid: ESPRESSIF_VID,
            ..SerialPort::new(path, serial, Some(0))
        }
    }

    #[test]
    fn cdc_interface_resolves_to_the_matching_tty() {
        let id = serial(COMPOSITE);
        let usb = UsbAccess::CdcInterface { interface: 3 };
        let endpoint = resolve(ChipFamily::Esp32, usb, Some(&id), &composite()).unwrap();
        assert_eq!(endpoint, tty("/dev/ttyACM2", Some(&id)));
    }

    #[test]
    fn cdc_interface_by_topology_resolves_the_interface_it_names() {
        let id = usb_path("platform-x-usb-0:3:1.3");
        let usb = UsbAccess::CdcInterface { interface: 3 };
        let endpoint = resolve(ChipFamily::Esp32, usb, Some(&id), &composite()).unwrap();
        assert_eq!(endpoint, tty("/dev/ttyACM2", Some(&id)));

        let wrong = UsbAccess::CdcInterface { interface: 1 };
        let err = resolve(ChipFamily::Esp32, wrong, Some(&id), &composite()).unwrap_err();
        assert!(err.to_string().contains("no CDC interface 1"), "{err}");
    }

    #[test]
    fn enumeration_without_interface_numbers_is_named_as_the_cause() {
        let ports = vec![SerialPort::new("/dev/ttyACM1", Some(COMPOSITE), None)];
        let usb = UsbAccess::CdcInterface { interface: 3 };
        let err = resolve(ChipFamily::Esp32, usb, Some(&serial(COMPOSITE)), &ports)
            .unwrap_err()
            .to_string();
        assert!(err.contains("no interface numbers"), "{err}");
    }

    #[test]
    fn missing_cdc_interface_lists_what_is_present() {
        let usb = UsbAccess::CdcInterface { interface: 5 };
        let ports = composite();
        let err = resolve(ChipFamily::Esp32, usb, Some(&serial(COMPOSITE)), &ports)
            .unwrap_err()
            .to_string();
        assert!(err.contains("if01 → /dev/ttyACM1"), "{err}");
        assert!(err.contains("if03 → /dev/ttyACM2"), "{err}");
    }

    #[test]
    fn native_stm32_resolves_to_the_usb_serial_without_a_tty() {
        let id = serial(COMPOSITE);
        let ports = composite();
        let endpoint = resolve(ChipFamily::Stm32, UsbAccess::Native, Some(&id), &ports).unwrap();
        assert_eq!(endpoint, FlashEndpoint::UsbSerial(COMPOSITE.into()));
    }

    #[test]
    fn native_stm32_refuses_a_topology_path_or_tty() {
        for id in [usb_path(CH340_PATH), tty_id("/dev/ttyUSB1")] {
            let err = resolve(ChipFamily::Stm32, UsbAccess::Native, Some(&id), &ch340())
                .unwrap_err()
                .to_string();
            assert!(err.starts_with("DFU needs the board's USB serial"), "{err}");
        }
    }

    #[test]
    fn native_esp32_with_several_ttys_asks_for_a_cdc_interface() {
        let id = serial(COMPOSITE);
        let ports = composite();
        let err = resolve(ChipFamily::Esp32, UsbAccess::Native, Some(&id), &ports)
            .unwrap_err()
            .to_string();
        assert!(err.contains("cdc_interface"), "{err}");
        assert!(err.contains("usb:4B305017002A0042"), "{err}");
    }

    #[test]
    fn native_esp32_with_one_tty_resolves_to_it() {
        let ports = vec![port("/dev/ttyACM0", "58:8C", 0)];
        let id = serial("58:8C");
        let endpoint = resolve(ChipFamily::Esp32, UsbAccess::Native, Some(&id), &ports).unwrap();
        assert_eq!(endpoint, tty("/dev/ttyACM0", Some(&id)));
    }

    #[test]
    fn a_topology_path_resolves_a_bridge_with_no_serial() {
        let id = usb_path(CH340_PATH);
        let endpoint = resolve(ChipFamily::Esp32, UsbAccess::Native, Some(&id), &ch340()).unwrap();
        assert_eq!(endpoint, tty("/dev/ttyUSB1", Some(&id)));
    }

    #[test]
    fn a_tty_identity_resolves_only_when_enumerated() {
        let id = tty_id("/dev/ttyUSB1");
        let endpoint = resolve(ChipFamily::Esp32, UsbAccess::Native, Some(&id), &ch340()).unwrap();
        assert_eq!(endpoint, tty("/dev/ttyUSB1", Some(&id)));

        let err = resolve(ChipFamily::Esp32, UsbAccess::Native, Some(&id), &[]).unwrap_err();
        assert_eq!(err, FlashError::NotAttached("/dev/ttyUSB1".into()));
    }

    #[test]
    fn a_programmer_resolves_by_any_identity() {
        let id = usb_path(CH340_PATH);
        let endpoint = resolve_endpoint(
            ChipFamily::Esp32,
            UsbAccess::None,
            Transport::ViaProgrammer,
            Some(&id),
            &ch340(),
        )
        .unwrap();
        assert_eq!(endpoint, tty("/dev/ttyUSB1", Some(&id)));
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
    fn programmer_transport_needs_a_pinned_identity() {
        let err = resolve_endpoint(
            ChipFamily::Esp32,
            UsbAccess::None,
            Transport::ViaProgrammer,
            None,
            &[],
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("port identity"), "{err}");
    }

    #[test]
    fn auto_detect_reports_the_port_by_its_most_stable_identity() {
        let ports = vec![
            SerialPort::new("/dev/ttyUSB0", Some("BRIDGE"), Some(0)),
            espressif("/dev/ttyACM0", Some("58:8C")).with_topology(&["platform-x-usb-0:1:1.0"]),
        ];
        let endpoint = resolve(ChipFamily::Esp32, UsbAccess::Native, None, &ports).unwrap();
        assert_eq!(endpoint, tty("/dev/ttyACM0", Some(&serial("58:8C"))));

        let unserialled = vec![espressif("/dev/ttyACM0", None).with_topology(&[CH340_PATH])];
        let endpoint = resolve(ChipFamily::Esp32, UsbAccess::Native, None, &unserialled).unwrap();
        assert_eq!(endpoint, tty("/dev/ttyACM0", Some(&usb_path(CH340_PATH))));

        let anonymous = vec![espressif("/dev/ttyACM0", None)];
        let endpoint = resolve(ChipFamily::Esp32, UsbAccess::Native, None, &anonymous).unwrap();
        assert_eq!(endpoint, tty("/dev/ttyACM0", None));
    }

    #[test]
    fn a_missing_serial_is_a_typed_not_attached_error() {
        for usb in [UsbAccess::Native, UsbAccess::CdcInterface { interface: 1 }] {
            let err = resolve(ChipFamily::Esp32, usb, Some(&serial("GONE")), &[]).unwrap_err();
            assert_eq!(err, FlashError::NotAttached("usb:GONE".into()));
            assert_eq!(err.to_string(), "USB device \"usb:GONE\" not attached");
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
            espressif("/dev/ttyACM0", Some("A")),
            espressif("/dev/ttyACM1", Some("B")),
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
