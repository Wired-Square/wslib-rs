//! USB-serial ports as the flashers see them. The pure helpers work on any
//! slice; `discover` (feature `ports`) is the only thing that asks the host.

use std::sync::Arc;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SerialPort {
    pub path: String,
    pub label: String,
    pub serial_number: Option<String>,
    pub interface: Option<u8>,
    pub vid: u16,
    pub pid: u16,
    pub manufacturer: Option<String>,
    pub product: Option<String>,
}

impl SerialPort {
    /// A port known only by path, USB serial and interface number.
    pub fn new(path: &str, serial_number: Option<&str>, interface: Option<u8>) -> Self {
        Self {
            path: path.to_string(),
            label: path.to_string(),
            serial_number: serial_number.map(str::to_string),
            interface,
            ..Default::default()
        }
    }
}

pub type Enumerator = Arc<dyn Fn() -> Vec<SerialPort> + Send + Sync>;

pub fn ports_for_serial<'a>(ports: &'a [SerialPort], serial: &str) -> Vec<&'a SerialPort> {
    let mut matched: Vec<&SerialPort> = ports
        .iter()
        .filter(|p| p.serial_number.as_deref() == Some(serial))
        .collect();
    matched.sort_by(|a, b| {
        a.interface
            .cmp(&b.interface)
            .then_with(|| a.path.cmp(&b.path))
    });
    matched
}

pub fn describe_ports(ports: &[&SerialPort]) -> String {
    ports
        .iter()
        .map(|p| match p.interface {
            Some(i) => format!("if{i:02} → {}", p.path),
            None => p.path.clone(),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn describe_serials<'a>(ports: impl IntoIterator<Item = &'a SerialPort>) -> String {
    ports
        .into_iter()
        .map(|p| {
            format!(
                "{} ({})",
                p.path,
                p.serial_number.as_deref().unwrap_or("no serial")
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// A composite device re-enumerates one interface at a time, so its ttys
/// count as back only once two consecutive snapshots agree.
#[cfg(any(feature = "dfu", feature = "dfu-util"))]
#[derive(Default)]
pub(crate) struct TtySettle {
    previous: Vec<SerialPort>,
    attached: Vec<SerialPort>,
}

#[cfg(any(feature = "dfu", feature = "dfu-util"))]
impl TtySettle {
    pub(crate) fn observe(
        &mut self,
        ports: Vec<SerialPort>,
        usb_serial: &str,
    ) -> Option<Vec<SerialPort>> {
        let present: Vec<SerialPort> = ports_for_serial(&ports, usb_serial)
            .into_iter()
            .cloned()
            .collect();
        self.attached = ports;
        let settled = !present.is_empty() && present == self.previous;
        self.previous = present;
        settled.then(|| self.previous.clone())
    }

    pub(crate) fn timeout_error(
        &self,
        usb_serial: &str,
        timeout: std::time::Duration,
    ) -> crate::error::FlashError {
        crate::error::FlashError::Message(format!(
            "USB device {usb_serial} did not re-enumerate within {}s; attached: [{}]",
            timeout.as_secs(),
            describe_serials(&self.attached)
        ))
    }
}

#[cfg(feature = "ports")]
mod host {
    use super::SerialPort;
    use crate::error::{FlashError, Result};

    fn enumerate() -> std::result::Result<Vec<SerialPort>, serialport::Error> {
        let mut results: Vec<SerialPort> = serialport::available_ports()?
            .into_iter()
            .filter_map(|info| match info.port_type {
                serialport::SerialPortType::UsbPort(usb) => Some(SerialPort {
                    label: nice_label(&info.port_name, &usb),
                    serial_number: usb.serial_number,
                    interface: usb.interface,
                    vid: usb.vid,
                    pid: usb.pid,
                    manufacturer: usb.manufacturer,
                    product: usb.product,
                    path: info.port_name,
                }),
                _ => None,
            })
            .collect();
        results.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(results)
    }

    fn nice_label(path: &str, usb: &serialport::UsbPortInfo) -> String {
        let basename = path.rsplit('/').next().unwrap_or(path);
        match (usb.manufacturer.as_deref(), usb.product.as_deref()) {
            (Some(mfr), Some(prod)) => format!("{basename} — {mfr} {prod}"),
            (Some(mfr), None) => format!("{basename} — {mfr}"),
            (None, Some(prod)) => format!("{basename} — {prod}"),
            (None, None) => basename.to_string(),
        }
    }

    /// Every USB serial port on the host, sorted by path; empty if enumeration fails.
    pub fn discover() -> Vec<SerialPort> {
        enumerate().unwrap_or_default()
    }

    pub fn usb_info_for(path: &str) -> Option<SerialPort> {
        discover().into_iter().find(|p| p.path == path)
    }

    /// The first tty of the USB device with this serial number.
    pub fn resolve_by_serial(serial: &str) -> Result<String> {
        let ports = enumerate()
            .map_err(|e| FlashError::Message(format!("serialport enumeration failed: {e}")))?;
        super::ports_for_serial(&ports, serial)
            .first()
            .map(|p| p.path.clone())
            .ok_or_else(|| FlashError::NotAttached(serial.to_string()))
    }

    impl From<serialport::Error> for FlashError {
        fn from(e: serialport::Error) -> Self {
            FlashError::Message(format!("serialport: {e}"))
        }
    }
}

#[cfg(feature = "ports")]
pub use host::{discover, resolve_by_serial, usb_info_for};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ports_for_serial_filters_and_orders_by_interface() {
        let ports = vec![
            SerialPort::new("/dev/ttyACM2", Some("S1"), Some(3)),
            SerialPort::new("/dev/ttyACM0", Some("OTHER"), Some(0)),
            SerialPort::new("/dev/ttyACM1", Some("S1"), Some(1)),
        ];
        let paths: Vec<&str> = ports_for_serial(&ports, "S1")
            .iter()
            .map(|p| p.path.as_str())
            .collect();
        assert_eq!(paths, vec!["/dev/ttyACM1", "/dev/ttyACM2"]);
        assert!(ports_for_serial(&ports, "NOPE").is_empty());
    }

    #[test]
    fn describe_ports_names_interfaces_when_known() {
        let a = SerialPort::new("/dev/ttyACM1", Some("S"), Some(1));
        let b = SerialPort::new("/dev/ttyACM2", Some("S"), None);
        assert_eq!(
            describe_ports(&[&a, &b]),
            "if01 → /dev/ttyACM1, /dev/ttyACM2"
        );
    }
}
