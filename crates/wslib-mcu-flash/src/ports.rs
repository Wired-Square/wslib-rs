//! USB-serial ports as the flashers see them. The pure helpers work on any
//! slice; `discover` (feature `ports`) is the only thing that asks the host.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use crate::error::FlashError;
use crate::identity::{PortIdentity, USB_PATH_PREFIX};

pub const SERIAL_BY_PATH_DIR: &str = "/dev/serial/by-path";

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
    #[cfg_attr(feature = "serde", serde(default))]
    pub topology: Vec<String>,
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

    pub fn with_topology(self, names: &[&str]) -> Self {
        Self {
            topology: names.iter().map(|n| n.to_string()).collect(),
            ..self
        }
    }

    pub fn matches(&self, id: &PortIdentity) -> bool {
        match id {
            PortIdentity::UsbSerial(serial) => {
                self.serial_number.as_deref() == Some(serial.as_str())
            }
            PortIdentity::UsbPath(name) => self.topology.iter().any(|n| n == name),
            PortIdentity::Tty(path) => self.path == *path,
        }
    }
}

pub type Enumerator = Arc<dyn Fn() -> Vec<SerialPort> + Send + Sync>;

pub fn by_path_index(dir: &Path) -> HashMap<String, Vec<String>> {
    let mut index: HashMap<String, Vec<String>> = HashMap::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return index;
    };
    for entry in entries.flatten() {
        let Ok(tty) = std::fs::canonicalize(entry.path()) else {
            continue;
        };
        index
            .entry(tty.to_string_lossy().into_owned())
            .or_default()
            .push(entry.file_name().to_string_lossy().into_owned());
    }
    index.values_mut().for_each(|names| names.sort());
    index
}

pub fn ports_for_identity<'a>(ports: &'a [SerialPort], id: &PortIdentity) -> Vec<&'a SerialPort> {
    let mut matched: Vec<&SerialPort> = ports.iter().filter(|p| p.matches(id)).collect();
    matched.sort_by(|a, b| {
        a.interface
            .cmp(&b.interface)
            .then_with(|| a.path.cmp(&b.path))
    });
    matched
}

pub fn identities_for(id: &PortIdentity, ports: &[SerialPort]) -> Vec<PortIdentity> {
    let mut all = vec![id.clone()];
    for port in ports_for_identity(ports, id) {
        all.push(PortIdentity::Tty(port.path.clone()));
        all.extend(port.serial_number.clone().map(PortIdentity::UsbSerial));
        all.extend(port.topology.iter().cloned().map(PortIdentity::UsbPath));
    }
    let mut seen = HashSet::new();
    all.retain(|i| seen.insert(i.clone()));
    all
}

pub fn not_attached(id: &PortIdentity) -> FlashError {
    match id {
        PortIdentity::UsbPath(_) if !cfg!(target_os = "linux") => FlashError::Message(format!(
            "topology identities need Linux: no {SERIAL_BY_PATH_DIR} on this host"
        )),
        _ => FlashError::NotAttached(id.to_string()),
    }
}

pub fn describe_ports(ports: &[&SerialPort]) -> String {
    ports
        .iter()
        .map(|p| {
            let at = match p.topology.first() {
                Some(name) => format!("{} ({USB_PATH_PREFIX}{name})", p.path),
                None => p.path.clone(),
            };
            match p.interface {
                Some(i) => format!("if{i:02} → {at}"),
                None => at,
            }
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
        let id = PortIdentity::UsbSerial(usb_serial.to_string());
        let present: Vec<SerialPort> = ports_for_identity(&ports, &id)
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
    use std::collections::HashMap;

    use super::SerialPort;
    use crate::error::{FlashError, Result};
    use crate::identity::PortIdentity;

    #[cfg(target_os = "linux")]
    fn topology_index() -> HashMap<String, Vec<String>> {
        super::by_path_index(std::path::Path::new(super::SERIAL_BY_PATH_DIR))
    }

    #[cfg(not(target_os = "linux"))]
    fn topology_index() -> HashMap<String, Vec<String>> {
        HashMap::new()
    }

    fn topology_of(index: &HashMap<String, Vec<String>>, path: &str) -> Vec<String> {
        let canonical = std::fs::canonicalize(path)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| path.to_string());
        index.get(&canonical).cloned().unwrap_or_default()
    }

    fn enumerate() -> std::result::Result<Vec<SerialPort>, serialport::Error> {
        let index = topology_index();
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
                    topology: topology_of(&index, &info.port_name),
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

    pub fn resolve_identity(id: &PortIdentity) -> Result<String> {
        let ports = enumerate()
            .map_err(|e| FlashError::Message(format!("serialport enumeration failed: {e}")))?;
        super::ports_for_identity(&ports, id)
            .first()
            .map(|p| p.path.clone())
            .ok_or_else(|| super::not_attached(id))
    }

    impl From<serialport::Error> for FlashError {
        fn from(e: serialport::Error) -> Self {
            FlashError::Message(format!("serialport: {e}"))
        }
    }
}

#[cfg(feature = "ports")]
pub use host::{discover, resolve_identity, usb_info_for};

#[cfg(test)]
mod tests {
    use super::*;

    const ALIAS_V1: &str = "platform-x-usb-0:1.4:1.0-port0";
    const ALIAS_V2: &str = "platform-x-usbv2-0:1.4:1.0-port0";
    const SIBLING: &str = "platform-x-usb-0:1.4:1.2-port0";
    const ACM_PATH: &str = "platform-x-usb-0:2:1.0";

    fn serial(s: &str) -> PortIdentity {
        PortIdentity::UsbSerial(s.into())
    }

    fn usb_path(s: &str) -> PortIdentity {
        PortIdentity::UsbPath(s.into())
    }

    fn tty(s: &str) -> PortIdentity {
        PortIdentity::Tty(s.into())
    }

    fn paths(ports: Vec<&SerialPort>) -> Vec<&str> {
        ports.iter().map(|p| p.path.as_str()).collect()
    }

    fn ch340(path: &str, serial: Option<&str>, names: &[&str]) -> SerialPort {
        SerialPort::new(path, serial, None).with_topology(names)
    }

    #[test]
    fn a_port_matches_every_identity_that_names_it() {
        let port = ch340("/dev/ttyUSB1", Some("S1"), &[ALIAS_V1, ALIAS_V2]);
        for id in [
            serial("S1"),
            usb_path(ALIAS_V1),
            usb_path(ALIAS_V2),
            tty("/dev/ttyUSB1"),
        ] {
            assert!(port.matches(&id), "{id}");
        }
        for id in [serial("S2"), usb_path(SIBLING), tty("/dev/ttyUSB0")] {
            assert!(!port.matches(&id), "{id}");
        }
        let unserialed = ch340("/dev/ttyUSB1", None, &[]);
        assert!(!unserialed.matches(&serial("S1")));
    }

    #[test]
    fn a_serial_identity_filters_and_orders_by_interface() {
        let ports = vec![
            SerialPort::new("/dev/ttyACM2", Some("S1"), Some(3)),
            SerialPort::new("/dev/ttyACM0", Some("OTHER"), Some(0)),
            SerialPort::new("/dev/ttyACM1", Some("S1"), Some(1)),
        ];
        let matched = ports_for_identity(&ports, &serial("S1"));
        assert_eq!(paths(matched), vec!["/dev/ttyACM1", "/dev/ttyACM2"]);
        assert!(ports_for_identity(&ports, &serial("NOPE")).is_empty());
    }

    #[test]
    fn a_topology_identity_matches_either_alias_exactly() {
        let ports = vec![
            ch340("/dev/ttyUSB1", None, &[ALIAS_V1, ALIAS_V2]),
            ch340("/dev/ttyUSB2", None, &[SIBLING]),
        ];
        for alias in [ALIAS_V1, ALIAS_V2] {
            let matched = ports_for_identity(&ports, &usb_path(alias));
            assert_eq!(paths(matched), vec!["/dev/ttyUSB1"]);
        }
        let prefix = usb_path("platform-x-usb-0:1.4:1");
        assert!(ports_for_identity(&ports, &prefix).is_empty());
    }

    #[test]
    fn a_tty_identity_matches_the_path_exactly() {
        let ports = vec![ch340("/dev/ttyUSB1", None, &[])];
        let matched = ports_for_identity(&ports, &tty("/dev/ttyUSB1"));
        assert_eq!(paths(matched), vec!["/dev/ttyUSB1"]);
        assert!(ports_for_identity(&ports, &tty("/dev/ttyUSB")).is_empty());
    }

    #[test]
    fn identities_for_lists_every_name_of_the_matched_port_once() {
        let ports = vec![ch340("/dev/ttyUSB1", Some("S"), &[ALIAS_V1, ALIAS_V2])];
        let expected = vec![
            usb_path(ALIAS_V1),
            tty("/dev/ttyUSB1"),
            serial("S"),
            usb_path(ALIAS_V2),
        ];
        assert_eq!(identities_for(&usb_path(ALIAS_V1), &ports), expected);
        let gone = serial("GONE");
        assert_eq!(identities_for(&gone, &ports), vec![gone]);
    }

    #[test]
    fn describe_ports_names_interfaces_and_topology_when_known() {
        let a = SerialPort::new("/dev/ttyACM1", Some("S"), Some(1));
        let b = ch340("/dev/ttyUSB1", None, &[ALIAS_V1, ALIAS_V2]);
        let expected = format!("if01 → /dev/ttyACM1, /dev/ttyUSB1 (usb-path:{ALIAS_V1})");
        assert_eq!(describe_ports(&[&a, &b]), expected);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_missing_topology_port_is_not_attached_on_linux() {
        let expected = FlashError::NotAttached(format!("usb-path:{ALIAS_V1}"));
        assert_eq!(not_attached(&usb_path(ALIAS_V1)), expected);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn a_topology_identity_off_linux_says_it_needs_linux() {
        let err = not_attached(&usb_path(ALIAS_V1)).to_string();
        let expected = "topology identities need Linux: no /dev/serial/by-path on this host";
        assert_eq!(err, expected);
    }

    #[test]
    fn other_missing_identities_are_not_attached() {
        let expected = FlashError::NotAttached("/dev/ttyUSB1".into());
        assert_eq!(not_attached(&tty("/dev/ttyUSB1")), expected);
    }

    #[cfg(unix)]
    #[test]
    fn by_path_index_groups_aliases_under_their_canonical_tty() {
        let root = tempfile::tempdir().unwrap();
        let by_path = root.path().join("serial/by-path");
        std::fs::create_dir_all(&by_path).unwrap();
        for name in ["ttyUSB1", "ttyACM2"] {
            std::fs::write(root.path().join(name), b"").unwrap();
        }
        for (link, target) in [
            (ALIAS_V2, "../../ttyUSB1"),
            (ALIAS_V1, "../../ttyUSB1"),
            (ACM_PATH, "../../ttyACM2"),
        ] {
            std::os::unix::fs::symlink(target, by_path.join(link)).unwrap();
        }
        let canonical = |name: &str| {
            let path = std::fs::canonicalize(root.path().join(name)).unwrap();
            path.to_string_lossy().into_owned()
        };
        let index = by_path_index(&by_path);
        assert_eq!(index.len(), 2);
        assert_eq!(index[&canonical("ttyUSB1")], vec![ALIAS_V1, ALIAS_V2]);
        assert_eq!(index[&canonical("ttyACM2")], vec![ACM_PATH]);
    }

    #[test]
    fn by_path_index_of_a_missing_directory_is_empty() {
        let root = tempfile::tempdir().unwrap();
        assert!(by_path_index(&root.path().join("absent")).is_empty());
    }
}
