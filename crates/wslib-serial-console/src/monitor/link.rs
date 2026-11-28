use std::{error::Error, io, path::Path};

use wslib_mcu_flash::ports::{SERIAL_BY_PATH_DIR, by_path_index, not_attached};
use wslib_serial::{
    Access, LineSettings, Parity, PortKind, SerialError, SerialEvent, SerialOptions, SerialTask,
    SerialWriter,
};

use super::PortKey;
#[cfg(any(test, feature = "test-support"))]
use crate::test_support::{FakeLink, FakePorts};
use wslib_error::Chain;

/// Where a monitor's ports come from.
#[derive(Clone)]
pub(crate) enum Opener {
    Serial,
    #[cfg(any(test, feature = "test-support"))]
    Fake(FakePorts),
}

pub(super) enum Unresolved {
    /// No attached device answers to the key.
    Missing(String),
    Failed(String),
}

fn usb_serial_tty(serial: &str) -> Result<Option<String>, Unresolved> {
    Ok(wslib_serial::ports()
        .map_err(listing_failed)?
        .into_iter()
        .filter(|port| matches!(&port.kind, PortKind::Usb(usb) if usb.serial.as_deref() == Some(serial)))
        .map(|port| port.path)
        .min_by_key(|path| (!path.starts_with("/dev/cu."), path.clone())))
}

fn listing_failed(error: io::Error) -> Unresolved {
    Unresolved::Failed(format!("listing ports: {}", Chain::new(&error)))
}

fn topology_tty(name: &str) -> Option<String> {
    by_path_index(Path::new(SERIAL_BY_PATH_DIR))
        .into_iter()
        .find(|(_, names)| names.iter().any(|n| n == name))
        .map(|(tty, _)| tty)
}

impl Opener {
    pub(super) fn resolve(&self, key: &PortKey) -> Result<String, Unresolved> {
        let found = match (self, key) {
            (_, PortKey::Tty(path)) => return Ok(path.clone()),
            (Self::Serial, PortKey::UsbSerial(serial)) => usb_serial_tty(serial)?,
            (Self::Serial, PortKey::UsbPath(name)) => topology_tty(name),
            #[cfg(any(test, feature = "test-support"))]
            (Self::Fake(ports), _) => ports.resolve(key),
        };
        found.ok_or_else(|| Unresolved::Missing(not_attached(key).to_string()))
    }

    pub(super) fn open(&self, path: &str, baud: u32) -> Result<Link, SerialError> {
        match self {
            Self::Serial => {
                let line = LineSettings {
                    baud,
                    data_bits: 8,
                    parity: Parity::None,
                    stop_bits: 1,
                };
                let options = SerialOptions {
                    access: Access::ReadWrite,
                    reopen: None,
                    ..SerialOptions::default()
                };
                let task = wslib_serial::open(path, line, options)?;
                Ok(Link::Serial(task.writer(), task))
            }
            #[cfg(any(test, feature = "test-support"))]
            Self::Fake(ports) => ports.open(path).map(Link::Fake),
        }
    }
}

pub(super) type Unwritten = Box<dyn Error + Send + Sync>;

/// One open of a port, ended by its first loss.
pub(super) enum Link {
    Serial(SerialWriter, SerialTask),
    #[cfg(any(test, feature = "test-support"))]
    Fake(FakeLink),
}

impl Link {
    pub(super) async fn next_event(&mut self) -> Option<SerialEvent> {
        match self {
            Self::Serial(_, task) => task.next_event().await,
            #[cfg(any(test, feature = "test-support"))]
            Self::Fake(link) => link.next_event().await,
        }
    }

    pub(super) async fn write(&self, bytes: Vec<u8>) -> Result<(), Unwritten> {
        match self {
            Self::Serial(writer, _) => Ok(writer.write(bytes).await??),
            #[cfg(any(test, feature = "test-support"))]
            Self::Fake(link) => Ok(link.write(bytes)?),
        }
    }

    pub(super) async fn set_dtr(&self, level: bool) -> Result<(), Unwritten> {
        match self {
            Self::Serial(writer, _) => Ok(writer.set_dtr(level).await??),
            #[cfg(any(test, feature = "test-support"))]
            Self::Fake(link) => Ok(link.set_dtr(level)?),
        }
    }

    pub(super) async fn stop(self) {
        match self {
            Self::Serial(_, task) => task.stop().await,
            #[cfg(any(test, feature = "test-support"))]
            Self::Fake(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fmt;

    use super::*;

    #[derive(Debug)]
    struct Denied(io::Error);

    impl fmt::Display for Denied {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("the port list is unreadable")
        }
    }

    impl Error for Denied {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            Some(&self.0)
        }
    }

    #[test]
    fn a_listing_that_failed_says_so_with_each_cause() {
        let cause = io::Error::new(io::ErrorKind::PermissionDenied, "sysfs is closed");
        let failed = listing_failed(io::Error::other(Denied(cause)));
        let Unresolved::Failed(why) = failed else {
            panic!("a failure");
        };
        assert_eq!(
            why,
            "listing ports: the port list is unreadable: sysfs is closed"
        );
    }
}
