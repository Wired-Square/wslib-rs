//! Fake ports for tests of code built on [`Monitors`], on any OS.

use std::{
    collections::{HashMap, VecDeque},
    io,
    sync::{Arc, Mutex, MutexGuard},
    time::SystemTime,
};

use tokio::sync::mpsc;
use wslib_serial::{SerialError, SerialEvent};

use crate::{
    MonitorOptions, Monitors,
    monitor::{Opener, lock},
};

/// Stops every port's monitor when dropped, so a test that fails doesn't
/// leave one holding its port.
pub struct StopReaders(pub Monitors);

impl Drop for StopReaders {
    fn drop(&mut self) {
        self.0.stop_all();
    }
}

/// Ports a test plugs in by path, each device opened once.
#[derive(Clone, Default)]
pub struct FakePorts(Arc<Mutex<Plugged>>);

#[derive(Default)]
struct Plugged {
    waiting: HashMap<String, VecDeque<FakeLink>>,
    /// USB serial to path, while the device is plugged in.
    usb: HashMap<String, String>,
}

/// What the monitor put on a fake device's line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Wired {
    Bytes(Vec<u8>),
    Dtr(bool),
}

/// A device on a fake port. Dropping it unplugs it.
pub struct FakeDevice {
    reads: mpsc::UnboundedSender<SerialEvent>,
    wire: mpsc::UnboundedReceiver<Wired>,
    unplug: Option<(FakePorts, String)>,
}

pub(crate) struct FakeLink {
    events: mpsc::UnboundedReceiver<SerialEvent>,
    wire: mpsc::UnboundedSender<Wired>,
}

impl FakePorts {
    pub fn monitors(&self, options: MonitorOptions) -> Monitors {
        Monitors::with_opener(options, Opener::Fake(self.clone()))
    }

    /// A device for the next open of `path`.
    pub fn plug(&self, path: &str) -> FakeDevice {
        self.plug_with(path, None)
    }

    /// A device for the next open of `path`, which `usb_serial` resolves to
    /// until the device is dropped.
    pub fn plug_usb(&self, path: &str, usb_serial: &str) -> FakeDevice {
        self.lock()
            .usb
            .insert(usb_serial.to_owned(), path.to_owned());
        self.plug_with(path, Some(usb_serial.to_owned()))
    }

    fn plug_with(&self, path: &str, usb_serial: Option<String>) -> FakeDevice {
        let (reads, events) = mpsc::unbounded_channel();
        let (wire, wired) = mpsc::unbounded_channel();
        let _ = reads.send(SerialEvent::Connected);
        let link = FakeLink { events, wire };
        self.lock()
            .waiting
            .entry(path.to_owned())
            .or_default()
            .push_back(link);
        FakeDevice {
            reads,
            wire: wired,
            unplug: usb_serial.map(|serial| (self.clone(), serial)),
        }
    }

    pub(crate) fn resolve(&self, usb_serial: &str) -> Option<String> {
        self.lock().usb.get(usb_serial).cloned()
    }

    pub(crate) fn open(&self, path: &str) -> Result<FakeLink, SerialError> {
        self.lock()
            .waiting
            .get_mut(path)
            .and_then(VecDeque::pop_front)
            .ok_or_else(|| SerialError::Open {
                path: path.to_owned(),
                source: io::ErrorKind::NotFound.into(),
            })
    }

    fn lock(&self) -> MutexGuard<'_, Plugged> {
        lock(&self.0)
    }
}

impl FakeDevice {
    /// Bytes from the device, as one read.
    pub fn send(&self, bytes: &[u8]) {
        let _ = self.reads.send(SerialEvent::Read {
            bytes: bytes.to_vec(),
            at: SystemTime::now(),
        });
    }

    /// What the monitor next put on the line; `None` once it has closed the
    /// port.
    pub async fn next(&mut self) -> Option<Wired> {
        self.wire.recv().await
    }

    /// The bytes the monitor wrote, up to `len`, skipping control lines.
    pub async fn read(&mut self, len: usize) -> Vec<u8> {
        let mut got = Vec::new();
        while got.len() < len {
            match self.next().await {
                Some(Wired::Bytes(bytes)) => got.extend(bytes),
                Some(Wired::Dtr(_)) => {}
                None => break,
            }
        }
        got
    }

    /// True once the monitor has closed the port.
    pub fn is_closed(&self) -> bool {
        self.wire.is_closed()
    }

    /// Fails the monitor's writes and control lines from now on, as a device
    /// that stopped taking bytes would.
    pub fn fail_writes(&mut self) {
        self.wire.close();
    }
}

impl Drop for FakeDevice {
    fn drop(&mut self) {
        if let Some((ports, usb_serial)) = self.unplug.take() {
            ports.lock().usb.remove(&usb_serial);
        }
    }
}

impl FakeLink {
    pub(crate) async fn next_event(&mut self) -> Option<SerialEvent> {
        self.events.recv().await
    }

    pub(crate) fn write(&self, bytes: Vec<u8>) -> io::Result<()> {
        self.put(Wired::Bytes(bytes))
    }

    pub(crate) fn set_dtr(&self, level: bool) -> io::Result<()> {
        self.put(Wired::Dtr(level))
    }

    fn put(&self, wired: Wired) -> io::Result<()> {
        self.wire
            .send(wired)
            .map_err(|_| io::ErrorKind::BrokenPipe.into())
    }
}
