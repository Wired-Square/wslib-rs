use std::{
    collections::VecDeque,
    io,
    sync::mpsc::{self, Receiver, RecvTimeoutError, Sender},
    thread,
    time::Duration,
};

use tokio::sync::oneshot;
use wslib_can::{CanEvent, CanOptions, CanTask, TimeMapping};

use super::{
    bus::{Bus, BusError, CanBus, refusal},
    frame::RawFrame,
};

#[cfg(any(feature = "can-slcan", feature = "can-gsusb", feature = "can-pcan"))]
const BITRATE: u32 = 500_000;

type Read = Result<Vec<RawFrame>, BusError>;

struct TaskBus {
    reads: Receiver<Read>,
    pending: VecDeque<RawFrame>,
    _stop: oneshot::Sender<()>,
}

impl Bus for TaskBus {
    fn read(&mut self, timeout: Duration) -> Result<Option<RawFrame>, BusError> {
        if let Some(frame) = self.pending.pop_front() {
            return Ok(Some(frame));
        }
        match self.reads.recv_timeout(timeout) {
            Ok(read) => {
                self.pending.extend(read?);
                Ok(self.pending.pop_front())
            }
            Err(RecvTimeoutError::Timeout) => Ok(None),
            Err(RecvTimeoutError::Disconnected) => {
                Err(BusError::Ended("the CAN task ended".into()))
            }
        }
    }
}

fn translated(event: CanEvent) -> Option<Read> {
    match event {
        CanEvent::Read(reads) => Some(Ok(reads
            .into_iter()
            .filter(|read| !read.frame.rtr && !read.frame.fd)
            .map(|read| RawFrame {
                id: read.frame.arb_id,
                extended: read.frame.extended,
                data: read.frame.data,
            })
            .collect())),
        CanEvent::Disconnected {
            error,
            retry_in: Some(_),
            ..
        } => Some(Err(BusError::Lost(error.to_string()))),
        CanEvent::Disconnected {
            error,
            retry_in: None,
            ..
        } => Some(Err(BusError::Ended(error.to_string()))),
        _ => None,
    }
}

async fn forward(mut task: CanTask, reads: Sender<Read>, mut stop: oneshot::Receiver<()>) {
    loop {
        let event = tokio::select! {
            biased;
            _ = &mut stop => return,
            event = task.next_event() => event,
        };
        let Some(event) = event else { return };
        if let Some(read) = translated(event)
            && reads.send(read).is_err()
        {
            return;
        }
    }
}

fn options() -> CanOptions {
    let mut options = CanOptions::default();
    options.time = TimeMapping::Host;
    options
}

async fn open_task(bus: &CanBus) -> io::Result<CanTask> {
    match bus {
        #[cfg(feature = "can-slcan")]
        CanBus::Slcan { port } => {
            use wslib_serial::{LineSettings, Parity};
            const LINE: LineSettings = LineSettings {
                baud: 115_200,
                data_bits: 8,
                parity: Parity::None,
                stop_bits: 1,
            };
            let slcan = wslib_can_slcan::SlcanOptions {
                path: port.path(),
                line: LINE,
                bitrate: BITRATE,
                data_bitrate: None,
            };
            named(bus, wslib_can_slcan::open(slcan, options()).await)
        }
        #[cfg(all(feature = "can-socketcan", target_os = "linux"))]
        CanBus::SocketCan { interface } => {
            let socketcan = wslib_can_socketcan::SocketCanOptions {
                interface: interface.clone(),
                fd: false,
            };
            named(bus, wslib_can_socketcan::open(socketcan, options()).await)
        }
        #[cfg(all(feature = "can-gsusb", any(target_os = "macos", target_os = "windows")))]
        CanBus::GsUsb { serial } => {
            let device = usb::only_adapter(
                bus,
                "gsusb",
                wslib_can_gsusb::devices(),
                serial.as_deref(),
                |device| device.serial.as_deref(),
            )?;
            named(
                bus,
                wslib_can_gsusb::open(
                    wslib_can_gsusb::GsUsbOptions::new(device, BITRATE),
                    options(),
                )
                .await,
            )
        }
        #[cfg(all(feature = "can-pcan", any(target_os = "macos", target_os = "windows")))]
        CanBus::Pcan { serial } => {
            let device = usb::only_adapter(
                bus,
                "pcan",
                wslib_can_pcan::devices(),
                serial.as_deref(),
                |device| device.serial.as_deref(),
            )?;
            named(
                bus,
                wslib_can_pcan::open(wslib_can_pcan::PcanOptions::new(device, BITRATE), options())
                    .await,
            )
        }
        #[cfg(feature = "can-gvret")]
        CanBus::Gvret { host, port } => {
            const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
            let link = wslib_can_gvret::Link::Tcp {
                endpoint: wslib_can_gvret::tcp_endpoint(host, *port),
                connect_timeout: CONNECT_TIMEOUT,
            };
            named(
                bus,
                wslib_can_gvret::open(link, wslib_can_gvret::GvretOptions::default(), options())
                    .await,
            )
        }
        _ => Err(refusal(bus)),
    }
}

fn named(bus: &CanBus, opened: Result<CanTask, wslib_can::CanError>) -> io::Result<CanTask> {
    opened.map_err(|e| io::Error::other(format!("{bus}: {e}")))
}

/// Opens the bus on a thread of its own running its own runtime, so a caller
/// inside a tokio runtime never blocks on it; dropping the bus ends both.
pub fn open_bus(bus: &CanBus) -> io::Result<Box<dyn Bus>> {
    let (opened_tx, opened) = mpsc::sync_channel(1);
    let (reads_tx, reads) = mpsc::channel();
    let (stop, stopping) = oneshot::channel();
    let on = bus.clone();
    thread::Builder::new()
        .name(format!("can {bus}"))
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(e) => {
                    let _ = opened_tx.send(Err(e));
                    return;
                }
            };
            runtime.block_on(async {
                match open_task(&on).await {
                    Ok(task) => {
                        if opened_tx.send(Ok(())).is_ok() {
                            forward(task, reads_tx, stopping).await;
                        }
                    }
                    Err(e) => {
                        let _ = opened_tx.send(Err(e));
                    }
                }
            });
        })?;
    opened.recv().map_err(|_| {
        io::Error::other(format!(
            "{bus}: the CAN thread stopped before it opened the bus"
        ))
    })??;
    Ok(Box::new(TaskBus {
        reads,
        pending: VecDeque::new(),
        _stop: stop,
    }))
}

#[cfg(any(
    test,
    all(
        any(feature = "can-gsusb", feature = "can-pcan"),
        any(target_os = "macos", target_os = "windows")
    )
))]
mod usb {
    use std::io;

    use super::CanBus;

    const NO_SERIAL: &str = "(no serial)";
    const LIST_SEPARATOR: &str = ", ";

    pub fn only_adapter<D>(
        bus: &CanBus,
        kind: &str,
        found: io::Result<Vec<D>>,
        wanted: Option<&str>,
        serial_of: fn(&D) -> Option<&str>,
    ) -> io::Result<D> {
        let found = found.map_err(|e| io::Error::other(format!("{bus}: {e}")))?;
        let listed = found
            .iter()
            .map(|device| serial_of(device).unwrap_or(NO_SERIAL))
            .collect::<Vec<_>>()
            .join(LIST_SEPARATOR);
        let mut matching: Vec<D> = found
            .into_iter()
            .filter(|device| wanted.is_none_or(|wanted| serial_of(device) == Some(wanted)))
            .collect();
        match matching.len() {
            1 => Ok(matching.remove(0)),
            0 if listed.is_empty() => Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("{bus}: no adapter found"),
            )),
            0 => Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("{bus}: no adapter has that serial; found {listed}"),
            )),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{bus}: several adapters found ({listed}); name one as {kind}=<serial>"),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adapter(
        wanted: Option<&str>,
        found: &[Option<&'static str>],
    ) -> io::Result<Option<&'static str>> {
        let bus = CanBus::GsUsb {
            serial: wanted.map(str::to_owned),
        };
        usb::only_adapter(&bus, "gsusb", Ok(found.to_vec()), wanted, |device| *device)
    }

    #[test]
    fn a_lone_usb_adapter_is_taken_without_naming_its_serial() {
        assert_eq!(adapter(None, &[Some("A1")]).unwrap(), Some("A1"));
        assert_eq!(adapter(None, &[None]).unwrap(), None);
    }

    #[test]
    fn a_serial_picks_its_adapter_among_several() {
        assert_eq!(
            adapter(Some("B2"), &[Some("A1"), Some("B2")]).unwrap(),
            Some("B2")
        );
    }

    #[test]
    fn several_usb_adapters_without_a_serial_are_refused_listing_their_serials() {
        let error = adapter(None, &[Some("A1"), None]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("A1, (no serial)"), "{error}");
        assert!(error.to_string().contains("gsusb=<serial>"), "{error}");
    }

    #[test]
    fn a_serial_no_adapter_has_is_refused_listing_those_found() {
        let error = adapter(Some("C3"), &[Some("A1")]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert_eq!(
            error.to_string(),
            "gsusb=C3: no adapter has that serial; found A1"
        );
        assert_eq!(
            adapter(None, &[]).unwrap_err().to_string(),
            "gsusb: no adapter found"
        );
    }
}
