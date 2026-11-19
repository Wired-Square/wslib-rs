//! An in-memory CAN bus for tests. Every frame a port writes reaches every
//! port open on the bus, the writer as a `Tx` read. A [`CanTask`] on a port
//! behaves as one on a real adapter with `own_frames`.

use std::{
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use tokio::{
    sync::{Notify, mpsc},
    time::sleep,
};

use crate::{
    CanError, CanFrame, CanOptions, CanTask, Device, DeviceInfo, Direction, Limits, Received,
    Stamp, WriteFailed,
};

type Wire = mpsc::UnboundedSender<(usize, CanFrame)>;
type Matcher = Box<dyn Fn(&CanFrame) -> bool + Send>;

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[derive(Default)]
struct BusShared {
    ports: Mutex<Vec<(usize, Wire)>>,
    next: AtomicUsize,
}

/// One bus. A clone is another handle on it.
#[derive(Clone, Default)]
pub struct LoopbackBus(Arc<BusShared>);

impl LoopbackBus {
    /// A new port, which joins the bus each time a task opens it.
    pub fn port(&self) -> LoopbackPort {
        LoopbackPort(Arc::new(PortShared {
            bus: self.clone(),
            stall: Mutex::new(None),
            lose: Mutex::new(None),
            fail: Mutex::new(None),
            unplug: Notify::new(),
            closes: AtomicUsize::new(0),
        }))
    }
}

struct PortShared {
    bus: LoopbackBus,
    stall: Mutex<Option<Duration>>,
    lose: Mutex<Option<Matcher>>,
    fail: Mutex<Option<WriteFailed>>,
    unplug: Notify,
    closes: AtomicUsize,
}

/// A port on a [`LoopbackBus`], and the [`Device::Config`] of a
/// [`Loopback`]. A clone is another handle on the same port.
#[derive(Clone)]
pub struct LoopbackPort(Arc<PortShared>);

impl LoopbackPort {
    /// Opens a task on this port, as [`open`](crate::open) does.
    pub async fn open(&self, options: CanOptions) -> Result<CanTask, CanError> {
        crate::open::<Loopback>(self.clone(), options).await
    }

    /// The port's next write waits `by` before it reaches the bus.
    pub fn stall_next_write(&self, by: Duration) {
        *locked(&self.0.stall) = Some(by);
    }

    /// The port's next write that `matching` picks never reaches the bus, as
    /// a frame lost on the wire. No port reads it, this one included.
    pub fn lose_next_write(&self, matching: impl Fn(&CanFrame) -> bool + Send + 'static) {
        *locked(&self.0.lose) = Some(Box::new(matching));
    }

    /// The port's next write fails with `failed`, and reaches no port.
    pub fn fail_next_write(&self, failed: WriteFailed) {
        *locked(&self.0.fail) = Some(failed);
    }

    /// The device open on the port reads [`CanError::Closed`], once.
    pub fn unplug(&self) {
        self.0.unplug.notify_one();
    }

    /// How many times a device on this port has closed.
    pub fn closes(&self) -> usize {
        self.0.closes.load(Ordering::SeqCst)
    }

    fn lost(&self, frame: &CanFrame) -> bool {
        let mut lose = locked(&self.0.lose);
        let matched = lose.as_ref().is_some_and(|matching| matching(frame));
        if matched {
            *lose = None;
        }
        matched
    }
}

/// The [`Device`] a [`LoopbackPort`] opens.
pub struct Loopback {
    id: usize,
    port: LoopbackPort,
    frames: mpsc::UnboundedReceiver<(usize, CanFrame)>,
}

impl Loopback {
    /// The buses a frame may name, as [`Limits::buses`].
    pub const BUSES: u8 = 2;
}

impl Device for Loopback {
    type Config = LoopbackPort;

    async fn open(port: &LoopbackPort, _: &CanOptions) -> Result<(Self, DeviceInfo), CanError> {
        let (sender, frames) = mpsc::unbounded_channel();
        let bus = &port.0.bus.0;
        let id = bus.next.fetch_add(1, Ordering::SeqCst);
        locked(&bus.ports).push((id, sender));
        let device = Self {
            id,
            port: port.clone(),
            frames,
        };
        let info = DeviceInfo {
            buses: Some(Self::BUSES),
            ..DeviceInfo::default()
        };
        Ok((device, info))
    }

    fn limits(&self) -> Limits {
        Limits {
            buses: Some(Self::BUSES),
            ..Limits::ANY
        }
    }

    async fn read(&mut self) -> Result<Vec<Received>, CanError> {
        let (origin, frame) = tokio::select! {
            () = self.port.0.unplug.notified() => return Err(CanError::Closed),
            frame = self.frames.recv() => frame.ok_or(CanError::Closed)?,
        };
        let direction = if origin == self.id {
            Direction::Tx
        } else {
            Direction::Rx
        };
        Ok(vec![Received {
            frame,
            direction,
            stamp: Stamp::Read,
            overflow: false,
        }])
    }

    async fn write(&mut self, frame: &CanFrame) -> Result<(), WriteFailed> {
        let stall = locked(&self.port.0.stall).take();
        if let Some(stall) = stall {
            sleep(stall).await;
        }
        if let Some(failed) = locked(&self.port.0.fail).take() {
            return Err(failed);
        }
        if self.port.lost(frame) {
            return Ok(());
        }
        for (_, port) in locked(&self.port.0.bus.0.ports).iter() {
            let _ = port.send((self.id, frame.clone()));
        }
        Ok(())
    }

    async fn close(self) {
        locked(&self.port.0.bus.0.ports).retain(|(id, _)| *id != self.id);
        self.port.0.closes.fetch_add(1, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CanEvent, CanRead};

    const BUS: u8 = 0;
    const ID: u32 = 0x123;
    const LOST: u32 = 0x456;
    const DATA: [u8; 2] = [0xAB, 0xCD];

    fn frame(arb_id: u32) -> CanFrame {
        CanFrame::data(BUS, arb_id, false, false, false, DATA.to_vec())
    }

    fn own_frames() -> CanOptions {
        CanOptions {
            own_frames: true,
            reopen: None,
            ..CanOptions::default()
        }
    }

    async fn next_read(task: &mut CanTask) -> CanRead {
        loop {
            if let Some(CanEvent::Read(mut reads)) = task.next_event().await {
                return reads.remove(0);
            }
        }
    }

    #[tokio::test]
    async fn a_frame_reaches_every_port_and_its_writer_as_tx() {
        let bus = LoopbackBus::default();
        let mut writer = bus.port().open(own_frames()).await.unwrap();
        let mut reader = bus.port().open(own_frames()).await.unwrap();
        writer.writer().send(frame(ID)).await.unwrap().unwrap();
        let echo = next_read(&mut writer).await;
        let read = next_read(&mut reader).await;
        assert_eq!((echo.frame.arb_id, echo.direction), (ID, Direction::Tx));
        assert_eq!((read.frame.arb_id, read.direction), (ID, Direction::Rx));
    }

    #[tokio::test]
    async fn a_lost_write_reaches_no_port_and_the_next_does() {
        let bus = LoopbackBus::default();
        let port = bus.port();
        let mut writer = port.open(own_frames()).await.unwrap();
        let mut reader = bus.port().open(own_frames()).await.unwrap();
        port.lose_next_write(|frame| frame.arb_id == LOST);
        for arb_id in [LOST, ID, LOST] {
            writer.writer().send(frame(arb_id)).await.unwrap().unwrap();
        }
        assert_eq!(next_read(&mut reader).await.frame.arb_id, ID);
        assert_eq!(next_read(&mut reader).await.frame.arb_id, LOST);
        let echo = next_read(&mut writer).await;
        assert_eq!((echo.frame.arb_id, echo.direction), (ID, Direction::Tx));
        assert_eq!(next_read(&mut writer).await.frame.arb_id, LOST);
    }

    #[tokio::test]
    async fn a_device_reports_the_buses_its_limits_allow() {
        let mut task = LoopbackBus::default()
            .port()
            .open(own_frames())
            .await
            .unwrap();
        let Some(CanEvent::Connected(info)) = task.next_event().await else {
            panic!("the first event is Connected");
        };
        assert_eq!(info.buses, Some(Loopback::BUSES));
        let mut over = frame(ID);
        over.bus = Loopback::BUSES;
        assert!(task.writer().send(over).await.is_err());
    }

    #[tokio::test]
    async fn an_unplugged_port_closes_its_device() {
        let bus = LoopbackBus::default();
        let port = bus.port();
        let mut task = port.open(own_frames()).await.unwrap();
        port.unplug();
        while task.next_event().await.is_some() {}
        assert_eq!(port.closes(), 1);
    }
}
