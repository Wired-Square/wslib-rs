use std::{
    collections::VecDeque,
    io,
    sync::mpsc::{self, Receiver, RecvTimeoutError, Sender},
    time::Duration,
};

use tokio::sync::oneshot;
use wslib_can::{CanEvent, CanOptions, CanTask, TimeMapping};

use super::{
    bus::{Bus, BusError, CanBus, chain, failed, feature, refused},
    frame::RawFrame,
};
use crate::worker::{RELEASE_WITHIN, Worker};

const BITRATE: u32 = 500_000;

type Read = Result<Vec<RawFrame>, BusError>;

struct TaskBus {
    reads: Receiver<Read>,
    pending: VecDeque<RawFrame>,
    // Declared before `_task`, so the task is told to end before it is waited for.
    _stop: oneshot::Sender<()>,
    _task: Worker,
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
        } => Some(Err(BusError::Lost(chain(&error)))),
        CanEvent::Disconnected {
            error,
            retry_in: None,
            ..
        } => Some(Err(BusError::Ended(chain(&error)))),
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

fn opens(bus: &CanBus) -> bool {
    let kind = bus.kind();
    feature(kind).1 && kind.reachable()
}

async fn open_task(bus: &CanBus) -> io::Result<CanTask> {
    if !opens(bus) {
        return Err(refused(bus));
    }
    wslib_can_bus::open(
        bus,
        wslib_can_bus::BusConfig::classic(Some(BITRATE)),
        options(),
    )
    .await
    .map_err(failed)
}

/// Opens the bus on a thread of its own running its own runtime, so a caller
/// inside a tokio runtime never blocks on it; dropping the bus ends both.
pub(crate) fn open_bus(bus: &CanBus) -> io::Result<Box<dyn Bus>> {
    let (opened_tx, opened) = mpsc::sync_channel(1);
    let (reads_tx, reads) = mpsc::channel();
    let (stop, stopping) = oneshot::channel();
    let on = bus.clone();
    let task = Worker::spawn("can", RELEASE_WITHIN, move || {
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
        _task: task,
    }))
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        thread,
    };

    use super::*;

    const CLOSING: Duration = Duration::from_millis(50);

    #[test]
    fn dropping_the_bus_waits_for_its_task_to_close_the_adapter() {
        let (stop, stopping) = oneshot::channel::<()>();
        let closed = Arc::new(AtomicBool::new(false));
        let closing = Arc::clone(&closed);
        let task = Worker::spawn("can", RELEASE_WITHIN, move || {
            let _ = stopping.blocking_recv();
            thread::sleep(CLOSING);
            closing.store(true, Ordering::Relaxed);
        })
        .unwrap();
        drop(TaskBus {
            reads: mpsc::channel().1,
            pending: VecDeque::new(),
            _stop: stop,
            _task: task,
        });
        assert!(closed.load(Ordering::Relaxed));
    }
}
