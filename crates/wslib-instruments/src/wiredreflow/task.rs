use std::{
    collections::VecDeque,
    sync::{
        Arc,
        mpsc::{self, Receiver, RecvTimeoutError, Sender},
    },
    time::Duration,
};

use tokio::sync::oneshot;
use wslib_can::{CanEvent, CanOptions, CanTask, TimeMapping};

use super::{
    bus::{Bus, BusError, CanBus, feature, refused},
    frame::RawFrame,
};
use crate::{
    probe::StartError,
    worker::{RELEASE_WITHIN, Worker},
};

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
            Err(RecvTimeoutError::Disconnected) => Err(BusError::Ended(None)),
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
        } => Some(Err(BusError::Lost(Arc::new(error)))),
        CanEvent::Disconnected {
            error,
            retry_in: None,
            ..
        } => Some(Err(BusError::Ended(Some(Arc::new(error))))),
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

async fn open_task(bus: &CanBus) -> Result<CanTask, StartError> {
    if !opens(bus) {
        return Err(refused(bus));
    }
    wslib_can_bus::open(
        bus,
        wslib_can_bus::BusConfig::classic(Some(BITRATE)),
        options(),
    )
    .await
    .map_err(StartError::Bus)
}

/// Opens the bus on a thread of its own running its own runtime, so a caller
/// inside a tokio runtime never blocks on it; dropping the bus ends both.
pub(crate) fn open_bus(bus: &CanBus) -> Result<Box<dyn Bus>, StartError> {
    let on = bus.clone();
    open_bus_with(async move || open_task(&on).await)
}

fn open_bus_with(
    open: impl AsyncFnOnce() -> Result<CanTask, StartError> + Send + 'static,
) -> Result<Box<dyn Bus>, StartError> {
    let (opened_tx, opened) = mpsc::sync_channel(1);
    let (reads_tx, reads) = mpsc::channel();
    let (stop, stopping) = oneshot::channel();
    let task = Worker::spawn("can", RELEASE_WITHIN, move || {
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(e) => {
                let _ = opened_tx.send(Err(StartError::Runtime(e)));
                return;
            }
        };
        runtime.block_on(async {
            match open().await {
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
    })
    .map_err(StartError::Thread)?;
    opened.recv().map_err(|_| StartError::Panicked)??;
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

    fn panics() -> Result<CanTask, StartError> {
        panic!("the adapter's open panicked")
    }

    #[test]
    fn an_open_that_panics_on_the_can_thread_is_a_panicked_start() {
        let refused = open_bus_with(async || panics()).err().unwrap();

        assert!(matches!(refused, StartError::Panicked), "{refused:?}");
        assert_eq!(
            refused.to_string(),
            "the probe's thread panicked before it opened its instrument"
        );
    }

    fn read_failed() -> wslib_can::CanError {
        wslib_can::CanError::Read(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "the adapter went away",
        ))
    }

    fn is_read_failed(cause: &(dyn std::error::Error + Send + Sync + 'static)) -> bool {
        matches!(
            cause.downcast_ref::<wslib_can::CanError>(),
            Some(wslib_can::CanError::Read(e)) if e.kind() == std::io::ErrorKind::BrokenPipe
        )
    }

    #[test]
    fn a_disconnect_keeps_the_cans_error_typed() {
        let lost = translated(CanEvent::Disconnected {
            error: read_failed(),
            consecutive: 1,
            retry_in: Some(Duration::from_secs(1)),
        });
        assert!(
            matches!(&lost, Some(Err(BusError::Lost(cause))) if is_read_failed(&**cause)),
            "{lost:?}"
        );
        let ended = translated(CanEvent::Disconnected {
            error: read_failed(),
            consecutive: 1,
            retry_in: None,
        });
        assert!(
            matches!(&ended, Some(Err(BusError::Ended(Some(cause)))) if is_read_failed(&**cause)),
            "{ended:?}"
        );
    }
}
