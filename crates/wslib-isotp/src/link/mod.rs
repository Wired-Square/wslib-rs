mod config;
mod period;
mod receive;
mod send;
mod shared;
mod stats;

use std::sync::{Arc, Weak};

use tokio::sync::{mpsc, oneshot};
use wslib_can::{CanEvent, CanRead, CanTask, CanWriter, Direction};

pub use config::LinkConfig;
pub use send::SendFailed;
pub use stats::{LinkStats, SendFailures};

use receive::Queued;
use shared::Shared;

/// One ISO-TP link on a CAN adapter, sending one message at a time. A clone
/// is another handle on the same link. Its receive task ends when the last
/// handle is dropped.
#[derive(Clone)]
pub struct IsoTpLink {
    inner: Arc<Inner>,
}

struct Inner {
    shared: Arc<Shared>,
    frames: mpsc::Sender<Queued>,
}

/// The complete messages a link received, in order.
pub struct Messages(mpsc::Receiver<Vec<u8>>);

impl Messages {
    /// Messages held for the caller. One completed with the queue full is
    /// dropped and counted.
    pub const CAPACITY: usize = 64;

    /// The next message, or `None` once the queue is drained and the link has
    /// ended: every handle dropped, [`IsoTpLink::close`] called, or the CAN
    /// task under [`IsoTpLink::over`] ended.
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.0.recv().await
    }
}

impl IsoTpLink {
    /// A link whose caller passes it every read with [`feed`](Self::feed). The
    /// task that feeds it must never await its [`send`](Self::send), or the
    /// send's flow control is never fed. Panics outside a tokio runtime.
    pub fn new(writer: CanWriter, config: LinkConfig) -> (Self, Messages) {
        let (link, messages, _done) = Self::spawn(writer, config);
        (link, messages)
    }

    /// Like [`new`](Self::new), but a spawned task owns `task`, feeds the link
    /// and resets it on each disconnect. When the CAN task ends, so does the
    /// link: sends fail and [`Messages::recv`] returns `None`. Dropping the
    /// last handle stops the CAN task.
    pub fn over(task: CanTask, config: LinkConfig) -> (Self, Messages) {
        let (link, messages, done) = Self::spawn(task.writer(), config);
        tokio::spawn(pump(task, Arc::downgrade(&link.inner), done));
        (link, messages)
    }

    fn spawn(writer: CanWriter, config: LinkConfig) -> (Self, Messages, oneshot::Receiver<()>) {
        let (frames, queue) = mpsc::channel(config.rx_queue.max(1));
        let (delivered, messages) = mpsc::channel(Messages::CAPACITY);
        let (done, ended) = oneshot::channel();
        let shared = Arc::new(Shared::new(writer, config));
        tokio::spawn(receive::run(shared.clone(), queue, delivered, done));
        let inner = Arc::new(Inner { shared, frames });
        (Self { inner }, Messages(messages), ended)
    }

    /// Queues a read for the receive task without waiting. It keeps only
    /// received classic data frames on the link's bus, rx id and id width.
    pub fn feed(&self, read: &CanRead) {
        let shared = &self.inner.shared;
        let config = &shared.config;
        let frame = &read.frame;
        let ours = read.direction == Direction::Rx
            && frame.bus == config.bus
            && frame.arb_id == config.rx_id
            && frame.extended == config.extended
            && !frame.fd
            && !frame.rtr;
        if !ours {
            return;
        }
        let queued = Queued {
            generation: shared.generation(),
            data: frame.data.clone(),
        };
        match self.inner.frames.try_send(queued) {
            Ok(()) => shared.stats.frames_in.add(),
            Err(_) => shared.stats.frames_dropped.add(),
        }
    }

    /// Sends one message of 1 to 4095 bytes after any send under way, and
    /// returns once the adapter has taken its last frame. If the send is
    /// dropped part-way, a frame the adapter has may still reach the bus.
    pub async fn send(&self, message: &[u8]) -> Result<(), SendFailed> {
        self.inner.shared.send(message).await
    }

    /// Drops the message being received and its queued frames. The send under
    /// way hands the adapter no more frames and fails with
    /// [`SendFailed::Reset`]. If the adapter holds one of its frames, the send
    /// waits for it, and ends as that frame does if it fails or is the last.
    pub fn reset(&self) {
        self.inner.shared.reset();
    }

    /// Ends the link for every handle. Later sends fail with
    /// [`SendRefused::Stopped`](wslib_can::SendRefused::Stopped), as does the
    /// send under way, on the terms of [`reset`](Self::reset).
    /// [`Messages::recv`] returns `None` once drained. A link made with
    /// [`over`](Self::over) stops its CAN task.
    pub fn close(&self) {
        self.inner.shared.close();
    }

    pub fn stats(&self) -> LinkStats {
        self.inner.shared.stats.snapshot()
    }
}

async fn pump(mut task: CanTask, link: Weak<Inner>, mut ended: oneshot::Receiver<()>) {
    loop {
        let event = tokio::select! {
            biased;
            _ = &mut ended => break,
            event = task.next_event() => event,
        };
        let Some(inner) = link.upgrade() else {
            break;
        };
        let Some(event) = event else {
            inner.shared.close();
            break;
        };
        let link = IsoTpLink { inner };
        match event {
            CanEvent::Read(reads) => reads.iter().for_each(|read| link.feed(read)),
            CanEvent::Disconnected { .. } => link.reset(),
            _ => {}
        }
    }
    task.stop().await;
}
