use std::{io, time::Duration};

use tokio::{
    sync::oneshot,
    time::{Instant, sleep, timeout_at},
};
use wslib_can::SendRefused;

use super::{
    period::Period,
    shared::{Delivery, Shared},
    stats::Counters,
};
use crate::{FlowControl, LengthError, Segmenter, flow_control::UNLIMITED_BLOCK};

/// Why [`IsoTpLink::send`](super::IsoTpLink::send) failed. The peer gets no
/// message, except perhaps when the last frame fails as
/// [`Unconfirmed`](Self::Unconfirmed).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SendFailed {
    #[error(transparent)]
    Length(#[from] LengthError),
    #[error("no flow control within N_Bs")]
    NoFlowControl,
    #[error("the receiver has no room for the message")]
    Overflow,
    #[error("too many flow control waits in a row")]
    TooManyWaits,
    #[error("flow control with reserved status {0:#x}")]
    ReservedStatus(u8),
    #[error("send refused: {0}")]
    Refused(SendRefused),
    #[error("send failed: {0}")]
    Io(io::Error),
    /// The adapter's queue had no room within N_As. The frame was not sent.
    #[error("the adapter's queue had no room within N_As")]
    AdapterTimeout,
    /// The adapter has the frame and may still put it on the bus.
    #[error("the adapter didn't confirm a frame within N_As")]
    Unconfirmed,
    /// [`IsoTpLink::reset`](super::IsoTpLink::reset) ran during the send.
    #[error("the link was reset")]
    Reset,
}

type Reply = oneshot::Receiver<Delivery>;

struct Disarm<'a>(&'a Shared);

impl Drop for Disarm<'_> {
    fn drop(&mut self) {
        self.0.disarm();
    }
}

struct Pending<'a> {
    stats: &'a Counters,
    finished: bool,
}

impl Drop for Pending<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.stats.cancelled();
        }
    }
}

impl Shared {
    pub(super) async fn send(&self, message: &[u8]) -> Result<(), SendFailed> {
        let mut pending = Pending {
            stats: &self.stats,
            finished: false,
        };
        let sent = self.transmit(message).await;
        pending.finished = true;
        match &sent {
            Ok(()) => self.stats.messages_out.add(),
            Err(error) => self.stats.failed(error),
        }
        sent
    }

    async fn transmit(&self, message: &[u8]) -> Result<(), SendFailed> {
        let mut frames = Segmenter::new(message)?;
        let _turn = self.turn.lock().await;
        let generation = self.generation();
        if frames.is_single() {
            return self.out(generation, frames.first()).await;
        }
        let _period = Period::begin();
        let _disarm = Disarm(self);
        let mut reply = self.arm();
        self.out(generation, frames.first()).await?;
        loop {
            let cts = self.continue_to_send(reply).await?;
            match self.block(generation, &mut frames, cts).await? {
                Some(next) => reply = next,
                None => return Ok(()),
            }
        }
    }

    async fn continue_to_send(&self, mut reply: Reply) -> Result<FlowControl, SendFailed> {
        let mut waits = 0;
        loop {
            let deadline = Instant::now() + self.config.n_bs;
            self.wait_until(deadline);
            reply = match timeout_at(deadline, reply).await {
                Err(_) => return Err(SendFailed::NoFlowControl),
                Ok(Err(_)) => return Err(self.interrupted()),
                Ok(Ok(Delivery::Proceed(cts))) => return Ok(cts),
                Ok(Ok(Delivery::Overflow)) => return Err(SendFailed::Overflow),
                Ok(Ok(Delivery::Reserved(status))) => {
                    return Err(SendFailed::ReservedStatus(status));
                }
                Ok(Ok(Delivery::Wait(next))) => next,
            };
            waits += 1;
            if waits > self.config.wait_limit {
                return Err(SendFailed::TooManyWaits);
            }
        }
    }

    async fn block(
        &self,
        generation: u64,
        frames: &mut Segmenter<'_>,
        cts: FlowControl,
    ) -> Result<Option<Reply>, SendFailed> {
        let gap = cts.st_min.duration();
        let block = usize::from(cts.block_size);
        let mut sent = 0;
        while let Some(frame) = frames.next() {
            sent += 1;
            let more = frames.len() > 0;
            let next =
                (more && cts.block_size != UNLIMITED_BLOCK && sent == block).then(|| self.arm());
            self.out(generation, frame).await?;
            if !more || next.is_some() {
                return Ok(next);
            }
            self.pace(generation, gap).await?;
        }
        Ok(None)
    }

    async fn pace(&self, generation: u64, gap: Duration) -> Result<(), SendFailed> {
        if gap.is_zero() {
            return Ok(());
        }
        self.unless_interrupted(generation, sleep(gap)).await
    }
}
