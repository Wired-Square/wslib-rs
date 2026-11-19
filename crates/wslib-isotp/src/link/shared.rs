use std::{
    future::Future,
    pin::pin,
    sync::{
        Mutex, MutexGuard, PoisonError,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

use tokio::{
    sync::{Notify, oneshot},
    time::{Instant, timeout_at},
};
use wslib_can::{CanFrame, CanWriter, SendRefused};

use super::{LinkConfig, SendFailed, stats::Counters};
use crate::{FlowControl, FlowControlError, FlowStatus};

pub(super) enum Delivery {
    Proceed(FlowControl),
    Wait(oneshot::Receiver<Delivery>),
    Overflow,
    Reserved(u8),
}

struct Waiter {
    reply: oneshot::Sender<Delivery>,
    until: Option<Instant>,
}

impl Waiter {
    fn new(reply: oneshot::Sender<Delivery>) -> Self {
        Self { reply, until: None }
    }

    fn expired(&self) -> bool {
        self.until.is_some_and(|until| Instant::now() >= until)
    }
}

pub(super) struct Shared {
    pub config: LinkConfig,
    pub stats: Counters,
    pub turn: tokio::sync::Mutex<()>,
    pub reset: Notify,
    pub closing: Notify,
    pub interrupt: Notify,
    writer: CanWriter,
    waiter: Mutex<Option<Waiter>>,
    generation: AtomicU64,
    closed: AtomicBool,
}

impl Shared {
    pub(super) fn new(writer: CanWriter, config: LinkConfig) -> Self {
        Self {
            config,
            stats: Counters::default(),
            turn: tokio::sync::Mutex::new(()),
            reset: Notify::new(),
            closing: Notify::new(),
            interrupt: Notify::new(),
            writer,
            waiter: Mutex::new(None),
            generation: AtomicU64::new(0),
            closed: AtomicBool::new(false),
        }
    }

    pub(super) fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    pub(super) fn reset(&self) {
        self.generation.fetch_add(1, Ordering::AcqRel);
        self.waiter().take();
        self.reset.notify_one();
        self.interrupt.notify_waiters();
    }

    pub(super) fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.waiter().take();
        self.closing.notify_one();
        self.interrupt.notify_waiters();
    }

    pub(super) fn closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    pub(super) fn stale(&self, generation: u64) -> bool {
        self.generation() != generation || self.closed()
    }

    pub(super) fn interrupted(&self) -> SendFailed {
        if self.closed() {
            SendFailed::Refused(SendRefused::Stopped)
        } else {
            SendFailed::Reset
        }
    }

    pub(super) async fn unless_interrupted<F: Future>(
        &self,
        generation: u64,
        future: F,
    ) -> Result<F::Output, SendFailed> {
        let mut interrupt = pin!(self.interrupt.notified());
        interrupt.as_mut().enable();
        if self.stale(generation) {
            return Err(self.interrupted());
        }
        tokio::select! {
            biased;
            () = interrupt => Err(self.interrupted()),
            output = future => Ok(output),
        }
    }

    pub(super) async fn out(&self, generation: u64, data: Vec<u8>) -> Result<(), SendFailed> {
        let config = &self.config;
        let frame = CanFrame::data(
            config.bus,
            config.tx_id,
            config.extended,
            false,
            false,
            data,
        );
        let deadline = Instant::now() + config.n_as;
        let room = timeout_at(deadline, self.writer.send_when_ready(frame));
        let answer = match self.unless_interrupted(generation, room).await? {
            Err(_) => return Err(SendFailed::AdapterTimeout),
            Ok(Err(refused)) => return Err(SendFailed::Refused(refused)),
            Ok(Ok(answer)) => answer,
        };
        match timeout_at(deadline, answer).await {
            Err(_) => Err(SendFailed::Unconfirmed),
            Ok(Err(refused)) => Err(SendFailed::Refused(refused)),
            Ok(Ok(Err(error))) => Err(SendFailed::Write(error)),
            Ok(Ok(Ok(()))) => {
                self.stats.frames_out.add();
                Ok(())
            }
        }
    }

    pub(super) fn arm(&self) -> oneshot::Receiver<Delivery> {
        let (reply, delivery) = oneshot::channel();
        *self.waiter() = Some(Waiter::new(reply));
        delivery
    }

    pub(super) fn wait_until(&self, until: Instant) {
        if let Some(waiter) = self.waiter().as_mut() {
            waiter.until = Some(until);
        }
    }

    pub(super) fn disarm(&self) {
        self.waiter().take();
    }

    pub(super) fn route(&self, frame: &[u8]) {
        let flow = match FlowControl::parse(frame) {
            Ok(flow) => Ok(flow),
            Err(FlowControlError::ReservedStatus(status)) => Err(status),
            Err(FlowControlError::NotFlowControl) => return,
        };
        let mut slot = self.waiter();
        let waiter = match slot.take() {
            Some(waiter) if !waiter.expired() => waiter,
            kept => {
                *slot = kept;
                self.stats.flow_controls_dropped.add();
                return;
            }
        };
        let delivery = match flow {
            Err(status) => Delivery::Reserved(status),
            Ok(flow) => match flow.status {
                FlowStatus::ContinueToSend => Delivery::Proceed(flow),
                FlowStatus::Overflow => Delivery::Overflow,
                FlowStatus::Wait => {
                    let (next, delivery) = oneshot::channel();
                    *slot = Some(Waiter::new(next));
                    Delivery::Wait(delivery)
                }
            },
        };
        if waiter.reply.send(delivery).is_err() {
            *slot = None;
            self.stats.flow_controls_dropped.add();
        }
    }

    fn waiter(&self) -> MutexGuard<'_, Option<Waiter>> {
        self.waiter.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::sync::oneshot::error::TryRecvError;
    use wslib_can::{CanOptions, loopback::LoopbackBus};

    use super::*;
    use crate::StMin;

    const BUS: u8 = 0;
    const TX: u32 = 0x7E0;
    const RX: u32 = 0x7E8;
    const EARLY: Duration = Duration::from_millis(1);
    const CTS: FlowControl = FlowControl {
        status: FlowStatus::ContinueToSend,
        block_size: 0,
        st_min: StMin(0),
    };

    async fn shared() -> (Shared, wslib_can::CanTask) {
        let task = LoopbackBus::default()
            .port()
            .open(CanOptions::default())
            .await
            .unwrap();
        (
            Shared::new(task.writer(), LinkConfig::new(BUS, TX, RX)),
            task,
        )
    }

    #[tokio::test(start_paused = true)]
    async fn a_flow_control_at_the_deadline_is_dropped_and_leaves_the_waiter() {
        let (shared, _task) = shared().await;
        let mut reply = shared.arm();
        shared.wait_until(Instant::now());
        shared.route(&CTS.encode());
        assert!(matches!(reply.try_recv(), Err(TryRecvError::Empty)));
        assert_eq!(shared.stats.snapshot().flow_controls_dropped, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_flow_control_before_the_deadline_is_delivered() {
        let (shared, _task) = shared().await;
        let mut reply = shared.arm();
        shared.wait_until(Instant::now() + EARLY);
        shared.route(&CTS.encode());
        assert!(matches!(reply.try_recv(), Ok(Delivery::Proceed(CTS))));
        assert_eq!(shared.stats.snapshot().flow_controls_dropped, 0);
    }
}
