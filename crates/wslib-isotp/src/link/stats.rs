use std::sync::atomic::{AtomicU64, Ordering};

use super::SendFailed;

/// Failed sends, by kind.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct SendFailures {
    pub length: u64,
    pub no_flow_control: u64,
    pub overflow: u64,
    pub too_many_waits: u64,
    pub reserved_status: u64,
    pub refused: u64,
    pub io: u64,
    pub adapter_timeout: u64,
    pub unconfirmed: u64,
    pub reset: u64,
    /// Sends dropped before they finished. A frame the adapter has may still
    /// reach the bus.
    pub cancelled: u64,
}

/// A link's counters since it was made.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct LinkStats {
    /// Frames fed and queued for the receive task.
    pub frames_in: u64,
    /// Frames the adapter took, flow control included.
    pub frames_out: u64,
    pub messages_in: u64,
    pub messages_out: u64,
    /// Frames fed to a full queue.
    pub frames_dropped: u64,
    /// Messages completed while [`Messages`](super::Messages) was full or gone.
    pub messages_dropped: u64,
    /// Flow controls that arrived with no send waiting, or at or after N_Bs.
    pub flow_controls_dropped: u64,
    /// Flow controls the receive task sent that the adapter didn't take.
    pub flow_controls_failed: u64,
    /// Messages received in part and dropped: out of sequence, truncated,
    /// superseded, or no consecutive frame within N_Cr.
    pub aborts: u64,
    pub send_failures: SendFailures,
}

#[derive(Default)]
pub(super) struct Counter(AtomicU64);

impl Counter {
    pub(super) fn add(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

#[derive(Default)]
pub(super) struct Counters {
    pub frames_in: Counter,
    pub frames_out: Counter,
    pub messages_in: Counter,
    pub messages_out: Counter,
    pub frames_dropped: Counter,
    pub messages_dropped: Counter,
    pub flow_controls_dropped: Counter,
    pub flow_controls_failed: Counter,
    pub aborts: Counter,
    failures: Failures,
}

#[derive(Default)]
struct Failures {
    length: Counter,
    no_flow_control: Counter,
    overflow: Counter,
    too_many_waits: Counter,
    reserved_status: Counter,
    refused: Counter,
    io: Counter,
    adapter_timeout: Counter,
    unconfirmed: Counter,
    reset: Counter,
    cancelled: Counter,
}

impl Counters {
    pub(super) fn failed(&self, error: &SendFailed) {
        let failures = &self.failures;
        match error {
            SendFailed::Length(_) => &failures.length,
            SendFailed::NoFlowControl => &failures.no_flow_control,
            SendFailed::Overflow => &failures.overflow,
            SendFailed::TooManyWaits => &failures.too_many_waits,
            SendFailed::ReservedStatus(_) => &failures.reserved_status,
            SendFailed::Refused(_) => &failures.refused,
            SendFailed::Io(_) => &failures.io,
            SendFailed::AdapterTimeout => &failures.adapter_timeout,
            SendFailed::Unconfirmed => &failures.unconfirmed,
            SendFailed::Reset => &failures.reset,
        }
        .add();
    }

    pub(super) fn cancelled(&self) {
        self.failures.cancelled.add();
    }

    pub(super) fn snapshot(&self) -> LinkStats {
        let failures = &self.failures;
        LinkStats {
            frames_in: self.frames_in.get(),
            frames_out: self.frames_out.get(),
            messages_in: self.messages_in.get(),
            messages_out: self.messages_out.get(),
            frames_dropped: self.frames_dropped.get(),
            messages_dropped: self.messages_dropped.get(),
            flow_controls_dropped: self.flow_controls_dropped.get(),
            flow_controls_failed: self.flow_controls_failed.get(),
            aborts: self.aborts.get(),
            send_failures: SendFailures {
                length: failures.length.get(),
                no_flow_control: failures.no_flow_control.get(),
                overflow: failures.overflow.get(),
                too_many_waits: failures.too_many_waits.get(),
                reserved_status: failures.reserved_status.get(),
                refused: failures.refused.get(),
                io: failures.io.get(),
                adapter_timeout: failures.adapter_timeout.get(),
                unconfirmed: failures.unconfirmed.get(),
                reset: failures.reset.get(),
                cancelled: failures.cancelled.get(),
            },
        }
    }
}
