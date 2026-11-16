use std::sync::Arc;

use tokio::{
    sync::{mpsc, oneshot},
    time::{Instant, sleep_until},
};

use super::shared::Shared;
use crate::{PciKind, Reassembler, StMin, Step};

pub(super) struct Queued {
    pub generation: u64,
    pub data: Vec<u8>,
}

enum Turn {
    Reset,
    Frame(Queued),
    Expired,
    Closed,
}

pub(super) async fn run(
    shared: Arc<Shared>,
    mut frames: mpsc::Receiver<Queued>,
    messages: mpsc::Sender<Vec<u8>>,
    _done: oneshot::Sender<()>,
) {
    let config = &shared.config;
    let mut reassembler = Reassembler::new(config.block_size, StMin::from_duration(config.st_min));
    let mut generation = shared.generation();
    let mut n_cr: Option<Instant> = None;
    loop {
        let turn = tokio::select! {
            biased;
            () = shared.closing.notified() => Turn::Closed,
            () = shared.reset.notified() => Turn::Reset,
            queued = frames.recv() => queued.map_or(Turn::Closed, Turn::Frame),
            () = sleep_until(n_cr.unwrap_or_else(Instant::now)), if n_cr.is_some() => Turn::Expired,
        };
        if shared.generation() != generation {
            generation = shared.generation();
            reassembler.reset();
        }
        let expired = match turn {
            Turn::Expired => true,
            Turn::Frame(_) => n_cr.is_some_and(|deadline| Instant::now() >= deadline),
            Turn::Reset | Turn::Closed => false,
        };
        if expired && reassembler.is_receiving() {
            reassembler.reset();
            shared.stats.aborts.add();
        }
        match turn {
            Turn::Closed => return,
            Turn::Reset | Turn::Expired => {}
            Turn::Frame(queued) if queued.generation != generation => {}
            Turn::Frame(Queued { data, .. })
                if PciKind::classify(&data) == Some(PciKind::FlowControl) =>
            {
                shared.route(&data);
            }
            Turn::Frame(Queued { data, .. }) => {
                let outcome = reassembler.on_frame(&data);
                if outcome.aborted.is_some() {
                    shared.stats.aborts.add();
                }
                match outcome.step {
                    Step::Nothing => {}
                    Step::Accepted => n_cr = Some(Instant::now() + config.n_cr),
                    Step::SendFlowControl(flow) => {
                        if shared.out(generation, flow.encode()).await.is_err() {
                            shared.stats.flow_controls_failed.add();
                        }
                        n_cr = Some(Instant::now() + config.n_cr);
                    }
                    Step::Message(message) => match messages.try_send(message) {
                        Ok(()) => shared.stats.messages_in.add(),
                        Err(_) => shared.stats.messages_dropped.add(),
                    },
                }
            }
        }
        if !reassembler.is_receiving() {
            n_cr = None;
        }
    }
}
