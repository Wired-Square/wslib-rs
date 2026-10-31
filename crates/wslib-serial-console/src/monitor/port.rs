use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex},
};

use tokio::{
    sync::{broadcast, mpsc, watch},
    task::JoinHandle,
    time::{Duration, Instant, sleep, sleep_until},
};
use wslib_backoff::Backoff;
use wslib_serial::SerialEvent;

use super::{
    MonitorOptions, Opener, PortKey, Refusal, Update,
    bounds::Ring,
    echo::EchoMatcher,
    link::{Link, Unresolved},
    lock,
};
use crate::{COLOURS, MonitorState, Participant, Span};

const RESET_PULSE: Duration = Duration::from_millis(10);

pub(super) enum Command {
    Write { bytes: Vec<u8>, by: Option<String> },
    Reset,
}

pub(super) struct Port {
    pub(super) key: PortKey,
    pub(super) baud: u32,
    /// Held across a read's push and its broadcast, so a new subscriber's
    /// replay and its live updates neither overlap nor leave a gap.
    pub(super) ring: Mutex<Ring>,
    pub(super) events: broadcast::Sender<Update>,
    pub(super) status: Mutex<(MonitorState, Option<String>)>,
    roster: Mutex<Roster>,
    /// Set while the line is open, so input never waits for a reopen.
    commands: Mutex<Option<mpsc::UnboundedSender<Command>>>,
    paused: watch::Sender<bool>,
    task: Mutex<Option<JoinHandle<()>>>,
}

/// Who is attached through each subscription, and the colour each name was
/// given on first sight, kept for the port's life.
#[derive(Default)]
struct Roster {
    by_subscription: BTreeMap<u64, (String, Vec<String>)>,
    colours: HashMap<String, u8>,
}

impl Roster {
    fn colour(&mut self, name: &str) -> u8 {
        let next = (self.colours.len() % usize::from(COLOURS)) as u8;
        *self.colours.entry(name.to_owned()).or_insert(next)
    }

    fn everyone(&mut self) -> Vec<Participant> {
        let mut all: Vec<(String, String)> = self
            .by_subscription
            .values()
            .flat_map(|(via, names)| names.iter().map(|name| (name.clone(), via.clone())))
            .collect();
        all.sort();
        all.dedup();
        all.into_iter()
            .map(|(name, via)| Participant {
                colour: self.colour(&name),
                name,
                via,
            })
            .collect()
    }
}

impl Port {
    pub(super) fn new(key: PortKey, baud: u32, options: &MonitorOptions, paused: bool) -> Self {
        let state = match paused {
            true => MonitorState::Paused,
            false => MonitorState::Resolving,
        };
        Self {
            key,
            baud,
            ring: Mutex::new(Ring::new(options.ring_bytes)),
            events: broadcast::channel(options.broadcast.max(1)).0,
            status: Mutex::new((state, None)),
            roster: Mutex::default(),
            commands: Mutex::default(),
            paused: watch::Sender::new(paused),
            task: Mutex::default(),
        }
    }

    pub(super) fn start(self: &Arc<Self>, opener: Opener, backoff: Backoff) {
        self.paused.send_replace(false);
        *lock(&self.task) = Some(tokio::spawn(self.clone().run(opener, backoff)));
    }

    pub(super) fn signal_stop(&self) {
        self.paused.send_replace(true);
    }

    pub(super) async fn stop(&self) {
        self.signal_stop();
        let task = lock(&self.task).take();
        if let Some(task) = task {
            let _ = task.await;
        }
    }

    pub(super) fn is_paused(&self) -> bool {
        *self.paused.borrow()
    }

    pub(super) fn command(&self, command: Command) -> Result<(), Refusal> {
        if self.is_paused() {
            return Err(Refusal::Paused(self.key.clone()));
        }
        let commands = lock(&self.commands);
        commands
            .as_ref()
            .filter(|_| self.events.receiver_count() > 0)
            .and_then(|commands| commands.send(command).ok())
            .ok_or_else(|| Refusal::NotOpen(self.key.clone()))
    }

    pub(super) fn set_status(&self, state: MonitorState, message: Option<String>) {
        *lock(&self.status) = (state, message.clone());
        let _ = self.events.send(Update::State { state, message });
    }

    pub(super) fn participants(&self) -> Vec<Participant> {
        lock(&self.roster).everyone()
    }

    /// No names takes the subscription out of the roster. True when the
    /// roster changed, and every subscriber was told.
    pub(super) fn set_participants(
        &self,
        subscription: u64,
        via: &str,
        names: Vec<String>,
    ) -> bool {
        let mut roster = lock(&self.roster);
        let before = roster.everyone();
        match names.is_empty() {
            true => roster.by_subscription.remove(&subscription),
            false => roster
                .by_subscription
                .insert(subscription, (via.to_owned(), names)),
        };
        let after = roster.everyone();
        let changed = after != before;
        if changed {
            let _ = self.events.send(Update::Participants(after));
        }
        changed
    }

    async fn run(self: Arc<Self>, opener: Opener, mut backoff: Backoff) {
        let mut paused = self.paused.subscribe();
        let mut echoes = EchoMatcher::default();
        while !*paused.borrow_and_update() {
            self.set_status(MonitorState::Resolving, None);
            let (state, why) = match opener.resolve(&self.key) {
                Err(Unresolved::Missing(why)) => (MonitorState::TtyMissing, why),
                Err(Unresolved::Failed(why)) => (MonitorState::Backoff, why),
                Ok(path) => {
                    self.set_status(MonitorState::Opening, Some(path.clone()));
                    match opener.open(&path, self.baud) {
                        Err(e) => (MonitorState::Backoff, format!("open {path}: {e}")),
                        Ok(link) => {
                            backoff.reset();
                            let Some(lost) =
                                self.serve(link, &path, &mut echoes, &mut paused).await
                            else {
                                break;
                            };
                            tracing::warn!(port = %self.key, error = %lost, "serial port lost");
                            (MonitorState::Backoff, lost)
                        }
                    }
                }
            };
            let wait = backoff.next();
            tracing::debug!(
                port = %self.key, reason = %why, retry_in = ?wait,
                "serial port reopen waits"
            );
            self.set_status(state, Some(why));
            tokio::select! {
                biased;
                () = until_paused(&mut paused) => break,
                () = sleep(wait) => {}
            }
        }
    }

    /// Reads and writes the line until it is lost, returning why, or until
    /// paused, returning `None`.
    async fn serve(
        &self,
        mut link: Link,
        path: &str,
        echoes: &mut EchoMatcher,
        paused: &mut watch::Receiver<bool>,
    ) -> Option<String> {
        let (commands, mut queued) = mpsc::unbounded_channel();
        let lost = loop {
            let expiry = echoes.next_expiry();
            tokio::select! {
                biased;
                () = until_paused(paused) => break None,
                () = sleep_until(expiry.unwrap_or_else(Instant::now)), if expiry.is_some() => {
                    for unechoed in echoes.expire(Instant::now()) {
                        let _ = self.events.send(unechoed);
                    }
                }
                Some(command) = queued.recv() => {
                    if let Err(failed) = self.run_command(command, &link, path, echoes).await {
                        break Some(failed);
                    }
                }
                event = link.next_event() => match event {
                    Some(SerialEvent::Connected) => {
                        tracing::info!(
                            port = %self.key, path, baud = self.baud,
                            "serial port opened"
                        );
                        *lock(&self.commands) = Some(commands.clone());
                        self.set_status(MonitorState::Reading, Some(path.to_owned()));
                    }
                    Some(SerialEvent::Read { bytes, .. }) => {
                        let spans = echoes.echoed(&bytes);
                        self.output(bytes, spans);
                    }
                    Some(SerialEvent::Disconnected { error, .. }) => break Some(format!("read {path}: {error}")),
                    None => break Some(format!("read {path}: the line closed")),
                },
            }
        };
        *lock(&self.commands) = None;
        link.stop().await;
        lost
    }

    /// Why the line is lost, if the command failed.
    async fn run_command(
        &self,
        command: Command,
        link: &Link,
        path: &str,
        echoes: &mut EchoMatcher,
    ) -> Result<(), String> {
        match command {
            Command::Write { bytes, by } => {
                if let Some(by) = by {
                    let colour = lock(&self.roster).colour(&by);
                    echoes.sent(&by, colour, &bytes, Instant::now());
                }
                link.write(bytes)
                    .await
                    .map_err(|e| format!("write {path}: {e}"))
            }
            Command::Reset => {
                let pulsed = async {
                    link.set_dtr(false).await?;
                    sleep(RESET_PULSE).await;
                    link.set_dtr(true).await
                };
                pulsed.await.map_err(|e| format!("reset {path}: {e}"))
            }
        }
    }

    fn output(&self, bytes: Vec<u8>, spans: Vec<Span>) {
        let bytes: Arc<[u8]> = bytes.into();
        let mut ring = lock(&self.ring);
        ring.push(Instant::now(), bytes.clone());
        let _ = self.events.send(Update::Output { bytes, spans });
    }
}

async fn until_paused(paused: &mut watch::Receiver<bool>) {
    let _ = paused.wait_for(|paused| *paused).await;
}
