//! One monitor per port: a task holding the line through wslib-serial, a ring
//! of its recent output, and a broadcast every subscriber reads.

mod bounds;
mod echo;
mod link;
mod port;
mod subscription;
#[cfg(test)]
mod tests;

use std::{
    collections::HashMap,
    convert::Infallible,
    fmt,
    str::FromStr,
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

use tokio::time::Duration;
use wslib_backoff::Backoff;

pub use bounds::Bounds;
pub(crate) use link::Opener;
use port::{Command, Port};
pub use subscription::{Seat, Subscription};

use crate::{EndReason, MonitorState, Participant, RefusalReason, Span};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitorOptions {
    /// The rate a port opens at when its first subscriber names none.
    pub default_baud: u32,
    /// The output kept for `tail` and `since_ms`.
    pub ring_bytes: usize,
    /// The wait before the first reopen after a loss or a failed open,
    /// doubling with each failure up to `reopen_max`.
    pub reopen: Duration,
    pub reopen_max: Duration,
    /// The reads a subscriber can fall behind by; one further behind misses
    /// the reads it lagged over.
    pub broadcast: usize,
}

impl Default for MonitorOptions {
    fn default() -> Self {
        Self {
            default_baud: 115200,
            ring_bytes: 64 * 1024,
            reopen: Duration::from_secs(1),
            reopen_max: Duration::from_secs(30),
            broadcast: 256,
        }
    }
}

/// The port a monitor holds. A USB serial is resolved to its path at every
/// open, since a replug can move it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PortKey {
    Path(String),
    UsbSerial(String),
}

impl PortKey {
    /// The USB serial when there is one, so consoles that name it share the
    /// device's monitor whichever path they were given.
    pub fn new(path: Option<&str>, usb_serial: Option<&str>) -> Option<Self> {
        match (usb_serial, path) {
            (Some(serial), _) => Some(Self::UsbSerial(serial.to_owned())),
            (None, Some(path)) => Some(Self::Path(path.to_owned())),
            (None, None) => None,
        }
    }
}

impl fmt::Display for PortKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Path(path) => f.write_str(path),
            Self::UsbSerial(serial) => write!(f, "usb:{serial}"),
        }
    }
}

impl FromStr for PortKey {
    type Err = Infallible;

    fn from_str(key: &str) -> Result<Self, Infallible> {
        Ok(match key.strip_prefix("usb:") {
            Some(serial) => Self::UsbSerial(serial.to_owned()),
            None => Self::Path(key.to_owned()),
        })
    }
}

/// Why the monitor turned a request away.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Refusal {
    #[error("{0} is paused for a flash")]
    Paused(PortKey),
    #[error("{0} is not open")]
    NotOpen(PortKey),
}

impl Refusal {
    pub fn reason(&self) -> RefusalReason {
        match self {
            Self::Paused(_) => RefusalReason::Paused,
            Self::NotOpen(_) => RefusalReason::NoActiveReader,
        }
    }
}

/// What a subscriber is told, in the order it happened at the port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Update {
    /// One read, and whose echo is in it.
    Output {
        bytes: Arc<[u8]>,
        spans: Vec<Span>,
    },
    State {
        state: MonitorState,
        message: Option<String>,
    },
    /// Input the device didn't echo within 300 ms: a count and its control
    /// keys, never the bytes.
    Unechoed {
        by: String,
        colour: u8,
        count: u32,
        controls: String,
    },
    Participants(Vec<Participant>),
    /// The last update.
    End(EndReason),
}

/// A port a monitor holds, and the path of its line while it is open.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Monitored {
    pub key: PortKey,
    pub open: Option<String>,
}

/// Every port's monitor, created on its first subscriber and kept until it
/// is released, so a replug or a flash keeps its ring and its consoles.
#[derive(Clone)]
pub struct Monitors(Arc<Shared>);

struct Shared {
    options: MonitorOptions,
    opener: Opener,
    registry: Mutex<Registry>,
    next_subscriber: AtomicU64,
    close_when_idle: AtomicBool,
}

#[derive(Default)]
struct Registry {
    ports: HashMap<PortKey, Arc<Port>>,
    /// Pauses not yet resumed; a port keyed here opens paused.
    flashing: HashMap<PortKey, usize>,
}

impl Monitors {
    pub fn new(options: MonitorOptions) -> Self {
        Self::with_opener(options, Opener::Serial)
    }

    pub(crate) fn with_opener(options: MonitorOptions, opener: Opener) -> Self {
        Self(Arc::new(Shared {
            options,
            opener,
            registry: Mutex::default(),
            next_subscriber: AtomicU64::new(0),
            close_when_idle: AtomicBool::new(false),
        }))
    }

    /// Closes a port's line when its last subscriber leaves, keeping its ring,
    /// and reopens it for the next. Applies to ports first subscribed after.
    pub fn closing_when_idle(self) -> Self {
        self.0.close_when_idle.store(true, Ordering::Relaxed);
        self
    }

    /// The path `key` names: the line its monitor has open, or else resolved
    /// now. `None` when no attached device has its USB serial.
    pub fn resolve(&self, key: &PortKey) -> Option<String> {
        let open = self
            .port(key)
            .ok()
            .and_then(|port| lock(&port.open).clone());
        open.or_else(|| self.0.opener.resolve(key).ok())
    }

    /// `baud` opens the port when this is its first subscriber, and is
    /// ignored after that. Panics outside a tokio runtime.
    pub fn subscribe(&self, key: PortKey, baud: Option<u32>, bounds: Bounds) -> Subscription {
        self.subscribe_resolved(key, None, baud, bounds)
    }

    /// As [`subscribe`](Self::subscribe), with `path` from
    /// [`resolve`](Self::resolve): if the line is not open, its next open is
    /// of `path` rather than resolved again, so a check made on `path` holds.
    pub fn subscribe_resolved(
        &self,
        key: PortKey,
        path: Option<String>,
        baud: Option<u32>,
        bounds: Bounds,
    ) -> Subscription {
        let (port, start) = {
            let mut registry = lock(&self.0.registry);
            let paused = registry.flashing.contains_key(&key);
            let (port, start) = match registry.ports.get(&key) {
                Some(port) => (port.clone(), false),
                None => {
                    let baud = baud.unwrap_or(self.0.options.default_baud);
                    let idle = self.0.close_when_idle.load(Ordering::Relaxed);
                    let port = Port::new(key.clone(), baud, &self.0.options, paused, idle);
                    let port = Arc::new(port);
                    registry.ports.insert(key, port.clone());
                    (port, !paused)
                }
            };
            if path.is_some() && lock(&port.open).is_none() {
                *lock(&port.next_path) = path;
            }
            (port, start)
        };
        let id = self.0.next_subscriber.fetch_add(1, Ordering::Relaxed);
        let subscription = port.subscribe(id, bounds);
        if start {
            self.start(&port);
        }
        subscription
    }

    /// Sends `bytes` to the port, its echo attributed to `by`. Refused, never
    /// queued, while the port is paused or not open.
    pub fn write(&self, key: &PortKey, bytes: Vec<u8>, by: Option<&str>) -> Result<(), Refusal> {
        let by = by.map(str::to_owned);
        self.port(key)?.command(Command::Write { bytes, by })
    }

    /// Pulses DTR low for 10 ms, which resets a board that wires it to its
    /// reset pin. Refused as [`write`](Self::write) is.
    pub fn reset(&self, key: &PortKey) -> Result<(), Refusal> {
        self.port(key)?.command(Command::Reset)
    }

    /// Lets go of the port for a flash, returning once it is closed. Its
    /// consoles stay attached, shown [`MonitorState::Paused`], and their input
    /// is refused until every pause is resumed.
    pub async fn pause(&self, key: &PortKey) {
        let port = {
            let mut registry = lock(&self.0.registry);
            *registry.flashing.entry(key.clone()).or_default() += 1;
            registry.ports.get(key).cloned()
        };
        if let Some(port) = port {
            port.stop().await;
            port.set_status(MonitorState::Paused, None);
        }
        tracing::info!(port = %key, "serial port paused for a flash");
    }

    /// Ends one [`pause`](Self::pause); the last reopens the port, resolving
    /// its USB serial afresh.
    pub fn resume(&self, key: &PortKey) {
        let port = {
            let mut registry = lock(&self.0.registry);
            match registry.flashing.get_mut(key) {
                Some(count) if *count > 1 => {
                    *count -= 1;
                    return;
                }
                Some(_) => registry.flashing.remove(key),
                None => return,
            };
            registry.ports.get(key).cloned()
        };
        tracing::info!(port = %key, "serial port resumed");
        if let Some(port) = port {
            lock(&port.next_path).take();
            self.start(&port);
        }
    }

    /// Shown to the consoles of a paused port, as the flash's progress.
    pub fn progress(&self, key: &PortKey, message: &str) {
        if let Ok(port) = self.port(key)
            && port.is_paused()
        {
            port.set_status(MonitorState::Paused, Some(message.to_owned()));
        }
    }

    /// Closes the port and ends its subscriptions [`EndReason::Released`], so
    /// another program can open it; false when no monitor had it. Refused
    /// while a flash has it paused.
    pub async fn release(&self, key: &PortKey) -> Result<bool, Refusal> {
        let port = {
            let mut registry = lock(&self.0.registry);
            if registry.flashing.contains_key(key) {
                return Err(Refusal::Paused(key.clone()));
            }
            registry.ports.remove(key)
        };
        let Some(port) = port else {
            return Ok(false);
        };
        port.stop().await;
        tracing::info!(port = %key, "serial port released");
        Ok(true)
    }

    /// Ends every subscription to `key` and closes its line, as
    /// [`release`](Self::release) does but paused or not, each subscription
    /// told `reason` by [`Subscription::revoked`]; false when no monitor had it.
    pub async fn revoke(&self, key: &PortKey, reason: &str) -> bool {
        let Some(port) = lock(&self.0.registry).ports.remove(key) else {
            return false;
        };
        let _ = port.revoked.set(reason.to_owned());
        port.stop().await;
        tracing::info!(port = %key, reason, "serial port revoked");
        true
    }

    /// Every port a monitor holds, by key.
    pub fn monitored(&self) -> Vec<Monitored> {
        let mut all: Vec<Monitored> = lock(&self.0.registry)
            .ports
            .iter()
            .map(|(key, port)| Monitored {
                key: key.clone(),
                open: lock(&port.open).clone(),
            })
            .collect();
        all.sort_by(|a, b| a.key.cmp(&b.key));
        all
    }

    /// True from the first subscribe to `key` until it is released, paused or
    /// not.
    pub fn is_monitored(&self, key: &PortKey) -> bool {
        lock(&self.0.registry).ports.contains_key(key)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn stop_all(&self) {
        for port in lock(&self.0.registry).ports.values() {
            port.signal_stop();
        }
    }

    fn port(&self, key: &PortKey) -> Result<Arc<Port>, Refusal> {
        lock(&self.0.registry)
            .ports
            .get(key)
            .cloned()
            .ok_or_else(|| Refusal::NotOpen(key.clone()))
    }

    fn start(&self, port: &Arc<Port>) {
        let options = &self.0.options;
        let backoff = Backoff::new(options.reopen, options.reopen_max);
        port.start(self.0.opener.clone(), backoff);
    }
}

pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[allow(dead_code)]
fn futures_are_send(monitors: Monitors, mut subscription: Subscription, key: PortKey) {
    fn is_send<T: Send>(_: &T) {}
    fn is_sync<T: Sync>(_: &T) {}
    is_send(&subscription.seat());
    is_sync(&subscription.seat());
    is_send(&monitors.pause(&key));
    is_send(&monitors.release(&key));
    is_send(&monitors.revoke(&key, ""));
    is_send(&subscription.next());
}
