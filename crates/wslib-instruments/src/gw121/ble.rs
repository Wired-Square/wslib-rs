use std::{
    collections::{HashMap, HashSet},
    fmt,
    future::Future,
    hash::Hash,
    io,
    pin::Pin,
    sync::mpsc::{self, Receiver, RecvTimeoutError, Sender},
    thread,
    time::{Duration, Instant},
};

use btleplug::{
    api::{
        BDAddr, Central as _, CentralEvent, Manager as _, Peripheral as _, ScanFilter,
        ValueNotification,
    },
    platform::{Adapter, Manager, Peripheral, PeripheralId},
};
use futures_util::{FutureExt as _, Stream, StreamExt, future::ready};
use tokio::sync::watch;
use uuid::Uuid;

use super::{Chunk, Replay, Target, decode};
use crate::{
    probe::{Probe, ProbeError},
    sample::{Sample, Stamp},
    signal::SignalKey,
    uri::ProbeUri,
    worker::{RELEASE_WITHIN, Worker},
};

pub(crate) const DATA_CHARACTERISTIC: Uuid =
    Uuid::from_u128(0xe7add780_b042_4876_aae1_112855353cc1);

const ADAPTER_TIMEOUT: Duration = Duration::from_secs(5);
const SCAN_CONTROL_TIMEOUT: Duration = Duration::from_secs(2);
const DESCRIBE_TIMEOUT: Duration = Duration::from_secs(5);
const FIND_TIMEOUT: Duration = Duration::from_secs(10);
const FIND_POLL: Duration = Duration::from_millis(250);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const SUBSCRIBE_WITHIN: Duration = Duration::from_secs(4);
const DISCONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECTION_CHECK_TIMEOUT: Duration = Duration::from_secs(2);
const RELEASE_WALK_TIMEOUT: Duration = Duration::from_secs(10);
const SILENCE: Duration = Duration::from_secs(5);
const CONNECT_BURST: Duration = Duration::from_secs(1);
const RECONNECT_BACKOFF: Duration = Duration::from_secs(2);
const MAX_INTERVAL: Duration = Duration::from_secs(2);
const NOT_ADVERTISING: &str =
    "the 121GW isn't advertising — check BT is on, or toggle it (hold 1ms PEAK twice)";
const HIDDEN_ADDRESS_TARGET: &str = "an all-zero address can't identify a meter; target it by name";
pub const ADDRESS_HIDDEN: &str = "(address hidden by this platform)";

impl Target {
    fn matches(&self, name: Option<&str>, address: BDAddr) -> bool {
        match self {
            Target::Address(a) => {
                shown_address(address).is_some_and(|shown| a.eq_ignore_ascii_case(&shown))
            }
            Target::Name(n) => name == Some(n.as_str()),
        }
    }

    fn is_hidden_address(&self) -> bool {
        matches!(self, Target::Address(a) if a.parse::<BDAddr>() == Ok(BDAddr::default()))
    }

    fn described(&self) -> String {
        match self {
            Target::Address(a) => format!("at {a}"),
            Target::Name(n) => format!("named {n}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Advertiser<Id> {
    id: Id,
    name: Option<String>,
    address: BDAddr,
    rssi: Option<i16>,
}

fn shown_address(address: BDAddr) -> Option<String> {
    (address != BDAddr::default()).then(|| address.to_string())
}

fn matching<'a, Id: Eq + Hash>(
    target: &Target,
    heard: &HashSet<Id>,
    advertisers: &'a [Advertiser<Id>],
) -> Vec<&'a Advertiser<Id>> {
    advertisers
        .iter()
        .filter(|a| heard.contains(&a.id) && target.matches(a.name.as_deref(), a.address))
        .collect()
}

fn choose<'a, Id: Eq + Hash>(
    target: &Target,
    heard: &HashSet<Id>,
    advertisers: &'a [Advertiser<Id>],
) -> Result<Option<&'a Advertiser<Id>>, String> {
    if target.is_hidden_address() {
        return Err(HIDDEN_ADDRESS_TARGET.into());
    }
    match matching(target, heard, advertisers).as_slice() {
        [] => Ok(None),
        [one] => Ok(Some(one)),
        many => {
            let addresses: Vec<String> = many
                .iter()
                .map(|a| shown_address(a.address).unwrap_or_else(|| ADDRESS_HIDDEN.into()))
                .collect();
            Err(format!(
                "{} meters {} in range ({}); target one by address where the platform shows it, \
                 or switch the other meter's Bluetooth off",
                many.len(),
                target.described(),
                addresses.join(", ")
            ))
        }
    }
}

type Delivery = Result<Vec<Sample>, ProbeError>;
type StopRx = watch::Receiver<bool>;
type Tap = Option<Sender<Chunk>>;
type Link = (Receiver<Delivery>, Worker);
type SpawnLink = fn(Target, StopRx, Tap) -> io::Result<Link>;
type Events = Pin<Box<dyn Stream<Item = CentralEvent> + Send>>;

enum Halt {
    Stopped,
    Failed(String),
}

impl From<Halt> for io::Error {
    fn from(halt: Halt) -> Self {
        match halt {
            Halt::Stopped => io::Error::new(io::ErrorKind::Interrupted, "stopped"),
            Halt::Failed(why) => io::Error::other(why),
        }
    }
}

async fn stopped(stop: &StopRx) {
    let mut stop = stop.clone();
    let _ = stop.wait_for(|stopped| *stopped).await;
}

async fn until_stopped<F: Future>(fut: F, stop: &StopRx) -> Option<F::Output> {
    tokio::select! {
        biased;
        () = stopped(stop) => None,
        out = fut => Some(out),
    }
}

async fn back_off(stop: &StopRx) -> bool {
    until_stopped(tokio::time::sleep(RECONNECT_BACKOFF), stop)
        .await
        .is_some()
}

async fn step<T, E: fmt::Display>(
    what: &str,
    limit: Duration,
    fut: impl Future<Output = Result<T, E>>,
    stop: &StopRx,
) -> Result<T, Halt> {
    match until_stopped(tokio::time::timeout(limit, fut), stop).await {
        None => Err(Halt::Stopped),
        Some(Err(_)) => Err(Halt::Failed(format!("{what}: timed out after {limit:?}"))),
        Some(Ok(Err(e))) => Err(Halt::Failed(format!("{what}: {e}"))),
        Some(Ok(Ok(value))) => Ok(value),
    }
}

async fn acquire_adapter(stop: &StopRx) -> Result<(Manager, Adapter), Halt> {
    let manager = step("Bluetooth manager", ADAPTER_TIMEOUT, Manager::new(), stop).await?;
    let adapters = step(
        "Bluetooth adapters",
        ADAPTER_TIMEOUT,
        manager.adapters(),
        stop,
    )
    .await?;
    let adapter = adapters
        .into_iter()
        .next()
        .ok_or_else(|| Halt::Failed("no Bluetooth adapter".into()))?;
    Ok((manager, adapter))
}

fn advertised(event: &CentralEvent) -> Option<&PeripheralId> {
    match event {
        CentralEvent::DeviceDiscovered(id)
        | CentralEvent::DeviceUpdated(id)
        | CentralEvent::ManufacturerDataAdvertisement { id, .. }
        | CentralEvent::ServiceDataAdvertisement { id, .. }
        | CentralEvent::ServicesAdvertisement { id, .. }
        | CentralEvent::RssiUpdate { id, .. } => Some(id),
        _ => None,
    }
}

fn discard_ready<S: Stream + Unpin>(events: &mut S) {
    while let Some(Some(_)) = events.next().now_or_never() {}
}

async fn while_scanning<T>(
    adapter: &Adapter,
    stop: &StopRx,
    listen: impl AsyncFnOnce(&mut Events) -> Result<T, Halt>,
) -> Result<T, Halt> {
    let mut events = step(
        "adapter events",
        SCAN_CONTROL_TIMEOUT,
        adapter.events(),
        stop,
    )
    .await?;
    discard_ready(&mut events);
    let outcome = async {
        step(
            "start scan",
            SCAN_CONTROL_TIMEOUT,
            adapter.start_scan(ScanFilter::default()),
            stop,
        )
        .await?;
        listen(&mut events).await
    }
    .await;
    let _ = tokio::time::timeout(SCAN_CONTROL_TIMEOUT, adapter.stop_scan()).await;
    outcome
}

async fn describe(
    adapter: &Adapter,
    heard: &HashSet<PeripheralId>,
) -> (
    Vec<Advertiser<PeripheralId>>,
    HashMap<PeripheralId, Peripheral>,
) {
    let mut advertisers = Vec::with_capacity(heard.len());
    let mut peripherals = HashMap::with_capacity(heard.len());
    for id in heard {
        if let Ok(peripheral) = adapter.peripheral(id).await
            && let Ok(Some(props)) = peripheral.properties().await
        {
            advertisers.push(Advertiser {
                id: id.clone(),
                name: props.local_name,
                address: props.address,
                rssi: props.rssi,
            });
            peripherals.insert(id.clone(), peripheral);
        }
    }
    (advertisers, peripherals)
}

async fn hunt(
    adapter: &Adapter,
    events: &mut Events,
    target: &Target,
) -> Result<Peripheral, String> {
    let mut heard = HashSet::new();
    let mut poll = tokio::time::interval(FIND_POLL);
    loop {
        tokio::select! {
            event = events.next() => match event {
                Some(event) => heard.extend(advertised(&event).cloned()),
                None => return Err("the adapter's event stream ended".into()),
            },
            _ = poll.tick() => {
                let (advertisers, mut peripherals) = describe(adapter, &heard).await;
                if let Some(chosen) = choose(target, &heard, &advertisers)?
                    && let Some(meter) = peripherals.remove(&chosen.id)
                {
                    return Ok(meter);
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Known {
    names: Vec<String>,
    address: BDAddr,
    connected: Option<bool>,
    described: bool,
}

fn identifying_names(
    advertisement_name: Option<String>,
    local_name: Option<String>,
    address: BDAddr,
) -> Vec<String> {
    let placeholder = address.to_string().replace(':', "-");
    advertisement_name
        .into_iter()
        .chain(local_name)
        .filter(|n| !n.eq_ignore_ascii_case(&placeholder))
        .collect()
}

fn is_target(target: &Target, known: &Known) -> bool {
    target.matches(None, known.address)
        || known
            .names
            .iter()
            .any(|n| target.matches(Some(n), known.address))
}

fn unidentifiable(target: &Target, known: &Known) -> bool {
    match target {
        Target::Name(_) => known.names.is_empty(),
        Target::Address(_) => shown_address(known.address).is_none(),
    }
}

fn orphan_to_release(target: &Target, known: &[Known]) -> Option<usize> {
    let blind = known
        .iter()
        .any(|k| !k.described || (k.connected != Some(false) && unidentifiable(target, k)));
    if blind {
        return None;
    }
    let matches: Vec<(usize, &Known)> = known
        .iter()
        .enumerate()
        .filter(|(_, k)| is_target(target, k))
        .collect();
    let mut connected = matches.iter().filter(|(_, k)| k.connected == Some(true));
    let (index, _) = connected.next()?;
    let others_settled = matches.iter().all(|(_, k)| k.connected.is_some());
    (connected.next().is_none() && others_settled).then_some(*index)
}

async fn known_peripherals(adapter: &Adapter) -> (Vec<Known>, Vec<Peripheral>) {
    let Ok(Ok(peripherals)) = tokio::time::timeout(DESCRIBE_TIMEOUT, adapter.peripherals()).await
    else {
        return (Vec::new(), Vec::new());
    };
    let (mut known, mut handles) = (
        Vec::with_capacity(peripherals.len()),
        Vec::with_capacity(peripherals.len()),
    );
    for peripheral in peripherals {
        let described = tokio::time::timeout(DESCRIBE_TIMEOUT, peripheral.properties()).await;
        let connected = tokio::time::timeout(CONNECTION_CHECK_TIMEOUT, peripheral.is_connected())
            .await
            .ok()
            .and_then(Result::ok);
        known.push(match described {
            Ok(Ok(Some(props))) => Known {
                names: identifying_names(props.advertisement_name, props.local_name, props.address),
                address: props.address,
                connected,
                described: true,
            },
            _ => Known {
                names: Vec::new(),
                address: peripheral.address(),
                connected,
                described: false,
            },
        });
        handles.push(peripheral);
    }
    (known, handles)
}

async fn release_orphans(adapter: &Adapter, target: &Target) {
    let Ok((known, handles)) =
        tokio::time::timeout(RELEASE_WALK_TIMEOUT, known_peripherals(adapter)).await
    else {
        return;
    };
    if let Some(orphan) = orphan_to_release(target, &known).and_then(|index| handles.get(index)) {
        let _ = tokio::time::timeout(DISCONNECT_TIMEOUT, orphan.disconnect()).await;
    }
}

async fn find(
    adapter: &Adapter,
    target: &Target,
    stop: &StopRx,
) -> Result<Option<Peripheral>, Halt> {
    while_scanning(
        adapter,
        stop,
        async |events: &mut Events| match until_stopped(
            tokio::time::timeout(FIND_TIMEOUT, hunt(adapter, events, target)),
            stop,
        )
        .await
        {
            None => Err(Halt::Stopped),
            Some(Err(_)) => Ok(None),
            Some(Ok(found)) => found.map(Some).map_err(Halt::Failed),
        },
    )
    .await
}

fn data_values(
    notifications: impl Stream<Item = ValueNotification> + Unpin,
) -> impl Stream<Item = Vec<u8>> + Unpin {
    notifications.filter_map(|n| ready((n.uuid == DATA_CHARACTERISTIC).then_some(n.value)))
}

async fn pump(
    mut stream: impl Stream<Item = Vec<u8>> + Unpin,
    tx: &Sender<Delivery>,
    tap: &Tap,
    silence: Duration,
    connect_burst: Duration,
    stop: &StopRx,
) {
    let mut replay = Replay::default();
    let mut last_frame = tokio::time::Instant::now();
    let mut first_chunk = None;
    while let Some(next) = until_stopped(
        tokio::time::timeout(silence.saturating_sub(last_frame.elapsed()), stream.next()),
        stop,
    )
    .await
    {
        match next {
            Ok(Some(bytes)) => {
                let chunk = (Stamp::now(), bytes);
                let frames = replay.push(&chunk);
                if let Some(tap) = tap {
                    let _ = tap.send(chunk);
                }
                let first_chunk = *first_chunk.get_or_insert_with(tokio::time::Instant::now);
                if !frames.is_empty() {
                    last_frame = tokio::time::Instant::now();
                }
                if first_chunk.elapsed() < connect_burst {
                    continue;
                }
                for frame in frames {
                    if tx.send(Ok(frame.samples)).is_err() {
                        return;
                    }
                }
            }
            Ok(None) => {
                let _ = tx.send(Err(ProbeError::Disconnected(
                    "the notification stream ended".into(),
                )));
                return;
            }
            Err(_) => {
                let _ = tx.send(Err(ProbeError::Disconnected(format!(
                    "no frames for {silence:?}"
                ))));
                return;
            }
        }
    }
}

async fn subscribed(
    meter: &Peripheral,
) -> Result<impl Stream<Item = ValueNotification> + Unpin + use<>, String> {
    meter
        .discover_services()
        .await
        .map_err(|e| format!("services: {e}"))?;
    let data = meter
        .characteristics()
        .into_iter()
        .find(|c| c.uuid == DATA_CHARACTERISTIC)
        .ok_or("the meter has no 121GW data characteristic")?;
    let notifications = meter
        .notifications()
        .await
        .map_err(|e| format!("notifications: {e}"))?;
    meter
        .subscribe(&data)
        .await
        .map_err(|e| format!("subscribe: {e}"))?;
    Ok(notifications)
}

async fn connected(
    meter: &Peripheral,
    tx: &Sender<Delivery>,
    tap: &Tap,
    stop: &StopRx,
) -> Result<(), Halt> {
    let notifications = step("subscribe", SUBSCRIBE_WITHIN, subscribed(meter), stop).await?;
    pump(
        data_values(notifications),
        tx,
        tap,
        SILENCE,
        CONNECT_BURST,
        stop,
    )
    .await;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ended {
    BeforeConnecting,
    AfterConnecting { still_connected: Option<bool> },
}

fn must_disconnect(ended: Ended) -> bool {
    match ended {
        Ended::BeforeConnecting => true,
        Ended::AfterConnecting { still_connected } => still_connected != Some(false),
    }
}

async fn still_connected(meter: &Peripheral) -> Option<bool> {
    tokio::time::timeout(CONNECTION_CHECK_TIMEOUT, meter.is_connected())
        .await
        .ok()
        .and_then(Result::ok)
}

async fn session(
    adapter: &Adapter,
    target: &Target,
    tx: &Sender<Delivery>,
    tap: &Tap,
    stop: &StopRx,
) -> Result<(), Halt> {
    until_stopped(release_orphans(adapter, target), stop)
        .await
        .ok_or(Halt::Stopped)?;
    let Some(meter) = find(adapter, target, stop).await? else {
        let _ = tx.send(Err(ProbeError::NotAdvertising(NOT_ADVERTISING.into())));
        return Ok(());
    };
    let (ended, outcome) = match step("connect", CONNECT_TIMEOUT, meter.connect(), stop).await {
        Err(halt) => (Ended::BeforeConnecting, Err(halt)),
        Ok(()) => {
            let outcome = connected(&meter, tx, tap, stop).await;
            (
                Ended::AfterConnecting {
                    still_connected: still_connected(&meter).await,
                },
                outcome,
            )
        }
    };
    if must_disconnect(ended) {
        let _ = tokio::time::timeout(DISCONNECT_TIMEOUT, meter.disconnect()).await;
    }
    outcome
}

fn carry_on(outcome: Result<(), Halt>, tx: &Sender<Delivery>) -> bool {
    match outcome {
        Ok(()) => true,
        Err(Halt::Stopped) => false,
        Err(Halt::Failed(why)) => tx.send(Err(ProbeError::Disconnected(why))).is_ok(),
    }
}

async fn link(target: &Target, tx: &Sender<Delivery>, tap: &Tap, stop: &StopRx) {
    let (_manager, adapter) = loop {
        match acquire_adapter(stop).await {
            Ok(found) => break found,
            Err(halt) => {
                if !carry_on(Err(halt), tx) || !back_off(stop).await {
                    return;
                }
            }
        }
    };
    while carry_on(session(&adapter, target, tx, tap, stop).await, tx) && back_off(stop).await {}
}

fn spawn_link(target: Target, stop: StopRx, tap: Tap) -> io::Result<Link> {
    let (tx, readings) = mpsc::channel();
    let worker = Worker::spawn("121gw", RELEASE_WITHIN, move || {
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(e) => {
                let _ = tx.send(Err(ProbeError::Disconnected(format!("tokio runtime: {e}"))));
                return;
            }
        };
        runtime.block_on(link(&target, &tx, &tap, &stop));
    })?;
    Ok((readings, worker))
}

pub struct Gw121Probe {
    target: Target,
    readings: Receiver<Delivery>,
    stop: watch::Sender<bool>,
    spawn: SpawnLink,
    tap: Tap,
    link: Worker,
}

impl Gw121Probe {
    pub fn start(target: Target) -> io::Result<Self> {
        Self::spawned(target, None)
    }

    pub fn start_tapped(target: Target, tap: Sender<Chunk>) -> io::Result<Self> {
        Self::spawned(target, Some(tap))
    }

    fn spawned(target: Target, tap: Tap) -> io::Result<Self> {
        let (stop, stopping) = watch::channel(false);
        let (readings, link) = spawn_link(target.clone(), stopping, tap.clone())?;
        Ok(Self {
            target,
            readings,
            stop,
            spawn: spawn_link,
            tap,
            link,
        })
    }

    fn relink(&mut self) -> ProbeError {
        if *self.stop.borrow() {
            return ProbeError::Disconnected("the link thread stopped".into());
        }
        match (self.spawn)(self.target.clone(), self.stop.subscribe(), self.tap.clone()) {
            Ok((readings, link)) => {
                self.readings = readings;
                self.link = link;
                ProbeError::Disconnected("the link thread stopped; restarting".into())
            }
            Err(e) => ProbeError::Disconnected(format!(
                "the link thread stopped and could not restart: {e}"
            )),
        }
    }
}

impl Drop for Gw121Probe {
    fn drop(&mut self) {
        self.stop.send_replace(true);
    }
}

impl Probe for Gw121Probe {
    fn name(&self) -> String {
        ProbeUri::Gw121 {
            target: self.target.clone(),
            selected: vec![],
        }
        .to_string()
    }

    fn signals(&self) -> Vec<SignalKey> {
        decode::signals()
    }

    fn display_name(&self, key: &SignalKey) -> Option<&'static str> {
        decode::display_name(key)
    }

    fn next(&mut self, deadline: Instant) -> Result<Vec<Sample>, ProbeError> {
        match self
            .readings
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        {
            Ok(first) => self.readings.try_iter().last().unwrap_or(first),
            Err(RecvTimeoutError::Timeout) => Err(ProbeError::Timeout),
            Err(RecvTimeoutError::Disconnected) => {
                let error = self.relink();
                thread::sleep(deadline.saturating_duration_since(Instant::now()));
                Err(error)
            }
        }
    }

    fn max_interval(&self) -> Duration {
        MAX_INTERVAL
    }

    fn release_within(&self) -> Duration {
        self.link.release_within()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Seen {
    pub name: String,
    pub address: Option<String>,
    pub rssi: Option<i16>,
}

fn seen_meters<Id: Eq + Hash>(heard: &HashSet<Id>, advertisers: &[Advertiser<Id>]) -> Vec<Seen> {
    matching(&Target::Name(super::METER_NAME.into()), heard, advertisers)
        .into_iter()
        .map(|a| Seen {
            name: super::METER_NAME.into(),
            address: shown_address(a.address),
            rssi: a.rssi,
        })
        .collect()
}

async fn overhear(events: &mut Events, duration: Duration) -> HashSet<PeripheralId> {
    let mut heard = HashSet::new();
    let listening = async {
        while let Some(event) = events.next().await {
            heard.extend(advertised(&event).cloned());
        }
    };
    let _ = tokio::time::timeout(duration, listening).await;
    heard
}

/// Runs on the caller's tokio runtime, which needs its time driver. On macOS, a
/// process without Bluetooth permission finds nothing rather than failing.
pub async fn scan(duration: Duration) -> io::Result<Vec<Seen>> {
    let (_running, stop) = watch::channel(false);
    let (_manager, adapter) = acquire_adapter(&stop).await?;
    let heard = while_scanning(&adapter, &stop, async |events: &mut Events| {
        Ok(overhear(events, duration).await)
    })
    .await?;
    let (advertisers, _) = tokio::time::timeout(DESCRIBE_TIMEOUT, describe(&adapter, &heard))
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!("describing what was heard: timed out after {DESCRIBE_TIMEOUT:?}"),
            )
        })?;
    Ok(seen_meters(&heard, &advertisers))
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    use super::*;
    use crate::{
        gw121::{
            METER_NAME,
            frame::{FRAME_LEN, START},
        },
        value::Value,
    };

    const MAC_OCTETS: usize = 6;
    const SERVICE: Uuid = Uuid::from_u128(0x0bd51666_e7cb_469b_8e4d_2742f1ba77cc);

    const WATCHDOG: Duration = Duration::from_secs(1);
    const TEST_SILENCE: Duration = Duration::from_millis(50);
    const STOP_DELAY: Duration = Duration::from_millis(10);
    const TRICKLE_INTERVAL: Duration = Duration::from_millis(1);
    const FOREIGN_CHARACTERISTIC: Uuid = Uuid::nil();
    const RESTART_DEADLINE: Duration = Duration::from_millis(100);
    const ROOM_TENTHS: i64 = 210;
    const HOT_TENTHS: i64 = 2_500;
    const TENTHS: i8 = -1;
    const HEARD_RSSI: i16 = -60;
    const METER_A: [u8; MAC_OCTETS] = [0x88, 0x6B, 0x0F, 0x81, 0xA9, 0x53];
    const METER_B: [u8; MAC_OCTETS] = [0x88, 0x6B, 0x0F, 0x81, 0xA9, 0x54];
    const HIDDEN: [u8; MAC_OCTETS] = [0; MAC_OCTETS];
    const OTHER_NAME: &str = "Thermostat";

    static RESPAWNS: AtomicUsize = AtomicUsize::new(0);
    static RESPAWNED_STOP: Mutex<Option<StopRx>> = Mutex::new(None);

    fn finished_link() -> Link {
        (
            mpsc::channel().1,
            Worker::spawn("121gw", RELEASE_WITHIN, || {}).unwrap(),
        )
    }

    fn dead_link(_: Target, _: StopRx, _: Tap) -> io::Result<Link> {
        RESPAWNS.fetch_add(1, Ordering::Relaxed);
        Ok(finished_link())
    }

    fn unexpected_link(_: Target, _: StopRx, _: Tap) -> io::Result<Link> {
        panic!("the link was respawned although its channel was still open")
    }

    fn stop_capturing_link(_: Target, stop: StopRx, _: Tap) -> io::Result<Link> {
        *RESPAWNED_STOP.lock().unwrap() = Some(stop);
        Ok(finished_link())
    }

    fn probe_on(readings: Receiver<Delivery>, spawn: SpawnLink) -> Gw121Probe {
        Gw121Probe {
            target: Target::Name(METER_NAME.into()),
            readings,
            stop: watch::channel(false).0,
            spawn,
            tap: None,
            link: finished_link().1,
        }
    }

    fn stop_after(delay: Duration) -> StopRx {
        let (stop, stopping) = watch::channel(false);
        thread::spawn(move || {
            thread::sleep(delay);
            stop.send_replace(true);
        });
        stopping
    }

    fn running() -> (watch::Sender<bool>, StopRx) {
        watch::channel(false)
    }

    fn advertiser(id: u32, name: &str, address: [u8; MAC_OCTETS]) -> Advertiser<u32> {
        Advertiser {
            id,
            name: Some(name.into()),
            address: BDAddr::from(address),
            rssi: Some(HEARD_RSSI),
        }
    }

    fn heard(ids: &[u32]) -> HashSet<u32> {
        ids.iter().copied().collect()
    }

    fn batch(tenths: i64) -> Vec<Sample> {
        vec![Sample::new(
            decode::THERMOCOUPLE,
            Value::new(tenths, TENTHS),
            Stamp::now(),
        )]
    }

    fn thermocouple_tenths(samples: &[Sample]) -> Option<i64> {
        samples
            .iter()
            .find(|s| s.key == decode::THERMOCOUPLE)
            .map(|s| s.value.mantissa)
    }

    fn trickle<T: Clone>(item: T) -> impl Stream<Item = T> + Unpin {
        Box::pin(futures_util::stream::unfold(item, |item| async move {
            tokio::time::sleep(TRICKLE_INTERVAL).await;
            let next = item.clone();
            Some((next, item))
        }))
    }

    fn valid_frame() -> Vec<u8> {
        let mut bytes = [0u8; FRAME_LEN];
        bytes[0] = START;
        bytes[FRAME_LEN - 1] = START;
        bytes.to_vec()
    }

    fn watched<F: Future>(
        runtime: &tokio::runtime::Runtime,
        future: F,
    ) -> Result<F::Output, tokio::time::error::Elapsed> {
        runtime.block_on(async { tokio::time::timeout(WATCHDOG, future).await })
    }

    #[test]
    fn a_connection_left_up_by_a_dead_process_is_released_only_when_it_is_unambiguously_the_target()
    {
        let meter: BDAddr = "88:6B:0F:81:A9:53".parse().unwrap();
        let other: BDAddr = "88:6B:0F:81:A9:54".parse().unwrap();
        let known = |name: &str, address, connected| Known {
            names: vec![name.into()],
            address,
            connected,
            described: true,
        };
        let by_address = Target::Address("88:6B:0F:81:A9:53".into());
        let by_name = Target::Name(METER_NAME.into());
        let orphan = known(METER_NAME, meter, Some(true));
        assert_eq!(
            orphan_to_release(&by_address, std::slice::from_ref(&orphan)),
            Some(0),
            "connected and ours: release it"
        );
        assert_eq!(
            orphan_to_release(
                &by_name,
                &[known(OTHER_NAME, other, Some(true)), orphan.clone()]
            ),
            Some(1)
        );
        assert_eq!(
            orphan_to_release(&by_address, &[known(METER_NAME, other, Some(true))]),
            None,
            "another address"
        );
        assert_eq!(
            orphan_to_release(&by_name, &[known(OTHER_NAME, meter, Some(true))]),
            None,
            "another name"
        );
        assert_eq!(
            orphan_to_release(&by_address, &[known(METER_NAME, meter, Some(false))]),
            None,
            "not connected"
        );
        assert_eq!(
            orphan_to_release(&by_address, &[known(METER_NAME, meter, None)]),
            None,
            "unknown: leave it"
        );
        let homonyms = [orphan.clone(), known(METER_NAME, other, Some(true))];
        assert_eq!(
            orphan_to_release(&by_name, &homonyms),
            None,
            "two connected 121GWs: never drop a live one"
        );
        assert_eq!(
            orphan_to_release(&by_address, &homonyms),
            Some(0),
            "an address target stays exact"
        );
        let unsure = [orphan.clone(), known(METER_NAME, other, None)];
        assert_eq!(
            orphan_to_release(&by_name, &unsure),
            None,
            "a homonym of unknown state might be live"
        );
        let skipped = Known {
            names: vec![],
            address: other,
            connected: None,
            described: false,
        };
        let incomplete = [orphan.clone(), skipped];
        assert_eq!(
            orphan_to_release(&by_name, &incomplete),
            None,
            "an undescribed peripheral could be a live 121GW"
        );
        assert_eq!(
            orphan_to_release(&by_address, &incomplete),
            None,
            "an incomplete walk releases nothing"
        );
        let nameless = |connected| Known {
            names: vec![],
            address: other,
            connected,
            described: true,
        };
        let hidden = |connected| Known {
            names: vec![METER_NAME.into()],
            address: BDAddr::default(),
            connected,
            described: true,
        };
        let with = |second: Known| [orphan.clone(), second];
        assert_eq!(
            orphan_to_release(&by_name, &with(nameless(Some(true)))),
            None,
            "a nameless link might be a 121GW"
        );
        assert_eq!(orphan_to_release(&by_name, &with(nameless(None))), None);
        assert_eq!(
            orphan_to_release(&by_name, &with(nameless(Some(false)))),
            Some(0),
            "a disconnected beacon is no risk"
        );
        assert_eq!(
            orphan_to_release(&by_address, &with(hidden(Some(true)))),
            None,
            "a hidden address might be ours"
        );
        let renamed = Known {
            names: vec!["Oven probe".into(), METER_NAME.into()],
            address: meter,
            connected: Some(true),
            described: true,
        };
        assert_eq!(
            orphan_to_release(&by_name, &[renamed]),
            Some(0),
            "the advertised name counts when the alias differs"
        );
    }

    #[test]
    fn bluez_s_address_alias_for_an_unnamed_device_does_not_count_as_a_name() {
        let unnamed: BDAddr = "4C:1A:7C:8C:CA:3F".parse().unwrap();
        assert_eq!(
            identifying_names(None, Some("4C-1A-7C-8C-CA-3F".into()), unnamed),
            Vec::<String>::new()
        );
        assert_eq!(
            identifying_names(None, Some("4c-1a-7c-8c-ca-3f".into()), unnamed),
            Vec::<String>::new()
        );
        assert_eq!(
            identifying_names(Some(METER_NAME.into()), Some("Oven probe".into()), unnamed),
            vec![METER_NAME.to_owned(), "Oven probe".to_owned()]
        );
        let meter: BDAddr = "88:6B:0F:81:A9:53".parse().unwrap();
        let orphan = Known {
            names: vec![METER_NAME.into()],
            address: meter,
            connected: Some(true),
            described: true,
        };
        let aliased = Known {
            names: identifying_names(None, Some("4C-1A-7C-8C-CA-3F".into()), unnamed),
            address: unnamed,
            connected: Some(true),
            described: true,
        };
        assert_eq!(
            orphan_to_release(&Target::Name(METER_NAME.into()), &[orphan, aliased]),
            None,
            "a connected device BlueZ can only name by its address might be a 121GW"
        );
    }

    #[test]
    fn the_probe_is_named_by_its_canonical_uri_which_parses_back() {
        let name = probe_on(mpsc::channel().1, unexpected_link).name();
        assert_eq!(name, "121gw:121GW");
        assert_eq!(name.parse::<ProbeUri>().unwrap().to_string(), name);
    }

    #[test]
    fn matching_ignores_address_case() {
        let target = Target::Address("88:6b:0f:81:a9:53".into());
        assert!(target.matches(Some(METER_NAME), BDAddr::from(METER_A)));
        assert!(!target.matches(Some(METER_NAME), BDAddr::from(METER_B)));
    }

    #[test]
    fn silence_is_detected_as_a_dropped_link() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let silent = futures_util::stream::pending::<Vec<u8>>();
        let (_running, stop) = running();
        let outcome = watched(
            &runtime,
            pump(silent, &tx, &None, TEST_SILENCE, Duration::ZERO, &stop),
        );
        assert!(
            outcome.is_ok(),
            "pump did not return before the test watchdog"
        );
        assert!(matches!(
            rx.try_recv(),
            Ok(Err(ProbeError::Disconnected(_)))
        ));
    }

    #[test]
    fn data_values_drops_foreign_uuid_notifications_and_keeps_the_data_characteristic() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let foreign = ValueNotification {
            uuid: FOREIGN_CHARACTERISTIC,
            service_uuid: SERVICE,
            value: vec![0xFF],
        };
        let data = ValueNotification {
            uuid: DATA_CHARACTERISTIC,
            service_uuid: SERVICE,
            value: vec![0x01],
        };
        let values: Vec<Vec<u8>> = runtime
            .block_on(data_values(futures_util::stream::iter(vec![foreign, data])).collect());
        assert_eq!(values, vec![vec![0x01]]);
    }

    #[test]
    fn a_stream_of_only_foreign_uuid_notifications_is_treated_as_silence() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let foreign = ValueNotification {
            uuid: FOREIGN_CHARACTERISTIC,
            service_uuid: SERVICE,
            value: vec![0xFF],
        };
        let stream = data_values(trickle(foreign));
        let (_running, stop) = running();
        let outcome = watched(
            &runtime,
            pump(stream, &tx, &None, TEST_SILENCE, Duration::ZERO, &stop),
        );
        assert!(
            outcome.is_ok(),
            "pump did not return before the test watchdog"
        );
        assert!(matches!(
            rx.try_recv(),
            Ok(Err(ProbeError::Disconnected(_)))
        ));
    }

    #[test]
    fn chunks_that_never_assemble_into_a_frame_are_treated_as_silence() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let junk = trickle(vec![0x00u8]);
        let (_running, stop) = running();
        let outcome = watched(
            &runtime,
            pump(junk, &tx, &None, TEST_SILENCE, Duration::ZERO, &stop),
        );
        assert!(
            outcome.is_ok(),
            "pump did not return before the test watchdog"
        );
        assert!(matches!(
            rx.try_recv(),
            Ok(Err(ProbeError::Disconnected(_)))
        ));
    }

    const TEST_BURST: Duration = Duration::from_millis(200);
    const SECOND_STALE_AFTER: Duration = Duration::from_millis(150);
    const LIVE_AFTER_SECOND: Duration = Duration::from_millis(100);
    const STALE_TENTHS: u16 = 246;
    const LIVE_TENTHS: u16 = 226;
    const TEMPLATE: [u8; FRAME_LEN] = [
        0xF2, 0x17, 0x80, 0x00, 0x00, 0x05, 0x20, 0x00, 0xD2, 0x64, 0x01, 0x00, 0xD8, 0x15, 0x00,
        0x02, 0x40, 0x00, 0x78,
    ];
    const MAIN_VALUE: usize = 7;

    fn temperature_frame(tenths: u16) -> Vec<u8> {
        let mut bytes = TEMPLATE;
        bytes[MAIN_VALUE..MAIN_VALUE + 2].copy_from_slice(&tenths.to_be_bytes());
        bytes[FRAME_LEN - 1] = bytes[..FRAME_LEN - 1].iter().fold(0, |x, b| x ^ b);
        bytes.to_vec()
    }

    #[test]
    fn the_stale_burst_the_meter_sends_on_connecting_is_dropped_and_live_frames_follow() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let first = futures_util::stream::once(async { temperature_frame(STALE_TENTHS) });
        let second = futures_util::stream::once(async {
            tokio::time::sleep(SECOND_STALE_AFTER).await;
            temperature_frame(STALE_TENTHS)
        });
        let live = futures_util::stream::once(async {
            tokio::time::sleep(LIVE_AFTER_SECOND).await;
            temperature_frame(LIVE_TENTHS)
        });
        let stream = Box::pin(first.chain(second).chain(live));
        let (_running, stop) = running();
        let outcome = watched(
            &runtime,
            pump(stream, &tx, &None, TEST_SILENCE * 4, TEST_BURST, &stop),
        );
        assert!(
            outcome.is_ok(),
            "pump did not return before the test watchdog"
        );
        let delivered: Vec<Delivery> = rx.try_iter().collect();
        let values: Vec<i64> = delivered
            .iter()
            .filter_map(|d| d.as_ref().ok().and_then(|s| thermocouple_tenths(s)))
            .collect();
        assert_eq!(
            values,
            [i64::from(LIVE_TENTHS)],
            "the meter replays its last session's value on connect (24.6 °C against a live 22.6 °C, 2026-09-27); \
             only frames after the burst may be read, and the window runs from the first frame, not the latest"
        );
    }

    #[test]
    fn every_chunk_is_tapped_raw_including_the_connect_burst() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let (tx, _rx) = std::sync::mpsc::channel();
        let (tap, tapped) = std::sync::mpsc::channel();
        let first = futures_util::stream::once(async { temperature_frame(STALE_TENTHS) });
        let stream = Box::pin(first);
        let (_running, stop) = running();
        let outcome = watched(
            &runtime,
            pump(stream, &tx, &Some(tap), TEST_SILENCE, TEST_BURST, &stop),
        );
        assert!(
            outcome.is_ok(),
            "pump did not return before the test watchdog"
        );
        let chunks: Vec<Vec<u8>> = tapped.try_iter().map(|(_, chunk)| chunk).collect();
        assert_eq!(
            chunks,
            [temperature_frame(STALE_TENTHS)],
            "the burst is dropped from samples, never from the capture"
        );
    }

    #[test]
    fn the_stop_signal_ends_pump_promptly_even_on_a_live_stream() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let (tx, _rx) = std::sync::mpsc::channel();
        let stop = stop_after(STOP_DELAY);
        let live = trickle(valid_frame());
        let started = Instant::now();
        let outcome = watched(
            &runtime,
            pump(live, &tx, &None, TEST_SILENCE, Duration::ZERO, &stop),
        );
        assert!(
            outcome.is_ok(),
            "pump did not return before the test watchdog"
        );
        assert!(
            started.elapsed() < TEST_SILENCE,
            "pump ran a full silence window even though stop was set"
        );
    }

    #[test]
    fn a_dead_link_thread_is_restarted_and_the_caller_waits_out_its_deadline() {
        let mut probe = probe_on(mpsc::channel().1, dead_link);
        let started = Instant::now();
        let result = probe.next(started + RESTART_DEADLINE);
        assert!(
            started.elapsed() >= RESTART_DEADLINE,
            "next returned after {:?}, so callers spin",
            started.elapsed()
        );
        assert!(
            matches!(result, Err(ProbeError::Disconnected(_))),
            "{result:?}"
        );
        assert_eq!(
            RESPAWNS.load(Ordering::Relaxed),
            1,
            "the link thread was not restarted"
        );
    }

    #[test]
    fn the_newest_queued_reading_is_returned_not_the_oldest() {
        let (tx, rx) = mpsc::channel();
        tx.send(Ok(batch(ROOM_TENTHS))).unwrap();
        tx.send(Ok(batch(HOT_TENTHS))).unwrap();
        let mut probe = probe_on(rx, unexpected_link);
        assert_eq!(
            probe.next(Instant::now()).map(|s| thermocouple_tenths(&s)),
            Ok(Some(HOT_TENTHS))
        );
    }

    #[test]
    fn a_queued_error_newer_than_the_last_reading_is_returned() {
        let (tx, rx) = mpsc::channel();
        tx.send(Ok(batch(ROOM_TENTHS))).unwrap();
        tx.send(Err(ProbeError::Disconnected("no frames for 5 s".into())))
            .unwrap();
        let mut probe = probe_on(rx, unexpected_link);
        assert!(matches!(
            probe.next(Instant::now()),
            Err(ProbeError::Disconnected(_))
        ));
    }

    #[test]
    fn a_stop_signal_abandons_a_pending_ble_await_promptly() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let stop = stop_after(STOP_DELAY);
        let started = Instant::now();
        let outcome = watched(
            &runtime,
            until_stopped(futures_util::future::pending::<()>(), &stop),
        );
        assert_eq!(
            outcome,
            Ok(None),
            "a pending await outlived the stop signal"
        );
        assert!(started.elapsed() < WATCHDOG);
    }

    #[test]
    fn a_future_that_finishes_before_stop_keeps_its_output() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let (_running, stop) = running();
        assert_eq!(
            runtime.block_on(until_stopped(ready(ROOM_TENTHS), &stop)),
            Some(ROOM_TENTHS)
        );
    }

    #[test]
    fn the_reconnect_backoff_wakes_on_stop() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let stop = stop_after(STOP_DELAY);
        let started = Instant::now();
        let carried_on = runtime.block_on(back_off(&stop));
        assert!(
            !carried_on,
            "back_off reported a completed wait although stop was signalled"
        );
        assert!(
            started.elapsed() < RECONNECT_BACKOFF,
            "back_off slept {:?} through a stop",
            started.elapsed()
        );
    }

    #[test]
    fn a_dropped_probe_counts_as_stopped() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let (stop, stopping) = running();
        drop(stop);
        let outcome = watched(
            &runtime,
            until_stopped(futures_util::future::pending::<()>(), &stopping),
        );
        assert_eq!(outcome, Ok(None));
    }

    #[test]
    fn a_step_that_overruns_its_deadline_fails_naming_the_step() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let (_running, stop) = running();
        let never = futures_util::future::pending::<Result<(), String>>();
        let outcome = watched(&runtime, step("subscribe", TEST_SILENCE, never, &stop)).unwrap();
        assert!(
            matches!(&outcome, Err(Halt::Failed(why)) if why.starts_with("subscribe: timed out"))
        );
    }

    #[test]
    fn a_restarted_link_hears_the_same_stop_signal() {
        let probe = &mut probe_on(mpsc::channel().1, stop_capturing_link);
        let _ = probe.next(Instant::now());
        let respawned = RESPAWNED_STOP
            .lock()
            .unwrap()
            .take()
            .expect("the link was not respawned");
        assert!(!*respawned.borrow());
        drop(std::mem::replace(
            probe,
            probe_on(mpsc::channel().1, unexpected_link),
        ));
        assert!(
            *respawned.borrow(),
            "dropping the probe did not stop the respawned link"
        );
    }

    #[test]
    fn dropping_the_probe_waits_for_its_link_to_let_the_meter_go() {
        let (stop, stopping) = running();
        let released = Arc::new(AtomicBool::new(false));
        let releasing = Arc::clone(&released);
        let mut probe = probe_on(mpsc::channel().1, unexpected_link);
        probe.stop = stop;
        probe.link = Worker::spawn("121gw", RELEASE_WITHIN, move || {
            while !*stopping.borrow() {
                thread::sleep(STOP_DELAY);
            }
            thread::sleep(STOP_DELAY);
            releasing.store(true, Ordering::Relaxed);
        })
        .unwrap();
        drop(probe);
        assert!(released.load(Ordering::Relaxed));
    }

    #[test]
    fn a_cached_peripheral_not_heard_in_this_scan_is_not_a_match() {
        let target = Target::Name(METER_NAME.into());
        let cached = [advertiser(1, METER_NAME, METER_A)];
        assert_eq!(choose(&target, &heard(&[]), &cached), Ok(None));
        assert_eq!(choose(&target, &heard(&[1]), &cached), Ok(Some(&cached[0])));
    }

    #[test]
    fn an_all_zero_address_target_is_refused_rather_than_matching_every_hidden_address() {
        let target: Target = "00:00:00:00:00:00".parse().unwrap();
        let hidden = [
            advertiser(1, METER_NAME, HIDDEN),
            advertiser(2, OTHER_NAME, HIDDEN),
        ];
        let chosen = choose(&target, &heard(&[1, 2]), &hidden);
        assert!(
            chosen.is_err(),
            "an all-zero address target chose {chosen:?}"
        );
    }

    #[test]
    fn an_all_zero_address_never_matches_an_address_target() {
        let target = Target::Address(BDAddr::from(HIDDEN).to_string());
        assert!(!target.matches(Some(METER_NAME), BDAddr::from(HIDDEN)));
    }

    #[test]
    fn one_meter_named_by_a_name_target_is_chosen_even_with_its_address_hidden() {
        let target = Target::Name(METER_NAME.into());
        let heard_here = [
            advertiser(1, METER_NAME, HIDDEN),
            advertiser(2, OTHER_NAME, HIDDEN),
        ];
        assert_eq!(
            choose(&target, &heard(&[1, 2]), &heard_here),
            Ok(Some(&heard_here[0]))
        );
    }

    #[test]
    fn two_meters_answering_a_name_target_are_refused_listing_their_addresses() {
        let target = Target::Name(METER_NAME.into());
        let two = [
            advertiser(1, METER_NAME, METER_A),
            advertiser(2, METER_NAME, HIDDEN),
        ];
        let refused = choose(&target, &heard(&[1, 2]), &two).unwrap_err();
        assert!(
            refused.starts_with("2 meters named 121GW in range ("),
            "{refused}"
        );
        assert!(
            refused.contains(&BDAddr::from(METER_A).to_string()),
            "{refused}"
        );
        assert!(refused.contains(ADDRESS_HIDDEN), "{refused}");
        assert!(
            refused.ends_with(
                "; target one by address where the platform shows it, or switch the other meter's Bluetooth off"
            ),
            "{refused}"
        );
    }

    #[test]
    fn a_connect_that_never_succeeded_is_still_released_in_case_it_completes_in_the_background() {
        assert!(must_disconnect(Ended::BeforeConnecting));
    }

    #[test]
    fn a_meter_that_dropped_the_link_itself_is_not_disconnected_again() {
        assert!(!must_disconnect(Ended::AfterConnecting {
            still_connected: Some(false)
        }));
    }

    #[test]
    fn a_meter_still_connected_when_the_session_ends_is_released() {
        assert!(must_disconnect(Ended::AfterConnecting {
            still_connected: Some(true)
        }));
    }

    #[test]
    fn a_connection_check_that_errs_or_times_out_still_releases_the_meter() {
        assert!(must_disconnect(Ended::AfterConnecting {
            still_connected: None
        }));
    }

    #[test]
    fn an_address_target_picks_exactly_its_meter_among_several() {
        let target = Target::Address(BDAddr::from(METER_B).to_string());
        let two = [
            advertiser(1, METER_NAME, METER_A),
            advertiser(2, METER_NAME, METER_B),
        ];
        assert_eq!(choose(&target, &heard(&[1, 2]), &two), Ok(Some(&two[1])));
    }

    #[test]
    fn scan_lists_only_meters_heard_and_hides_all_zero_addresses() {
        let everyone = [
            advertiser(1, METER_NAME, METER_A),
            advertiser(2, METER_NAME, HIDDEN),
            advertiser(3, METER_NAME, METER_B),
            advertiser(4, OTHER_NAME, METER_B),
        ];
        let seen = seen_meters(&heard(&[1, 2, 4]), &everyone);
        let addresses: Vec<Option<String>> = seen.into_iter().map(|s| s.address).collect();
        assert_eq!(
            addresses,
            vec![Some(BDAddr::from(METER_A).to_string()), None]
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn a_meter_seen_in_a_scan_serialises_for_json() {
        let seen = Seen {
            name: METER_NAME.into(),
            address: None,
            rssi: Some(HEARD_RSSI),
        };
        let text = serde_json::to_value(&seen).unwrap();
        assert_eq!(
            text,
            serde_json::json!({ "name": METER_NAME, "address": null, "rssi": HEARD_RSSI })
        );
        assert_eq!(serde_json::from_value::<Seen>(text).unwrap(), seen);
    }
}
