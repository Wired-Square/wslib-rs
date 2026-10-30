use std::{
    collections::BTreeSet,
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError, Sender},
    },
    thread,
    time::{Duration, Instant},
};

use super::{
    bus::{Bus, BusError, CanBus, open_bus},
    frame::{self, Decoder, RawFrame, SLOT_THERMOCOUPLES, device_of, device_text, known_slot},
};
use crate::{
    probe::{Probe, ProbeError},
    sample::{Sample, Stamp},
    signal::SignalKey,
    uri::ProbeUri,
};

pub(crate) const DISCOVERY_WINDOW: Duration = Duration::from_secs(2);
const MAX_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Timing {
    pub(crate) poll: Duration,
    pub(crate) silence: Duration,
}

pub(crate) const TIMING: Timing = Timing {
    poll: Duration::from_millis(100),
    silence: Duration::from_secs(5),
};

type Delivery = Result<Vec<Sample>, ProbeError>;

fn is_thermocouple_broadcast(frame: &RawFrame) -> bool {
    known_slot(frame) == Some(SLOT_THERMOCOUPLES)
}

pub(crate) fn discover(bus: &mut dyn Bus, on: &CanBus, window: Duration) -> io::Result<u32> {
    let started = Instant::now();
    let mut seen = BTreeSet::new();
    let mut lost = None;
    while started.elapsed() < window {
        match bus.read(window.saturating_sub(started.elapsed())) {
            Ok(Some(frame)) => {
                seen.extend(device_of(&frame).filter(|_| is_thermocouple_broadcast(&frame)))
            }
            Ok(None) => {}
            Err(BusError::Lost(why)) => lost = Some(why),
            Err(BusError::Ended(why)) => return Err(io::Error::other(why)),
        }
    }
    let mut devices = seen.into_iter();
    match (devices.next(), devices.next()) {
        (Some(device), None) => Ok(device),
        (None, _) => {
            let mut why = format!(
                "no WiredReflow on {on} within {} s; is it powered and is {on} up?",
                window.as_secs_f64()
            );
            if let Some(reason) = lost {
                why.push_str(&format!(" The adapter was lost while listening: {reason}"));
            }
            Err(io::Error::new(io::ErrorKind::NotFound, why))
        }
        (Some(first), Some(second)) => {
            let ids: Vec<String> = [first, second]
                .into_iter()
                .chain(devices)
                .map(device_text)
                .collect();
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "more than one WiredReflow on {on} ({}); choose one with @<device-id>",
                    ids.join(", ")
                ),
            ))
        }
    }
}

fn link(
    mut bus: Box<dyn Bus>,
    device: u32,
    timing: Timing,
    tx: Sender<Delivery>,
    stop: Arc<AtomicBool>,
) {
    let mut decoder = Decoder::new(device);
    let mut last_frame = Instant::now();
    let mut reported = false;
    let mut lost = false;
    while !stop.load(Ordering::Relaxed) {
        match bus.read(timing.poll) {
            Ok(Some(raw)) => {
                let samples = decoder.samples(&raw, Stamp::now());
                if !samples.is_empty() {
                    last_frame = Instant::now();
                    reported = false;
                    lost = false;
                    if tx.send(Ok(samples)).is_err() {
                        return;
                    }
                }
            }
            Ok(None) => {}
            Err(BusError::Lost(why)) => {
                if !lost {
                    lost = true;
                    if tx.send(Err(ProbeError::Disconnected(why))).is_err() {
                        return;
                    }
                }
            }
            Err(BusError::Ended(why)) => {
                let _ = tx.send(Err(ProbeError::Disconnected(why)));
                return;
            }
        }
        if !reported && last_frame.elapsed() >= timing.silence {
            reported = true;
            let silent = format!(
                "no WiredReflow frames for {} s",
                timing.silence.as_secs_f64()
            );
            if tx.send(Err(ProbeError::Disconnected(silent))).is_err() {
                return;
            }
        }
    }
}

pub struct WiredReflowProbe {
    on: CanBus,
    device: u32,
    readings: Receiver<Delivery>,
    held: Option<ProbeError>,
    stop: Arc<AtomicBool>,
}

pub(crate) type Opener = Box<dyn FnOnce() -> io::Result<Box<dyn Bus>> + Send>;

type Opened = io::Result<(Box<dyn Bus>, u32)>;

impl WiredReflowProbe {
    pub fn start(bus: &CanBus, device: Option<u32>) -> io::Result<Self> {
        let on = bus.clone();
        Self::start_with(
            Box::new(move || open_bus(&on)),
            bus,
            device,
            DISCOVERY_WINDOW,
            TIMING,
        )
    }

    pub(crate) fn start_with(
        opener: Opener,
        bus: &CanBus,
        device: Option<u32>,
        window: Duration,
        timing: Timing,
    ) -> io::Result<Self> {
        let on = bus.clone();
        Self::spawned(bus.clone(), timing, move || {
            let mut opened = opener()?;
            let device = match device {
                Some(device) => device,
                None => discover(opened.as_mut(), &on, window)?,
            };
            Ok((opened, device))
        })
    }

    #[cfg(test)]
    pub(crate) fn with_bus(
        on: &CanBus,
        device: u32,
        bus: Box<dyn Bus>,
        timing: Timing,
    ) -> io::Result<Self> {
        Self::spawned(on.clone(), timing, move || Ok((bus, device)))
    }

    fn spawned(
        on: CanBus,
        timing: Timing,
        open: impl FnOnce() -> Opened + Send + 'static,
    ) -> io::Result<Self> {
        let (outcome_tx, outcome) = mpsc::sync_channel(0);
        let (tx, readings) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        thread::Builder::new()
            .name("wiredreflow".into())
            .spawn(move || match open() {
                Ok((bus, device)) => {
                    if outcome_tx.send(Ok(device)).is_ok() {
                        link(bus, device, timing, tx, stopping);
                    }
                }
                Err(error) => {
                    let _ = outcome_tx.send(Err(error));
                }
            })?;
        let device = outcome.recv().map_err(|_| {
            io::Error::other("the WiredReflow link thread stopped before it opened the bus")
        })??;
        Ok(Self {
            on,
            device,
            readings,
            held: None,
            stop,
        })
    }
}

impl Drop for WiredReflowProbe {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

impl Probe for WiredReflowProbe {
    fn name(&self) -> String {
        ProbeUri::WiredReflow {
            bus: self.on.clone(),
            device: Some(self.device),
            selected: vec![],
        }
        .to_string()
    }

    fn signals(&self) -> Vec<SignalKey> {
        frame::signals()
    }

    fn display_name(&self, key: &SignalKey) -> Option<&'static str> {
        frame::display_name(key)
    }

    fn next(&mut self, deadline: Instant) -> Result<Vec<Sample>, ProbeError> {
        if let Some(error) = self.held.take() {
            return Err(error);
        }
        let mut samples = match self
            .readings
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        {
            Ok(first) => first?,
            Err(RecvTimeoutError::Timeout) => return Err(ProbeError::Timeout),
            Err(RecvTimeoutError::Disconnected) => {
                thread::sleep(deadline.saturating_duration_since(Instant::now()));
                return Err(ProbeError::Disconnected(
                    "the WiredReflow link thread stopped".into(),
                ));
            }
        };
        for delivery in self.readings.try_iter() {
            match delivery {
                Ok(batch) => samples.extend(batch),
                Err(error) => {
                    self.held = Some(error);
                    break;
                }
            }
        }
        let order = frame::signals();
        samples.sort_by_key(|sample| order.iter().position(|key| *key == sample.key));
        Ok(samples)
    }

    fn max_interval(&self) -> Duration {
        MAX_INTERVAL
    }
}

#[cfg(test)]
mod tests;
