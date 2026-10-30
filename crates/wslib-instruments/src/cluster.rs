use std::{
    collections::HashMap,
    io,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use crate::{
    probe::{Probe, ProbeError},
    sample::Sample,
    signal::SignalKey,
};

const POLL_DEADLINE: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Latest {
    pub sample: Option<Sample>,
    pub error: Option<ProbeError>,
    pub max_interval: Duration,
}

impl Latest {
    pub fn age(&self) -> Option<Duration> {
        self.sample
            .map(|sample| Instant::now().saturating_duration_since(sample.at))
    }

    pub fn current(&self) -> Result<&Sample, ProbeError> {
        if let Some(error) = &self.error {
            return Err(error.clone());
        }
        let Some(sample) = &self.sample else {
            return Err(ProbeError::Timeout);
        };
        let age = Instant::now().saturating_duration_since(sample.at);
        if age > self.max_interval {
            return Err(ProbeError::Stale(age));
        }
        Ok(sample)
    }
}

#[derive(Default)]
struct Slot {
    samples: HashMap<SignalKey, Sample>,
    error: Option<ProbeError>,
}

struct Watched {
    name: String,
    max_interval: Duration,
    slot: Arc<Mutex<Slot>>,
}

pub struct Cluster {
    probes: Vec<Watched>,
    stop: Arc<AtomicBool>,
}

impl Cluster {
    pub fn start(probes: Vec<Box<dyn Probe>>) -> io::Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let mut watched = Vec::with_capacity(probes.len());
        for mut probe in probes {
            let (name, max_interval) = (probe.name(), probe.max_interval());
            let slot = Arc::new(Mutex::new(Slot::default()));
            let (mine, stopping) = (Arc::clone(&slot), Arc::clone(&stop));
            let spawned = thread::Builder::new()
                .name(format!("probe {name}"))
                .spawn(move || {
                    while !stopping.load(Ordering::Relaxed) {
                        let polled = Instant::now();
                        let result =
                            probe.next(polled.checked_add(POLL_DEADLINE).unwrap_or(polled));
                        let mut slot = mine.lock().unwrap_or_else(PoisonError::into_inner);
                        match result {
                            Ok(samples) => {
                                slot.samples
                                    .extend(samples.into_iter().map(|sample| (sample.key, sample)));
                                slot.error = None;
                            }
                            Err(ProbeError::Timeout) => {}
                            Err(error) => slot.error = Some(error),
                        }
                    }
                });
            if let Err(e) = spawned {
                stop.store(true, Ordering::Relaxed);
                return Err(e);
            }
            watched.push(Watched {
                name,
                max_interval,
                slot,
            });
        }
        Ok(Self {
            probes: watched,
            stop,
        })
    }

    pub fn names(&self) -> Vec<String> {
        self.probes
            .iter()
            .map(|watched| watched.name.clone())
            .collect()
    }

    pub fn latest(&self, probe: usize, key: &SignalKey) -> Option<Latest> {
        let watched = self.probes.get(probe)?;
        let slot = watched.slot.lock().unwrap_or_else(PoisonError::into_inner);
        Some(Latest {
            sample: slot.samples.get(key).copied(),
            error: slot.error.clone(),
            max_interval: watched.max_interval,
        })
    }
}

impl Drop for Cluster {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}
