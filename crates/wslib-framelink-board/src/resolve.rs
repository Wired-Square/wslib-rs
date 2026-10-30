//! Names resolved against a device's live capabilities and signal list, never
//! a board TOML: a signal by its tuple, an interface by its type and index.
//! A device whose ids were reset, or whose board differs, resolves as soon as
//! it connects.

use std::collections::HashMap;

use wslib_framelink_protocol::capabilities::Capabilities;
use wslib_framelink_protocol::dsig;

use crate::{Error, scaffold};

/// Signal and interface names to the device's current ids and indices.
pub struct SignalResolver {
    by_name: HashMap<String, ResolvedSignal>,
    iface_name_to_index: HashMap<String, u8>,
}

struct ResolvedSignal {
    id: u16,
    group: String,
}

impl SignalResolver {
    /// A signal resolves by its derived name, such as `"CAN0 Bitrate"`, and by
    /// its bare detail, such as `"Temperature"`, when no other signal shares
    /// it.
    pub fn from_device(caps: &Capabilities, signals: &[dsig::SignalInfo]) -> Self {
        let derived: Vec<(&dsig::SignalInfo, scaffold::DerivedSignalName)> = signals
            .iter()
            .map(|sig| (sig, scaffold::derive_signal(sig, caps)))
            .collect();

        let mut by_name: HashMap<String, ResolvedSignal> = HashMap::new();
        for (sig, d) in &derived {
            by_name.insert(
                d.name.clone(),
                ResolvedSignal {
                    id: sig.signal_id,
                    group: d.group.clone().unwrap_or_default(),
                },
            );
        }

        let mut bare_name_counts: HashMap<&str, usize> = HashMap::new();
        for (_, d) in &derived {
            *bare_name_counts.entry(d.detail.as_str()).or_default() += 1;
        }
        for (sig, d) in &derived {
            if bare_name_counts.get(d.detail.as_str()) == Some(&1) {
                by_name.entry(d.detail.clone()).or_insert(ResolvedSignal {
                    id: sig.signal_id,
                    group: d.group.clone().unwrap_or_default(),
                });
            }
        }

        let iface_name_to_index = caps
            .interfaces
            .iter()
            .map(|i| (scaffold::derive_interface_name(i, caps), i.index))
            .collect();

        Self {
            by_name,
            iface_name_to_index,
        }
    }

    pub fn resolve_signal(&self, name: &str) -> Result<u16, Error> {
        self.by_name
            .get(name)
            .map(|r| r.id)
            .ok_or_else(|| Error::SignalNotFound {
                name: name.to_string(),
                available: sorted_keys(&self.by_name),
            })
    }

    pub fn resolve_interface(&self, name: &str) -> Result<u8, Error> {
        self.interface_index(name)
            .ok_or_else(|| Error::InterfaceNotFound {
                name: name.to_string(),
                available: sorted_keys(&self.iface_name_to_index),
            })
    }

    pub fn interface_index(&self, name: &str) -> Option<u8> {
        self.iface_name_to_index.get(name).copied()
    }

    /// The signal's target prefix, such as `"CAN0"`; empty for the device's
    /// own signals.
    pub fn signal_group(&self, name: &str) -> Option<&str> {
        self.by_name.get(name).map(|r| r.group.as_str())
    }
}

fn sorted_keys<V>(map: &HashMap<String, V>) -> Vec<String> {
    let mut names: Vec<String> = map.keys().cloned().collect();
    names.sort();
    names
}

#[cfg(test)]
mod tests {
    use super::*;
    use wslib_framelink_protocol::capabilities::{Capabilities, Interface, Peripheral};
    use wslib_framelink_protocol::dsig::SignalInfo;
    use wslib_framelink_protocol::{frame_def, types};

    /// A device with two CAN interfaces and a temperature sensor — enough to
    /// exercise prefix disambiguation and a device-unique bare name. Signal
    /// ids are arbitrary; resolution must follow them.
    fn device() -> (Capabilities, Vec<SignalInfo>) {
        let caps = Capabilities {
            device_meta: vec![],
            interfaces: vec![
                Interface {
                    index: 0,
                    iface_type: types::IFACE_CAN,
                    meta: vec![],
                },
                Interface {
                    index: 1,
                    iface_type: types::IFACE_CAN,
                    meta: vec![],
                },
            ],
            peripherals: vec![Peripheral {
                index: 0,
                kind: types::PERIPH_KIND_SENSOR,
                meta: vec![],
            }],
        };
        let sig = |id, tt, ti, role, quantity, aspect| SignalInfo {
            signal_id: id,
            target_type: tt,
            target_index: ti,
            role,
            quantity,
            aspect,
            channel: types::SIGNAL_CHANNEL_NONE,
            flags: 0,
            value_type: frame_def::VALUE_TYPE_UNSIGNED,
            value_len: 4,
            scale: 1.0,
            offset: 0.0,
            min_raw: 0,
            max_raw: 0,
        };
        let signals = vec![
            sig(
                0xFF00,
                types::SIGNAL_TARGET_INTERFACE,
                0,
                types::ROLE_CONFIG,
                types::QTY_DATARATE,
                types::ASPECT_DEFAULT,
            ),
            sig(
                0xFF01,
                types::SIGNAL_TARGET_INTERFACE,
                0,
                types::ROLE_CONFIG,
                types::QTY_BOOL,
                types::ASPECT_DEFAULT,
            ),
            sig(
                0xFF02,
                types::SIGNAL_TARGET_INTERFACE,
                1,
                types::ROLE_CONFIG,
                types::QTY_DATARATE,
                types::ASPECT_DEFAULT,
            ),
            sig(
                0xFF03,
                types::SIGNAL_TARGET_INTERFACE,
                1,
                types::ROLE_CONFIG,
                types::QTY_BOOL,
                types::ASPECT_DEFAULT,
            ),
            sig(
                0xFF04,
                types::SIGNAL_TARGET_PERIPHERAL,
                0,
                types::ROLE_MEASUREMENT,
                types::QTY_TEMPERATURE,
                types::ASPECT_DEFAULT,
            ),
        ];
        (caps, signals)
    }

    #[test]
    fn unique_tuple_resolves_by_bare_name_to_the_device_id() {
        let (caps, signals) = device();
        let resolver = SignalResolver::from_device(&caps, &signals);
        // A tuple detail that occurs once resolves by its bare name — to
        // whatever id the device assigned it. Resolution follows the device,
        // not a static map.
        assert_eq!(resolver.resolve_signal("Temperature").unwrap(), 0xFF04);
    }

    #[test]
    fn prefixed_names_disambiguate_per_interface() {
        let (caps, signals) = device();
        let resolver = SignalResolver::from_device(&caps, &signals);
        assert_eq!(resolver.resolve_signal("CAN0 Bitrate").unwrap(), 0xFF00);
        assert_eq!(resolver.resolve_signal("CAN1 Bitrate").unwrap(), 0xFF02);
        // The bare, ambiguous "Bitrate" must NOT resolve (two interfaces have it).
        assert!(resolver.resolve_signal("Bitrate").is_err());
    }

    #[test]
    fn interfaces_resolve_by_caps_derived_name() {
        let (caps, signals) = device();
        let resolver = SignalResolver::from_device(&caps, &signals);
        assert_eq!(resolver.resolve_interface("CAN0").unwrap(), 0);
        assert_eq!(resolver.resolve_interface("CAN1").unwrap(), 1);
    }

    #[test]
    fn unknown_signal_lists_available() {
        let (caps, signals) = device();
        let resolver = SignalResolver::from_device(&caps, &signals);
        let err = resolver.resolve_signal("Nonexistent").unwrap_err();
        assert!(err.to_string().contains("CAN0 Bitrate"));
    }
}
