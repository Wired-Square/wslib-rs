use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::format_frame_id;

/// One frame identity, `(protocol, frame_id, is_extended)`, with its rollup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct InventoryRow {
    pub protocol: String,
    pub frame_id: u32,
    pub frame_id_hex: String,
    pub is_extended: bool,
    pub count: i64,
    pub first_us: i64,
    pub last_us: i64,
    pub max_dlc: u16,
    /// The bus the identity was grouped on; none when grouped across buses.
    pub bus: Option<u8>,
}

impl InventoryRow {
    pub fn new(
        protocol: &str,
        frame_id: u32,
        is_extended: bool,
        count: i64,
        first_us: i64,
        last_us: i64,
        max_dlc: u16,
    ) -> Self {
        Self {
            protocol: protocol.to_string(),
            frame_id,
            frame_id_hex: format_frame_id(frame_id, is_extended),
            is_extended,
            count,
            first_us,
            last_us,
            max_dlc,
            bus: None,
        }
    }

    pub fn on_bus(self, bus: u8) -> Self {
        Self {
            bus: Some(bus),
            ..self
        }
    }
}

/// A protocol and the frame ids selected under it: CAN 0x100 and Modbus
/// register 256 share a number but are different frames.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct ProtocolFrames {
    pub protocol: String,
    pub frame_ids: Vec<u32>,
    /// Every id of this protocol, seen or not, `frame_ids` notwithstanding.
    #[serde(default)]
    pub all_ids: bool,
}

impl ProtocolFrames {
    pub fn ids(protocol: impl Into<String>, frame_ids: Vec<u32>) -> Self {
        Self {
            protocol: protocol.into(),
            frame_ids,
            all_ids: false,
        }
    }

    pub fn whole(protocol: impl Into<String>) -> Self {
        Self {
            protocol: protocol.into(),
            frame_ids: Vec::new(),
            all_ids: true,
        }
    }
}

/// How a frame's payloads are sampled: a contiguous run of the newest, for
/// reading consecutive pairs, or spread across the whole recording.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sampling {
    Spread,
    Recent,
}

/// Which payloads to read: up to `limit` of them, oldest first. `protocol` is
/// the identity's other half and `is_extended` the tie-break; `None` matches any.
#[derive(Clone, Copy, Debug)]
pub struct PayloadQuery<'a> {
    pub protocol: Option<&'a str>,
    pub frame_id: u32,
    pub is_extended: Option<bool>,
    pub limit: u32,
    pub sampling: Sampling,
}

/// A normalised frame selection, where empty selects everything: groups
/// without ids are dropped, ids deduplicated, and a protocol selected whole
/// absorbs the ids listed under it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FrameSelection {
    ids: HashMap<String, HashSet<u32>>,
    whole: HashSet<String>,
}

impl FrameSelection {
    pub fn from_groups(groups: Vec<ProtocolFrames>) -> Self {
        let mut selection = Self::default();
        for group in groups {
            if group.all_ids {
                selection.whole.insert(group.protocol);
            } else if !group.frame_ids.is_empty() {
                selection
                    .ids
                    .entry(group.protocol)
                    .or_default()
                    .extend(group.frame_ids);
            }
        }
        let whole = &selection.whole;
        selection
            .ids
            .retain(|protocol, _| !whole.contains(protocol));
        selection
    }

    pub fn is_empty(&self) -> bool {
        self.ids.is_empty() && self.whole.is_empty()
    }

    /// Whether every frame seen, as each protocol's ids, is selected, so the
    /// filter can be skipped.
    pub fn covers<'a, I>(&self, seen: impl IntoIterator<Item = (&'a str, I)>) -> bool
    where
        I: IntoIterator<Item = &'a u32>,
    {
        seen.into_iter().all(|(protocol, ids)| {
            self.whole.contains(protocol)
                || self
                    .ids
                    .get(protocol)
                    .is_some_and(|selected| ids.into_iter().all(|id| selected.contains(id)))
        })
    }

    pub fn contains(&self, protocol: &str, frame_id: u32) -> bool {
        self.whole.contains(protocol)
            || self
                .ids
                .get(protocol)
                .is_some_and(|ids| ids.contains(&frame_id))
    }

    /// The `(frame_id, protocol)` pairs, sorted; a protocol selected whole
    /// contributes none.
    pub fn pairs(&self) -> Vec<(u32, &str)> {
        let mut pairs: Vec<(u32, &str)> = self
            .ids
            .iter()
            .flat_map(|(protocol, ids)| ids.iter().map(move |id| (*id, protocol.as_str())))
            .collect();
        pairs.sort_unstable();
        pairs
    }

    /// The protocols selected whole, sorted.
    pub fn protocols(&self) -> Vec<&str> {
        let mut out: Vec<&str> = self.whole.iter().map(String::as_str).collect();
        out.sort_unstable();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn groups(entries: &[(&str, &[u32])]) -> Vec<ProtocolFrames> {
        entries
            .iter()
            .map(|(protocol, ids)| ProtocolFrames::ids(*protocol, ids.to_vec()))
            .collect()
    }

    #[test]
    fn groups_with_no_ids_normalise_to_an_empty_selection() {
        assert!(FrameSelection::from_groups(groups(&[("can", &[])])).is_empty());
        assert!(FrameSelection::from_groups(Vec::new()).is_empty());
        assert!(!FrameSelection::from_groups(groups(&[("can", &[256])])).is_empty());
    }

    #[test]
    fn repeated_groups_merge_and_deduplicate() {
        let selection =
            FrameSelection::from_groups(groups(&[("can", &[256, 256]), ("can", &[257])]));
        assert_eq!(selection.pairs(), vec![(256, "can"), (257, "can")]);
    }

    /// Keyed on the bare id, a CAN-only selection "covered" a capture holding
    /// Modbus too, and the tail returned unfiltered rows.
    #[test]
    fn covers_is_protocol_aware() {
        let seen: &[(&str, &[u32])] = &[("can", &[256]), ("modbus", &[256])];
        let covers = |selection: FrameSelection| selection.covers(seen.iter().copied());

        assert!(!covers(FrameSelection::from_groups(groups(&[(
            "can",
            &[256, 257]
        )]))));
        assert!(covers(FrameSelection::from_groups(groups(seen))));
    }

    #[test]
    fn a_protocol_selected_whole_covers_ids_it_has_not_seen() {
        let selection = FrameSelection::from_groups(vec![ProtocolFrames::whole("modbus_rtu")]);
        assert!(!selection.is_empty());
        assert!(selection.contains("modbus_rtu", 0x0265));
        assert!(!selection.contains("can", 0x0265));
        let modbus: &[(&str, &[u32])] = &[("modbus_rtu", &[288, 613])];
        assert!(selection.covers(modbus.iter().copied()));
        let mixed_seen: &[(&str, &[u32])] = &[("modbus_rtu", &[288]), ("can", &[256])];
        assert!(!selection.covers(mixed_seen.iter().copied()));
        assert!(selection.pairs().is_empty());
        assert_eq!(selection.protocols(), vec!["modbus_rtu"]);

        let mut mixed = groups(&[("can", &[256]), ("modbus_rtu", &[288])]);
        mixed.push(ProtocolFrames::whole("modbus_rtu"));
        let mixed = FrameSelection::from_groups(mixed);
        assert_eq!(mixed.pairs(), vec![(256, "can")]);
        assert_eq!(mixed.protocols(), vec!["modbus_rtu"]);
    }

    #[test]
    fn pairs_are_sorted_regardless_of_insertion_order() {
        let a = FrameSelection::from_groups(groups(&[("modbus", &[257, 256]), ("can", &[256])]));
        let b = FrameSelection::from_groups(groups(&[("can", &[256]), ("modbus", &[256, 257])]));
        assert_eq!(a.pairs(), b.pairs());
        assert_eq!(
            a.pairs(),
            vec![(256, "can"), (256, "modbus"), (257, "modbus")]
        );
    }

    #[test]
    fn an_inventory_row_carries_its_hex_id() {
        let row = InventoryRow::new("can", 0x7B, true, 2, 10, 20, 8);
        assert_eq!(row.frame_id_hex, "0x0000007B");
        assert_eq!(
            serde_json::to_value(&row).unwrap(),
            serde_json::json!({
                "protocol": "can", "frame_id": 123, "frame_id_hex": "0x0000007B",
                "is_extended": true, "count": 2, "first_us": 10, "last_us": 20, "max_dlc": 8,
                "bus": null
            })
        );
    }

    #[test]
    fn on_bus_sets_the_bus() {
        let row = InventoryRow::new("can", 0x7B, false, 2, 10, 20, 8).on_bus(1);
        assert_eq!(row.bus, Some(1));
    }
}
