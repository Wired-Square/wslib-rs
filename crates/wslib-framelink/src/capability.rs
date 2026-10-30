//! What a device advertises it can do: the manufacturer data's capability
//! bits as a set. A bit this crate has no name for is `Capability::Other`.

use core::fmt;
use core::ops::{BitAnd, BitOr, BitOrAssign, Not, Sub};
use serde::{Deserialize, Serialize};
use wslib_framelink_protocol::manufacturer_data::CapabilityFlags;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum Capability {
    WifiProv,
    Smp,
    FrameLinkBle,
    Caps,
    PairingRequired,
    /// A bit this crate has no name for, by its position (0 to 15).
    Other(u8),
}

impl Capability {
    pub const fn bit(self) -> u8 {
        match self {
            Self::WifiProv => 0,
            Self::Smp => 1,
            Self::FrameLinkBle => 2,
            Self::Caps => 3,
            Self::PairingRequired => 4,
            Self::Other(b) => b,
        }
    }

    pub const fn from_bit(bit: u8) -> Self {
        match bit {
            0 => Self::WifiProv,
            1 => Self::Smp,
            2 => Self::FrameLinkBle,
            3 => Self::Caps,
            4 => Self::PairingRequired,
            b => Self::Other(b),
        }
    }

    const fn mask(self) -> u16 {
        1u16 << self.bit()
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WifiProv => f.write_str("wifi-prov"),
            Self::Smp => f.write_str("smp"),
            Self::FrameLinkBle => f.write_str("framelink-ble"),
            Self::Caps => f.write_str("caps"),
            Self::PairingRequired => f.write_str("pairing-required"),
            Self::Other(b) => write!(f, "bit-{b}"),
        }
    }
}

/// A set of [`Capability`], serialised as the list of its members.
///
/// ```
/// # use wslib_framelink::CapabilitySet;
/// let caps = CapabilitySet::WIFI_PROV | CapabilitySet::SMP;
/// assert!(caps.contains(CapabilitySet::SMP));
/// assert_eq!(CapabilitySet::from_bits(0b0011), caps);
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct CapabilitySet(u16);

impl CapabilitySet {
    pub const WIFI_PROV: Self = Self(1 << 0);
    pub const SMP: Self = Self(1 << 1);
    pub const FRAMELINK_BLE: Self = Self(1 << 2);
    pub const CAPS: Self = Self(1 << 3);
    pub const PAIRING_REQUIRED: Self = Self(1 << 4);

    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn from_bits(bits: u16) -> Self {
        Self(bits)
    }

    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Whether every member of `other` is in `self`.
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub const fn len(self) -> u32 {
        self.0.count_ones()
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// Members of `self` not in `other`.
    pub const fn difference(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    /// Members in ascending bit order.
    pub fn iter(self) -> CapabilityIter {
        CapabilityIter { remaining: self.0 }
    }
}

impl fmt::Debug for CapabilitySet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut dbg = f.debug_set();
        for cap in self.iter() {
            dbg.entry(&format_args!("{cap}"));
        }
        dbg.finish()
    }
}

impl fmt::Display for CapabilitySet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for cap in self.iter() {
            if !first {
                f.write_str(", ")?;
            }
            write!(f, "{cap}")?;
            first = false;
        }
        Ok(())
    }
}

impl BitOr for CapabilitySet {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        self.union(rhs)
    }
}

impl BitOrAssign for CapabilitySet {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl BitAnd for CapabilitySet {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        self.intersection(rhs)
    }
}

impl Sub for CapabilitySet {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        self.difference(rhs)
    }
}

impl Not for CapabilitySet {
    type Output = Self;
    fn not(self) -> Self {
        Self(!self.0)
    }
}

impl From<Capability> for CapabilitySet {
    fn from(cap: Capability) -> Self {
        Self(cap.mask())
    }
}

impl FromIterator<Capability> for CapabilitySet {
    fn from_iter<I: IntoIterator<Item = Capability>>(iter: I) -> Self {
        let mut bits = 0u16;
        for cap in iter {
            bits |= cap.mask();
        }
        Self(bits)
    }
}

impl IntoIterator for CapabilitySet {
    type Item = Capability;
    type IntoIter = CapabilityIter;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

pub struct CapabilityIter {
    remaining: u16,
}

impl Iterator for CapabilityIter {
    type Item = Capability;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let bit = self.remaining.trailing_zeros() as u8;
        self.remaining &= self.remaining - 1;
        Some(Capability::from_bit(bit))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let n = self.remaining.count_ones() as usize;
        (n, Some(n))
    }
}

impl ExactSizeIterator for CapabilityIter {}

impl Serialize for CapabilitySet {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut seq = ser.serialize_seq(Some(self.len() as usize))?;
        for cap in self.iter() {
            seq.serialize_element(&cap)?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for CapabilitySet {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let caps: Vec<Capability> = Vec::deserialize(de)?;
        Ok(caps.into_iter().collect())
    }
}

impl From<CapabilityFlags> for CapabilitySet {
    fn from(flags: CapabilityFlags) -> Self {
        Self(flags.bits())
    }
}

impl From<CapabilitySet> for CapabilityFlags {
    fn from(set: CapabilitySet) -> Self {
        CapabilityFlags::from_bits(set.bits())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_constants_are_distinct_single_bits() {
        for cap in [
            CapabilitySet::WIFI_PROV,
            CapabilitySet::SMP,
            CapabilitySet::FRAMELINK_BLE,
            CapabilitySet::CAPS,
            CapabilitySet::PAIRING_REQUIRED,
        ] {
            assert_eq!(cap.bits().count_ones(), 1, "{cap} not a single bit");
        }
        let all = CapabilitySet::WIFI_PROV
            | CapabilitySet::SMP
            | CapabilitySet::FRAMELINK_BLE
            | CapabilitySet::CAPS
            | CapabilitySet::PAIRING_REQUIRED;
        assert_eq!(all.bits().count_ones(), 5);
    }

    #[test]
    fn contains_requires_all_bits() {
        let caps = CapabilitySet::WIFI_PROV | CapabilitySet::SMP;
        assert!(caps.contains(CapabilitySet::WIFI_PROV));
        assert!(caps.contains(CapabilitySet::SMP));
        assert!(caps.contains(CapabilitySet::WIFI_PROV | CapabilitySet::SMP));
        assert!(!caps.contains(CapabilitySet::FRAMELINK_BLE));
        assert!(!caps.contains(CapabilitySet::WIFI_PROV | CapabilitySet::FRAMELINK_BLE));
    }

    #[test]
    fn iter_yields_known_variants_in_order() {
        let caps = CapabilitySet::SMP | CapabilitySet::WIFI_PROV | CapabilitySet::CAPS;
        let collected: Vec<_> = caps.iter().collect();
        assert_eq!(
            collected,
            vec![Capability::WifiProv, Capability::Smp, Capability::Caps]
        );
    }

    #[test]
    fn iter_surfaces_unknown_bits_as_other() {
        let caps = CapabilitySet::from_bits(0b0001_0000_1000_0001);
        let collected: Vec<_> = caps.iter().collect();
        assert_eq!(
            collected,
            vec![
                Capability::WifiProv,
                Capability::Other(7),
                Capability::Other(12)
            ]
        );
    }

    #[test]
    fn from_iter_round_trips_through_iter() {
        let caps = CapabilitySet::WIFI_PROV
            | CapabilitySet::FRAMELINK_BLE
            | CapabilitySet::PAIRING_REQUIRED;
        let collected: CapabilitySet = caps.iter().collect();
        assert_eq!(collected, caps);
    }

    #[test]
    fn other_variant_round_trips_through_set() {
        let caps: CapabilitySet = [Capability::Other(9), Capability::Smp]
            .into_iter()
            .collect();
        assert_eq!(caps.bits(), (1 << 9) | (1 << 1));
        let collected: Vec<_> = caps.iter().collect();
        assert_eq!(collected, vec![Capability::Smp, Capability::Other(9)]);
    }

    #[test]
    fn set_ops_behave_as_expected() {
        let a = CapabilitySet::WIFI_PROV | CapabilitySet::SMP;
        let b = CapabilitySet::SMP | CapabilitySet::CAPS;
        assert_eq!(
            a | b,
            CapabilitySet::WIFI_PROV | CapabilitySet::SMP | CapabilitySet::CAPS
        );
        assert_eq!(a & b, CapabilitySet::SMP);
        assert_eq!(a - b, CapabilitySet::WIFI_PROV);
    }

    #[test]
    fn display_lists_known_names_comma_separated() {
        let caps = CapabilitySet::WIFI_PROV | CapabilitySet::SMP;
        assert_eq!(format!("{caps}"), "wifi-prov, smp");
    }

    #[test]
    fn display_other_uses_bit_position() {
        let caps = CapabilitySet::from_bits(1 << 11);
        assert_eq!(format!("{caps}"), "bit-11");
    }

    #[test]
    fn capability_bit_round_trip() {
        for bit in 0u8..16 {
            assert_eq!(Capability::from_bit(bit).bit(), bit);
        }
    }

    #[test]
    fn empty_set_iterates_nothing() {
        assert!(CapabilitySet::empty().iter().next().is_none());
        assert!(CapabilitySet::empty().is_empty());
        assert_eq!(CapabilitySet::empty().len(), 0);
    }

    #[test]
    fn serde_round_trip_known_caps() {
        let caps = CapabilitySet::WIFI_PROV | CapabilitySet::SMP;
        let json = serde_json::to_string(&caps).expect("serialise");
        assert_eq!(json, r#"["wifi-prov","smp"]"#);
        let back: CapabilitySet = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(back, caps);
    }

    #[test]
    fn serde_round_trip_with_unknown_bit() {
        let caps: CapabilitySet = [Capability::WifiProv, Capability::Other(7)]
            .into_iter()
            .collect();
        let json = serde_json::to_string(&caps).expect("serialise");
        assert_eq!(json, r#"["wifi-prov",{"other":7}]"#);
        let back: CapabilitySet = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(back, caps);
    }

    #[test]
    fn from_capability_flags_preserves_bits() {
        use wslib_framelink_protocol::manufacturer_data::CapabilityFlagsBuilder;
        let flags = CapabilityFlagsBuilder::new()
            .wifi_prov(true)
            .smp(true)
            .build();
        let set: CapabilitySet = flags.into();
        assert_eq!(set, CapabilitySet::WIFI_PROV | CapabilitySet::SMP);
    }
}
