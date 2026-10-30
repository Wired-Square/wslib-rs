//! The six-byte BLE manufacturer data a device advertises under
//! [`COMPANY_ID`], so a scanner learns what it can do without connecting.
//!
//! Layout (LE byte order):
//! ```text
//! offset  size  field
//! 0       1     schema_version (start at SCHEMA_VERSION_V1)
//! 1       2     capability_flags (u16)
//! 3       1     hw_rev (high nibble = major, low nibble = minor)
//! 4       2     fw_version (u8 major, u8 minor)
//! ```

use core::fmt;

/// The Bluetooth SIG's reserved test company identifier, until a registered
/// one replaces it.
pub const COMPANY_ID: u16 = 0xFFFF;

/// Bumps only when a bit's meaning changes; scanners ignore unknown bits.
pub const SCHEMA_VERSION_V1: u8 = 0x01;

/// The newest schema this crate decodes; a newer one is refused.
pub const SCHEMA_VERSION_MAX: u8 = SCHEMA_VERSION_V1;

pub const PAYLOAD_LEN: usize = 6;

mod cap_bits {
    pub const WIFI_PROV: u16 = 1 << 0;
    pub const SMP: u16 = 1 << 1;
    pub const FRAMELINK_BLE_TRANSPORT: u16 = 1 << 2;
    pub const CAPS: u16 = 1 << 3;
    pub const PAIRING_REQUIRED: u16 = 1 << 4;
}

#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct CapabilityFlags(u16);

impl CapabilityFlags {
    pub const fn from_bits(bits: u16) -> Self {
        Self(bits)
    }

    pub const fn bits(self) -> u16 {
        self.0
    }

    pub const fn has_wifi_prov(self) -> bool {
        self.0 & cap_bits::WIFI_PROV != 0
    }
    pub const fn has_smp(self) -> bool {
        self.0 & cap_bits::SMP != 0
    }
    pub const fn has_framelink_ble(self) -> bool {
        self.0 & cap_bits::FRAMELINK_BLE_TRANSPORT != 0
    }
    pub const fn has_caps(self) -> bool {
        self.0 & cap_bits::CAPS != 0
    }
    pub const fn requires_pairing(self) -> bool {
        self.0 & cap_bits::PAIRING_REQUIRED != 0
    }
}

impl fmt::Debug for CapabilityFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CapabilityFlags")
            .field("wifi_prov", &self.has_wifi_prov())
            .field("smp", &self.has_smp())
            .field("framelink_ble", &self.has_framelink_ble())
            .field("caps", &self.has_caps())
            .field("requires_pairing", &self.requires_pairing())
            .field("raw", &format_args!("{:#06x}", self.0))
            .finish()
    }
}

#[derive(Clone, Copy, Default)]
pub struct CapabilityFlagsBuilder {
    bits: u16,
}

impl CapabilityFlagsBuilder {
    pub const fn new() -> Self {
        Self { bits: 0 }
    }

    const fn with(mut self, bit: u16, on: bool) -> Self {
        self.bits = if on {
            self.bits | bit
        } else {
            self.bits & !bit
        };
        self
    }

    pub const fn wifi_prov(self, v: bool) -> Self {
        self.with(cap_bits::WIFI_PROV, v)
    }
    pub const fn smp(self, v: bool) -> Self {
        self.with(cap_bits::SMP, v)
    }
    pub const fn framelink_ble(self, v: bool) -> Self {
        self.with(cap_bits::FRAMELINK_BLE_TRANSPORT, v)
    }
    pub const fn caps(self, v: bool) -> Self {
        self.with(cap_bits::CAPS, v)
    }
    pub const fn pairing_required(self, v: bool) -> Self {
        self.with(cap_bits::PAIRING_REQUIRED, v)
    }
    pub const fn build(self) -> CapabilityFlags {
        CapabilityFlags(self.bits)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManufacturerPayload {
    pub schema_version: u8,
    pub capabilities: CapabilityFlags,
    /// Major in the high nibble, minor in the low: `0x10` is 1.0.
    pub hw_rev: u8,
    pub fw_version: (u8, u8),
}

impl ManufacturerPayload {
    pub const fn new_v1(
        capabilities: CapabilityFlags,
        hw_rev: u8,
        fw_major: u8,
        fw_minor: u8,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION_V1,
            capabilities,
            hw_rev,
            fw_version: (fw_major, fw_minor),
        }
    }

    pub fn encode(&self) -> [u8; PAYLOAD_LEN] {
        let cap = self.capabilities.bits().to_le_bytes();
        [
            self.schema_version,
            cap[0],
            cap[1],
            self.hw_rev,
            self.fw_version.0,
            self.fw_version.1,
        ]
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, crate::Error> {
        if bytes.len() != PAYLOAD_LEN {
            return Err(crate::Error::ManufacturerDataLength {
                actual: bytes.len(),
            });
        }
        let version = bytes[0];
        if version > SCHEMA_VERSION_MAX {
            return Err(crate::Error::UnsupportedSchema {
                found: version,
                max_known: SCHEMA_VERSION_MAX,
            });
        }
        let cap_bits = u16::from_le_bytes([bytes[1], bytes[2]]);
        Ok(Self {
            schema_version: version,
            capabilities: CapabilityFlags::from_bits(cap_bits),
            hw_rev: bytes[3],
            fw_version: (bytes[4], bytes[5]),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_all_caps_set() {
        let caps = CapabilityFlagsBuilder::new()
            .wifi_prov(true)
            .smp(true)
            .framelink_ble(true)
            .caps(true)
            .pairing_required(true)
            .build();
        let payload = ManufacturerPayload::new_v1(caps, 0x10, 0, 1);
        let bytes = payload.encode();
        let back = ManufacturerPayload::decode(&bytes).expect("decode");
        assert_eq!(payload, back);
    }

    #[test]
    fn known_byte_pattern_v1_wfl_minimum() {
        let caps = CapabilityFlagsBuilder::new()
            .wifi_prov(true)
            .smp(true)
            .caps(true)
            .pairing_required(true)
            .build();
        let payload = ManufacturerPayload::new_v1(caps, 0x10, 0, 1);
        assert_eq!(payload.encode(), [0x01, 0x1B, 0x00, 0x10, 0x00, 0x01]);
    }

    #[test]
    fn rejects_short_payload() {
        let err = ManufacturerPayload::decode(&[0x01, 0x00, 0x00]).unwrap_err();
        assert_eq!(err, crate::Error::ManufacturerDataLength { actual: 3 });
        assert_eq!(err.to_string(), "manufacturer data length 3, expected 6");
    }

    #[test]
    fn rejects_future_schema_version() {
        let bytes = [0xFF, 0, 0, 0, 0, 0];
        let err = ManufacturerPayload::decode(&bytes).unwrap_err();
        assert_eq!(
            err.to_string(),
            "manufacturer data schema 0xff is newer than supported 0x01"
        );
    }

    #[test]
    fn capability_accessors_are_independent() {
        let caps = CapabilityFlagsBuilder::new().smp(true).build();
        assert!(caps.has_smp());
        assert!(!caps.has_wifi_prov());
        assert!(!caps.has_framelink_ble());
        assert!(!caps.has_caps());
        assert!(!caps.requires_pairing());
    }
}
