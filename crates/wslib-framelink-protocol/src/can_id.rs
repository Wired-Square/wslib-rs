//! FrameLink's CAN id scheme: a host bit, the device id, and a slot.

use std::{fmt, str::FromStr};

pub const CAN_HOST_BIT: u32 = 0x1000_0000;
pub const CAN_DEVICE_ID_MASK: u32 = 0x0FFF_FF00;
pub const CAN_SLOT_MASK: u32 = 0xFF;

pub const SLOT_ISOTP_H2D: u8 = 0x40;
pub const SLOT_ISOTP_D2H: u8 = 0x41;

/// The device id's bit offset in a CAN id: `can_device_id(id) >> DEVICE_ID_SHIFT`
/// is the device id, and [`can_id`] takes `device_id << DEVICE_ID_SHIFT`.
pub const DEVICE_ID_SHIFT: u32 = CAN_DEVICE_ID_MASK.trailing_zeros();
/// The largest device id a CAN id carries.
pub const DEVICE_ID_MAX: u32 = CAN_DEVICE_ID_MASK >> DEVICE_ID_SHIFT;
/// How many hex digits [`device_id_text`] writes.
pub const DEVICE_ID_DIGITS: usize = 6;

const HEX: u32 = 16;
const HEX_PREFIX: &str = "0x";

/// Why text is not a device id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DeviceIdError {
    #[error("a device id is hex digits, after an optional 0x")]
    NotHex,
    #[error("a device id is at most {DEVICE_ID_MAX:X}")]
    TooLarge,
}

/// A device id as text: [`DEVICE_ID_DIGITS`] upper-case hex digits.
pub fn device_id_text(device_id: u32) -> String {
    format!("{device_id:0width$X}", width = DEVICE_ID_DIGITS)
}

/// A device id from 0 to [`DEVICE_ID_MAX`], written by [`device_id_text`] and
/// read by [`parse_device_id`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DeviceId(u32);

impl DeviceId {
    pub const fn new(device_id: u32) -> Result<Self, DeviceIdError> {
        if device_id > DEVICE_ID_MAX {
            return Err(DeviceIdError::TooLarge);
        }
        Ok(Self(device_id))
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

impl FromStr for DeviceId {
    type Err = DeviceIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_device_id(s).map(Self)
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&device_id_text(self.0))
    }
}

/// Reads a device id as hex up to [`DEVICE_ID_MAX`], after an optional `0x`
/// in either case.
pub fn parse_device_id(text: &str) -> Result<u32, DeviceIdError> {
    let digits = text
        .split_at_checked(HEX_PREFIX.len())
        .filter(|(prefix, _)| prefix.eq_ignore_ascii_case(HEX_PREFIX))
        .map_or(text, |(_, digits)| digits);
    if digits.is_empty() || !digits.chars().all(|digit| digit.is_ascii_hexdigit()) {
        return Err(DeviceIdError::NotHex);
    }
    u32::from_str_radix(digits, HEX)
        .ok()
        .filter(|id| *id <= DEVICE_ID_MAX)
        .ok_or(DeviceIdError::TooLarge)
}

pub fn can_id(device_id: u32, slot: u8, host: bool) -> u32 {
    let id = (device_id & CAN_DEVICE_ID_MASK) | (u32::from(slot) & CAN_SLOT_MASK);
    if host { id | CAN_HOST_BIT } else { id }
}

pub fn can_device_id(id: u32) -> u32 {
    id & CAN_DEVICE_ID_MASK
}

pub fn can_slot(id: u32) -> u8 {
    (id & CAN_SLOT_MASK) as u8
}

pub fn can_host(id: u32) -> bool {
    id & CAN_HOST_BIT != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tunnel_ids_match_the_c_vectors() {
        let device = 0x00AB_CD00;

        assert_eq!(can_id(device, SLOT_ISOTP_H2D, true), 0x10AB_CD40);
        assert_eq!(can_id(device, SLOT_ISOTP_D2H, false), 0x00AB_CD41);
    }

    #[test]
    fn device_bits_outside_the_mask_are_dropped() {
        assert_eq!(can_id(0xFFFF_FFFF, 0x40, true), 0x1FFF_FF40);
        assert_eq!(can_id(0x23, 0x21, false), 0x21);
    }

    #[test]
    fn a_device_id_is_the_masks_twenty_bits() {
        assert_eq!(DEVICE_ID_SHIFT, 8);
        assert_eq!(DEVICE_ID_MAX, 0x0F_FFFF);
        assert_eq!(can_device_id(0x028F_0841) >> DEVICE_ID_SHIFT, 0x02_8F08);
    }

    #[test]
    fn a_device_id_is_written_in_six_upper_case_digits() {
        assert_eq!(device_id_text(0x02_8F08), "028F08");
        assert_eq!(device_id_text(0), "000000");
        assert_eq!(device_id_text(DEVICE_ID_MAX), "0FFFFF");
    }

    #[test]
    fn a_device_id_is_read_as_hex_with_an_optional_0x() {
        for text in ["028F08", "28f08", "0x28F08", "0X028f08"] {
            assert_eq!(parse_device_id(text), Ok(0x02_8F08), "{text}");
        }
        assert_eq!(parse_device_id("FFFFF"), Ok(DEVICE_ID_MAX));
    }

    #[test]
    fn a_device_id_that_is_not_hex_digits_is_refused() {
        for text in ["", "0x", "xyz", "+28F08", "-1", "28 F08", "0x0x1"] {
            assert_eq!(parse_device_id(text), Err(DeviceIdError::NotHex), "{text}");
        }
    }

    #[test]
    fn a_device_id_over_the_largest_is_refused() {
        for text in ["100000", "FFFFFFFF", "123456789"] {
            assert_eq!(
                parse_device_id(text),
                Err(DeviceIdError::TooLarge),
                "{text}"
            );
        }
    }

    #[test]
    fn a_device_id_is_at_most_the_largest() {
        assert_eq!(
            DeviceId::new(DEVICE_ID_MAX).map(DeviceId::get),
            Ok(DEVICE_ID_MAX)
        );
        assert_eq!(
            DeviceId::new(DEVICE_ID_MAX + 1),
            Err(DeviceIdError::TooLarge)
        );
        assert_eq!(DeviceId::new(u32::MAX), Err(DeviceIdError::TooLarge));
    }

    #[test]
    fn a_device_id_round_trips_through_its_text() {
        let id: DeviceId = "0x28f08".parse().unwrap();
        assert_eq!(id.get(), 0x02_8F08);
        assert_eq!(id.to_string(), "028F08");
        assert_eq!(id.to_string().parse(), Ok(id));
        assert_eq!("xyz".parse::<DeviceId>(), Err(DeviceIdError::NotHex));
        assert_eq!("100000".parse::<DeviceId>(), Err(DeviceIdError::TooLarge));
    }

    #[test]
    fn an_id_splits_back_into_its_parts() {
        let device = 0x028F_0800;
        let h2d = can_id(device, SLOT_ISOTP_H2D, true);

        assert!(can_host(h2d));
        assert_eq!(can_slot(h2d), SLOT_ISOTP_H2D);
        assert_eq!(can_device_id(h2d), device);
    }
}
