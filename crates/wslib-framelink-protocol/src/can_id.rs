//! FrameLink's CAN id scheme: a host bit, the device id, and a slot.

pub const CAN_HOST_BIT: u32 = 0x1000_0000;
pub const CAN_DEVICE_ID_MASK: u32 = 0x0FFF_FF00;
pub const CAN_SLOT_MASK: u32 = 0xFF;

pub const SLOT_ISOTP_H2D: u8 = 0x40;
pub const SLOT_ISOTP_D2H: u8 = 0x41;

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
    fn an_id_splits_back_into_its_parts() {
        let device = 0x028F_0800;
        let h2d = can_id(device, SLOT_ISOTP_H2D, true);

        assert!(can_host(h2d));
        assert_eq!(can_slot(h2d), SLOT_ISOTP_H2D);
        assert_eq!(can_device_id(h2d), device);
    }
}
