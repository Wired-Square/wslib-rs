pub const MAX_MESSAGE: usize = 4095;
pub const CLASSIC_LEN: usize = 8;

const TYPE_SHIFT: u32 = 4;
pub(crate) const LOW_NIBBLE: u8 = 0x0F;
pub(crate) const SN_FIRST: u8 = 1;

pub(crate) const SF_PCI_LEN: usize = 1;
pub(crate) const FF_PCI_LEN: usize = 2;
pub(crate) const CF_PCI_LEN: usize = 1;

pub(crate) const SF_ESCAPE_PCI_LEN: usize = 2;
pub(crate) const FF_ESCAPE_PCI_LEN: usize = 6;

#[cfg(test)]
pub(crate) const SF_MAX_DATA: usize = CLASSIC_LEN - SF_PCI_LEN;
#[cfg(test)]
pub(crate) const FF_DATA: usize = CLASSIC_LEN - FF_PCI_LEN;
#[cfg(test)]
pub(crate) const CF_MAX_DATA: usize = CLASSIC_LEN - CF_PCI_LEN;
#[cfg(test)]
pub(crate) const FF_DL_MIN: usize = SF_MAX_DATA + 1;

/// A frame's protocol control information type, its first byte's high nibble.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PciKind {
    Single = 0x0,
    First = 0x1,
    Consecutive = 0x2,
    FlowControl = 0x3,
}

impl PciKind {
    const ALL: [Self; 4] = [
        Self::Single,
        Self::First,
        Self::Consecutive,
        Self::FlowControl,
    ];

    /// The frame's kind, or `None` for an empty frame, one longer than
    /// [`CLASSIC_LEN`], or a reserved type.
    pub fn classify(frame: &[u8]) -> Option<Self> {
        if frame.len() > CLASSIC_LEN {
            return None;
        }
        Self::of(*frame.first()?)
    }

    pub(crate) fn of(pci: u8) -> Option<Self> {
        let nibble = pci >> TYPE_SHIFT;
        Self::ALL.into_iter().find(|kind| *kind as u8 == nibble)
    }

    pub(crate) const fn pci_byte(self, low: u8) -> u8 {
        (self as u8) << TYPE_SHIFT | (low & LOW_NIBBLE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_by_the_high_nibble() {
        assert_eq!(PciKind::classify(&[0x03, 1, 2, 3]), Some(PciKind::Single));
        assert_eq!(
            PciKind::classify(&[0x10, 0x08, 0, 0, 0, 0, 0, 0]),
            Some(PciKind::First)
        );
        assert_eq!(PciKind::classify(&[0x21, 0]), Some(PciKind::Consecutive));
        assert_eq!(PciKind::classify(&[0x30, 0, 0]), Some(PciKind::FlowControl));
    }

    #[test]
    fn classifies_a_padded_frame() {
        assert_eq!(
            PciKind::classify(&[0x30, 0, 0, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC]),
            Some(PciKind::FlowControl)
        );
    }

    #[test]
    fn refuses_an_empty_frame_a_reserved_type_and_an_fd_length() {
        assert_eq!(PciKind::classify(&[]), None);
        for pci in 0x40..=0xFF_u8 {
            assert_eq!(PciKind::classify(&[pci]), None, "{pci:#04x}");
        }
        assert_eq!(PciKind::classify(&[0x21; CLASSIC_LEN + 1]), None);
    }

    #[test]
    fn builds_a_pci_byte() {
        assert_eq!(PciKind::Consecutive.pci_byte(0x0F), 0x2F);
        assert_eq!(PciKind::FlowControl.pci_byte(0x12), 0x32);
    }
}
