/// How `open` runs a bus's adapter: its nominal rate and
/// whether it meets the bus as classic CAN or CAN FD.
///
/// An SLCAN, gs_usb or PEAK adapter sets the bus's rates, so it needs
/// `bitrate`, and in FD a data rate too. A SocketCAN interface and a GVRET
/// device keep their own rates and ignore both.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct BusConfig {
    /// The nominal rate.
    pub bitrate: Option<u32>,
    /// Classic CAN or CAN FD.
    pub mode: CanMode,
}

impl BusConfig {
    /// Classic CAN at `bitrate`.
    pub const fn classic(bitrate: Option<u32>) -> Self {
        Self {
            bitrate,
            mode: CanMode::Classic,
        }
    }

    /// CAN FD at `bitrate`, with `data_bitrate` for the data phase.
    pub const fn fd(bitrate: Option<u32>, data_bitrate: Option<u32>) -> Self {
        Self {
            bitrate,
            mode: CanMode::Fd { data_bitrate },
        }
    }
}

/// Classic CAN, or CAN FD with its data-phase rate.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum CanMode {
    /// Classic CAN only. The default.
    #[default]
    Classic,
    /// CAN FD, with the data phase at `data_bitrate`.
    Fd { data_bitrate: Option<u32> },
}

impl CanMode {
    /// Whether this is CAN FD.
    pub const fn is_fd(self) -> bool {
        matches!(self, CanMode::Fd { .. })
    }

    /// The data-phase rate, `None` in classic CAN.
    pub const fn data_bitrate(self) -> Option<u32> {
        match self {
            CanMode::Classic => None,
            CanMode::Fd { data_bitrate } => data_bitrate,
        }
    }
}

#[cfg(test)]
mod tests;
