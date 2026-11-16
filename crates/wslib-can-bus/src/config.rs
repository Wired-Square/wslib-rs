/// How [`open`](crate::open) runs a bus's adapter: its nominal rate and
/// whether it meets the bus as classic CAN or CAN FD.
///
/// An SLCAN, gs_usb or PEAK adapter sets the bus's rates, so it needs
/// `bitrate`, and in FD a data rate too. A SocketCAN interface and a GVRET
/// device keep their own rates and ignore both.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct BusConfig {
    pub bitrate: Option<u32>,
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
    #[default]
    Classic,
    Fd {
        data_bitrate: Option<u32>,
    },
}

impl CanMode {
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
