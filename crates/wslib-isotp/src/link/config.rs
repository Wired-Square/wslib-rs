use std::time::Duration;

/// One link's ids and timing. [`new`](Self::new) sets every other field to
/// its default.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LinkConfig {
    /// As `CanFrame::bus`.
    pub bus: u8,
    pub tx_id: u32,
    pub rx_id: u32,
    /// 29-bit ids, or 11-bit.
    pub extended: bool,
    /// The longest the adapter may take to queue and confirm one frame.
    pub n_as: Duration,
    /// The wait for a flow control after a first frame, a block or a WAIT.
    pub n_bs: Duration,
    /// The longest gap between received consecutive frames before the message
    /// is aborted.
    pub n_cr: Duration,
    /// Consecutive frames this link asks for per flow control, 0 for all.
    pub block_size: u8,
    /// The gap this link asks a sender to leave between consecutive frames,
    /// rounded up to an encodable STmin.
    pub st_min: Duration,
    /// WAITs in a row that a send survives. One more fails it.
    pub wait_limit: u32,
    /// Received frames the receive task's queue holds.
    pub rx_queue: usize,
}

impl LinkConfig {
    pub const DEFAULT_N_AS: Duration = Duration::from_secs(1);
    pub const DEFAULT_N_BS: Duration = Duration::from_secs(1);
    pub const DEFAULT_N_CR: Duration = Duration::from_secs(1);
    pub const DEFAULT_BLOCK_SIZE: u8 = 0;
    pub const DEFAULT_ST_MIN: Duration = Duration::from_millis(1);
    pub const DEFAULT_WAIT_LIMIT: u32 = 10;
    /// More than the 586 frames of a 4095-byte message.
    pub const DEFAULT_RX_QUEUE: usize = 1024;

    /// A link on `bus` sending on `tx_id` and receiving on `rx_id`, with
    /// extended ids.
    pub fn new(bus: u8, tx_id: u32, rx_id: u32) -> Self {
        Self {
            bus,
            tx_id,
            rx_id,
            extended: true,
            n_as: Self::DEFAULT_N_AS,
            n_bs: Self::DEFAULT_N_BS,
            n_cr: Self::DEFAULT_N_CR,
            block_size: Self::DEFAULT_BLOCK_SIZE,
            st_min: Self::DEFAULT_ST_MIN,
            wait_limit: Self::DEFAULT_WAIT_LIMIT,
            rx_queue: Self::DEFAULT_RX_QUEUE,
        }
    }
}
