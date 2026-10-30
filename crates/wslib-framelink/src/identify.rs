use wslib_framelink_board::{BoardDef, load_board_def};
use wslib_framelink_protocol::capabilities::Capabilities;
use wslib_framelink_protocol::dsig;

use crate::{Error, FrameLinkSession};

/// The TX queue depth assumed of a device that does not report one.
pub const DEFAULT_TX_QUEUE_DEPTH: u16 = 4;

/// Who a device is, from its capabilities, and its live signals.
#[derive(Debug)]
pub struct DeviceIdentity {
    pub capabilities: Capabilities,
    pub board_name: String,
    pub board_revision: String,
    pub device_id: Option<String>,
    pub tx_queue_depth: u16,
    /// The embedded definition for the board, if this crate embeds one.
    pub board_def: Option<BoardDef>,
    pub signals: Vec<dsig::SignalInfo>,
}

impl FrameLinkSession {
    /// Reads the device's capabilities and signals, and looks its board up
    /// among the embedded definitions.
    pub async fn identify(&self) -> Result<DeviceIdentity, Error> {
        let capabilities = self.capabilities().await?;
        let board_name = capabilities
            .board_name()
            .ok_or(Error::MissingIdentity("board name"))?
            .to_string();
        let board_revision = capabilities
            .board_revision()
            .ok_or(Error::MissingIdentity("board revision"))?
            .to_string();
        let signals = self.list_all_signals().await?;
        Ok(DeviceIdentity {
            device_id: capabilities.device_id().map(str::to_string),
            tx_queue_depth: capabilities
                .tx_queue_depth()
                .unwrap_or(DEFAULT_TX_QUEUE_DEPTH),
            board_def: load_board_def(&board_name, &board_revision),
            board_name,
            board_revision,
            capabilities,
            signals,
        })
    }
}
