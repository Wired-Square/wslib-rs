use std::time::Duration;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("frame error: {0}")]
    Frame(#[from] wslib_framelink_protocol::Error),

    #[error(transparent)]
    Board(#[from] wslib_framelink_board::Error),

    #[error("connection closed")]
    ConnectionClosed,

    #[error("send failed")]
    SendFailed,

    #[error("{0}")]
    Protocol(String),

    #[error("write locked: {0}")]
    WriteLocked(String),

    #[error("the device refused message 0x{request:02X}: {}", wslib_framelink_protocol::types::error_name(*.code))]
    Nack { request: u8, code: u8 },

    #[error("message 0x{request:02X} was answered with 0x{reply:02X}")]
    UnexpectedReply { request: u8, reply: u8 },

    #[error("command timed out after {0:?}")]
    Timeout(Duration),

    #[error("the device's capabilities carry no {0}")]
    MissingIdentity(&'static str),

    #[cfg(feature = "discovery")]
    #[error("device id not currently known to Discovery: {0}")]
    UnknownDevice(crate::DeviceId),

    #[cfg(feature = "discovery")]
    #[error("device {id} does not support transport {required}")]
    WrongTransport {
        id: crate::DeviceId,
        required: crate::Transport,
    },

    #[cfg(feature = "discovery")]
    #[error("device {id} does not advertise the {capability} capability")]
    CapabilityNotAdvertised {
        id: crate::DeviceId,
        capability: crate::Capability,
    },

    #[cfg(feature = "discovery")]
    #[error("mDNS: {0}")]
    Mdns(#[from] wslib_mdns::Error),

    #[cfg(feature = "discovery")]
    #[error("device registry file: {0}")]
    RegistryFile(#[from] serde_json::Error),

    #[cfg(feature = "ble")]
    #[error("BLE: {0}")]
    Ble(#[from] btleplug::Error),

    #[cfg(feature = "ble")]
    #[error("no BLE adapter on this host")]
    NoBleAdapter,

    /// Seen over BLE, but its peripheral is no longer held by this `Discovery`.
    #[cfg(feature = "ble")]
    #[error("BLE peripheral handle for {0} is no longer available")]
    BleHandleUnavailable(crate::DeviceId),

    #[cfg(feature = "ble")]
    #[error("GATT service {0} not present on the device")]
    GattServiceMissing(uuid::Uuid),

    #[cfg(feature = "ble")]
    #[error("GATT characteristic {0} not found")]
    CharacteristicNotFound(uuid::Uuid),

    #[cfg(feature = "ble")]
    #[error("characteristic write failed ({uuid}): {source}")]
    CharacteristicWrite {
        uuid: uuid::Uuid,
        source: btleplug::Error,
    },

    #[cfg(feature = "ble")]
    #[error("notification subscribe failed ({uuid}): {cause}")]
    NotifySubscribe { uuid: uuid::Uuid, cause: String },

    #[cfg(feature = "ble")]
    #[error("BLE link dropped")]
    BleLinkDropped,

    #[cfg(feature = "wifi-prov")]
    #[error("device reported a Wi-Fi provisioning error (status code 0x03)")]
    WifiProvFailed,
}
