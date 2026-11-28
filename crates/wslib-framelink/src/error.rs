use std::fmt;
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("I/O failed")]
    Io(#[from] std::io::Error),

    #[error("malformed frame")]
    Frame(#[from] wslib_framelink_protocol::Error),

    #[error("the board definition failed")]
    Board(#[from] wslib_framelink_board::Error),

    #[error("connection closed")]
    ConnectionClosed,

    /// A background task panicked.
    #[error("a background task panicked")]
    Panicked,

    /// The runtime cancelled a background task before it finished.
    #[error("a background task was cancelled")]
    Cancelled,

    /// The peer answered on another FrameLink protocol version, so the
    /// request waiting for a reply failed at once.
    #[error("the peer speaks FrameLink protocol version {0}, not {PROTOCOL_VERSION}", PROTOCOL_VERSION = wslib_framelink_protocol::PROTOCOL_VERSION)]
    PeerVersion(u8),

    #[error("send failed")]
    SendFailed,

    #[error("{0}")]
    Protocol(String),

    #[error("write locked: {0}")]
    WriteLocked(String),

    /// Unlocking after a WRITE_LOCKED refusal failed.
    #[error(transparent)]
    UnlockFailed(UnlockFailure),

    /// The device's WRITE_CHALLENGE reply doesn't parse; the source is the
    /// protocol's error.
    #[error("the write challenge does not parse")]
    Challenge(#[source] wslib_framelink_protocol::Error),

    #[error("the device refused message 0x{request:02X}: {}", wslib_framelink_protocol::types::error_name(*.code))]
    Nack { request: u8, code: u8 },

    #[error("message 0x{request:02X} was answered with 0x{reply:02X}")]
    UnexpectedReply { request: u8, reply: u8 },

    #[error("command timed out after {0:?}")]
    Timeout(Duration),

    #[error("the device's capabilities carry no {0}")]
    MissingIdentity(&'static str),

    #[cfg(feature = "can")]
    #[error("the CAN bus did not open")]
    CanOpen(#[from] wslib_can_bus::OpenError),

    /// Only a build without the `can` feature returns it.
    #[error("{0}: this build has no CAN transport; build wslib-framelink with its `can` feature")]
    NoCanTransport(crate::Peer),

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
    #[error("mDNS failed")]
    Mdns(#[from] wslib_mdns::Error),

    #[cfg(feature = "discovery")]
    #[error("device registry file is unreadable")]
    RegistryFile(#[from] serde_json::Error),

    #[cfg(feature = "ble")]
    #[error("BLE failed")]
    Ble(#[from] btleplug::Error),

    /// The host did not pair with the device, or paired and could not
    /// withdraw its pairing agent.
    #[cfg(feature = "ble")]
    #[error("pairing with the device failed")]
    Pairing(#[from] wslib_ble::PairError),

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
    #[error("characteristic write failed ({uuid})")]
    CharacteristicWrite {
        uuid: uuid::Uuid,
        source: btleplug::Error,
    },

    #[cfg(feature = "ble")]
    #[error("notification subscribe failed ({uuid})")]
    NotifySubscribe {
        uuid: uuid::Uuid,
        source: btleplug::Error,
    },

    #[cfg(feature = "ble")]
    #[error("notification subscribe failed ({0}): the characteristic does not support NOTIFY")]
    NotifyUnsupported(uuid::Uuid),

    #[cfg(feature = "ble")]
    #[error("the notifications for {0} ended")]
    NotificationsEnded(uuid::Uuid),

    #[cfg(feature = "ble")]
    #[error("BLE link dropped")]
    BleLinkDropped,

    #[cfg(feature = "smp")]
    #[error("SMP failed")]
    Smp(#[from] wslib_mcumgr::Error),

    #[cfg(feature = "smp")]
    #[error("SMP over {0} is not available in this build")]
    SmpUnavailable(crate::Transport),

    #[cfg(feature = "smp")]
    #[error("an update of {0} is already running")]
    OtaInProgress(crate::DeviceId),

    #[cfg(feature = "smp")]
    #[error("after the reset the device runs another image than the one uploaded")]
    OtaVerifyMismatch { expected: Vec<u8>, found: Vec<u8> },

    #[cfg(feature = "wifi-prov")]
    #[error("device reported a Wi-Fi provisioning error (status code 0x03)")]
    WifiProvFailed,
}

/// Why unlocking after a WRITE_LOCKED refusal failed: its `source()` is
/// the [`Error`] the unlock ended with.
#[derive(Debug)]
pub struct UnlockFailure(Box<Error>);

impl UnlockFailure {
    pub(crate) fn new(cause: Error) -> Self {
        Self(Box::new(cause))
    }

    /// The error the unlock ended with.
    pub fn cause(&self) -> &Error {
        &self.0
    }
}

impl fmt::Display for UnlockFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("write locked: the unlock after WRITE_LOCKED failed")
    }
}

impl std::error::Error for UnlockFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&*self.0)
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;

    use super::*;

    #[test]
    fn an_io_failure_says_only_its_own_layer() {
        let failed = Error::from(std::io::Error::other("the cause"));

        assert_eq!(failed.to_string(), "I/O failed");
        assert!(
            failed
                .source()
                .and_then(|s| s.downcast_ref::<std::io::Error>())
                .is_some()
        );
    }

    #[test]
    fn a_board_failure_is_its_own_layer_over_the_boards_error() {
        let refused = wslib_framelink_board::parse_board_def("not toml =").unwrap_err();

        let failed = Error::from(refused);

        assert_eq!(failed.to_string(), "the board definition failed");
        assert!(
            failed
                .source()
                .and_then(|s| s.downcast_ref::<wslib_framelink_board::Error>())
                .is_some()
        );
    }

    #[test]
    fn a_failed_unlock_keeps_the_failure_typed() {
        let failed =
            Error::UnlockFailed(UnlockFailure::new(Error::Timeout(Duration::from_secs(1))));

        assert_eq!(
            failed.to_string(),
            "write locked: the unlock after WRITE_LOCKED failed"
        );
        assert!(matches!(
            failed.source().and_then(|s| s.downcast_ref::<Error>()),
            Some(Error::Timeout(_))
        ));
        let Error::UnlockFailed(unlock) = &failed else {
            panic!("{failed:?}");
        };
        assert!(matches!(unlock.cause(), Error::Timeout(_)));
    }

    #[test]
    fn a_malformed_challenge_keeps_the_protocols_error() {
        let refused = wslib_framelink_protocol::dsig::parse_challenge_response(&[]).unwrap_err();

        let failed = Error::Challenge(refused);

        assert_eq!(failed.to_string(), "the write challenge does not parse");
        assert!(
            failed
                .source()
                .and_then(|s| s.downcast_ref::<wslib_framelink_protocol::Error>())
                .is_some()
        );
    }

    #[cfg(feature = "smp")]
    #[test]
    fn an_smp_failure_says_only_its_own_layer() {
        let failed = Error::from(wslib_mcumgr::Error::Timeout);

        assert_eq!(failed.to_string(), "SMP failed");
        assert!(matches!(
            failed
                .source()
                .and_then(|s| s.downcast_ref::<wslib_mcumgr::Error>()),
            Some(wslib_mcumgr::Error::Timeout)
        ));
    }
}
