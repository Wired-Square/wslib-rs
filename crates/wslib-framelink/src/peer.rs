use std::{fmt, net::SocketAddr, str::FromStr};

use wslib_can_bus::{BusParseError, CanBus, DEVICE_SEPARATOR};
use wslib_framelink_protocol::can_id::{
    DEVICE_ID_MAX, DeviceId as CanDeviceId, DeviceIdError as CanDeviceIdError,
};

const CAN_PREFIX: &str = "can:";

/// The device a session talks to: a TCP address, or a device on a CAN bus.
///
/// It is written and parsed as a [`SocketAddr`], or as `can:<bus>@<device-id>`
/// with a [`CanBus`] and a [`CanDeviceId`], e.g. `can:slcan=ttyACM0@028F08`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Peer {
    Tcp(SocketAddr),
    Can { bus: CanBus, device: CanDeviceId },
}

impl From<SocketAddr> for Peer {
    fn from(addr: SocketAddr) -> Self {
        Peer::Tcp(addr)
    }
}

/// Why text is not a [`Peer`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PeerParseError {
    /// Text that doesn't start with `can:` and isn't a socket address. That
    /// rule holds across releases, so a caller may look the text up as a name
    /// instead.
    #[error(
        "{0:?} is neither a socket address, such as 192.168.1.42:120, nor {CAN_PREFIX}<bus>{DEVICE_SEPARATOR}<device-id>"
    )]
    Unrecognised(String),
    #[error("{peer:?} names no CAN bus")]
    Bus {
        peer: String,
        #[source]
        why: BusParseError,
    },
    #[error("{0:?}: name the device id after '{DEVICE_SEPARATOR}'")]
    NoDeviceId(String),
    #[error("{0:?} is not a FrameLink device id: hex, up to {DEVICE_ID_MAX:X}")]
    DeviceId(String),
    #[error("device id {0} is over FrameLink's largest, {DEVICE_ID_MAX:X}")]
    DeviceIdTooLarge(String),
}

fn device(text: &str) -> Result<CanDeviceId, PeerParseError> {
    text.parse().map_err(|why| match why {
        CanDeviceIdError::TooLarge => PeerParseError::DeviceIdTooLarge(text.to_owned()),
        _ => PeerParseError::DeviceId(text.to_owned()),
    })
}

impl FromStr for Peer {
    type Err = PeerParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let Some(target) = s.strip_prefix(CAN_PREFIX) else {
            return s
                .parse()
                .map(Peer::Tcp)
                .map_err(|_| PeerParseError::Unrecognised(s.to_owned()));
        };
        let Some((bus, id)) = target.split_once(DEVICE_SEPARATOR) else {
            return Err(PeerParseError::NoDeviceId(s.to_owned()));
        };
        let bus = bus.parse().map_err(|why| PeerParseError::Bus {
            peer: s.to_owned(),
            why,
        })?;
        if id.is_empty() {
            return Err(PeerParseError::NoDeviceId(s.to_owned()));
        }
        Ok(Peer::Can {
            bus,
            device: device(id)?,
        })
    }
}

impl fmt::Display for Peer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Peer::Tcp(addr) => addr.fmt(f),
            Peer::Can { bus, device } => write!(f, "{CAN_PREFIX}{bus}{DEVICE_SEPARATOR}{device}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEVICE: u32 = 0x02_8F08;

    fn peer(text: &str) -> Peer {
        text.parse().unwrap()
    }

    fn refusal(text: &str) -> PeerParseError {
        text.parse::<Peer>().unwrap_err()
    }

    #[test]
    fn a_peer_round_trips_through_its_text() {
        for text in [
            "192.168.1.42:120",
            "[fe80::1%2]:120",
            "can:slcan=ttyACM0@028F08",
            "can:slcan=by-id:usb-Wired_Square-if00@000000",
            "can:can0@0FFFFF",
            "can:gsusb@000001",
            "can:pcan=ABC123@00ABCD",
            "can:gvret=[::1]:23@028F08",
        ] {
            assert_eq!(peer(text).to_string(), text);
        }
    }

    #[test]
    fn a_can_peer_is_its_bus_and_device_id() {
        assert_eq!(
            peer("can:slcan=ttyACM0@028F08"),
            Peer::Can {
                bus: "slcan=ttyACM0".parse().unwrap(),
                device: CanDeviceId::new(DEVICE).unwrap(),
            }
        );
    }

    #[test]
    fn a_tcp_peer_is_its_socket_address() {
        let addr: SocketAddr = "192.168.1.42:120".parse().unwrap();
        assert_eq!(peer("192.168.1.42:120"), Peer::Tcp(addr));
        assert_eq!(Peer::from(addr).to_string(), addr.to_string());
    }

    #[test]
    fn a_device_id_is_read_as_hex_with_or_without_0x_and_written_in_six_digits() {
        for text in ["can:can0@28F08", "can:can0@0x28f08", "can:can0@0X028F08"] {
            assert_eq!(peer(text).to_string(), "can:can0@028F08", "{text}");
        }
    }

    #[test]
    fn a_tcp_address_without_a_port_is_refused() {
        for text in ["192.168.1.42", "", "can0@028F08", "localhost:120"] {
            assert_eq!(
                refusal(text),
                PeerParseError::Unrecognised(text.to_owned()),
                "{text}"
            );
        }
    }

    #[test]
    fn an_empty_bus_is_refused_naming_the_buses_wslib_can_bus_opens() {
        let refused = refusal("can:@028F08");
        assert_eq!(
            refused,
            PeerParseError::Bus {
                peer: "can:@028F08".into(),
                why: BusParseError::Empty,
            }
        );
        assert_eq!(refused.to_string(), "\"can:@028F08\" names no CAN bus");
        let why = std::error::Error::source(&refused)
            .and_then(|s| s.downcast_ref::<BusParseError>())
            .expect("the bus's parse error")
            .to_string();
        assert!(
            why.contains(&wslib_can_bus::name_the_bus(
                "the CAN bus",
                wslib_can_bus::BUS_FORMS
            )),
            "{why}"
        );
    }

    #[test]
    fn a_bus_its_own_parser_refuses_is_refused_with_its_reason() {
        let why = "slcan=".parse::<CanBus>().unwrap_err();
        assert_eq!(
            refusal("can:slcan=@028F08"),
            PeerParseError::Bus {
                peer: "can:slcan=@028F08".into(),
                why,
            }
        );
    }

    #[test]
    fn a_missing_device_id_is_refused() {
        for text in ["can:can0", "can:can0@"] {
            assert_eq!(
                refusal(text),
                PeerParseError::NoDeviceId(text.into()),
                "{text}"
            );
        }
    }

    #[test]
    fn a_device_id_that_is_not_hex_is_refused() {
        for id in ["xyz", "+28F08", "0x", "28 F08", "-1", "@1"] {
            assert_eq!(
                refusal(&format!("can:can0@{id}")),
                PeerParseError::DeviceId(id.into()),
                "{id}"
            );
        }
    }

    #[test]
    fn a_device_id_over_the_largest_is_refused() {
        let over = DEVICE_ID_MAX + 1;
        for id in [format!("{over:X}"), "FFFFFFFF".into(), "123456789".into()] {
            let refused = refusal(&format!("can:can0@{id}"));
            assert_eq!(refused, PeerParseError::DeviceIdTooLarge(id.clone()));
            assert!(
                refused
                    .to_string()
                    .contains(&format!("{:X}", DEVICE_ID_MAX))
            );
        }
        assert_eq!(peer("can:can0@FFFFF").to_string(), "can:can0@0FFFFF");
    }
}
