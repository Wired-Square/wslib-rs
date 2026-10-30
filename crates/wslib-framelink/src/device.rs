use crate::CapabilitySet;
use core::fmt;
use core::str::FromStr;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// A discovered device's id, opaque: stable while a `Discovery` sees the
/// device, though one lost and found again may come back under another.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DeviceId(String);

impl DeviceId {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeviceId({:?})", self.0)
    }
}

impl FromStr for DeviceId {
    type Err = core::convert::Infallible;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_owned()))
    }
}

impl From<String> for DeviceId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for DeviceId {
    fn from(s: &str) -> Self {
        Self(s.to_owned())
    }
}

impl AsRef<str> for DeviceId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Transport {
    Ble,
    /// Found by mDNS, as `_framelink._tcp`.
    Tcp,
    /// Found by mDNS, as `_mcumgr._udp`.
    Udp,
}

impl fmt::Display for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ble => f.write_str("ble"),
            Self::Tcp => f.write_str("tcp"),
            Self::Udp => f.write_str("udp"),
        }
    }
}

/// A discovered device as last seen, on one transport: one found over BLE
/// and mDNS is two.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    id: DeviceId,
    name: String,
    transports: Vec<Transport>,
    capabilities: CapabilitySet,
    rssi: Option<i16>,
    address: Option<SocketAddr>,
}

impl Device {
    pub fn id(&self) -> &DeviceId {
        &self.id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn transports(&self) -> &[Transport] {
        &self.transports
    }

    pub fn capabilities(&self) -> CapabilitySet {
        self.capabilities
    }

    /// In dBm, over BLE.
    pub fn rssi(&self) -> Option<i16> {
        self.rssi
    }

    /// Found by mDNS.
    pub fn address(&self) -> Option<SocketAddr> {
        self.address
    }

    pub fn builder(id: impl Into<DeviceId>, name: impl Into<String>) -> DeviceBuilder {
        DeviceBuilder {
            id: id.into(),
            name: name.into(),
            transports: Vec::new(),
            capabilities: CapabilitySet::empty(),
            rssi: None,
            address: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct DeviceBuilder {
    id: DeviceId,
    name: String,
    transports: Vec<Transport>,
    capabilities: CapabilitySet,
    rssi: Option<i16>,
    address: Option<SocketAddr>,
}

impl DeviceBuilder {
    pub fn transport(mut self, t: Transport) -> Self {
        if !self.transports.contains(&t) {
            self.transports.push(t);
        }
        self
    }

    pub fn transports<I: IntoIterator<Item = Transport>>(mut self, ts: I) -> Self {
        for t in ts {
            self = self.transport(t);
        }
        self
    }

    pub fn capabilities(mut self, caps: CapabilitySet) -> Self {
        self.capabilities = caps;
        self
    }

    pub fn rssi(mut self, rssi: i16) -> Self {
        self.rssi = Some(rssi);
        self
    }

    pub fn maybe_rssi(mut self, rssi: Option<i16>) -> Self {
        self.rssi = rssi;
        self
    }

    pub fn address(mut self, addr: SocketAddr) -> Self {
        self.address = Some(addr);
        self
    }

    pub fn build(self) -> Device {
        Device {
            id: self.id,
            name: self.name,
            transports: self.transports,
            capabilities: self.capabilities,
            rssi: self.rssi,
            address: self.address,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Capability;

    #[test]
    fn device_id_round_trips_through_string() {
        let id = DeviceId::new("ble:14:23:45:67:89:AB");
        assert_eq!(id.as_str(), "ble:14:23:45:67:89:AB");
        assert_eq!(format!("{id}"), "ble:14:23:45:67:89:AB");
        let parsed: DeviceId = "ble:foo".parse().unwrap();
        assert_eq!(parsed.as_str(), "ble:foo");
    }

    #[test]
    fn device_id_serde_is_transparent_string() {
        let id = DeviceId::new("mdns:wfl-1234._framelink._tcp.local");
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, r#""mdns:wfl-1234._framelink._tcp.local""#);
        let back: DeviceId = serde_json::from_str(&json).unwrap();
        assert_eq!(back, id);
    }

    #[test]
    fn transport_serde_is_lowercase() {
        assert_eq!(serde_json::to_string(&Transport::Ble).unwrap(), r#""ble""#);
        assert_eq!(serde_json::to_string(&Transport::Tcp).unwrap(), r#""tcp""#);
        assert_eq!(serde_json::to_string(&Transport::Udp).unwrap(), r#""udp""#);
    }

    #[test]
    fn builder_constructs_ble_device() {
        let dev = Device::builder("ble:abc", "WFL-Test")
            .transport(Transport::Ble)
            .capabilities(CapabilitySet::WIFI_PROV | CapabilitySet::SMP)
            .rssi(-67)
            .build();
        assert_eq!(dev.id().as_str(), "ble:abc");
        assert_eq!(dev.name(), "WFL-Test");
        assert_eq!(dev.transports(), &[Transport::Ble]);
        assert_eq!(
            dev.capabilities(),
            CapabilitySet::WIFI_PROV | CapabilitySet::SMP
        );
        assert_eq!(dev.rssi(), Some(-67));
        assert_eq!(dev.address(), None);
    }

    #[test]
    fn builder_constructs_mdns_device() {
        let addr: SocketAddr = "192.168.1.42:1337".parse().unwrap();
        let dev = Device::builder("mdns:wfl-1234", "WFL-1234")
            .transport(Transport::Tcp)
            .capabilities(
                [Capability::WifiProv, Capability::FrameLinkBle]
                    .into_iter()
                    .collect(),
            )
            .address(addr)
            .build();
        assert_eq!(dev.transports(), &[Transport::Tcp]);
        assert_eq!(dev.address(), Some(addr));
        assert!(dev.rssi().is_none());
    }

    #[test]
    fn builder_dedupes_repeated_transports() {
        let dev = Device::builder("x", "y")
            .transport(Transport::Ble)
            .transport(Transport::Ble)
            .transports([Transport::Tcp, Transport::Ble])
            .build();
        assert_eq!(dev.transports(), &[Transport::Ble, Transport::Tcp]);
    }

    #[test]
    fn device_serde_round_trips() {
        let dev = Device::builder("ble:abc", "WFL-Test")
            .transport(Transport::Ble)
            .capabilities(CapabilitySet::SMP)
            .rssi(-50)
            .build();
        let json = serde_json::to_string(&dev).unwrap();
        let back: Device = serde_json::from_str(&json).unwrap();
        assert_eq!(back, dev);
    }
}
