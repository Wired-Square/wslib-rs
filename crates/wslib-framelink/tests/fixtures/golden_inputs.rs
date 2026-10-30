// Shared with the generator that wrote `goldens.json` from the source this
// crate was moved from; `s` is this crate.

fn json<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap()
}

fn ble_device() -> s::Device {
    s::Device::builder("ble:14:23:45:67:89:AB", "WiredFlexLink-9C1C")
        .transport(s::Transport::Ble)
        .capabilities(s::CapabilitySet::WIFI_PROV | s::CapabilitySet::FRAMELINK_BLE)
        .rssi(-67)
        .build()
}

fn mdns_device() -> s::Device {
    s::Device::builder("mdns:tcp:wfl-1234._framelink._tcp.local.", "wfl-1234")
        .transport(s::Transport::Tcp)
        .address("192.168.1.42:120".parse().unwrap())
        .build()
}

fn registry_file() -> String {
    let mut registry = s::registry::DeviceRegistry::default();
    registry.upsert(s::registry::DeviceRecord::manual(
        "udp:WiredFlexLink-4CD4",
        "10.0.52.162".parse().unwrap(),
    ));
    registry.upsert(s::registry::DeviceRecord::auto("wfl-1234"));
    serde_json::to_string_pretty(&registry).unwrap()
}

fn session_goldens() -> Vec<(&'static str, String)> {
    use s::ble::wifi_prov::*;
    use std::net::Ipv4Addr;

    let every_capability: s::CapabilitySet = [
        s::Capability::WifiProv,
        s::Capability::Smp,
        s::Capability::FrameLinkBle,
        s::Capability::Caps,
        s::Capability::PairingRequired,
        s::Capability::Other(9),
    ]
    .into_iter()
    .collect();
    vec![
        ("device_ble", json(&ble_device())),
        ("device_mdns", json(&mdns_device())),
        ("device_id", json(&s::DeviceId::new("mdns:udp:wfl._mcumgr._udp.local."))),
        (
            "transports",
            json(&[s::Transport::Ble, s::Transport::Tcp, s::Transport::Udp]),
        ),
        ("capability_other", json(&s::Capability::Other(12))),
        ("capability_set", json(&every_capability)),
        ("event_seen", json(&s::DiscoveryEvent::Seen { device: ble_device() })),
        (
            "event_updated",
            json(&s::DiscoveryEvent::Updated {
                id: s::DeviceId::new("ble:abc"),
                name: "WFL".into(),
                capabilities: s::CapabilitySet::SMP,
                rssi: None,
            }),
        ),
        (
            "event_lost",
            json(&s::DiscoveryEvent::Lost {
                id: s::DeviceId::new("mdns:tcp:wfl-1234._framelink._tcp.local."),
            }),
        ),
        (
            "event_error",
            json(&[
                s::DiscoveryEvent::Error {
                    source: s::ErrorSource::Ble,
                    message: "scan start".into(),
                },
                s::DiscoveryEvent::Error {
                    source: s::ErrorSource::Mdns,
                    message: "no IPv4 address".into(),
                },
            ]),
        ),
        (
            "device_record_manual",
            json(&s::registry::DeviceRecord::manual(
                "WFL-1",
                "10.0.0.9".parse().unwrap(),
            )),
        ),
        ("device_record_auto", json(&s::registry::DeviceRecord::auto("WFL-2"))),
        (
            "resolutions",
            json(&[s::registry::Resolution::Auto, s::registry::Resolution::Manual]),
        ),
        ("registry_file", registry_file()),
        (
            "wifi_securities",
            json(&[
                WifiSecurity::OPEN,
                WifiSecurity::WPA2_PSK,
                WifiSecurity::from_byte(7),
            ]),
        ),
        (
            "wifi_statuses",
            json(&[
                WifiStatus::Disconnected,
                WifiStatus::Connecting,
                WifiStatus::Connected,
                WifiStatus::Error,
            ]),
        ),
        (
            "wifi_credentials",
            json(&[
                WifiCredentials::open("Workshop"),
                WifiCredentials::psk("Workshop", "secret"),
            ]),
        ),
        (
            "provisioning_status",
            json(&ProvisioningStatus {
                ssid: Some("Workshop".into()),
                security: Some(WifiSecurity::WPA2_PSK),
                status: WifiStatus::Connected,
                ip_address: Some(Ipv4Addr::new(192, 168, 1, 42)),
            }),
        ),
        (
            "provisioning_events",
            json(&[
                ProvisioningEvent::Status {
                    status: WifiStatus::Connecting,
                },
                ProvisioningEvent::IpAddress {
                    address: Ipv4Addr::new(10, 0, 0, 7),
                },
            ]),
        ),
    ]
}
