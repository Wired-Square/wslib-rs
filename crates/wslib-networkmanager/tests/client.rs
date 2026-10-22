#![cfg(unix)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use wslib_networkmanager::testing::{FakeAccessPoint, FakeDevice, FakeNetworkManager};
use wslib_networkmanager::{
    Client, Device, DeviceKind, DeviceState, Ipv4, Ipv4Method, Objects, ProfileIpv4,
    RollbackResult, Security, Settings, WifiRadio, checkpoint, connection_type, group, interface,
    reason, set_ipv4,
};
use zbus::zvariant::{OwnedObjectPath, Value};

fn ip(a: &str) -> IpAddr {
    a.parse().unwrap()
}

fn wired_profile() -> Settings {
    Settings::from([
        (
            "connection".to_string(),
            group([
                ("id", Value::from("Wired")),
                ("type", Value::from("802-3-ethernet")),
            ]),
        ),
        ("ipv4".to_string(), Ipv4::Auto { dns: vec![] }.group()),
    ])
}

fn ops(strength: u8) -> FakeAccessPoint {
    FakeAccessPoint::new("Ops", strength, Security::WpaPsk).passphrase("correct horse")
}

async fn serve(fake: &FakeNetworkManager) -> (Client, zbus::Connection) {
    let (bus, served) = fake.connect().await.unwrap();
    (Client::new(bus), served)
}

async fn device(nm: &Client, interface: &str) -> Device {
    nm.devices()
        .await
        .unwrap()
        .into_iter()
        .find(|d| d.interface == interface)
        .unwrap()
}

#[tokio::test]
async fn devices_are_read_off_the_tree_by_name() {
    let fake = FakeNetworkManager::new()
        .with(FakeDevice::wifi("wlan0").unmanaged())
        .with(
            FakeDevice::ethernet("eth0")
                .hw_address("B8:27:EB:00:00:01")
                .address(ip("10.0.50.12"), 24)
                .address(ip("fe80::1"), 64)
                .gateway(ip("10.0.50.1"))
                .dns(ip("10.0.50.1"))
                .dns(ip("2001:db8::53"))
                .active(wired_profile()),
        )
        .with(FakeDevice::ethernet("eth1").unplugged())
        .with(FakeDevice::other("lo", 32));
    let (nm, _served) = serve(&fake).await;

    let devices = nm.devices().await.unwrap();
    let names: Vec<_> = devices.iter().map(|d| d.interface.as_str()).collect();
    assert_eq!(names, ["eth0", "eth1", "lo", "wlan0"]);

    let eth0 = &devices[0];
    assert_eq!(eth0.kind, DeviceKind::Ethernet);
    assert_eq!(eth0.state, DeviceState::Activated);
    assert!(eth0.managed && !eth0.unplugged());
    assert_eq!(eth0.hw_address.as_deref(), Some("B8:27:EB:00:00:01"));
    assert_eq!(eth0.carrier, Some(true));
    let ip4 = eth0.ip4.as_ref().unwrap();
    let gateway = Ipv4Addr::new(10, 0, 50, 1);
    assert_eq!(ip4.addresses[0].address, Ipv4Addr::new(10, 0, 50, 12));
    assert_eq!(
        (ip4.gateway, ip4.dns.as_slice()),
        (Some(gateway), &[gateway][..])
    );
    let resolver: Ipv6Addr = "2001:db8::53".parse().unwrap();
    assert_eq!(eth0.ip6.as_ref().unwrap().dns, [resolver]);
    let all: Vec<_> = eth0.addresses().map(|a| a.to_string()).collect();
    assert_eq!(all, ["10.0.50.12/24", "fe80::1/64"]);
    let profile = eth0
        .profile
        .as_ref()
        .expect("the active connection's profile");
    assert_eq!(
        connection_type(&nm.settings(profile).await.unwrap()).as_deref(),
        Some("802-3-ethernet")
    );

    let eth1 = &devices[1];
    assert!(eth1.unplugged(), "{eth1:?}");
    assert_eq!(
        eth1.reason, 2,
        "the reason NetworkManager leaves is not CARRIER"
    );
    assert_eq!((eth1.ip4.as_ref(), eth1.profile.as_ref()), (None, None));

    assert_eq!(devices[2].kind, DeviceKind::Other(32));
    assert_eq!(devices[2].carrier, None);

    let wlan0 = &devices[3];
    assert_eq!(wlan0.kind, DeviceKind::Wifi);
    assert!(!wlan0.managed);
    assert_eq!(wlan0.state, DeviceState::Unmanaged);
    assert_eq!(wlan0.carrier, None);
}

#[tokio::test]
async fn a_scan_answers_one_access_point_per_network_strongest_first() {
    let fake = FakeNetworkManager::new().with(
        FakeDevice::wifi("wlan0")
            .access_point(ops(40))
            .access_point(ops(70))
            .access_point(FakeAccessPoint::new("Corp", 90, Security::Eap))
            .access_point(FakeAccessPoint::new("", 95, Security::Open)),
    );
    let (nm, _served) = serve(&fake).await;
    let wlan0 = device(&nm, "wlan0").await;
    assert_eq!(
        wlan0.access_points.len(),
        3,
        "a hidden network's nameless one is left out"
    );

    let seen = |networks: Vec<wslib_networkmanager::AccessPoint>| {
        networks
            .into_iter()
            .map(|ap| {
                (
                    String::from_utf8(ap.ssid).unwrap(),
                    ap.strength,
                    ap.security,
                )
            })
            .collect::<Vec<_>>()
    };
    let expected = [
        ("Corp".to_string(), 90, Security::Eap),
        ("Ops".to_string(), 70, Security::WpaPsk),
    ];
    assert_eq!(seen(nm.scan(&wlan0.path).await.unwrap()), expected);
    assert_eq!(fake.heard(), ["RequestScan"]);

    fake.refuse("RequestScan");
    assert_eq!(
        seen(nm.scan(&wlan0.path).await.unwrap()),
        expected,
        "a refused scan still answers what NetworkManager holds"
    );
}

#[tokio::test]
async fn a_join_with_the_right_passphrase_associates_and_a_wrong_one_fails_later() {
    let fake = FakeNetworkManager::new().with(
        FakeDevice::wifi("wlan0")
            .access_point(ops(70))
            .access_point(FakeAccessPoint::new("Home", 50, Security::Sae)),
    );
    let (nm, _served) = serve(&fake).await;
    let wlan0 = device(&nm, "wlan0").await;

    let profile = wlan0.wifi_profile(b"Ops", Some("correct horse")).unwrap();
    let joined = nm.add_and_activate(profile, &wlan0.path).await.unwrap();
    let wlan0 = device(&nm, "wlan0").await;
    assert_eq!(wlan0.state, DeviceState::Activated);
    assert_eq!(wlan0.active_access_point.as_ref().unwrap().ssid, b"Ops");
    assert_eq!(wlan0.profile, Some(joined.profile.clone()));
    let read = nm.settings(&joined.profile).await.unwrap();
    assert!(
        !read["802-11-wireless-security"].contains_key("psk"),
        "secrets are not read back"
    );

    let wrong = wlan0.wifi_profile(b"Ops", Some("battery staple")).unwrap();
    nm.add_and_activate(wrong, &wlan0.path).await.unwrap();
    let wlan0 = device(&nm, "wlan0").await;
    assert_eq!(
        (wlan0.state, wlan0.reason),
        (DeviceState::Failed, reason::NO_SECRETS)
    );
    assert_eq!(wlan0.active_access_point, None);

    let away = wlan0.wifi_profile(b"Elsewhere", Some("anything")).unwrap();
    nm.add_and_activate(away, &wlan0.path).await.unwrap();
    let wlan0 = device(&nm, "wlan0").await;
    assert_eq!(wlan0.reason, reason::SSID_NOT_FOUND);

    let wpa3 = wlan0.wifi_profile(b"Home", Some("anything")).unwrap();
    nm.add_and_activate(wpa3, &wlan0.path).await.unwrap();
    let held = fake.profiles();
    let key_mgmt: Vec<_> = held
        .iter()
        .map(|p| String::try_from(p["802-11-wireless-security"]["key-mgmt"].clone()).unwrap())
        .collect();
    assert_eq!(key_mgmt, ["wpa-psk", "wpa-psk", "wpa-psk", "sae"]);
    assert_eq!(
        String::try_from(held[0]["802-11-wireless-security"]["psk"].clone()).unwrap(),
        "correct horse"
    );
}

#[tokio::test]
async fn a_checkpoint_rolls_back_a_join_and_a_destroyed_one_keeps_it() {
    let fake = FakeNetworkManager::new().with(FakeDevice::wifi("wlan0").access_point(ops(70)));
    let (nm, _served) = serve(&fake).await;
    let wlan0 = device(&nm, "wlan0").await;
    let flags = checkpoint::DESTROY_ALL | checkpoint::DELETE_NEW_CONNECTIONS;
    let join = || wlan0.wifi_profile(b"Ops", Some("correct horse")).unwrap();

    let made = nm
        .create_checkpoint(&[&wlan0.path], 180, flags)
        .await
        .unwrap();
    assert_eq!(nm.checkpoints().await.unwrap(), std::slice::from_ref(&made));
    assert!(
        nm.create_checkpoint(&[&wlan0.path], 180, 0).await.is_err(),
        "one checkpoint at a time without DESTROY_ALL"
    );
    nm.add_and_activate(join(), &wlan0.path).await.unwrap();
    let results = nm.roll_back(&made).await.unwrap();
    assert_eq!(
        results.into_values().collect::<Vec<_>>(),
        [RollbackResult::Ok]
    );
    assert!(nm.checkpoints().await.unwrap().is_empty());
    assert_eq!(device(&nm, "wlan0").await.state, DeviceState::Disconnected);
    assert!(
        nm.profiles().await.unwrap().is_empty(),
        "the new profile is deleted"
    );

    let kept = nm
        .create_checkpoint(&[&wlan0.path], 180, flags)
        .await
        .unwrap();
    nm.add_and_activate(join(), &wlan0.path).await.unwrap();
    nm.destroy_checkpoint(&kept).await.unwrap();
    assert!(
        nm.roll_back(&kept).await.is_err(),
        "nothing left to roll back"
    );
    assert_eq!(device(&nm, "wlan0").await.state, DeviceState::Activated);

    nm.create_checkpoint(&[&wlan0.path], 180, flags)
        .await
        .unwrap();
    nm.delete_profile(&device(&nm, "wlan0").await.profile.unwrap())
        .await
        .unwrap();
    fake.expire_checkpoints();
    assert_eq!(
        device(&nm, "wlan0").await.state,
        DeviceState::Activated,
        "the timer put the deleted profile back"
    );
    assert_eq!(nm.profiles().await.unwrap().len(), 1);
}

#[tokio::test]
async fn an_address_change_is_written_to_disk_then_reapplied_or_else_activated() {
    let fake = FakeNetworkManager::new().with(FakeDevice::ethernet("eth0").active(wired_profile()));
    let (nm, _served) = serve(&fake).await;
    let eth0 = device(&nm, "eth0").await;
    let profile = eth0.profile.clone().unwrap();

    let mut settings = nm.settings(&profile).await.unwrap();
    assert!(ProfileIpv4::read(&settings).unwrap().is_plain_auto());
    set_ipv4(
        &mut settings,
        &Ipv4::Manual {
            address: Ipv4Addr::new(10, 0, 50, 12),
            prefix: 24,
            gateway: None,
            dns: vec![Ipv4Addr::new(10, 0, 50, 1)],
        },
    );
    nm.update_profile(&profile, settings.clone()).await.unwrap();
    nm.apply(&eth0.path, &profile, settings.clone())
        .await
        .unwrap();
    let back = ProfileIpv4::read(&nm.settings(&profile).await.unwrap()).unwrap();
    assert_eq!(back.method, Some(Ipv4Method::Manual));
    assert_eq!(back.dns, [Ipv4Addr::new(10, 0, 50, 1)]);

    fake.refuse("Reapply");
    nm.apply(&eth0.path, &profile, settings).await.unwrap();
    assert_eq!(
        fake.heard(),
        [
            format!("Update2 {profile} 0x1"),
            "Reapply eth0 manual".to_string(),
            "Reapply eth0 manual".to_string(),
            format!("ActivateConnection {profile} {}", eth0.path),
        ]
    );
}

#[tokio::test]
async fn saved_profiles_are_listed_and_deleted() {
    let fake = FakeNetworkManager::new()
        .with(FakeDevice::wifi("wlan0").access_point(ops(70)))
        .saved(wired_profile());
    let (nm, _served) = serve(&fake).await;
    let wlan0 = device(&nm, "wlan0").await;
    let joined = nm
        .add_and_activate(
            wlan0.wifi_profile(b"Ops", Some("correct horse")).unwrap(),
            &wlan0.path,
        )
        .await
        .unwrap();

    let profiles = nm.profiles().await.unwrap();
    assert_eq!(profiles.len(), 2);
    let mut kinds = Vec::new();
    for profile in &profiles {
        kinds.push(connection_type(&nm.settings(profile).await.unwrap()).unwrap());
    }
    assert_eq!(kinds, ["802-3-ethernet", "802-11-wireless"]);

    nm.delete_profile(&joined.profile).await.unwrap();
    assert_eq!(nm.profiles().await.unwrap(), [profiles[0].clone()]);
    assert_eq!(device(&nm, "wlan0").await.profile, None);
    assert!(nm.settings(&joined.profile).await.is_err());
}

fn method_error(e: zbus::Error) -> String {
    match e {
        zbus::Error::MethodError(name, _, _) => name.to_string(),
        other => panic!("not a method error: {other:?}"),
    }
}

#[tokio::test]
async fn a_disconnect_drops_the_network_and_keeps_its_profile() {
    let fake = FakeNetworkManager::new().with(FakeDevice::wifi("wlan0").access_point(ops(70)));
    let (nm, _served) = serve(&fake).await;
    let wlan0 = device(&nm, "wlan0").await;
    let joined = nm
        .add_and_activate(
            wlan0.wifi_profile(b"Ops", Some("correct horse")).unwrap(),
            &wlan0.path,
        )
        .await
        .unwrap();

    nm.disconnect(&wlan0.path).await.unwrap();
    let wlan0 = device(&nm, "wlan0").await;
    assert_eq!(
        (wlan0.state, wlan0.reason),
        (DeviceState::Disconnected, reason::USER_REQUESTED)
    );
    assert_eq!((wlan0.profile, wlan0.active_access_point), (None, None));
    assert_eq!(
        nm.profiles().await.unwrap(),
        std::slice::from_ref(&joined.profile)
    );

    nm.activate(&joined.profile, &wlan0.path).await.unwrap();
    let wlan0 = device(&nm, "wlan0").await;
    assert_eq!(wlan0.state, DeviceState::Activated);
    assert_eq!(wlan0.profile, Some(joined.profile));
    assert_eq!(wlan0.active_access_point.unwrap().ssid, b"Ops");
    assert_eq!(fake.heard()[1], "Disconnect wlan0");
}

#[tokio::test]
async fn disconnecting_a_disconnected_device_is_not_active() {
    let fake = FakeNetworkManager::new().with(FakeDevice::ethernet("eth0"));
    let (nm, _served) = serve(&fake).await;
    let eth0 = device(&nm, "eth0").await;
    let refused = nm.disconnect(&eth0.path).await.unwrap_err();
    assert_eq!(
        method_error(refused),
        "org.freedesktop.NetworkManager.Device.NotActive"
    );
}

#[tokio::test]
async fn a_failed_join_leaves_no_connection_to_disconnect() {
    let fake = FakeNetworkManager::new().with(FakeDevice::wifi("wlan0").access_point(ops(70)));
    let (nm, _served) = serve(&fake).await;
    let wlan0 = device(&nm, "wlan0").await;
    for (ssid, passphrase) in [(&b"Ops"[..], "battery staple"), (b"Elsewhere", "anything")] {
        let profile = wlan0.wifi_profile(ssid, Some(passphrase)).unwrap();
        nm.add_and_activate(profile, &wlan0.path).await.unwrap();
        let failed = device(&nm, "wlan0").await;
        assert_eq!(
            (failed.state, failed.profile, failed.active_access_point),
            (DeviceState::Failed, None, None)
        );
        let refused = nm.disconnect(&wlan0.path).await.unwrap_err();
        assert_eq!(
            method_error(refused),
            "org.freedesktop.NetworkManager.Device.NotActive"
        );
    }
    assert_eq!(
        nm.profiles().await.unwrap().len(),
        2,
        "a failed join keeps its profile"
    );
}

#[tokio::test]
async fn a_refused_disconnect_leaves_the_connection_up() {
    let fake = FakeNetworkManager::new().with(FakeDevice::ethernet("eth0").active(wired_profile()));
    let (nm, _served) = serve(&fake).await;
    let eth0 = device(&nm, "eth0").await;
    fake.refuse("Disconnect");
    let refused = nm.disconnect(&eth0.path).await.unwrap_err();
    assert_eq!(
        method_error(refused),
        "org.freedesktop.NetworkManager.Device.Failed"
    );
    assert_eq!(device(&nm, "eth0").await.state, DeviceState::Activated);
}

#[tokio::test]
async fn the_wifi_radio_reads_both_switches_and_turns() {
    let fake = FakeNetworkManager::new();
    let (nm, _served) = serve(&fake).await;
    let on = WifiRadio {
        enabled: true,
        hardware_enabled: Some(true),
    };
    assert_eq!(nm.wifi_radio().await.unwrap(), on);
    nm.set_wifi_enabled(false).await.unwrap();
    assert!(!fake.radio().enabled);

    for hardware_enabled in [Some(false), None] {
        fake.set_radio(WifiRadio {
            enabled: true,
            hardware_enabled,
        });
        assert_eq!(
            nm.wifi_radio().await.unwrap().hardware_enabled,
            hardware_enabled,
            "an unreadable kill switch is None, not an error"
        );
    }
}

#[tokio::test]
async fn the_owner_changes_when_networkmanager_restarts_and_takes_its_checkpoints() {
    let fake = FakeNetworkManager::new().with(FakeDevice::ethernet("eth0"));
    let (nm, _served) = serve(&fake).await;
    let eth0 = device(&nm, "eth0").await;
    let before = nm
        .owner()
        .await
        .unwrap()
        .expect("NetworkManager is running");
    assert!(before.starts_with(':'));
    nm.create_checkpoint(&[&eth0.path], 180, checkpoint::DESTROY_ALL)
        .await
        .unwrap();

    fake.restart();
    let after = nm.owner().await.unwrap().unwrap();
    assert_ne!(before, after);
    assert!(nm.checkpoints().await.unwrap().is_empty());
}

#[test]
fn a_hand_built_tree_reads_as_devices() {
    let path = |p: &str| OwnedObjectPath::try_from(p).unwrap();
    let device = |name: &str, kind: u32| {
        HashMap::from([(
            interface::DEVICE.to_string(),
            group([
                ("Interface", Value::from(name)),
                ("DeviceType", Value::from(kind)),
                ("State", Value::from(100u32)),
                ("Ip4Config", Value::from(path("/"))),
            ]),
        )])
    };
    let objects = Objects::from([
        (
            path("/org/freedesktop/NetworkManager/Devices/1"),
            device("lo", 32),
        ),
        (
            path("/org/freedesktop/NetworkManager/Devices/2"),
            device("eth0", 1),
        ),
    ]);

    let devices = Device::from_objects(&objects);
    let read: Vec<_> = devices
        .iter()
        .map(|d| (d.interface.as_str(), d.kind))
        .collect();
    assert_eq!(
        read,
        [
            ("eth0", DeviceKind::Ethernet),
            ("lo", DeviceKind::Other(32))
        ]
    );
    assert_eq!(devices[0].state, DeviceState::Activated);
    assert_eq!(devices[0].ip4, None, "`/` links to nothing");
}
