# wslib-networkmanager

NetworkManager over D-Bus, typed: devices and what they have now, Wi-Fi scan
and join, checkpoints that NetworkManager rolls back by itself, profile
updates, and the Wi-Fi radio. A fake NetworkManager for tests comes with the
`testing` feature.

```rust
use wslib_networkmanager::{Client, DeviceKind, checkpoint};

let nm = Client::new(zbus::Connection::system().await?);
let devices = nm.devices().await?;
let wifi = devices.iter().find(|d| d.kind == DeviceKind::Wifi).ok_or("no Wi-Fi")?;
let networks = nm.scan(&wifi.path).await?;

let profile = wifi.wifi_profile(b"Ops", Some(passphrase))?;
let undo = nm
    .create_checkpoint(&[&wifi.path], 180, checkpoint::DESTROY_ALL | checkpoint::DELETE_NEW_CONNECTIONS)
    .await?;
nm.add_and_activate(profile, &wifi.path).await?;
// Still reachable? Keep it; otherwise NetworkManager undoes it in 180 s.
nm.destroy_checkpoint(&undo).await?;
```

## What's here

- **`Client`** on any `zbus::Connection`, reading properties fresh on every
  call. Nothing is logged, and every call answers a `zbus::Error`: read it
  with `wslib-systemd`'s `nobody_owns` (a host on some other network stack)
  and `refused` (polkit or bus policy).
- **`devices`**: every device off one `GetManagedObjects`, by interface name,
  each a `Device`: kind, `DeviceState` and its reason (the ones worth acting
  on named in `reason`), managed or not, MAC, carrier, the live IPv4 and IPv6
  `IpConfig` (addresses, gateway, resolvers), the profile behind the active
  connection, and for Wi-Fi the access points and the one it is associated
  with. `unplugged()` reads `Carrier`, since NetworkManager does not reliably
  leave `CARRIER` as the reason; `networks()` is one access point per SSID,
  the strongest.
- **`scan`** asks for a scan and waits up to 7.5 s for `LastScan` to move,
  then answers the device's networks. NetworkManager refuses a scan while one
  runs or just after, and the list it holds is answered all the same.
- **`Security`**, read off an access point's three flag words: open, WEP,
  OWE, WPA-PSK, WPA3-SAE alone (a mixed network is PSK) and 802.1X.
- **`Device::wifi_profile`** builds a join's profile, secured as the
  strongest access point by that name asks: a WPA3-only network refuses
  `wpa-psk`. Out of range it is WPA-PSK with a passphrase and open without. A
  passphrase for a network that takes none is not sent. WEP and 802.1X are a
  `JoinError`, as is a missing passphrase. **`add_and_activate`** adds and
  starts it; a wrong passphrase shows afterwards as the device `Failed` with
  `NO_SECRETS`, not as the call's error.
- **Checkpoints**: `create_checkpoint` over devices with a timeout and the
  `checkpoint` flags, `destroy_checkpoint` to keep what changed,
  `roll_back` to undo it now (each device's `RollbackResult`), and
  `checkpoints` for those NetworkManager still holds. The timer runs inside
  NetworkManager, so it outlives the process that set it; neither a reboot
  nor a NetworkManager restart rolls one back, they just lose it.
- **Profiles**: `profiles`, `settings` (secrets left out), `update_profile`
  (written to disk), `delete_profile`, and `apply`: `Reapply` in place, or
  activation when NetworkManager cannot change it in place.
- **`Ipv4`** writes a whole `ipv4` group, `set_ipv4` puts it in a profile's
  settings. No gateway is an absent key, never `""`, which NetworkManager
  refuses; resolvers are packed in host byte order with `ignore-auto-dns`;
  DHCP writes an empty `address-data`. **`ProfileIpv4`** reads one back, and
  `connection_type` a profile's type.
- **`wifi_radio`** reads `WirelessEnabled` and the kill switch,
  `WirelessHardwareEnabled`; `set_wifi_enabled` turns the first, which
  NetworkManager persists, and which does nothing under the second.
- **Proxies** for the root object, the object tree, `Settings`, a device, a
  Wi-Fi device and a profile, declaring only the members used; `manager()`
  gives the root's for anything the client does not wrap.
- **`testing::FakeNetworkManager`** (feature `testing`, Unix only): wired and
  Wi-Fi devices with addresses, profiles and access points, served in-process
  over a socket pair. A join succeeds with the access point's passphrase and
  otherwise leaves the device `Failed`; checkpoints snapshot and restore, and
  `expire_checkpoints` plays the timer. It records each call that changes
  something and can be told to refuse a method.

## What isn't

What to manage and when to change it: which devices a product shows, the
words for a state or a security, waiting for confirmation before the
deadline and remembering a checkpoint across a restart. Hidden networks,
WEP and 802.1X joins, IPv6 addressing, VPNs, and signals.
