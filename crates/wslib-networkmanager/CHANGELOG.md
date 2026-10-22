# Changelog

## 0.1.0

- `Client` over a zbus 5 connection, tokio only, properties uncached.
- `devices` reads the object tree into `Device`s: kind, `DeviceState` and
  reason (with `reason` constants), managed, MAC, carrier, live `IpConfig`
  for each family, the active profile, access points and the associated one.
  `unplugged`, `addresses` and `networks` (strongest per SSID).
- `scan` requests a scan, waits up to 7.5 s for `LastScan`, and answers the
  networks, a refused scan included.
- `Security` from an access point's flag words; `Device::wifi_profile`
  builds a join's profile from it, refusing WEP, 802.1X and a missing
  passphrase with `JoinError`; `add_and_activate` starts it.
- Checkpoints: `create_checkpoint` with the `checkpoint` flags,
  `destroy_checkpoint`, `roll_back` with each device's `RollbackResult`, and
  `checkpoints`.
- Profiles: `profiles`, `settings`, `update_profile` (to disk),
  `delete_profile`, and `apply` (`Reapply`, else activation). `Ipv4` and
  `set_ipv4` write an `ipv4` group; `ProfileIpv4` and `connection_type` read
  one.
- `wifi_radio` and `set_wifi_enabled` for `WirelessEnabled`, with the kill
  switch as `hardware_enabled`.
- Proxies: `NetworkManagerProxy`, `NmObjectsProxy`, `NmSettingsProxy`,
  `DeviceProxy`, `WirelessProxy` and `ProfileProxy`.
- `testing::FakeNetworkManager` behind the `testing` feature, on Unix.
