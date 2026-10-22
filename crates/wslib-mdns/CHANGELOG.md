# Changelog

## 0.1.0

- `ServiceType`, `Subtype`, `InstanceName`, `Txt` and `HostName`, checked
  on parse with `Invalid` naming the rule.
- `Service`, `Resolved` and `BrowseEvent`.
- `Advert`, withdrawn on drop or by `withdraw`, with a watch of
  `AdvertState`: `Registering`, `Established`, `Collided`, `Renamed` or
  `Failed`.
- `InProcess` behind `in-process`, over mdns-sd 0.21, kept out of the API:
  `Options` with `Interfaces` and `Host` (by default not the machine's own
  name), `advertise` with the host's addresses kept current, `browse` and
  `Browse::verify`.
- `avahi::Avahi` behind `avahi`, over zbus 5: `advertise` in an entry group,
  `AddressGroup`, `is_running`, `host_name`, `set_host_name`, `restarts`,
  `server_states` and `renamed_by_avahi`.
- `Responder` with both: avahi where it runs, else in process.
- `testing::FakeAvahi` behind `testing`, on Unix.
