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
- `Invalid` converts into `Error`. `Txt::pairs` builds entries from
  `(key, value)` pairs.
- `InstanceName` compares and hashes without regard to ASCII case, and keeps
  its spelling.
- In-process advert states are followed on one thread per daemon rather
  than a task, so `Established` follows the announcement without the
  caller's runtime, and `advertise` no longer needs a tokio runtime.
- In-process instance names with a dot or backslash read the same in
  `Resolved`, `Removed` and `Renamed`.
