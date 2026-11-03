# Changelog

## 0.1.1

- tokio's floor is 1.53.3, futures-util's 0.3.34.

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
- avahi publishes are `Send` and own their group before filling it, so a
  publish dropped while filling or committing frees the group.
- `Error::NotRunning` when nothing owns `org.freedesktop.Avahi`;
  `Error::Collision` keeps the bus's error. The avahi functions answer
  `Error` rather than `zbus::Error`.
- `set_host_name` takes avahi's `NoChangeError` as done.
- `AddressGroup::publish` takes any iterator of `(interface, address)`;
  `avahi::own_addresses` picks them as avahi does for its own name.
- `FakeAvahi`: real error names (`ServiceUnknown` while stopped, for every
  call including `GetHostName`), `GetHostName` and refused calls recorded,
  `refuse_next`, `forgive`, `hold`, and `NoChangeError` for a rename to the
  same name.
- `FakeAvahi` sends every signal from avahi's current unique name, which
  moves with `restart` and `stop` and is read with `owner()`, and answers
  `GetNameOwner`, so its signals still reach the client after a restart.
