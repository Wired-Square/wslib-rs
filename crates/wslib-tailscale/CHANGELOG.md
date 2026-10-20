# Changelog

## 0.1.0

- `LocalApi`: tailscaled's LocalAPI over its Unix socket, by hand-written
  HTTP/1.0. `status`, `status_within`, `prefs`, `logout`, `reset_auth`, and a
  raw `request`. Reads wait 5 s, changes 30 s, both settable; answers are
  capped at 1 MiB. `Absent` off Unix.
- `Status` with a `BackendState` that keeps unknown states, the own node,
  addresses and health; `null` lists read as empty. `Status::enrolled` is the
  name unless the node needs a login. `Prefs` with the control URL.
- `Error` keeps `Absent`, `Silent`, `Refused` (status and first line),
  `Malformed` and `Io` apart. No logging.
- `is_tailnet_address` for Tailscale's IPv4 and IPv6 ranges, unmapping
  IPv4-mapped addresses.
- `testing::FakeTailscaled` behind the `testing` feature: node state, a log of
  request lines, stop and start, silent and refusing modes.
