# wslib-systemd

Typed zbus proxies for the systemd services an appliance drives over D-Bus:
the manager and its units, hostnamed, timedated, timesyncd and logind. Ways
to read their refusals, so a host without the service or a caller without
permission is told apart from a failed call. Hostname validation that names
the rule a name broke. Fake services for tests come with the `testing`
feature.

```rust
let bus = zbus::Connection::system().await?;
let hostname = wslib_systemd::HostnameProxy::new(&bus).await?;
let name = wslib_systemd::clean_hostname(asked)?;
match hostname.set_static_hostname(name, false).await {
    Err(e) if wslib_systemd::refused(&e) => println!("not permitted"),
    Err(e) if wslib_systemd::nobody_owns(&e) => println!("no hostnamed here"),
    other => other?,
}
```

## What's here

- **Proxies**, each with its service's default name and path:
  `SystemdProxy` (`org.freedesktop.systemd1.Manager`: start, stop, restart
  and try-restart a unit, mask and unmask unit files, reload, a unit file's
  state, `LoadUnit`, `ListUnitsFiltered` as `UnitRow`s, and
  `FinishTimestampMonotonic`); `UnitProxy` (`LoadState`, `ActiveState`,
  `Job`), which takes the path `LoadUnit` gave when it is built;
  `HostnameProxy` (set the static and transient names, read both);
  `TimedateProxy` (zone, NTP switch, time, the zone list, `NTP`, `CanNTP`,
  `NTPSynchronized`); `TimesyncProxy` (`ServerName`); `Login1Proxy`
  (reboot, power off, and whether each is possible). hostnamed and timedated
  are activatable, so the first call is also the probe for whether they are
  installed. Pass `interactive` as `false` on a headless box: with no polkit
  agent, an interactive call waits for an answer nobody gives.
- Only the members a consumer uses are declared, since each one is something
  more to drift from the service. A new member is an additive 0.1.x release;
  until it ships, declare your own `#[zbus::proxy]` for anything missing.
- **Refusals**, read from any `zbus::Error`: `error_is(&e, name)` for one
  D-Bus error name; `nobody_owns(&e)` when the service is not installed, or
  its unit is disabled or masked (the names in `NOBODY_OWNS_IT`, as
  dbus-daemon and dbus-broker each say it); `refused(&e)` for `AccessDenied`
  and `InteractiveAuthorizationRequired` (`REFUSALS`), typically a caller
  that is not root. What each means to the app is the app's to map. Nothing
  is logged.
- **`clean_hostname`**: trims a name and accepts it if every dot-separated
  part is an RFC 1123 label of ASCII letters, digits and inner hyphens, at
  most `MAX_HOSTNAME_LEN` (63) bytes in all. Stricter than hostnamed, since
  the name lands in certificates, mDNS and URLs, and a newline in it would
  forge a log line. A refusal is a `HostnameError` naming the rule, with a
  sentence for each to show the user.
- **`testing::Fakes`** (feature `testing`, Unix only): interface objects at
  object paths, served in-process over a socket pair. `connect` gives the
  peer-to-peer client connection and the fakes' end, which must be kept
  alive. No bus is touched. Write the fakes in the test, with whatever the
  test needs them to do.

## What isn't

NetworkManager, Avahi, BlueZ and RAUC. Any policy over which units to
start or what a refusal means, which stays with the app.
