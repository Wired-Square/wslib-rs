# wslib-systemd-notify

Tells systemd a service is ready, stopping or still alive: the sd_notify
protocol, a datagram to the socket in `$NOTIFY_SOCKET`, written directly, so
a static musl build needs no libsystemd.

```rust
wslib_systemd_notify::ready()?;
wslib_systemd_notify::status("serving on :443")?;

// With the `tokio` feature, beside the server:
tokio::spawn(wslib_systemd_notify::feed_watchdog(stop.clone().cancelled_owned()));

// On shutdown:
wslib_systemd_notify::stopping()?;
```

## What's here

- **`ready`, `status`, `stopping`, `watchdog`**: send `READY=1`, `STATUS=…`,
  `STOPPING=1` and `WATCHDOG=1`. **`notify`** sends any `KEY=value` fields in
  one datagram. A newline in a value, or a key that is empty or holds `=`, is
  refused as `InvalidInput` rather than sent as an extra line.
- Every call is a successful no-op when `$NOTIFY_SOCKET` is unset or empty, so
  the same binary runs outside systemd, and on targets other than Unix. The
  socket is an absolute path, or on Linux an abstract name written `@name`.
  The variable is read on every call and never unset.
- **`watchdog_interval`**: `WATCHDOG_USEC` as a `Duration`, or `None` when it
  is unset or invalid or `WATCHDOG_PID` names another process.
- **`feed_watchdog(stop)`** (feature `tokio`): sends `WATCHDOG=1` at once and
  then at half the interval until `stop` completes. It returns the first send
  that fails. Without a watchdog interval it sends nothing and only waits for
  `stop`, so it can be spawned or joined unconditionally.

## The unit file

```ini
[Service]
Type=notify
WatchdogSec=30
NotifyAccess=main
```

`Type=notify` holds the unit in "activating" until `READY=1`, so units ordered
after it start once it is actually serving. `WatchdogSec=` sets
`WATCHDOG_USEC` and restarts the service (with `Restart=on-watchdog` or
`always`) when no ping arrives within it. `NotifyAccess=main`, the default
for `Type=notify`, accepts messages only from the main process; use `all` if
a child sends them.
