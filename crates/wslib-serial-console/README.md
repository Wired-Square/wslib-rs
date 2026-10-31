# wslib-serial-console

A serial console that every browser on a port shares: the JSON it speaks,
the port's monitor, and the `/ws/serial` handler. Device bytes travel in
binary frames; everything else is a `ConsoleEvent` text frame.

```rust
use wslib_serial_console::{Monitors, MonitorOptions, ws};

let monitors = Monitors::new(MonitorOptions::default());
let app = axum::Router::new().route("/ws/serial", ws::console(monitors.clone(), hooks));
// a flash takes the port, and gives it back
monitors.pause(&key).await;
monitors.resume(&key);
```

- The wire types need no feature: `ConsoleEvent`, `MonitorState`, `Span`,
  `Participant`, `ConsoleAction` and `Finished`.
- `Monitors`: one monitor per port, keyed by its path or its USB serial,
  which is resolved at every open so a replug can move it. It keeps a ring
  of recent output for `tail` and `since_ms`, reopens a lost line, and
  attributes each echo to whoever typed it. Input the device doesn't echo
  within 300 ms is shown as a count, never the bytes. A flash `pause`s the
  port: its consoles stay attached and their input is refused, not queued.
- `ws::console`: a console with no bounds joins the shared session and may
  type if `ConsoleHooks::attendee` says so; one with bounds is a read-only
  stream ending with `Finished`. `ConsoleHooks::may_open` can refuse a port,
  as when an app holds it.

## Features

None is on by default; without one the crate is serde types alone.

- `monitor`: `Monitors`, over wslib-serial's port task.
- `ws`: `ws::console`, through axum.
- `ts`: derives `ts_rs::TS` (ts-rs 12) on the wire types;
  `cargo test --features ts` pins their declarations.
- `test-support`: `FakePorts`, devices a test plugs in and drives, and
  `StopReaders`, which stops every monitor when dropped.
