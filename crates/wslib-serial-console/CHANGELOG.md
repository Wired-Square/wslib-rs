# Changelog

## 0.1.0

- The console's wire types, always built: `ConsoleEvent`, `MonitorState`
  and its `label`, `Span`, `Participant`, `ConsoleAction`, `Finished` and
  `EndReason`. `Attached` carries the port's actual `baud`, and `Refused` a
  `RefusalReason` (`paused`, `no_active_reader`, `not_permitted`) with an
  optional `detail`. `ts` derives `ts_rs::TS` (ts-rs 12) on each.

- `monitor`: `Monitors`, one monitor per `PortKey` (a path or a USB serial,
  resolved afresh at every open, parsed from its `Display`), over
  wslib-serial's port task. A
  `Subscription` is told the monitor's state, then the replay its `Bounds`
  ask for from the always-on ring, then live `Update`s until `wait_for`,
  `lines`, `duration_ms` or `timeout_ms` ends it, or a replay without
  `follow` does. A lost line is reopened after a wait doubling from
  `reopen` to `reopen_max`, keeping the ring and every subscriber; a failed
  write or reset loses the line as a failed read does, which
  `FakeDevice::fail_writes` fakes.
  A subscriber more than `broadcast` reads behind misses those reads.
  `join` puts a subscriber in the shared session, as does its `Seat` from
  any task, and either changes its names later: each echo is attributed
  to its writer in a colour of their own, input with no echo within 300 ms
  is a count and its control keys, never the bytes, and the roster reaches
  everyone. `pause` and `resume` let go of the port for a flash, refusing
  input rather than queuing it; `progress` shows the flash's progress;
  `release` closes the port for another program, and `is_monitored` says
  whether a monitor holds it. `write` and `reset`
  attribute and pulse DTR. `test-support`: `FakePorts` and `StopReaders`.

- `ws`: `console`, the axum `GET` for `/ws/serial`: device bytes in binary
  frames both ways, `ConsoleEvent` text frames out and `ConsoleAction` in.
  `ConsoleHooks<S>` names the attendee, and whether they write, and may
  refuse a port, each given the router's state for extractors that need
  it. A console with bounds in its `ConsoleQuery` is a read-only stream
  ending with `Finished`. A refused write or reset reaches only the console
  that sent it. A console naming no port is upgraded, sent an `error` frame
  saying so, and closed. `frames` and `text_frame` turn an `Update` or a
  wire type into the frames a console is sent, for a host relaying them.
