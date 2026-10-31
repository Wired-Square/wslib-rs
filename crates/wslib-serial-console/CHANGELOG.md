# Changelog

## 0.1.0

- The console's wire types, always built: `ConsoleEvent`, `MonitorState`
  and its `label`, `Span`, `Participant`, `ConsoleAction`, `Finished` and
  `EndReason`. `Attached` carries the port's actual `baud`, and `Refused` a
  `RefusalReason` (`paused`, `no_active_reader`, `not_permitted`) with an
  optional `detail`. `ts` derives `ts_rs::TS` (ts-rs 12) on each.
