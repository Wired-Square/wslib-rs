# wslib-systemd-journal

Reads the systemd journal through `journalctl --output=json`: a bounded
query, newest entry first, parsed into typed entries, with word of whether
the journal held more. No libsystemd and no shell.

```rust
use wslib_systemd_journal::{Priority, Query, Since, Source};

let excerpt = Query::default()
    .with_source(Source::Units(vec!["sshd@*.service".into(), "sshd.socket".into()]))
    .with_priority(Priority::Warning)
    .with_since(Since::Ago(Duration::from_secs(3600)))
    .with_lines(50)
    .read()
    .await?;
```

## What's here

- **`Query`**: `/usr/bin/journalctl` by default (`with_program` for another,
  or a fake script in tests). `Source::All`, `Kernel` (`--dmesg`, this boot)
  or `Units`, whose names may hold journalctl's globs and are checked against
  systemd's unit name characters before anything runs. `Priority` and more
  urgent; `Since::Boot` or `Since::Ago(span)`. Bounds: 200 entries, 10 s,
  8 MiB of output and 4 KiB of each message, all settable. journalctl is
  killed at the timeout or the output bound.
- **`Excerpt`**: the `Entry`s, newest first, and `truncated`, set when the
  journal held more than the line bound (one extra line is asked for to tell)
  or the output bound was reached.
- **`Entry`**: `at` as a `SystemTime`, `priority` (`Info` when absent),
  `unit` (`_SYSTEMD_UNIT`, else `UNIT`), `identifier`, `pid` and `message`,
  cut at a character boundary and ended with `…` past its bound. A field
  journald writes as an array of bytes (not UTF-8) is read lossily; a field
  repeated in one entry keeps its first value. A line that isn't JSON, or an
  entry without `__REALTIME_TIMESTAMP`, is dropped.
- **`Error`** keeps `NotInstalled`, `Io`, `Exited` (journalctl's status),
  `Timeout`, `Lines` (a bound of 0) and `Unit` (a name refused) apart.
  Nothing is logged.

## What isn't

Following the journal, cursors, matches on other fields (`--identifier`,
`_PID`), other machines' or files' journals, and fields beyond the six above.
journalctl's stderr is discarded.
