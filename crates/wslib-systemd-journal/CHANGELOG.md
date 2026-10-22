# Changelog

## 0.1.0

- `Query`: a bounded `journalctl --output=json` read, newest first. `Source`
  (all, the kernel, or units with globs), `Priority`, `Since` (this boot or a
  span ago), a line bound (200), a timeout (10 s), an output bound (8 MiB) and
  a message bound (4 KiB). `with_program` runs another journalctl. Unit names
  are checked before it runs, and nothing goes through a shell.
- `Excerpt` gives the `Entry`s and whether the journal held more than the
  line or output bound let through. A field journald writes as bytes or
  repeats is read; an entry without a timestamp is dropped.
- `Error` keeps `NotInstalled`, `Io`, `Exited`, `Timeout`, `Lines` and `Unit`
  apart. Nothing is logged.
