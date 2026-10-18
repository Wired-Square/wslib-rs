# Changelog

## 0.1.2

- Dependency floors raised to what the crate compiles against:
  tracing-subscriber 0.3.17, tracing 0.1.40.

## 0.1.1

- The ring strips `user:password@` from URLs in a message or field value,
  keeping the host. `strip_userinfo` is public.

## 0.1.0

- Promoted from `Logs` in `appliance-core`, and `LogLevel`, `LogRecord`,
  `LogSnapshot`, `LOG_RING` and `LOG_TEXT_MAX` in `appliance-types`, in
  wslib-appliance-rs. The types' docs, and so their TypeScript, are unchanged.
- `Logs` captures only the targets its maker names, a crate or a `prefix*`;
  the chassis's own prefix is no longer built in. `Logs::builder` gives fields
  a budget of their own (`own_budget`), extends the redacted names
  (`redact`) and names the log file (`writing_to`).
- Records are stamped to the microsecond, which is what a SQLite round-trip
  gives back. A cut value ends with the public `TRUNCATED`.
- `Logs::tap` replaces the audit bridge: a bounded queue of records whose event
  carries a given name, opened at the call, with lost records counted for the
  drain to report. `close_tap` lets the drain finish and end.
- `snapshot`, `subscribe`, `uptime`, `started_at` and `truncate` are public.
- `Telemetry` installs one subscriber: `RUST_LOG` or the caller's default
  filter, with a warning when `RUST_LOG` does not parse; text, `json` or
  `journald` output; colour only on a terminal without `NO_COLOR`; and
  optionally the ring.
- Features: `setup` and `ansi` by default; `types` needs no `tracing` or
  tokio; `ring`, `ts`, `json`, `journald` and `test-support` are opt-in.
