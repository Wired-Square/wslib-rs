# Changelog

## 0.1.4

- A default filter that does not parse is warned about once the subscriber is
  installed, as a bad `RUST_LOG` is, and the directives of it that parse are
  used, or `info` when none does. `warning`, in any case, is read as `warn`,
  where tracing took a bare `WARNING` for a target and logged nothing.
- Empty directives are skipped and each is trimmed, under `setup-core` as under
  `setup`: `Targets` read an empty one, as in `"foo=info,"`, as a global
  `error`. A default filter with no directives is `info`, with a warning, as
  one that does not parse is; a `RUST_LOG` of only commas and spaces counts as
  unset.
- Docs: a `RUST_LOG` that parses replaces the default filter rather than
  adding to it.

## 0.1.3

- `setup-core` is `Telemetry` without tracing-subscriber's `env-filter`, and so
  without its regex engine: `RUST_LOG` and the default filter are target and
  level directives only. `setup` is `setup-core` with `env-filter`, as before.

## 0.1.2

- Dependency floors raised: tracing-subscriber 0.3.20, for RUSTSEC-2025-0055
  (the crate compiles from 0.3.17), and tracing 0.1.41, which it requires.

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
