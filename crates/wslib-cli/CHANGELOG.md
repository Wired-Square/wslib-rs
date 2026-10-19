# Changelog

## 0.1.0

- `Output`: human or JSON, from a global `--json` flag. `rows` draws a
  comfy-table for a person and pretty JSON for a program; `value` takes the
  caller's rendering for a single value. `OutputArgs` (feature `clap`) is the
  flag to flatten into a parser.
- `Exit`: 0 success, 1 failure, 2 usage, 3–123 the tool's own, 124 timeout,
  130 interrupted. `Exit::of` maps an error by its source chain, and
  `exit::fail` reports it on stderr, as JSON in JSON mode.
- `config::Discovery`: the config file is the named one, `<PREFIX>_CONFIG`, or
  `<app>/config.toml` under `$XDG_CONFIG_HOME` or `~/.config`, on macOS too;
  `var` reads a `<PREFIX>_<KEY>` override. `load` (feature `toml`) parses it.
- `op` (feature `op`): `resolve` reads a value that is an `op://` reference
  with `op read`, through a `ReadReference` that tests can fake.
