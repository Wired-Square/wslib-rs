# Changelog

## 0.2.0

- `ConfigError::Read` and `ConfigError::Parse` hold the `io::Error` and the
  `toml::de::Error` as `source`, in place of their text in `because`, and say
  only that the file cannot be read or parsed.
- `ConfigError::AppInPackage` is an `[app]` table in the package's file,
  which was a `Parse` with a sentence.
- `ConfigError::EnvUnusable` is an environment value that did not parse, or a
  `<PREFIX>_PACKAGE_CONFIG` file that could not be read, with the parser's or
  the read's error as `source`; `Env` keeps this crate's own sentences.
- `ConfigError::UiUnreadable` is a named browser bundle whose metadata could
  not be read, with the `io::Error` as `source`; `Ui` keeps the sentence for
  one that is not a directory.
- `ConfigError` no longer derives `Clone`, `PartialEq` or `Eq`.

## 0.1.2

- The README says when a host flattens `ApplianceArgs`. No code change.

## 0.1.1

- Dependency floor: `wslib-http-scaffold` 0.1.3 (was 0.1.1), the floor the
  rest of the family takes. No change to the API.

## 0.1.0

- Moved from `appliance-config` 0.17.1 in wslib-appliance-rs, unchanged:
  `Resolver` (`new`, `serving`, `resolve`), `Bootstrap`, `Tls`, `Proxied`,
  `ConfigError`, `default_ui_dir`, the clap groups `ApplianceArgs` and
  `ServingArgs`, and `BasePath` and `toml` re-exported.
