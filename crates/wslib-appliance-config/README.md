# wslib-appliance-config

An appliance's bootstrap settings: what has to be known before there is a
database. Where the database lives, what to listen on, which certificate to
serve, and a product's own `[app]` table; everything operational belongs in the
database instead.

```rust
use clap::Parser;
use wslib_appliance_config::{ApplianceArgs, Resolver, ServingArgs};

#[derive(Parser)]
struct Cli {
    #[command(flatten)]
    appliance: ApplianceArgs,
    #[command(flatten)]
    serving: ServingArgs,
}

let cli = Cli::parse();
let boot = Resolver::new("widget", "WIDGET")
    .serving(&cli.serving)
    .resolve(&cli.appliance)?;
let db = open(&boot.db);
```

## How a setting is settled

- **`flag > env > file > package > default`.** The flag is `--db`, the
  variable `WIDGET_DB`, the key `db` in `config.toml` (`--config`,
  `WIDGET_CONFIG`, else `$CONFIGURATION_DIRECTORY/config.toml`). The package's
  file is `WIDGET_PACKAGE_CONFIG`, environment-only and absolute; it takes the
  same keys but not `[app]`.
- **Every source that answered and lost is warned about**, naming both
  spellings; a package value that loses is not.
- **An unrecognised key in either file refuses to start**, naming every one.
  `[app]` is carried verbatim as `Bootstrap::app` and never checked.
- **Defaults follow systemd's directories**: `$STATE_DIRECTORY/<name>.db`,
  `$RUNTIME_DIRECTORY/<name>.sock` (a named pipe on Windows), the TLS pair
  `cert.pem` and `key.pem` in `$STATE_DIRECTORY`, `0.0.0.0:8443`, no
  redirect, base path `/`. Run by hand, they are relative to the working
  directory.
- **`ui`** defaults to `default_ui_dir(name)`, `/usr/share/<name>/ui`. A path
  someone named must be a directory; the default may be missing (headless).
- **`Tls::named`** says whether either half of the pair was named, so a
  caller knows whether the files are its to replace.
- **Environment-only switches**: `<PREFIX>_ONBOARDING` (`browser` or
  `socket`), and `<PREFIX>_APP_SOCKET` with `<PREFIX>_CONSOLE_UID` (and
  optionally `<PREFIX>_HOOKS_SOCKET`) for an app served behind a console,
  as `Bootstrap::proxied`.
- **No flag has a default or an `env`**: every field of the clap groups is an
  `Option`, so a flag never hides a file key.
- **`ServingArgs` is a group of its own**, so a product behind a console
  offers no listener flags, and a host with listener flags of its own still
  flattens `ApplianceArgs`. Without it the listener resolves from the
  environment, the files and the defaults.

`toml` and `wslib-http-scaffold`'s `BasePath` are re-exported.
