//! The settings that have to be known before there is a database.
//!
//! The order is `flag > env > file > package > default`; an unrecognised key in
//! either file refuses to start, and each setting read and ignored is warned
//! about, unless the package's value lost. A product's own keys go under `[app]`.
//!
//! The package's file is `<PREFIX>_PACKAGE_CONFIG`: absolute, readable, and
//! without `[app]`. Defaults come from systemd's `STATE_DIRECTORY`,
//! `RUNTIME_DIRECTORY` and `CONFIGURATION_DIRECTORY`, and are relative without
//! them; `ui` defaults to [`default_ui_dir`].
//!
//! Environment-only: `<PREFIX>_PACKAGE_CONFIG` (unset or blank is no such
//! layer), `<PREFIX>_ONBOARDING` (`browser` or `socket`), and
//! `<PREFIX>_APP_SOCKET` with `<PREFIX>_CONSOLE_UID`, both or neither, with an
//! optional `<PREFIX>_HOOKS_SOCKET` beside them.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;

mod args;
mod file;

pub use args::{ApplianceArgs, ServingArgs};
use file::FileConfig;
/// Re-exported, because [`Bootstrap::base_path`] is one.
pub use wslib_http_scaffold::BasePath;

/// Re-exported, because [`Bootstrap::app`] is one of its types.
pub use toml;

/// A setting more than one source answered: the losing spelling and the one in force.
#[derive(Debug, PartialEq, Eq)]
struct Shadowed {
    ignored: String,
    winner: String,
}

/// Everything that has to be known before the database is open; only
/// [`Resolver::resolve`] builds one.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Bootstrap {
    /// [`Resolver::new`]'s `name`.
    pub name: String,
    /// systemd's `StateDirectory=`, or empty for the working directory.
    pub state_dir: PathBuf,
    /// `ConfigurationDirectory=`, else a named configuration file's directory,
    /// else empty for the working directory.
    pub config_dir: PathBuf,
    pub db: PathBuf,
    /// The address both listeners bind.
    pub bind_address: IpAddr,
    pub https_port: u16,
    /// `None` when the http-to-https redirect is switched off.
    pub redirect_port: Option<u16>,
    pub socket: PathBuf,
    pub tls: Tls,
    /// The built browser bundle, or `None` for an appliance that serves only
    /// its API; a path somebody named refuses when it cannot be served from,
    /// and the default location never does.
    pub ui: Option<PathBuf>,
    /// What the TLS listener or the app socket serves every route under.
    pub base_path: BasePath,
    /// The file these were resolved against, whether or not it existed.
    pub config_path: PathBuf,
    #[doc(hidden)]
    pub env_prefix: String,

    /// The configuration file's `[app]` table, verbatim and unchecked.
    pub app: toml::Table,

    /// `<PREFIX>_ONBOARDING=browser`: a box with no accounts offers its first one
    /// to the browser, not only over the control socket.
    pub browser_onboarding: bool,

    /// Set when the app serves behind a console's proxy rather than on the network.
    pub proxied: Option<Proxied>,
}

/// Where a console's proxy reaches the app, the uid it connects as, and
/// where it calls the app's hooks.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Proxied {
    /// An absolute path with no `..`.
    pub app_socket: PathBuf,
    pub console_uid: u32,
    /// `<PREFIX>_HOOKS_SOCKET`: an absolute path with no `..`, not
    /// `app_socket`; `None` serves no hooks.
    pub hooks_socket: Option<PathBuf>,
}

/// The certificate to serve and its key, defaulting under the state directory;
/// a half not named takes its default.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Tls {
    pub cert: PathBuf,
    pub key: PathBuf,

    /// Whether either half was named; only an unnamed pair is the appliance's
    /// to replace.
    pub named: bool,
}

impl Tls {
    /// The pair an appliance nobody gave a certificate makes for itself:
    /// `cert.pem` and `key.pem` under `dir`, the state directory.
    pub fn default_in(dir: &Path) -> Self {
        Self {
            cert: dir.join("cert.pem"),
            key: dir.join("key.pem"),
            named: false,
        }
    }

    /// A pair somebody named at least one half of; the other may be the default.
    pub fn supplied(cert: PathBuf, key: PathBuf) -> Self {
        Self {
            cert,
            key,
            named: true,
        }
    }
}

/// File keys an earlier release read, refused by name rather than as unknown.
const RETIRED_KEYS: &[&str] = &["ssh_user"];

/// Why the bootstrap settings could not be resolved.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    #[error("{}: {because}", path.display())]
    Read { path: PathBuf, because: String },

    #[error("{}: {because}", path.display())]
    Parse { path: PathBuf, because: String },

    #[error("{}: unrecognised {}: {}", path.display(), if keys.len() == 1 { "setting" } else { "settings" }, keys.join(", "))]
    UnknownKeys { path: PathBuf, keys: Vec<String> },

    #[error("{}: {key} is no longer read; delete it", path.display())]
    Retired { path: PathBuf, key: String },

    #[error("{var}={value:?} is not usable: {because}")]
    Env {
        var: String,
        value: String,
        because: String,
    },

    /// A browser bundle that was named and cannot be served from.
    #[error("the browser bundle at {}: {because}", path.display())]
    Ui { path: PathBuf, because: String },
}

/// Where a packaged browser bundle lives, for the product called `name`; a
/// packaging step stages it with this rather than a copy of the string.
pub fn default_ui_dir(name: &str) -> PathBuf {
    PathBuf::from(format!("/usr/share/{name}/ui"))
}

/// The bundle directory, or `None` when there is no bundle to serve, by the rule
/// on [`Bootstrap::ui`].
fn bundle_at(path: PathBuf, named: bool) -> Result<Option<PathBuf>, ConfigError> {
    // Not inside the `tracing` macros: their fields are evaluated only when a
    // subscriber listens, so the tests would never run it.
    let (missing, because) = match std::fs::metadata(&path) {
        Ok(meta) if meta.is_dir() => return Ok(Some(path)),
        Ok(_) => (false, "this is not a directory".to_string()),
        Err(e) => (e.kind() == std::io::ErrorKind::NotFound, e.to_string()),
    };

    if named {
        return Err(ConfigError::Ui { path, because });
    }
    if missing {
        tracing::info!(
            ui = %path.display(),
            "no browser bundle here, so this appliance serves its API and nothing else"
        );
    } else {
        tracing::warn!(
            ui = %path.display(),
            because = %because,
            "there is something at the default browser-bundle location that cannot be served \
             from, so this appliance is serving its API only"
        );
    }
    Ok(None)
}

/// The file at `path`, refusing a retired or unrecognised key outside `[app]`.
fn known_keys_from(path: &Path, named: bool) -> Result<FileConfig, ConfigError> {
    let file = FileConfig::load(path, named)?;
    let unknown = file.unknown_keys();
    if let Some(key) = unknown
        .iter()
        .find(|key| RETIRED_KEYS.contains(&key.as_str()))
    {
        return Err(ConfigError::Retired {
            path: path.to_path_buf(),
            key: key.clone(),
        });
    }
    if !unknown.is_empty() {
        return Err(ConfigError::UnknownKeys {
            path: path.to_path_buf(),
            keys: unknown,
        });
    }
    Ok(file)
}

fn warn_about_shadowed(path: &Path, shadowed: &[Shadowed]) {
    for s in shadowed {
        tracing::warn!(
            config = %path.display(),
            ignored = %s.ignored,
            winner = %s.winner,
            "this setting is being ignored — it is answered somewhere else, and that wins"
        );
    }
}

/// Resolves the bootstrap settings for the product whose files are spelt `name`
/// and whose variables start `env_prefix`.
#[derive(Debug, Clone)]
pub struct Resolver {
    name: String,
    env_prefix: String,
    serving: ServingArgs,
}

impl Resolver {
    pub fn new(name: impl Into<String>, env_prefix: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            env_prefix: env_prefix.into(),
            serving: ServingArgs::default(),
        }
    }

    /// The listener flags, for a product that flattens [`ServingArgs`].
    pub fn serving(mut self, args: &ServingArgs) -> Self {
        self.serving = args.clone();
        self
    }

    /// Read the file the flags point at and settle every setting against it.
    pub fn resolve(&self, args: &ApplianceArgs) -> Result<Bootstrap, ConfigError> {
        let (bootstrap, shadowed) = self.settle(args)?;
        warn_about_shadowed(&bootstrap.config_path, &shadowed);
        Ok(bootstrap)
    }

    fn settle(&self, args: &ApplianceArgs) -> Result<(Bootstrap, Vec<Shadowed>), ConfigError> {
        let config_dir = systemd_dir("CONFIGURATION_DIRECTORY");

        let named = args
            .config
            .clone()
            .or_else(|| self.env("CONFIG").map(PathBuf::from));
        let config_path = named
            .clone()
            .unwrap_or_else(|| config_dir.join("config.toml"));
        let config_dir = if config_dir.as_os_str().is_empty() {
            config_path
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_default()
        } else {
            config_dir
        };

        let file = known_keys_from(&config_path, named.is_some())?;
        warn_if_everyone_can_read(&config_path);
        let package = self.package_file()?;

        let state_dir = systemd_dir("STATE_DIRECTORY");
        let runtime_dir = systemd_dir("RUNTIME_DIRECTORY");
        let mut shadowed = Vec::new();
        let serving = &self.serving;

        let redirect_port = self
            .pick(
                Key::REDIRECT_PORT,
                serving.redirect_port,
                [file.redirect_port, package.redirect_port],
                &mut shadowed,
            )?
            .unwrap_or(0);

        let db = self
            .pick(
                Key::DB,
                args.db.clone(),
                [file.db, package.db],
                &mut shadowed,
            )?
            .unwrap_or_else(|| state_dir.join(format!("{}.db", self.name)));
        let bind_address = self
            .pick(
                Key::BIND_ADDRESS,
                serving.bind_address,
                [file.bind_address, package.bind_address],
                &mut shadowed,
            )?
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        let https_port = self
            .pick(
                Key::HTTPS_PORT,
                serving.https_port,
                [file.https_port, package.https_port],
                &mut shadowed,
            )?
            .unwrap_or(8443);
        let socket = self
            .pick(
                Key::SOCKET,
                args.socket.clone(),
                [file.socket, package.socket],
                &mut shadowed,
            )?
            .unwrap_or_else(|| default_socket(&runtime_dir, &self.name));
        let tls = {
            let cert = self.pick(
                Key::TLS_CERT,
                serving.tls_cert.clone(),
                [file.tls.cert, package.tls.cert],
                &mut shadowed,
            )?;
            let key = self.pick(
                Key::TLS_KEY,
                serving.tls_key.clone(),
                [file.tls.key, package.tls.key],
                &mut shadowed,
            )?;
            let default = Tls::default_in(&state_dir);
            match (cert, key) {
                (None, None) => default,
                (cert, key) => {
                    Tls::supplied(cert.unwrap_or(default.cert), key.unwrap_or(default.key))
                }
            }
        };

        let ui = match self.pick(
            Key::UI,
            args.ui.clone(),
            [file.ui, package.ui],
            &mut shadowed,
        )? {
            Some(asked_for) => bundle_at(asked_for, true)?,
            None => bundle_at(default_ui_dir(&self.name), false)?,
        };

        let base_path = self
            .pick(
                Key::BASE_PATH,
                args.base_path.clone(),
                [file.base_path, package.base_path],
                &mut shadowed,
            )?
            .unwrap_or_default();

        let bootstrap = Bootstrap {
            name: self.name.clone(),
            state_dir,
            config_dir,
            db,
            bind_address,
            https_port,
            redirect_port: (redirect_port != 0).then_some(redirect_port),
            socket,
            tls,
            ui,
            base_path,
            config_path,
            env_prefix: self.env_prefix.clone(),
            app: file.app,
            browser_onboarding: self.switch("ONBOARDING", "browser", "socket")?,
            proxied: self.proxied()?,
        };
        Ok((bootstrap, shadowed))
    }

    /// The file `<PREFIX>_PACKAGE_CONFIG` names, or an empty one when it is unset.
    fn package_file(&self) -> Result<FileConfig, ConfigError> {
        let Some(value) = self.utf8_env("PACKAGE_CONFIG")? else {
            return Ok(FileConfig::default());
        };
        let path = self.absolute_path("PACKAGE_CONFIG", value)?;
        let file = match known_keys_from(&path, true) {
            Err(ConfigError::Read { because, .. }) => {
                return Err(self.refuse("PACKAGE_CONFIG", path.display().to_string(), because));
            }
            loaded => loaded?,
        };
        if !file.app.is_empty() {
            return Err(ConfigError::Parse {
                path,
                because: "`[app]` is not read from the package's file; it belongs in the \
                          configuration file"
                    .into(),
            });
        }
        Ok(file)
    }

    /// `<PREFIX>_APP_SOCKET` and `<PREFIX>_CONSOLE_UID`: both or neither; and
    /// `<PREFIX>_HOOKS_SOCKET` only with them.
    fn proxied(&self) -> Result<Option<Proxied>, ConfigError> {
        let without = |other: &str| format!("set without {}_{other}", self.env_prefix);
        let hooks = self.utf8_env("HOOKS_SOCKET")?;
        match (self.utf8_env("APP_SOCKET")?, self.utf8_env("CONSOLE_UID")?) {
            (None, None) => match hooks {
                Some(hooks) => Err(self.refuse("HOOKS_SOCKET", hooks, without("APP_SOCKET"))),
                None => Ok(None),
            },
            (Some(socket), None) => Err(self.refuse("APP_SOCKET", socket, without("CONSOLE_UID"))),
            (None, Some(uid)) => Err(self.refuse("CONSOLE_UID", uid, without("APP_SOCKET"))),
            (Some(socket), Some(uid)) => {
                let app_socket = self.absolute_path("APP_SOCKET", socket)?;
                let console_uid = uid
                    .parse::<u32>()
                    .map_err(|e| self.refuse("CONSOLE_UID", uid, e.to_string()))?;
                let hooks_socket = hooks
                    .map(|hooks| match self.absolute_path("HOOKS_SOCKET", hooks)? {
                        same if same == app_socket => Err(self.refuse(
                            "HOOKS_SOCKET",
                            same.display().to_string(),
                            format!("the same path as {}_APP_SOCKET", self.env_prefix),
                        )),
                        hooks => Ok(hooks),
                    })
                    .transpose()?;
                Ok(Some(Proxied {
                    app_socket,
                    console_uid,
                    hooks_socket,
                }))
            }
        }
    }

    /// An absolute path with no `..`.
    fn absolute_path(&self, name: &str, value: String) -> Result<PathBuf, ConfigError> {
        let path = PathBuf::from(&value);
        if !path.is_absolute() {
            return Err(self.refuse(name, value, "not an absolute path".into()));
        }
        if path.components().any(|c| c == Component::ParentDir) {
            return Err(self.refuse(name, value, "has a `..` component".into()));
        }
        Ok(path)
    }

    /// An environment-only key: `on`, `off`, or absent or blank for off;
    /// anything else refuses.
    fn switch(&self, name: &str, on: &str, off: &str) -> Result<bool, ConfigError> {
        match self.env(name) {
            None => Ok(false),
            Some(value) if value == on => Ok(true),
            Some(value) if value == off => Ok(false),
            Some(value) => Err(self.refuse(name, value, format!("expected {on:?} or {off:?}"))),
        }
    }

    fn refuse(&self, name: &str, value: String, because: String) -> ConfigError {
        ConfigError::Env {
            var: format!("{}_{name}", self.env_prefix),
            value,
            because,
        }
    }

    /// The value of `<PREFIX>_<name>`, trimmed, if it is not blank.
    fn env(&self, name: &str) -> Option<String> {
        std::env::var(format!("{}_{name}", self.env_prefix))
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    }

    /// [`env`](Self::env), refusing a value that is not UTF-8 rather than
    /// reading it as unset.
    fn utf8_env(&self, name: &str) -> Result<Option<String>, ConfigError> {
        if let Err(std::env::VarError::NotUnicode(raw)) =
            std::env::var(format!("{}_{name}", self.env_prefix))
        {
            let value = raw.to_string_lossy().into_owned();
            return Err(self.refuse(name, value, "not UTF-8".into()));
        }
        Ok(self.env(name))
    }

    /// Settle one setting, recording every source but the package that answered
    /// and lost; `None` leaves the default to the caller.
    fn pick<T>(
        &self,
        key: Key,
        flag: Option<T>,
        [file, package]: [Option<T>; 2],
        shadowed: &mut Vec<Shadowed>,
    ) -> Result<Option<T>, ConfigError>
    where
        T: FromStr,
        T::Err: fmt::Display,
    {
        let env = match self.env(key.env) {
            Some(raw) => Some(raw.parse::<T>().map_err(|e| ConfigError::Env {
                var: key.spell(Source::Env, &self.env_prefix),
                value: raw.clone(),
                because: e.to_string(),
            })?),
            None => None,
        };

        let mut answered = [
            (Source::Flag, flag),
            (Source::Env, env),
            (Source::File, file),
        ]
        .into_iter()
        .filter_map(|(source, value)| value.map(|value| (source, value)));
        let Some((winner, value)) = answered.next() else {
            return Ok(package);
        };
        for (loser, _) in answered {
            shadowed.push(Shadowed {
                ignored: key.spell(loser, &self.env_prefix),
                winner: key.spell(winner, &self.env_prefix),
            });
        }
        Ok(Some(value))
    }
}

#[derive(Debug, Clone, Copy)]
enum Source {
    Flag,
    Env,
    File,
}

/// How one setting is spelt in each of the three sources; `env` is the suffix
/// after the product's prefix.
#[derive(Debug, Clone, Copy)]
struct Key {
    file: &'static str,
    flag: &'static str,
    env: &'static str,
}

impl Key {
    const DB: Key = Key {
        file: "db",
        flag: "--db",
        env: "DB",
    };
    const BIND_ADDRESS: Key = Key {
        file: "bind_address",
        flag: "--bind-address",
        env: "BIND_ADDRESS",
    };
    const HTTPS_PORT: Key = Key {
        file: "https_port",
        flag: "--https-port",
        env: "HTTPS_PORT",
    };
    const REDIRECT_PORT: Key = Key {
        file: "redirect_port",
        flag: "--redirect-port",
        env: "REDIRECT_PORT",
    };
    const SOCKET: Key = Key {
        file: "socket",
        flag: "--socket",
        env: "SOCKET",
    };
    const TLS_CERT: Key = Key {
        file: "tls.cert",
        flag: "--tls-cert",
        env: "TLS_CERT",
    };
    const TLS_KEY: Key = Key {
        file: "tls.key",
        flag: "--tls-key",
        env: "TLS_KEY",
    };
    const UI: Key = Key {
        file: "ui",
        flag: "--ui",
        env: "UI",
    };
    const BASE_PATH: Key = Key {
        file: "base_path",
        flag: "--base-path",
        env: "BASE_PATH",
    };

    #[cfg(test)]
    const ALL: [Key; 9] = [
        Key::DB,
        Key::BIND_ADDRESS,
        Key::HTTPS_PORT,
        Key::REDIRECT_PORT,
        Key::SOCKET,
        Key::TLS_CERT,
        Key::TLS_KEY,
        Key::UI,
        Key::BASE_PATH,
    ];

    fn spell(&self, source: Source, prefix: &str) -> String {
        match source {
            Source::Flag => self.flag.to_string(),
            Source::Env => format!("{prefix}_{}", self.env),
            Source::File => self.file.to_string(),
        }
    }
}

/// The configuration directory is traversable by every account, so the file is
/// as private as its own mode.
#[cfg(unix)]
fn warn_if_everyone_can_read(config_path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(metadata) = std::fs::metadata(config_path)
        && metadata.permissions().mode() & 0o004 != 0
    {
        tracing::warn!(
            config = %config_path.display(),
            "this file is readable by every account on this box; chmod 0640 if anything in it \
             is not theirs to read"
        );
    }
}

#[cfg(not(unix))]
fn warn_if_everyone_can_read(_config_path: &Path) {}

/// The first entry of a systemd directory variable, which is a colon-separated
/// list; absent is the empty path.
fn systemd_dir(var: &str) -> PathBuf {
    std::env::var(var)
        .ok()
        .and_then(|list| list.split(':').next().map(PathBuf::from))
        .unwrap_or_default()
}

fn default_socket(runtime_dir: &Path, name: &str) -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(format!(r"\\.\pipe\{name}"))
    } else {
        runtime_dir.join(format!("{name}.sock"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard};
    use tempfile::TempDir;

    const PREFIX: &str = "TESTAPP";

    /// Every variable this crate reads, cleared around each test.
    const READS: &[&str] = &[
        "STATE_DIRECTORY",
        "RUNTIME_DIRECTORY",
        "CONFIGURATION_DIRECTORY",
        "TESTAPP_CONFIG",
        "TESTAPP_PACKAGE_CONFIG",
        "TESTAPP_DB",
        "TESTAPP_BIND_ADDRESS",
        "TESTAPP_HTTPS_PORT",
        "TESTAPP_REDIRECT_PORT",
        "TESTAPP_SOCKET",
        "TESTAPP_TLS_CERT",
        "TESTAPP_TLS_KEY",
        "TESTAPP_UI",
        "TESTAPP_BASE_PATH",
        "TESTAPP_ONBOARDING",
        "TESTAPP_APP_SOCKET",
        "TESTAPP_CONSOLE_UID",
        "TESTAPP_HOOKS_SOCKET",
    ];

    static ENV: Mutex<()> = Mutex::new(());

    /// Holds the environment still for one test; the lock is what makes each
    /// `set_var` sound, since every test here reads the environment.
    struct Env(#[allow(dead_code)] MutexGuard<'static, ()>);

    impl Env {
        fn set(vars: &[(&str, &str)]) -> Self {
            let guard = ENV.lock().unwrap_or_else(|e| e.into_inner());
            unsafe {
                for name in READS {
                    std::env::remove_var(name);
                }
                for (name, value) in vars {
                    std::env::set_var(name, value);
                }
            }
            Self(guard)
        }
    }

    impl Drop for Env {
        fn drop(&mut self) {
            unsafe {
                for name in READS {
                    std::env::remove_var(name);
                }
            }
        }
    }

    /// A file with `body` in it, and the resolver that will read it.
    fn with_file(body: &str) -> (TempDir, ApplianceArgs) {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("config.toml");
        std::fs::write(&path, body).expect("write");
        (
            dir,
            ApplianceArgs {
                config: Some(path),
                ..Default::default()
            },
        )
    }

    fn resolver() -> Resolver {
        Resolver::new("testapp", PREFIX)
    }

    #[test]
    fn every_settings_three_spellings_are_the_ones_that_are_declared() {
        use std::collections::BTreeSet;

        let command = <ApplianceArgs as clap::Args>::augment_args(clap::Command::new("t"));
        let command = <ServingArgs as clap::Args>::augment_args(command);
        let flags: BTreeSet<&str> = command
            .get_arguments()
            .filter_map(|a| a.get_long())
            .collect();
        for key in Key::ALL {
            let long = key.flag.strip_prefix("--").expect("a long option");
            assert!(flags.contains(long), "{} is not a flag", key.flag);
        }

        let sample = file::tests::EVERY_SETTING;
        let parsed: FileConfig = toml::from_str(sample).expect("parses");
        assert!(
            parsed.unknown_keys().is_empty(),
            "{:?}",
            parsed.unknown_keys()
        );

        let mut in_file = BTreeSet::new();
        for (name, value) in toml::from_str::<toml::Table>(sample).expect("parses") {
            match value.as_table() {
                Some(section) => in_file.extend(section.keys().map(|k| format!("{name}.{k}"))),
                None => {
                    in_file.insert(name);
                }
            }
        }
        assert_eq!(
            in_file,
            Key::ALL.iter().map(|k| k.file.to_string()).collect(),
        );
    }

    #[test]
    fn appliance_args_flatten_beside_a_products_own_serving_flags() {
        use clap::{CommandFactory, Parser};

        #[derive(clap::Args)]
        #[allow(dead_code)]
        struct ProductServing {
            #[arg(long)]
            bind_address: Option<String>,
            #[arg(long)]
            https_port: Option<String>,
            #[arg(long)]
            redirect_port: Option<String>,
            #[arg(long)]
            tls_cert: Option<String>,
            #[arg(long)]
            tls_key: Option<String>,
        }

        #[derive(Parser)]
        struct Cli {
            #[command(flatten)]
            appliance: ApplianceArgs,
            #[command(flatten)]
            serving: ProductServing,
        }

        Cli::command().debug_assert();
        let cli = Cli::parse_from(["t", "--https-port", "443", "--db", "x.db"]);
        assert_eq!(cli.serving.https_port.as_deref(), Some("443"));
        assert_eq!(cli.appliance.db, Some(PathBuf::from("x.db")));
    }

    #[test]
    fn nothing_configured_at_all_still_starts() {
        let _env = Env::set(&[]);
        let (b, shadowed) = resolver()
            .settle(&ApplianceArgs::default())
            .expect("defaults alone must resolve");

        assert_eq!(b.db, PathBuf::from("testapp.db"));
        #[cfg(unix)]
        assert_eq!(b.socket, PathBuf::from("testapp.sock"));
        #[cfg(windows)]
        assert_eq!(b.socket, PathBuf::from(r"\\.\pipe\testapp"));
        assert_eq!(b.tls.cert, PathBuf::from("cert.pem"));
        assert_eq!(b.bind_address, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(b.https_port, 8443);
        assert_eq!(b.redirect_port, None);
        assert!(shadowed.is_empty());
        assert_eq!(b.ui, None);
    }

    #[test]
    fn the_configuration_directory_is_the_units_else_the_named_files() {
        let _env = Env::set(&[("CONFIGURATION_DIRECTORY", "/etc/testapp")]);
        let (dir, named) = with_file("");
        let b = resolver().resolve(&named).expect("resolves");
        assert_eq!(b.config_dir, PathBuf::from("/etc/testapp"));
        drop(_env);

        let _env = Env::set(&[]);
        let b = resolver().resolve(&named).expect("resolves");
        assert_eq!(b.config_dir, dir.path());
        let b = resolver()
            .resolve(&ApplianceArgs::default())
            .expect("resolves");
        assert_eq!(
            b.config_dir,
            PathBuf::new(),
            "nothing named: the working directory"
        );
    }

    #[test]
    fn the_defaults_follow_the_units_own_directories() {
        let _env = Env::set(&[
            ("STATE_DIRECTORY", "/var/lib/testapp"),
            ("RUNTIME_DIRECTORY", "/run/testapp"),
            ("CONFIGURATION_DIRECTORY", "/etc/testapp"),
        ]);
        let b = resolver()
            .resolve(&ApplianceArgs::default())
            .expect("resolves");

        assert_eq!(b.db, PathBuf::from("/var/lib/testapp/testapp.db"));
        #[cfg(unix)]
        assert_eq!(b.socket, PathBuf::from("/run/testapp/testapp.sock"));
        #[cfg(windows)]
        assert_eq!(b.socket, PathBuf::from(r"\\.\pipe\testapp"));
        assert_eq!(b.config_path, PathBuf::from("/etc/testapp/config.toml"));
        assert_eq!(b.config_dir, PathBuf::from("/etc/testapp"));
        assert_eq!(b.tls.cert, PathBuf::from("/var/lib/testapp/cert.pem"));
        assert_eq!(b.tls.key, PathBuf::from("/var/lib/testapp/key.pem"));
    }

    #[test]
    fn a_units_second_state_directory_does_not_become_one_path_with_a_colon_in_it() {
        let _env = Env::set(&[("STATE_DIRECTORY", "/var/lib/testapp:/var/lib/testapp-spool")]);
        let b = resolver()
            .resolve(&ApplianceArgs::default())
            .expect("resolves");
        assert_eq!(b.state_dir, PathBuf::from("/var/lib/testapp"));
        assert_eq!(b.db, PathBuf::from("/var/lib/testapp/testapp.db"));
    }

    #[test]
    fn a_flag_beats_the_environment_which_beats_the_file() {
        let _env = Env::set(&[("TESTAPP_HTTPS_PORT", "9001")]);
        let (_dir, args) = with_file("https_port = 1234\nbind_address = \"127.0.0.1\"\n");

        let b = resolver().resolve(&args).expect("resolves");
        assert_eq!(b.https_port, 9001);
        let b = resolver()
            .serving(&ServingArgs {
                https_port: Some(4443),
                ..Default::default()
            })
            .resolve(&args)
            .expect("resolves");
        assert_eq!(b.https_port, 4443);
        assert_eq!(b.bind_address, "127.0.0.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn the_base_path_is_the_root_unless_a_flag_the_environment_or_the_file_says() {
        let base = |env: &[(&str, &str)], file: &str, flag: Option<&str>| {
            let _env = Env::set(env);
            let (_dir, mut args) = with_file(file);
            args.base_path = flag.map(|f| f.parse().unwrap());
            resolver().resolve(&args).map(|b| b.base_path.to_string())
        };
        let env = [("TESTAPP_BASE_PATH", "/apps/env")];
        let file = "base_path = \"apps/file\"\n";
        assert_eq!(base(&env, file, Some("/apps/flag")).unwrap(), "/apps/flag/");
        assert_eq!(base(&env, file, None).unwrap(), "/apps/env/");
        assert_eq!(base(&[], file, None).unwrap(), "/apps/file/");
        assert_eq!(base(&[], "", None).unwrap(), "/");
        assert!(matches!(
            base(&[("TESTAPP_BASE_PATH", "/../x")], "", None),
            Err(ConfigError::Env { .. })
        ));
        assert!(matches!(
            base(&[], "base_path = \"/a b/\"\n", None),
            Err(ConfigError::Parse { .. })
        ));
    }

    #[test]
    fn every_setting_that_was_answered_twice_is_named() {
        let _env = Env::set(&[("TESTAPP_DB", "/tmp/from-env.db")]);
        let (_dir, args) = with_file("https_port = 1234\ndb = \"/tmp/from-file.db\"\n");
        let serving = ServingArgs {
            https_port: Some(4443),
            ..Default::default()
        };

        let (_, shadowed) = resolver()
            .serving(&serving)
            .settle(&args)
            .expect("resolves");

        let lost = |ignored: &str, winner: &str| Shadowed {
            ignored: ignored.to_string(),
            winner: winner.to_string(),
        };
        assert_eq!(
            shadowed,
            [lost("db", "TESTAPP_DB"), lost("https_port", "--https-port")]
        );
    }

    #[test]
    fn a_typo_in_the_file_stops_the_daemon() {
        let _env = Env::set(&[]);
        let (_dir, args) = with_file("bnid = \"0.0.0.0\"\n");
        let e = resolver()
            .resolve(&args)
            .expect_err("an unrecognised key must be fatal");
        assert!(e.to_string().contains("bnid"), "{e}");
    }

    #[test]
    fn a_retired_key_is_refused_by_name() {
        let _env = Env::set(&[]);
        let (_dir, args) = with_file("ssh_user = \"root\"\n");
        let e = resolver()
            .resolve(&args)
            .expect_err("a retired key is fatal");
        assert!(
            matches!(&e, ConfigError::Retired { key, .. } if key == "ssh_user"),
            "{e}"
        );
        assert!(
            e.to_string()
                .ends_with("ssh_user is no longer read; delete it"),
            "{e}"
        );
    }

    #[test]
    fn the_redirect_is_off_unless_a_port_is_set() {
        let _env = Env::set(&[]);
        let (_dir, args) = with_file("");
        assert_eq!(
            resolver().resolve(&args).expect("resolves").redirect_port,
            None
        );

        let (_dir, args) = with_file("redirect_port = 8080\n");
        assert_eq!(
            resolver().resolve(&args).expect("resolves").redirect_port,
            Some(8080)
        );
    }

    #[test]
    fn an_unusable_variable_is_refused_by_name_and_value() {
        let _env = Env::set(&[("TESTAPP_HTTPS_PORT", "eight thousand")]);
        let e = resolver()
            .resolve(&ApplianceArgs::default())
            .expect_err("a port that is not a number must fail");
        let rendered = e.to_string();
        assert!(rendered.contains("TESTAPP_HTTPS_PORT"), "{rendered}");
        assert!(rendered.contains("eight thousand"), "{rendered}");
    }

    #[test]
    fn an_empty_variable_is_not_an_answer() {
        let _env = Env::set(&[("TESTAPP_DB", "")]);
        let b = resolver()
            .resolve(&ApplianceArgs::default())
            .expect("resolves");
        assert_eq!(b.db, PathBuf::from("testapp.db"));
    }

    #[test]
    fn onboarding_is_off_unless_the_unit_says_on_and_garbage_refuses() {
        let var = "TESTAPP_ONBOARDING";
        let resolved = |vars: &[(&str, &str)]| {
            let _env = Env::set(vars);
            resolver()
                .resolve(&ApplianceArgs::default())
                .map(|b| b.browser_onboarding)
        };
        assert_eq!(resolved(&[]), Ok(false));
        assert_eq!(resolved(&[(var, "")]), Ok(false));
        assert_eq!(resolved(&[(var, "socket")]), Ok(false));
        assert_eq!(resolved(&[(var, " browser ")]), Ok(true));
        for garbage in ["yes", "true", "BROWSER"] {
            let e = resolved(&[(var, garbage)]).expect_err("garbage must refuse");
            assert!(e.to_string().contains(&format!("{var}={garbage:?}")), "{e}");
        }
    }

    #[test]
    fn proxied_takes_an_absolute_socket_and_a_uid_together_or_neither() {
        let dir = TempDir::new().expect("temp dir");
        let socket = dir.path().join("app.sock");
        let socket = socket.to_str().expect("utf-8");
        let resolved = |vars: &[(&str, &str)]| {
            let _env = Env::set(vars);
            resolver()
                .resolve(&ApplianceArgs::default())
                .map(|b| b.proxied)
        };
        let (path, uid) = ("TESTAPP_APP_SOCKET", "TESTAPP_CONSOLE_UID");

        assert_eq!(resolved(&[]), Ok(None));
        assert_eq!(resolved(&[(path, " "), (uid, "")]), Ok(None));
        assert_eq!(
            resolved(&[(path, socket), (uid, "0")]),
            Ok(Some(Proxied {
                app_socket: PathBuf::from(socket),
                console_uid: 0,
                hooks_socket: None,
            }))
        );
        for (vars, refused) in [
            (&[(path, socket)][..], path),
            (&[(uid, "0")][..], uid),
            (&[(path, "app.sock"), (uid, "0")][..], path),
            (&[(path, "/run/x/../app.sock"), (uid, "0")][..], path),
            (&[(path, socket), (uid, "-1")][..], uid),
            (&[(path, socket), (uid, "root")][..], uid),
            (&[(path, socket), (uid, "4294967296")][..], uid),
        ] {
            let e = resolved(vars).expect_err("refused");
            assert!(
                matches!(&e, ConfigError::Env { var, .. } if var == refused),
                "{vars:?}: {e}"
            );
        }

        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            for (raw, other, value) in [(path, uid, "0"), (uid, path, socket)] {
                let _env = Env::set(&[(other, value)]);
                unsafe { std::env::set_var(raw, std::ffi::OsStr::from_bytes(b"/run/\xff")) };
                let e = resolver()
                    .resolve(&ApplianceArgs::default())
                    .expect_err("refused");
                assert!(
                    matches!(&e, ConfigError::Env { var, because, .. } if var == raw && because == "not UTF-8"),
                    "{e}"
                );
            }
        }
    }

    #[test]
    fn the_hooks_socket_is_an_absolute_path_beside_the_app_socket_and_not_it() {
        let dir = TempDir::new().expect("temp dir");
        let (app, hooks) = (dir.path().join("app.sock"), dir.path().join("hooks.sock"));
        let (app, hooks) = (app.to_str().expect("utf-8"), hooks.to_str().expect("utf-8"));
        let resolved = |vars: &[(&str, &str)]| {
            let _env = Env::set(vars);
            resolver()
                .resolve(&ApplianceArgs::default())
                .map(|b| b.proxied.and_then(|p| p.hooks_socket))
        };
        let (path, uid, var) = (
            "TESTAPP_APP_SOCKET",
            "TESTAPP_CONSOLE_UID",
            "TESTAPP_HOOKS_SOCKET",
        );
        let beside = |value| [(path, app), (uid, "0"), (var, value)];

        assert_eq!(resolved(&[(path, app), (uid, "0")]), Ok(None));
        assert_eq!(resolved(&beside(hooks)), Ok(Some(PathBuf::from(hooks))));
        for vars in [
            &[(var, hooks)][..],
            &beside("hooks.sock"),
            &beside("/run/x/../hooks.sock"),
            &beside(app),
        ] {
            let e = resolved(vars).expect_err("refused");
            assert!(
                matches!(&e, ConfigError::Env { var: refused, .. } if refused == var),
                "{vars:?}: {e}"
            );
        }

        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            let _env = Env::set(&[(path, app), (uid, "0")]);
            unsafe { std::env::set_var(var, std::ffi::OsStr::from_bytes(b"/run/\xff")) };
            let e = resolver()
                .resolve(&ApplianceArgs::default())
                .expect_err("refused");
            assert!(
                matches!(&e, ConfigError::Env { var: refused, because, .. } if refused == var && because == "not UTF-8"),
                "{e}"
            );
        }
    }

    #[test]
    fn a_config_path_that_was_named_must_exist() {
        let _env = Env::set(&[]);
        let args = ApplianceArgs {
            config: Some(PathBuf::from("/nonexistent/testapp/config.toml")),
            ..Default::default()
        };
        assert!(
            resolver().resolve(&args).is_err(),
            "naming a file that is not there means the flag did nothing"
        );
    }

    #[test]
    fn the_browser_bundles_default_is_written_down_rather_than_derived() {
        assert_eq!(
            default_ui_dir("testapp"),
            PathBuf::from("/usr/share/testapp/ui")
        );
    }

    #[test]
    fn a_bundle_that_was_named_must_be_there_and_a_default_one_need_not_be() {
        let dir = TempDir::new().expect("temp dir");
        let here = dir.path().to_path_buf();
        let absent = here.join("nothing");
        let file = here.join("index.html");
        std::fs::write(&file, "<!doctype html>").expect("write");

        assert_eq!(bundle_at(here.clone(), false), Ok(Some(here.clone())));
        assert_eq!(bundle_at(here, true), Ok(Some(dir.path().to_path_buf())));

        assert_eq!(bundle_at(absent.clone(), false), Ok(None));
        assert!(bundle_at(absent, true).is_err());

        // `ENOTDIR` rather than an unreadable directory, which root can read.
        let under_a_file = file.join("ui");
        for hopeless in [file, under_a_file] {
            assert_eq!(bundle_at(hopeless.clone(), false), Ok(None));
            assert!(bundle_at(hopeless, true).is_err());
        }
    }

    #[test]
    fn a_pair_named_in_any_source_is_marked_named_and_the_default_is_not() {
        let _env = Env::set(&[]);
        let dir = TempDir::new().expect("temp dir");
        assert!(
            !resolver()
                .resolve(&ApplianceArgs::default())
                .expect("resolves")
                .tls
                .named,
            "nobody named a pair, so both halves are the appliance's"
        );

        let by_flag = resolver()
            .serving(&ServingArgs {
                tls_cert: Some(dir.path().join("theirs.pem")),
                ..Default::default()
            })
            .resolve(&ApplianceArgs::default())
            .expect("resolves")
            .tls;
        assert_eq!(
            by_flag,
            Tls::supplied(dir.path().join("theirs.pem"), PathBuf::from("key.pem")),
            "a certificate on the command line names the pair, and the other half still takes \
             the default path"
        );

        let config = dir.path().join("config.toml");
        std::fs::write(&config, "[tls]\nkey = \"/etc/ours/key.pem\"\n").expect("write");
        assert!(
            resolver()
                .resolve(&ApplianceArgs {
                    config: Some(config),
                    ..Default::default()
                })
                .expect("resolves")
                .tls
                .named,
            "the file names it too, and either half is enough"
        );
    }

    #[test]
    fn the_app_table_is_carried_and_is_empty_when_absent() {
        let _env = Env::set(&[]);
        let dir = TempDir::new().expect("temp dir");
        assert!(
            resolver()
                .resolve(&ApplianceArgs::default())
                .expect("resolves")
                .app
                .is_empty(),
            "no file, so nothing under [app]"
        );

        let config = dir.path().join("config.toml");
        std::fs::write(&config, "[app]\npoll_seconds = 30\nanything = \"at all\"\n")
            .expect("write");
        let app = resolver()
            .resolve(&ApplianceArgs {
                config: Some(config),
                ..Default::default()
            })
            .expect("a key under [app] is the product's business")
            .app;
        assert_eq!(app["poll_seconds"].as_integer(), Some(30));
        assert_eq!(app["anything"].as_str(), Some("at all"));
    }

    #[test]
    fn a_bundle_can_be_named_on_the_command_line_or_in_the_file() {
        let _env = Env::set(&[]);
        let dir = TempDir::new().expect("temp dir");
        let made = |name: &str| {
            let path = dir.path().join(name);
            std::fs::create_dir(&path).expect("mkdir");
            path
        };
        let (by_flag, by_file) = (made("flag"), made("file"));

        let config = dir.path().join("config.toml");
        std::fs::write(&config, format!("ui = {by_file:?}\n")).expect("write");

        let resolves = |args: ApplianceArgs| resolver().resolve(&args).expect("resolves").ui;
        assert_eq!(
            resolves(ApplianceArgs {
                ui: Some(by_flag.clone()),
                ..Default::default()
            }),
            Some(by_flag)
        );
        assert_eq!(
            resolves(ApplianceArgs {
                config: Some(config),
                ..Default::default()
            }),
            Some(by_file)
        );

        let e = resolver()
            .resolve(&ApplianceArgs {
                ui: Some(dir.path().join("gone")),
                ..Default::default()
            })
            .expect_err("a bundle somebody named must exist, or naming it did nothing");
        assert!(e.to_string().contains("gone"), "{e}");
    }

    #[test]
    fn a_bundle_can_be_named_in_the_environment() {
        let dir = TempDir::new().expect("temp dir");
        let bundle = dir.path().join("ui");
        std::fs::create_dir(&bundle).expect("mkdir");

        let resolve = || resolver().resolve(&ApplianceArgs::default());
        let _env = Env::set(&[("TESTAPP_UI", bundle.to_str().expect("utf-8"))]);
        assert_eq!(resolve().expect("resolves").ui, Some(bundle));

        drop(_env);
        let _env = Env::set(&[("TESTAPP_UI", "/nonexistent/testapp/ui")]);
        assert!(resolve().is_err());
    }

    #[test]
    fn the_environment_can_name_the_config_file_too() {
        let (dir, _args) = with_file("https_port = 1234\n");
        let _env = Env::set(&[(
            "TESTAPP_CONFIG",
            dir.path().join("config.toml").to_str().unwrap(),
        )]);
        let b = resolver()
            .resolve(&ApplianceArgs::default())
            .expect("resolves");
        assert_eq!(b.https_port, 1234);
    }

    /// A package file holding `body`, and its path as the variable spells it.
    fn package_file(dir: &TempDir, body: &str) -> String {
        let path = dir.path().join("package.toml");
        std::fs::write(&path, body).expect("write");
        path.to_str().expect("utf-8").to_string()
    }

    #[test]
    fn a_flag_beats_the_environment_the_file_the_package_and_the_default() {
        let dir = TempDir::new().expect("temp dir");
        let package = package_file(&dir, "https_port = 4000\n");
        let port = |env: &[(&str, &str)], file: &str, flag: Option<u16>| {
            let mut vars = vec![("TESTAPP_PACKAGE_CONFIG", package.as_str())];
            vars.extend_from_slice(env);
            let _env = Env::set(&vars);
            let (_dir, args) = with_file(file);
            let (b, shadowed) = resolver()
                .serving(&ServingArgs {
                    https_port: flag,
                    ..Default::default()
                })
                .settle(&args)
                .expect("resolves");
            (b.https_port, shadowed.len())
        };
        let env = [("TESTAPP_HTTPS_PORT", "3000")];
        let file = "https_port = 2000\n";
        assert_eq!(port(&env, file, Some(1000)), (1000, 2));
        assert_eq!(port(&env, file, None), (3000, 1));
        assert_eq!(
            port(&[], file, None),
            (2000, 0),
            "the package's is not shadowed"
        );
        assert_eq!(port(&[], "", None), (4000, 0));

        let _env = Env::set(&[]);
        let (_dir, args) = with_file("");
        assert_eq!(
            resolver().resolve(&args).expect("resolves").https_port,
            8443
        );
    }

    #[test]
    fn an_unset_or_blank_variable_is_no_package_layer() {
        for vars in [&[][..], &[("TESTAPP_PACKAGE_CONFIG", " ")][..]] {
            let _env = Env::set(vars);
            let b = resolver()
                .resolve(&ApplianceArgs::default())
                .expect("resolves");
            assert_eq!(b.https_port, 8443, "{vars:?}");
        }
    }

    #[test]
    fn a_package_file_that_was_named_and_is_missing_refuses_naming_both() {
        let _env = Env::set(&[("TESTAPP_PACKAGE_CONFIG", "/nonexistent/testapp/config.toml")]);
        let e = resolver()
            .resolve(&ApplianceArgs::default())
            .expect_err("refused");
        assert!(
            matches!(&e, ConfigError::Env { var, .. } if var == "TESTAPP_PACKAGE_CONFIG"),
            "{e}"
        );
        assert!(
            e.to_string().contains("/nonexistent/testapp/config.toml"),
            "{e}"
        );
    }

    #[test]
    fn a_file_without_a_port_takes_the_packages() {
        let dir = TempDir::new().expect("temp dir");
        let package = package_file(&dir, "bind_address = \"::\"\nhttps_port = 9443\n");
        let _env = Env::set(&[("TESTAPP_PACKAGE_CONFIG", &package)]);
        let (_dir, args) = with_file("[tls]\ncert = \"/etc/testapp/cert.pem\"\n");
        let b = resolver().resolve(&args).expect("resolves");
        assert_eq!(b.https_port, 9443);
        assert_eq!(b.bind_address.to_string(), "::");
        assert_eq!(b.tls.cert, PathBuf::from("/etc/testapp/cert.pem"));
    }

    #[test]
    fn the_package_file_is_refused_on_the_keys_the_file_is() {
        let dir = TempDir::new().expect("temp dir");
        for (body, refused) in [
            ("bnid = \"0.0.0.0\"\n", "unrecognised setting: bnid"),
            ("ssh_user = \"root\"\n", "ssh_user is no longer read"),
        ] {
            let package = package_file(&dir, body);
            let _env = Env::set(&[("TESTAPP_PACKAGE_CONFIG", &package)]);
            let e = resolver()
                .resolve(&ApplianceArgs::default())
                .expect_err("refused");
            let e = e.to_string();
            assert!(e.contains("package.toml") && e.contains(refused), "{e}");
        }
    }

    #[test]
    fn the_package_file_refuses_app_which_belongs_in_the_file() {
        let dir = TempDir::new().expect("temp dir");
        let package = package_file(&dir, "[app]\npoll_seconds = 30\n");
        let _env = Env::set(&[("TESTAPP_PACKAGE_CONFIG", &package)]);
        let (_dir, args) = with_file("[app]\npoll_seconds = 5\n");
        let e = resolver().resolve(&args).expect_err("refused").to_string();
        assert!(
            e.contains("package.toml") && e.contains("[app]") && e.contains("configuration file"),
            "{e}"
        );
    }

    #[test]
    fn a_relative_package_file_refuses() {
        let _env = Env::set(&[("TESTAPP_PACKAGE_CONFIG", "share/config.toml")]);
        let e = resolver()
            .resolve(&ApplianceArgs::default())
            .expect_err("refused");
        assert!(
            matches!(&e, ConfigError::Env { var, because, .. }
                if var == "TESTAPP_PACKAGE_CONFIG" && because.contains("absolute")),
            "{e}"
        );
    }
}
