//! Where a command line finds its config file, and the environment variables
//! that override it.
//!
//! The file is the first of: the path the caller was given (a `--config`
//! flag), `<PREFIX>_CONFIG`, `$XDG_CONFIG_HOME/<app>/config.toml`, and
//! `~/.config/<app>/config.toml`. XDG rules apply on every platform, macOS
//! included. A setting is then taken from its flag, else `<PREFIX>_<KEY>`,
//! else the file.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::{env, fmt, fs, io};

/// A command line's config file and environment prefix.
#[derive(Clone, Debug)]
pub struct Discovery {
    app: String,
    prefix: String,
    file_name: String,
}

/// A config file that was found, and what it holds.
#[derive(Clone, Debug)]
pub struct ConfigFile {
    pub path: PathBuf,
    pub text: String,
}

impl Discovery {
    /// Looks in `<app>/config.toml` with the prefix `APP`, uppercased and
    /// with `-` as `_`.
    pub fn new(app: &str) -> Self {
        Self {
            app: app.to_owned(),
            prefix: app.to_uppercase().replace('-', "_"),
            file_name: "config.toml".to_owned(),
        }
    }

    pub fn file_name(mut self, name: &str) -> Self {
        self.file_name = name.to_owned();
        self
    }

    pub fn env_prefix(mut self, prefix: &str) -> Self {
        self.prefix = prefix.to_owned();
        self
    }

    /// `<PREFIX>_<key>`, unless unset, blank or not Unicode.
    pub fn var(&self, key: &str) -> Option<String> {
        self.var_in(key, |name| env::var_os(name))
    }

    /// Where the file is, or would be; `None` without a home directory.
    pub fn path(&self, explicit: Option<&Path>) -> Option<PathBuf> {
        self.locate(explicit, |name| env::var_os(name), env::home_dir())
            .map(|(path, _)| path)
    }

    /// The file, or `None` when the default one doesn't exist; a file that was
    /// named, by the caller or `<PREFIX>_CONFIG`, must.
    pub fn read(&self, explicit: Option<&Path>) -> Result<Option<ConfigFile>, ConfigError> {
        let Some((path, named)) = self.locate(explicit, |name| env::var_os(name), env::home_dir())
        else {
            return Ok(None);
        };
        match fs::read_to_string(&path) {
            Ok(text) => Ok(Some(ConfigFile { path, text })),
            Err(e) if e.kind() == io::ErrorKind::NotFound && !named => Ok(None),
            Err(source) => Err(ConfigError::Read { path, source }),
        }
    }

    /// The file parsed as TOML, or the default when there is none.
    #[cfg(feature = "toml")]
    pub fn load<T: serde::de::DeserializeOwned + Default>(
        &self,
        explicit: Option<&Path>,
    ) -> Result<T, ConfigError> {
        let Some(file) = self.read(explicit)? else {
            return Ok(T::default());
        };
        toml::from_str(&file.text).map_err(|source| ConfigError::Parse {
            path: file.path,
            source,
        })
    }

    fn var_in(&self, key: &str, env: impl Fn(&str) -> Option<OsString>) -> Option<String> {
        env(&format!("{}_{key}", self.prefix))
            .and_then(|value| value.into_string().ok())
            .filter(|value| !value.trim().is_empty())
    }

    fn locate(
        &self,
        explicit: Option<&Path>,
        env: impl Fn(&str) -> Option<OsString>,
        home: Option<PathBuf>,
    ) -> Option<(PathBuf, bool)> {
        if let Some(path) = explicit {
            return Some((path.to_owned(), true));
        }
        if let Some(path) = self.var_in("CONFIG", &env) {
            return Some((path.into(), true));
        }
        // A relative XDG_CONFIG_HOME is invalid by the XDG spec and is ignored.
        let base = env("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .or_else(|| home.map(|h| h.join(".config")))?;
        Some((base.join(&self.app).join(&self.file_name), false))
    }
}

/// A config file that couldn't be read or parsed.
#[derive(Debug)]
pub enum ConfigError {
    Read {
        path: PathBuf,
        source: io::Error,
    },
    #[cfg(feature = "toml")]
    Parse {
        path: PathBuf,
        source: toml::de::Error,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { path, .. } => write!(f, "read {}", path.display()),
            #[cfg(feature = "toml")]
            Self::Parse { path, .. } => write!(f, "parse {}", path.display()),
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Read { source, .. } => Some(source),
            #[cfg(feature = "toml")]
            Self::Parse { source, .. } => Some(source),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOME: &str = "/home/example";

    fn env<'a>(vars: &'a [(&str, &str)]) -> impl Fn(&str) -> Option<OsString> + 'a {
        |name| {
            vars.iter()
                .find(|(n, _)| *n == name)
                .map(|(_, v)| OsString::from(v))
        }
    }

    fn located(vars: &[(&str, &str)], explicit: Option<&Path>) -> Option<(PathBuf, bool)> {
        Discovery::new("bench-tool").locate(explicit, env(vars), Some(HOME.into()))
    }

    #[test]
    fn the_prefix_is_the_app_name_uppercased() {
        let d = Discovery::new("bench-tool");
        let vars = [("BENCH_TOOL_URL", "http://bench")];
        assert_eq!(d.var_in("URL", env(&vars)).as_deref(), Some("http://bench"));
    }

    #[test]
    fn a_blank_variable_is_unset() {
        let d = Discovery::new("bench-tool");
        assert_eq!(d.var_in("URL", env(&[("BENCH_TOOL_URL", "  ")])), None);
    }

    #[test]
    fn an_explicit_path_wins_over_the_environment() {
        let vars = [("BENCH_TOOL_CONFIG", "/etc/bench.toml")];
        assert_eq!(
            located(&vars, Some(Path::new("/tmp/flag.toml"))),
            Some(("/tmp/flag.toml".into(), true))
        );
        assert_eq!(located(&vars, None), Some(("/etc/bench.toml".into(), true)));
    }

    #[test]
    fn an_absolute_xdg_config_home_is_preferred() {
        let vars = [("XDG_CONFIG_HOME", "/xdg")];
        assert_eq!(
            located(&vars, None),
            Some(("/xdg/bench-tool/config.toml".into(), false))
        );
    }

    #[test]
    fn otherwise_it_is_dot_config_under_home_even_on_macos() {
        let expected = Some(("/home/example/.config/bench-tool/config.toml".into(), false));
        assert_eq!(located(&[], None), expected);
        assert_eq!(located(&[("XDG_CONFIG_HOME", "relative")], None), expected);
    }

    #[test]
    fn there_is_no_default_without_a_home() {
        assert_eq!(
            Discovery::new("bench-tool").locate(None, env(&[]), None),
            None
        );
    }

    #[test]
    fn a_named_file_must_exist() {
        let missing = env::temp_dir().join("wslib-cli-no-such-config.toml");
        let error = Discovery::new("bench-tool")
            .read(Some(&missing))
            .unwrap_err();
        assert!(matches!(error, ConfigError::Read { .. }));
    }

    #[cfg(feature = "toml")]
    #[test]
    fn a_toml_file_loads_into_the_callers_type() {
        #[derive(serde::Deserialize, Default, Debug, PartialEq)]
        struct Settings {
            url: Option<String>,
        }
        let path = env::temp_dir().join(format!("wslib-cli-{}.toml", std::process::id()));
        fs::write(&path, "url = \"http://bench\"\n").unwrap();
        let loaded: Settings = Discovery::new("bench-tool").load(Some(&path)).unwrap();
        fs::remove_file(&path).unwrap();
        assert_eq!(loaded.url.as_deref(), Some("http://bench"));
    }
}
