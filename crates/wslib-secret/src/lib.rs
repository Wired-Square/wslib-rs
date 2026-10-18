//! A string that will not print itself, and the ways a service is handed one.
//!
//! The guarantee is on the *value*, not the container, so `#[derive(Debug)]` stays
//! correct everywhere and a secret is safe the moment it is typed as one.
//!
//! **No `Deref<Target = str>` and no `PartialEq`**, deliberately. [`Secret::expose`]
//! puts a name on every place a secret becomes an ordinary string, so
//! `grep -rn '\.expose()'` enumerates them; [`Secret::matches`] is the only
//! comparison, and it takes the same time however far two secrets agree.
//!
//! **It does not reach inside somebody else's `Display`.** A `tracing` message is
//! `format!`, not a `Debug` of ours, and a foreign error type may well render a
//! credential it was handed.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::{fmt, fs, io};

use subtle::ConstantTimeEq;

/// A string whose `Debug` and `Display` render `set` or `unset`, never the value.
#[derive(Clone)]
pub struct Secret(String);

impl Secret {
    /// Wraps a plaintext value.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The plaintext.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Whether there is anything here at all, which is safe to show.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Whether two secrets are the same, in time that does not depend on how far
    /// they match.
    ///
    /// `subtle` rather than a `|=` loop, which says nothing to the optimiser and so
    /// leaves it free to add the early exit the loop was written to avoid.
    pub fn matches(&self, other: &Secret) -> bool {
        self.0.as_bytes().ct_eq(other.0.as_bytes()).into()
    }

    /// Reads a secret from `path`, less one trailing newline.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, LoadError> {
        let path = path.as_ref();
        let raw = fs::read_to_string(path).map_err(|source| LoadError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let value = raw
            .strip_suffix('\n')
            .map_or(raw.as_str(), |s| s.strip_suffix('\r').unwrap_or(s));
        if value.is_empty() {
            return Err(LoadError::Empty(path.to_path_buf()));
        }
        Ok(Self::new(value))
    }

    /// The secret in environment variable `name`, or in the file named by
    /// `name_FILE`; `None` when neither is set.
    pub fn from_env(name: &str) -> Result<Option<Self>, LoadError> {
        Self::from_vars(name, |var| std::env::var_os(var))
    }

    /// [`Secret::from_env`] reading variables through `lookup`.
    ///
    /// An empty variable counts as unset, as a compose file's `${VAR:-}` renders one.
    pub fn from_vars(
        name: &str,
        lookup: impl Fn(&str) -> Option<OsString>,
    ) -> Result<Option<Self>, LoadError> {
        let file_var = format!("{name}_FILE");
        let set = |var: &str| lookup(var).filter(|v| !v.is_empty());
        match (set(name), set(&file_var)) {
            (Some(_), Some(_)) => Err(LoadError::BothSet {
                var: name.to_string(),
                file_var,
            }),
            (Some(value), None) => value
                .into_string()
                .map(|v| Some(Self(v)))
                .map_err(|_| LoadError::NotUnicode(name.to_string())),
            (None, Some(path)) => Self::from_file(PathBuf::from(path)).map(Some),
            (None, None) => Ok(None),
        }
    }
}

impl From<String> for Secret {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for Secret {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(if self.is_empty() { "unset" } else { "set" })
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret({self})")
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Secret {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Secret {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self)
    }
}

/// `string`, as a primitive: a `type Secret = string` would wear the name while
/// carrying none of what it claims.
#[cfg(feature = "ts")]
impl ts_rs::TS for Secret {
    type WithoutGenerics = Self;
    type OptionInnerType = Self;

    fn name() -> String {
        String::name()
    }

    fn inline() -> String {
        String::inline()
    }

    fn inline_flattened() -> String {
        String::inline_flattened()
    }

    fn decl() -> String {
        String::decl()
    }

    fn decl_concrete() -> String {
        String::decl_concrete()
    }
}

/// Why a secret could not be loaded. Never carries the value.
#[derive(Debug)]
#[non_exhaustive]
pub enum LoadError {
    /// Both the variable and its `_FILE` were set, and neither can be preferred.
    BothSet { var: String, file_var: String },
    /// The variable named here is not valid Unicode.
    NotUnicode(String),
    /// The file could not be read.
    Read { path: PathBuf, source: io::Error },
    /// The file holds nothing but a newline, if that.
    Empty(PathBuf),
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BothSet { var, file_var } => write!(f, "both {var} and {file_var} are set"),
            Self::NotUnicode(var) => write!(f, "{var} is not valid Unicode"),
            Self::Read { path, source } => write!(f, "{}: {source}", path.display()),
            Self::Empty(path) => write!(f, "{} is empty", path.display()),
        }
    }
}

impl std::error::Error for LoadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Read { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str, contents: &str) -> Self {
            let path =
                std::env::temp_dir().join(format!("wslib-secret-{name}-{}", std::process::id()));
            fs::write(&path, contents).unwrap();
            Self(path)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    fn vars<'a>(set: &'a [(&str, &std::ffi::OsStr)]) -> impl Fn(&str) -> Option<OsString> + 'a {
        |var| {
            set.iter()
                .find(|(name, _)| *name == var)
                .map(|(_, value)| value.to_os_string())
        }
    }

    #[test]
    fn neither_debug_nor_display_shows_the_value() {
        let s = Secret::new("hunter2");
        assert_eq!(format!("{s:?}"), "Secret(set)");
        assert_eq!(s.to_string(), "set");
        assert_eq!(s.expose(), "hunter2");
    }

    #[test]
    fn an_empty_secret_reads_as_unset() {
        assert_eq!(format!("{:?}", Secret::new("")), "Secret(unset)");
        assert_eq!(Secret::new("").to_string(), "unset");
    }

    #[test]
    fn a_secret_nested_in_a_derived_debug_is_still_redacted() {
        #[derive(Debug)]
        #[allow(dead_code)]
        struct Config {
            host: String,
            api_key: Secret,
        }
        let rendered = format!(
            "{:?}",
            Config {
                host: "example.invalid".into(),
                api_key: Secret::new("sk-live-abc123"),
            }
        );
        assert!(rendered.contains("example.invalid"));
        assert!(!rendered.contains("sk-live-abc123"), "leaked: {rendered}");
    }

    #[test]
    fn secrets_match_only_when_every_byte_does() {
        let s = Secret::new("hunter2");
        assert!(s.matches(&Secret::new("hunter2")));
        assert!(!s.matches(&Secret::new("hunter3")));
        assert!(!s.matches(&Secret::new("hunter")));
        assert!(!s.matches(&Secret::new("hunter22")));
        assert!(Secret::new("").matches(&Secret::new("")));
    }

    #[test]
    fn a_file_loses_one_trailing_newline_and_no_more() {
        for (contents, want) in [
            ("abc", "abc"),
            ("abc\n", "abc"),
            ("abc\r\n", "abc"),
            ("abc\n\n", "abc\n"),
            (" abc \n", " abc "),
        ] {
            let file = Scratch::new("newline", contents);
            assert_eq!(
                Secret::from_file(&file.0).unwrap().expose(),
                want,
                "{contents:?}"
            );
        }
    }

    #[test]
    fn an_empty_or_missing_file_is_an_error() {
        let file = Scratch::new("empty", "\n");
        assert!(matches!(
            Secret::from_file(&file.0),
            Err(LoadError::Empty(_))
        ));
        let missing = file.0.with_extension("missing");
        assert!(matches!(
            Secret::from_file(missing),
            Err(LoadError::Read { .. })
        ));
    }

    #[test]
    fn the_variable_or_its_file_supplies_the_secret() {
        let file = Scratch::new("var-file", "from-file\n");
        let from_file = Secret::from_vars("KEY", vars(&[("KEY_FILE", file.0.as_os_str())]));
        assert_eq!(from_file.unwrap().unwrap().expose(), "from-file");

        let from_var = Secret::from_vars("KEY", vars(&[("KEY", "from-var".as_ref())]));
        assert_eq!(from_var.unwrap().unwrap().expose(), "from-var");

        assert!(Secret::from_vars("KEY", vars(&[])).unwrap().is_none());
    }

    #[test]
    fn setting_both_the_variable_and_its_file_is_an_error() {
        let file = Scratch::new("both", "from-file");
        let both = [
            ("KEY", "from-var".as_ref()),
            ("KEY_FILE", file.0.as_os_str()),
        ];
        let err = Secret::from_vars("KEY", vars(&both)).unwrap_err();
        assert!(matches!(err, LoadError::BothSet { .. }));
        assert_eq!(err.to_string(), "both KEY and KEY_FILE are set");
    }

    #[test]
    fn an_empty_variable_counts_as_unset() {
        let file = Scratch::new("empty-var", "from-file");
        let set = [("KEY", "".as_ref()), ("KEY_FILE", file.0.as_os_str())];
        let loaded = Secret::from_vars("KEY", vars(&set)).unwrap().unwrap();
        assert_eq!(loaded.expose(), "from-file");
        let unset = [("KEY", "".as_ref()), ("KEY_FILE", "".as_ref())];
        assert!(Secret::from_vars("KEY", vars(&unset)).unwrap().is_none());
    }

    #[test]
    fn a_load_error_never_carries_the_value() {
        let both = [
            ("KEY", "hunter2".as_ref()),
            ("KEY_FILE", "/nowhere".as_ref()),
        ];
        let err = Secret::from_vars("KEY", vars(&both)).unwrap_err();
        assert!(!format!("{err} {err:?}").contains("hunter2"));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_round_trips_the_bare_string() {
        let s: Secret = serde_json::from_str("\"hunter2\"").unwrap();
        assert_eq!(s.expose(), "hunter2");
        assert_eq!(serde_json::to_string(&s).unwrap(), "\"hunter2\"");
    }

    #[cfg(feature = "ts")]
    #[test]
    fn typescript_sees_a_plain_string() {
        use ts_rs::TS;

        #[derive(TS)]
        #[allow(dead_code)]
        struct Config {
            api_key: Secret,
        }
        assert_eq!(Secret::inline(), "string");
        assert_eq!(Config::decl(), "type Config = { api_key: string, };");
        assert!(Config::dependencies().is_empty());
    }
}
