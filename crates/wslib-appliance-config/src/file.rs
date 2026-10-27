//! The bootstrap file. Unknown keys are collected rather than denied by serde,
//! so a refusal names every one of them.

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::ConfigError;

/// The file's contents, as written; a consumer's own keys go under `[app]`.
#[derive(Debug, Default, Deserialize, PartialEq)]
pub(crate) struct FileConfig {
    /// The consuming product's own settings, untouched and unchecked.
    #[serde(default)]
    pub app: toml::Table,

    pub db: Option<PathBuf>,

    /// The interface both listeners bind.
    pub bind_address: Option<IpAddr>,
    pub https_port: Option<u16>,

    /// `0` is no redirect listener.
    pub redirect_port: Option<u16>,

    pub socket: Option<PathBuf>,

    /// The built browser bundle; absent is "not set here", not "no bundle".
    pub ui: Option<PathBuf>,

    pub base_path: Option<crate::BasePath>,

    #[serde(default)]
    pub tls: TlsSection,

    #[serde(flatten)]
    unknown: toml::Table,
}

#[derive(Debug, Default, Deserialize, PartialEq)]
pub(crate) struct TlsSection {
    pub cert: Option<PathBuf>,
    pub key: Option<PathBuf>,

    #[serde(flatten)]
    unknown: toml::Table,
}

impl FileConfig {
    /// Read the file: absent is the defaults unless `explicit`, malformed is an error.
    pub fn load(path: &Path, explicit: bool) -> Result<Self, ConfigError> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && !explicit => {
                return Ok(Self::default());
            }
            Err(e) => {
                return Err(ConfigError::Read {
                    path: path.to_path_buf(),
                    because: e.to_string(),
                });
            }
        };
        toml::from_str(&text).map_err(|e| ConfigError::Parse {
            path: path.to_path_buf(),
            because: e.to_string(),
        })
    }

    /// Every key outside `[app]` this crate does not recognise, dotted and sorted.
    pub fn unknown_keys(&self) -> Vec<String> {
        let mut keys: Vec<String> = self.unknown.keys().cloned().collect();
        keys.extend(self.tls.unknown.keys().map(|k| format!("tls.{k}")));
        keys.sort();
        keys
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Every setting this crate owns, and nothing else; `lib.rs` checks it against `Key::ALL`.
    pub(crate) const EVERY_SETTING: &str = r#"
        db = "/var/lib/myappliance/myappliance.db"
        bind_address = "0.0.0.0"
        https_port = 8443
        redirect_port = 80
        socket = "/run/myappliance/myappliance.sock"
        ui = "/usr/share/myappliance/ui"
        base_path = "/apps/myappliance/"

        [tls]
        cert = "/etc/myappliance/cert.pem"
        key = "/etc/myappliance/key.pem"
        "#;

    #[test]
    fn a_full_file_round_trips() {
        let parsed: FileConfig = toml::from_str(EVERY_SETTING).expect("parses");

        assert_eq!(parsed.bind_address, Some("0.0.0.0".parse().unwrap()));
        assert_eq!(parsed.https_port, Some(8443));
        assert_eq!(parsed.redirect_port, Some(80));
        assert_eq!(
            parsed.tls.cert,
            Some(PathBuf::from("/etc/myappliance/cert.pem"))
        );
        assert!(
            parsed.unknown_keys().is_empty(),
            "{:?}",
            parsed.unknown_keys()
        );
    }

    #[test]
    fn an_empty_file_is_all_defaults() {
        assert_eq!(
            toml::from_str::<FileConfig>("").expect("parses"),
            FileConfig::default()
        );
    }

    #[test]
    fn an_unrecognised_key_is_collected_by_name_rather_than_refused_here() {
        let parsed: FileConfig = toml::from_str(
            r#"
            bnid = "0.0.0.0"
            https_port = 8443

            [tls]
            certificate = "/etc/myappliance/cert.pem"
            "#,
        )
        .expect("an unknown key must still parse — see the module doc");

        assert_eq!(parsed.unknown_keys(), ["bnid", "tls.certificate"]);
        assert_eq!(parsed.https_port, Some(8443));
    }

    #[test]
    fn a_key_with_the_wrong_type_is_a_parse_failure_not_an_unknown_key() {
        let e = toml::from_str::<FileConfig>(r#"https_port = "8443""#)
            .expect_err("a string is not a port");
        assert!(e.to_string().contains("https_port"), "{e}");
    }

    #[test]
    fn a_missing_file_is_defaults_unless_it_was_named() {
        let absent = Path::new("/nonexistent/myappliance/config.toml");
        assert_eq!(
            FileConfig::load(absent, false).expect("absent is fine by default"),
            FileConfig::default()
        );
        assert!(
            FileConfig::load(absent, true).is_err(),
            "a path somebody named must exist, or naming it did nothing"
        );
    }

    #[test]
    fn a_malformed_file_names_itself() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "bind_address = not-a-string").expect("write");

        let e = FileConfig::load(&path, false).expect_err("malformed must fail");
        assert!(e.to_string().contains("config.toml"), "{e}");
    }

    #[test]
    fn a_products_own_settings_live_under_app_and_are_not_typos() {
        let parsed: FileConfig = toml::from_str(
            r#"
            https_port = 8443

            [app]
            catalogue = "/usr/share/myappliance/catalogue.toml"
            poll_interval_ms = 5000
            "#,
        )
        .expect("parses");

        assert!(
            parsed.unknown_keys().is_empty(),
            "{:?}",
            parsed.unknown_keys()
        );
        assert_eq!(parsed.https_port, Some(8443));
        assert_eq!(
            parsed.app["catalogue"].as_str(),
            Some("/usr/share/myappliance/catalogue.toml"),
            "and the product's half is handed over untouched"
        );
    }
}
