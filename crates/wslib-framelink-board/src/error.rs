#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("TOML parse error: {0}")]
    Toml(#[from] toml_edit::de::Error),

    #[error("TOML parse error: {0}")]
    TomlDocument(#[from] toml_edit::TomlError),

    #[error(transparent)]
    SignalKey(#[from] wslib_framelink_protocol::Error),

    #[error("{section} key '{key}': {source}")]
    Key {
        section: &'static str,
        key: String,
        source: std::num::ParseIntError,
    },

    #[error("{section}.{key}: expected table")]
    NotATable { section: &'static str, key: String },

    #[error(
        "mcus[{index}].usb: expected \"self\", \"none\" or {{ cdc_interface = N }}, got {word:?}"
    )]
    UsbAccess { index: usize, word: String },

    #[error("mcus: chip {0:?} declared more than once")]
    DuplicateMcu(String),

    #[error("signal '{name}' not found on device. Available: {}", .available.join(", "))]
    SignalNotFound {
        name: String,
        available: Vec<String>,
    },

    #[error("interface '{name}' not found on device. Available: {}", .available.join(", "))]
    InterfaceNotFound {
        name: String,
        available: Vec<String>,
    },

    #[error(transparent)]
    Io(#[from] std::io::Error),
}
