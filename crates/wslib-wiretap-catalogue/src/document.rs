use std::error::Error;

/// Why a catalogue's text was not edited, migrated or converted.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DocumentError {
    /// This crate's own reason, such as a missing target or a name collision.
    #[error("{0}")]
    Refused(String),
    #[error("catalogue is not valid TOML")]
    Toml(#[from] toml::de::Error),
    #[error("catalogue is not valid TOML")]
    TomlDocument(#[from] toml_edit::TomlError),
    /// The source is can-dbc's error.
    #[error("the DBC file does not parse")]
    Dbc(#[source] Box<dyn Error + Send + Sync>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dbc::{import::convert_dbc_to_toml, render_catalogue_as_dbc};
    use crate::edit::{apply_edits, bump_meta_version};
    use crate::migrate::migrate;
    use crate::parse::CatalogueError;

    const NOT_TOML: &str = "[meta";

    fn says_only_its_own_layer(error: &DocumentError) {
        assert_eq!(error.to_string(), "catalogue is not valid TOML");
    }

    #[test]
    fn an_edit_migration_or_bump_of_invalid_toml_keeps_toml_edits_error() {
        for error in [
            apply_edits(NOT_TOML, &[]).unwrap_err(),
            migrate(NOT_TOML).err().expect("refused"),
            bump_meta_version(NOT_TOML).unwrap_err(),
        ] {
            says_only_its_own_layer(&error);
            assert!(
                error
                    .source()
                    .and_then(|s| s.downcast_ref::<toml_edit::TomlError>())
                    .is_some(),
                "{error:?}"
            );
        }
    }

    #[test]
    fn an_export_of_invalid_toml_keeps_tomls_error() {
        let error = render_catalogue_as_dbc(NOT_TOML, "Vector__XXX").unwrap_err();

        says_only_its_own_layer(&error);
        assert!(
            error
                .source()
                .and_then(|s| s.downcast_ref::<toml::de::Error>())
                .is_some(),
            "{error:?}"
        );
    }

    #[test]
    fn a_dbc_that_does_not_parse_keeps_can_dbcs_error() {
        let error = convert_dbc_to_toml("BO_ nonsense").unwrap_err();

        assert_eq!(error.to_string(), "the DBC file does not parse");
        assert!(
            error
                .source()
                .and_then(|s| s.downcast_ref::<can_dbc::DbcError>())
                .is_some(),
            "{error:?}"
        );
    }

    #[test]
    fn a_catalogue_that_is_not_toml_says_only_its_own_layer() {
        let error = crate::Catalogue::parse(NOT_TOML).unwrap_err();

        assert!(matches!(error, CatalogueError::Toml(_)));
        assert_eq!(error.to_string(), "catalogue is not valid TOML");
        assert!(
            error
                .source()
                .and_then(|s| s.downcast_ref::<toml::de::Error>())
                .is_some()
        );
    }
}
