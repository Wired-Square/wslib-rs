//! What the appliance calls itself, and what it looks like: the [`Branding`] an
//! app compiles in, over a `theme.css` that gives every token a neutral value.
//! There is no runtime write path, and it is served before anybody signs in.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// The longest a token value may be.
pub const MAX_VALUE_LEN: usize = 256;

/// The most tokens a theme may carry.
pub const MAX_TOKENS: usize = 64;

/// The prefix every themeable custom property shares; nothing outside it can be set.
pub const PREFIX: &str = "--app-";

/// A validated set of CSS custom properties, checked on deserialise as in
/// [`ThemeTokens::new`]; a value may not hold `url(`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export, type = "Record<string, string>"))]
pub struct ThemeTokens(BTreeMap<String, String>);

/// Why a theme was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ThemeError {
    /// The name is not in the `--app-` namespace, or is not a legal property name.
    #[error(
        "theme token {0:?} is not a {PREFIX}* custom property; \
         only tokens the appliance defines can be themed"
    )]
    Name(String),
    /// The value is too long, or contains something a stylesheet must not carry.
    #[error("theme token {token:?} has an unusable value: {because}")]
    Value { token: String, because: String },
    /// More tokens than the cap allows.
    #[error("a theme may carry at most {MAX_TOKENS} tokens, got {0}")]
    TooMany(usize),
}

impl ThemeTokens {
    /// Validates and wraps a token map.
    pub fn new(tokens: BTreeMap<String, String>) -> Result<Self, ThemeError> {
        if tokens.len() > MAX_TOKENS {
            return Err(ThemeError::TooMany(tokens.len()));
        }
        for (name, value) in &tokens {
            legal_name(name)
                .then_some(())
                .ok_or_else(|| ThemeError::Name(name.clone()))?;
            legal_value(value).map_err(|because| ThemeError::Value {
                token: name.clone(),
                because,
            })?;
        }
        Ok(Self(tokens))
    }
}

fn legal_name(name: &str) -> bool {
    name.strip_prefix(PREFIX).is_some_and(|rest| {
        !rest.is_empty()
            && rest
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    })
}

fn legal_value(value: &str) -> Result<(), String> {
    if value.len() > MAX_VALUE_LEN {
        return Err(format!("longer than {MAX_VALUE_LEN} bytes"));
    }
    if value
        .as_bytes()
        .windows(4)
        .any(|w| w.eq_ignore_ascii_case(b"url("))
    {
        return Err("contains url(, which would fetch from a third party".into());
    }
    if let Some(bad) = value
        .chars()
        .find(|c| matches!(c, ';' | '{' | '}' | '<' | '>' | '\\') || c.is_control())
    {
        return Err(if bad.is_control() {
            "contains a control character".to_string()
        } else {
            format!("contains {bad:?}")
        });
    }
    Ok(())
}

impl Serialize for ThemeTokens {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(s)
    }
}

impl<'de> Deserialize<'de> for ThemeTokens {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = BTreeMap::<String, String>::deserialize(d)?;
        ThemeTokens::new(raw).map_err(serde::de::Error::custom)
    }
}

/// What an appliance calls itself, served publicly so the login screen is
/// branded; the logo is its own response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
#[non_exhaustive]
pub struct Branding {
    pub app_name: String,
    pub manufacturer: String,
    /// Overrides for the appliance's own tokens; empty uses the defaults.
    #[serde(default)]
    pub tokens: ThemeTokens,
    /// Overrides over `tokens`, applied under `<html data-app-scheme="dark">`, or
    /// `"light dark"` when the browser prefers dark.
    #[serde(default)]
    pub tokens_dark: ThemeTokens,
}

/// What `GET /api/branding` answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
pub struct BrandingView {
    #[serde(flatten)]
    pub branding: Branding,
    /// A digest of the version and the page; a browser that sees it change reloads.
    pub build: String,
    /// The running hostname, `null` unless the host's backend names the box.
    pub hostname: Option<String>,
}

impl Branding {
    /// An anonymous identity, which a product starts from and assigns to.
    pub fn unbranded() -> Self {
        Self {
            app_name: "Appliance".to_string(),
            manufacturer: String::new(),
            tokens: ThemeTokens::default(),
            tokens_dark: ThemeTokens::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tokens(pairs: &[(&str, &str)]) -> Result<ThemeTokens, ThemeError> {
        ThemeTokens::new(
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        )
    }

    #[test]
    fn an_app_may_override_the_appliances_tokens() {
        let t = tokens(&[("--app-accent", "#1b3f94"), ("--app-alert", "#c8102e")]).unwrap();
        assert_eq!(t.0["--app-accent"], "#1b3f94");
        assert_eq!(t.0.len(), 2);
    }

    #[test]
    fn only_the_app_namespace_is_themeable() {
        for name in [
            "--tw-ring-color",
            "color",
            "--App-Accent",
            "--app-",
            "--app-a_b",
        ] {
            assert!(
                matches!(tokens(&[(name, "red")]), Err(ThemeError::Name(_))),
                "{name} should have been refused"
            );
        }
    }

    #[test]
    fn a_token_may_not_fetch_from_a_third_party() {
        for value in ["url(https://evil.invalid/x.png)", "URL(//evil.invalid)"] {
            let err = tokens(&[("--app-accent", value)]).unwrap_err();
            assert!(
                matches!(&err, ThemeError::Value { because, .. } if because.contains("url(")),
                "got {err:?}"
            );
        }
    }

    #[test]
    fn a_token_may_not_end_or_nest_a_declaration() {
        for value in ["red; background: black", "red}", "{", "a<b", "a\\b"] {
            assert!(
                matches!(
                    tokens(&[("--app-accent", value)]),
                    Err(ThemeError::Value { .. })
                ),
                "{value:?} should have been refused"
            );
        }
    }

    #[test]
    fn ordinary_css_values_are_allowed_through() {
        let t = tokens(&[
            ("--app-accent", "#1b3f94"),
            ("--app-font", "Ubuntu, system-ui, sans-serif"),
            (
                "--app-surface",
                "linear-gradient(180deg, #fff 0%, #eee 100%)",
            ),
            ("--app-space-2", "0.5rem"),
        ]);
        assert!(t.is_ok(), "{t:?}");
    }

    #[test]
    fn a_theme_read_from_a_file_cannot_reach_a_browser_unchecked() {
        let json = r#"{"--app-accent":"url(https://evil.invalid)"}"#;
        assert!(serde_json::from_str::<ThemeTokens>(json).is_err());
    }

    #[test]
    fn the_public_endpoints_answer_is_bounded() {
        let many: BTreeMap<String, String> = (0..MAX_TOKENS + 1)
            .map(|i| (format!("--app-t{i}"), "red".to_string()))
            .collect();
        assert!(matches!(
            ThemeTokens::new(many),
            Err(ThemeError::TooMany(_))
        ));

        let long = "a".repeat(MAX_VALUE_LEN + 1);
        assert!(matches!(
            tokens(&[("--app-accent", long.as_str())]),
            Err(ThemeError::Value { .. })
        ));
    }

    #[test]
    fn the_dark_set_is_its_own_field_and_may_be_left_out() {
        let mut b = Branding::unbranded();
        b.tokens_dark = tokens(&[("--app-accent", "#9ab8e6")]).unwrap();
        assert_eq!(
            serde_json::to_value(&b).unwrap(),
            serde_json::json!({
                "app_name": "Appliance",
                "manufacturer": "",
                "tokens": {},
                "tokens_dark": { "--app-accent": "#9ab8e6" },
            })
        );

        let light_only: Branding =
            serde_json::from_str(r#"{"app_name":"A","manufacturer":"","tokens":{}}"#).unwrap();
        assert_eq!(light_only.tokens_dark, ThemeTokens::default());

        let hostile = r#"{"app_name":"A","manufacturer":"","tokens_dark":{"--app-bg":"url(x)"}}"#;
        assert!(serde_json::from_str::<Branding>(hostile).is_err());
    }

    #[test]
    fn the_unbranded_identity_is_anonymous() {
        let b = Branding::unbranded();
        assert_eq!(b.app_name, "Appliance");
        assert!(b.tokens.0.is_empty());
    }
}
