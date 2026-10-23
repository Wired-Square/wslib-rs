use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};
use wslib_secret::Secret;

use crate::Error;

/// A vault, from `op vault list` or `op vault get`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultInfo {
    pub id: String,
    #[serde(default)]
    pub name: String,
}

impl VaultInfo {
    /// Whether `name` is this vault's id, or its name ignoring case: `op` itself
    /// allows two vaults one name.
    pub fn is_named(&self, name: &str) -> bool {
        self.id == name || self.name.to_lowercase() == name.to_lowercase()
    }
}

/// An account the CLI is set up for, from `op account list`, which works signed out.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountInfo {
    /// The sign-in address as a bare host, `my.1password.com`.
    #[serde(deserialize_with = "bare_host")]
    pub url: String,
    pub email: String,
    #[serde(default)]
    pub account_uuid: String,
    #[serde(default)]
    pub user_uuid: String,
}

/// One account, from `op account get`, which resolves a shorthand, address or
/// UUID that `op account list` gives no way to match.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    /// The account UUID.
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub domain: String,
}

/// The account and user `op` is signed in as, from `op whoami`.
///
/// Every field defaults, since the payload varies by `op` version.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WhoAmI {
    /// A bare host, as [`AccountInfo::url`] is, though `op whoami` says `https://host/`.
    #[serde(default, deserialize_with = "bare_host")]
    pub url: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub account_uuid: String,
    #[serde(default)]
    pub user_uuid: String,
    #[serde(default)]
    pub user_type: String,
}

/// The signed-in user, from `op user get --me`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub email: String,
}

/// Which item a call means: by id, which never matches a title, or by title,
/// which fails as [`Error::Ambiguous`] when two items share it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ItemRef {
    Id(String),
    Title(String),
}

impl ItemRef {
    /// The item whose id is `id`.
    pub fn id(id: impl Into<String>) -> Self {
        Self::Id(id.into())
    }

    /// The one item titled `title`.
    pub fn title(title: impl Into<String>) -> Self {
        Self::Title(title.into())
    }

    /// The argument `op` is given; an id that is not one of `op`'s, which `op`
    /// would try as a title, is refused.
    pub(crate) fn arg(&self) -> Result<&str, Error> {
        match self {
            Self::Id(id) if !is_item_id(id) => Err(Error::InvalidItemId(id.clone())),
            Self::Id(id) | Self::Title(id) => Ok(id),
        }
    }
}

impl From<&ItemSummary> for ItemRef {
    fn from(item: &ItemSummary) -> Self {
        Self::id(&item.id)
    }
}

impl From<&Item> for ItemRef {
    fn from(item: &Item) -> Self {
        Self::id(&item.id)
    }
}

/// Whether `s` has the shape of an item id: 26 lowercase letters and digits.
pub(crate) fn is_item_id(s: &str) -> bool {
    s.len() == 26
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

/// An item as `op item list` describes it, without its fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemSummary {
    pub id: String,
    #[serde(default)]
    pub title: String,
    /// `op`'s JSON form, `SECURE_NOTE`, not the `Secure Note` that `--categories` takes.
    #[serde(default)]
    pub category: String,
    pub vault: VaultInfo,
}

/// An item with its fields, from `op item get`.
#[derive(Clone, Debug, Deserialize)]
pub struct Item {
    pub id: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub category: String,
    pub vault: VaultInfo,
    #[serde(default)]
    pub fields: Vec<Field>,
}

impl Item {
    /// The first field labelled `label`, in any section.
    pub fn field(&self, label: &str) -> Option<&Field> {
        self.fields.iter().find(|f| f.label == label)
    }

    /// The value of [`Item::field`], when it has one.
    pub fn value(&self, label: &str) -> Option<&Secret> {
        self.field(label)?.value.as_ref()
    }
}

/// One field of an [`Item`].
#[derive(Clone, Debug, Deserialize)]
pub struct Field {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub label: String,
    /// `op`'s JSON type: `STRING`, `CONCEALED`, `URL`, …
    #[serde(default, rename = "type")]
    pub field_type: String,
    /// `USERNAME`, `PASSWORD` or `NOTES` for a built-in field.
    #[serde(default)]
    pub purpose: Option<String>,
    #[serde(default)]
    pub section: Option<Section>,
    #[serde(default, deserialize_with = "text_value")]
    pub value: Option<Secret>,
}

/// The section a [`Field`] is in.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct Section {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub label: Option<String>,
}

/// Bytes whose `Debug` renders `set` or `unset`, never the value: a document or a
/// value read byte for byte.
#[derive(Clone)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// Wraps the bytes.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// The bytes.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// The bytes as a [`Secret`], when they are UTF-8.
    pub fn into_text(self) -> Result<Secret, Error> {
        String::from_utf8(self.0)
            .map(Secret::new)
            .map_err(|_| Error::NotUtf8)
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(if self.0.is_empty() {
            "SecretBytes(unset)"
        } else {
            "SecretBytes(set)"
        })
    }
}

fn bare_host<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    let url = String::deserialize(d)?;
    let host = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(&url);
    Ok(host.trim_end_matches('/').to_owned())
}

/// A string value; anything else is dropped, so a parse error can never quote a value.
fn text_value<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Secret>, D::Error> {
    Ok(match serde_json::Value::deserialize(d)? {
        serde_json::Value::String(s) => Some(Secret::new(s)),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whoami_and_account_list_agree_on_the_url() {
        let who: WhoAmI =
            serde_json::from_str(r#"{"url":"https://my.1password.com/","user_uuid":"U1"}"#)
                .unwrap();
        let account: AccountInfo = serde_json::from_str(
            r#"{"url":"my.1password.com","email":"a@example.com","user_uuid":"U1"}"#,
        )
        .unwrap();
        assert_eq!(who.url, account.url);
    }

    #[test]
    fn an_empty_whoami_still_reads() {
        assert_eq!(
            serde_json::from_str::<WhoAmI>("{}").unwrap(),
            WhoAmI::default()
        );
    }

    #[test]
    fn a_vault_is_named_by_id_or_by_name_in_any_case() {
        let vault = VaultInfo {
            id: "abc123".into(),
            name: "Café".into(),
        };
        assert!(vault.is_named("abc123"));
        assert!(vault.is_named("CAFÉ"));
        assert!(!vault.is_named("Café 2"));
    }

    #[test]
    fn an_item_never_prints_a_value() {
        let item: Item = serde_json::from_str(
            r#"{"id":"i1","title":"Key","vault":{"id":"v1","name":"Ops"},
                "fields":[{"id":"f1","label":"private_key","type":"CONCEALED","value":"hunter2"},
                          {"id":"f2","label":"size","type":"STRING","value":4096}]}"#,
        )
        .unwrap();
        assert_eq!(item.value("private_key").unwrap().expose(), "hunter2");
        assert!(item.value("size").is_none());
        assert!(!format!("{item:?}").contains("hunter2"));
    }

    #[test]
    fn secret_bytes_never_print_and_check_utf8() {
        let bytes = SecretBytes::new(b"s3cret".to_vec());
        assert_eq!(format!("{bytes:?}"), "SecretBytes(set)");
        assert_eq!(bytes.into_text().unwrap().expose(), "s3cret");
        assert!(matches!(
            SecretBytes::new(vec![0xff]).into_text(),
            Err(Error::NotUtf8)
        ));
    }
}
