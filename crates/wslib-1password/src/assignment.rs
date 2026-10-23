use std::fmt;
use std::str::FromStr;

use serde_json::{Value, json};
use wslib_secret::Secret;

use crate::Error;

/// A custom field's type, as an assignment names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldType {
    Password,
    Text,
    Email,
    Url,
    Date,
    MonthYear,
    Phone,
    Otp,
}

impl FieldType {
    const ALL: [(Self, &'static str, &'static str); 8] = [
        (Self::Password, "password", "CONCEALED"),
        (Self::Text, "text", "STRING"),
        (Self::Email, "email", "EMAIL"),
        (Self::Url, "url", "URL"),
        (Self::Date, "date", "DATE"),
        (Self::MonthYear, "monthYear", "MONTH_YEAR"),
        (Self::Phone, "phone", "PHONE"),
        (Self::Otp, "otp", "OTP"),
    ];

    fn entry(self) -> (Self, &'static str, &'static str) {
        Self::ALL
            .into_iter()
            .find(|(t, ..)| *t == self)
            .expect("every type is listed")
    }

    fn from_assignment(name: &str) -> Option<Self> {
        let name = if name == "concealed" {
            "password"
        } else {
            name
        };
        Self::ALL
            .into_iter()
            .find(|(_, n, _)| *n == name)
            .map(|(t, ..)| t)
    }
}

#[derive(Clone)]
enum Change {
    Set(Option<FieldType>, Secret),
    Delete,
}

/// One field to set or delete, in `op`'s v2 assignment syntax
/// (`section.label[type]=value`, `label[delete]`).
///
/// `Debug` and [`Assignment::shown`] never include the value.
#[derive(Clone)]
pub struct Assignment {
    section: Option<String>,
    label: String,
    change: Change,
}

const BUILT_IN: [(&str, &str, &str); 3] = [
    ("username", "STRING", "USERNAME"),
    ("password", "CONCEALED", "PASSWORD"),
    ("notesPlain", "STRING", "NOTES"),
];

impl Assignment {
    /// Sets a custom field of `field_type`.
    pub fn set(label: impl Into<String>, field_type: FieldType, value: impl Into<Secret>) -> Self {
        Self {
            section: None,
            label: label.into(),
            change: Change::Set(Some(field_type), value.into()),
        }
    }

    /// Sets a field without a type: a built-in one (`username`, `password`,
    /// `notesPlain`), or else a custom password field, as `op` makes one.
    pub fn untyped(label: impl Into<String>, value: impl Into<Secret>) -> Self {
        Self {
            section: None,
            label: label.into(),
            change: Change::Set(None, value.into()),
        }
    }

    /// Deletes a field; only an edit can.
    pub fn delete(label: impl Into<String>) -> Self {
        Self {
            section: None,
            label: label.into(),
            change: Change::Delete,
        }
    }

    /// The same field inside `section`.
    pub fn in_section(mut self, section: impl Into<String>) -> Self {
        self.section = Some(section.into());
        self
    }

    pub(crate) fn token(&self) -> String {
        match &self.change {
            Change::Set(_, value) => format!("{}={}", self.name(), value.expose()),
            Change::Delete => self.name(),
        }
    }

    /// The assignment with its value as `<redacted>`.
    pub fn shown(&self) -> String {
        match self.change {
            Change::Set(..) => format!("{}=<redacted>", self.name()),
            Change::Delete => self.name(),
        }
    }

    pub(crate) fn value(&self) -> Option<&str> {
        match &self.change {
            Change::Set(_, value) => Some(value.expose()),
            Change::Delete => None,
        }
    }

    fn name(&self) -> String {
        let label = escape(&self.label);
        let path = match &self.section {
            Some(section) => format!("{}.{label}", escape(section)),
            None => label,
        };
        let kind = match self.change {
            Change::Set(Some(t), _) => t.entry().1,
            Change::Set(None, _) => return path,
            Change::Delete => "delete",
        };
        format!("{path}[{kind}]")
    }

    pub(crate) fn template_field(&self) -> Result<Value, Error> {
        let Change::Set(kind, value) = &self.change else {
            return Err(Error::InvalidAssignment(format!(
                "{}: only an edit deletes a field",
                self.shown()
            )));
        };
        let built_in = BUILT_IN
            .iter()
            .find(|(id, ..)| *id == self.label && self.section.is_none());
        let mut field = match (kind, built_in) {
            (None, Some((id, field_type, purpose))) => {
                json!({"id": id, "type": field_type, "purpose": purpose})
            }
            (None, None) => json!({"label": self.label, "type": "CONCEALED"}),
            (Some(t), _) => json!({"label": self.label, "type": t.entry().2}),
        };
        field["value"] = Value::String(value.expose().to_owned());
        if let Some(section) = &self.section {
            field["section"] = json!({"id": section, "label": section});
        }
        Ok(field)
    }

    pub(crate) fn section(&self) -> Option<&str> {
        self.section.as_deref()
    }

    /// Reads one v2 assignment token, refusing `--field` flags and a token
    /// without `=` other than `label[delete]`.
    pub fn parse(token: &str) -> Result<Self, Error> {
        let invalid = |why: &str| {
            let shown = token
                .split_once('=')
                .map_or(token.to_owned(), |(name, _)| format!("{name}=<redacted>"));
            Error::InvalidAssignment(format!("{shown}: {why}"))
        };
        if token.starts_with("--") {
            return Err(invalid("use the assignment syntax, not a flag"));
        }
        let (name, value) = match split_unescaped(token, '=') {
            Some((name, value)) => (name, Some(value)),
            None => (token, None),
        };
        let (path, kind) = match name.strip_suffix(']').and_then(|n| n.rsplit_once('[')) {
            Some((path, kind)) => (path, Some(kind)),
            None => (name, None),
        };
        let (section, label) = match split_unescaped(path, '.') {
            Some((section, label)) => (Some(unescape(section)), unescape(label)),
            None => (None, unescape(path)),
        };
        if label.is_empty() {
            return Err(invalid("no field label"));
        }
        let change = match (kind, value) {
            (Some("delete"), None) => Change::Delete,
            (_, None) => return Err(invalid("expected label=value or label[delete]")),
            (Some("delete"), Some(_)) => return Err(invalid("a delete takes no value")),
            (None, Some(value)) => Change::Set(None, value.into()),
            (Some(kind), Some(value)) => {
                let kind = FieldType::from_assignment(kind)
                    .ok_or_else(|| invalid("unsupported field type"))?;
                Change::Set(Some(kind), value.into())
            }
        };
        Ok(Self {
            section,
            label,
            change,
        })
    }
}

impl FromStr for Assignment {
    type Err = Error;

    fn from_str(token: &str) -> Result<Self, Error> {
        Self::parse(token)
    }
}

impl fmt::Debug for Assignment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Assignment({})", self.shown())
    }
}

/// Template JSON for `op item create`, so values reach `op` on stdin, not in argv.
pub(crate) fn template(assignments: &[Assignment]) -> Result<Vec<u8>, Error> {
    let fields = assignments
        .iter()
        .map(Assignment::template_field)
        .collect::<Result<Vec<_>, _>>()?;
    let mut sections: Vec<&str> = Vec::new();
    for section in assignments.iter().filter_map(Assignment::section) {
        if !sections.contains(&section) {
            sections.push(section);
        }
    }
    let sections: Vec<Value> = sections
        .iter()
        .map(|s| json!({"id": s, "label": s}))
        .collect();
    Ok(
        serde_json::to_vec(&json!({"fields": fields, "sections": sections}))
            .expect("JSON values serialise"),
    )
}

fn escape(part: &str) -> String {
    let mut out = String::with_capacity(part.len());
    for c in part.chars() {
        if matches!(c, '\\' | '.' | '=') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn unescape(part: &str) -> String {
    let mut out = String::with_capacity(part.len());
    let mut chars = part.chars();
    while let Some(c) = chars.next() {
        out.push(if c == '\\' {
            chars.next().unwrap_or('\\')
        } else {
            c
        });
    }
    out
}

fn split_unescaped(s: &str, at: char) -> Option<(&str, &str)> {
    let mut escaped = false;
    for (i, c) in s.char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' => escaped = true,
            c if c == at => return Some((&s[..i], &s[i + 1..])),
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_reads_back_as_written() {
        for token in [
            "cn[text]=example.com",
            "private_key=-----BEGIN PRIVATE KEY-----\nAAA\n-----END PRIVATE KEY-----\n",
            "diffie-hellman.key_size[text]=2048",
            "a\\.b.c\\=d[url]=https://x/?q=1",
            "old_field[delete]",
            "template.default[delete]",
        ] {
            assert_eq!(Assignment::parse(token).unwrap().token(), token);
        }
    }

    #[test]
    fn escaped_dots_and_equals_stay_in_the_label() {
        let a = Assignment::parse("a\\.b.c\\=d[text]=v=w").unwrap();
        assert_eq!(a.section(), Some("a.b"));
        assert_eq!(a.label, "c=d");
        assert_eq!(a.value(), Some("v=w"));
    }

    #[test]
    fn a_field_flag_is_refused() {
        assert!(matches!(
            Assignment::parse("--field=foo"),
            Err(Error::InvalidAssignment(_))
        ));
    }

    #[test]
    fn a_token_without_a_value_is_refused_unless_it_deletes() {
        assert!(matches!(
            Assignment::parse("no_equals_sign"),
            Err(Error::InvalidAssignment(_))
        ));
        assert!(Assignment::parse("label[delete]").is_ok());
    }

    #[test]
    fn an_unknown_type_is_refused_without_quoting_the_value() {
        let e = Assignment::parse("key[blob]=hunter2").unwrap_err();
        assert!(!e.to_string().contains("hunter2"));
    }

    #[test]
    fn debug_never_shows_the_value() {
        let a = Assignment::set("private_key", FieldType::Password, "hunter2").in_section("keys");
        assert_eq!(
            format!("{a:?}"),
            "Assignment(keys.private_key[password]=<redacted>)"
        );
    }

    #[test]
    fn a_template_types_each_field() {
        let template: Value = serde_json::from_slice(
            &template(&[
                Assignment::set("cn", FieldType::Text, "example.com"),
                Assignment::untyped("notesPlain", "hello"),
                Assignment::untyped("private_key", "pem"),
                Assignment::set("key_size", FieldType::Text, "2048").in_section("diffie-hellman"),
            ])
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            template,
            json!({
                "fields": [
                    {"label": "cn", "type": "STRING", "value": "example.com"},
                    {"id": "notesPlain", "type": "STRING", "purpose": "NOTES", "value": "hello"},
                    {"label": "private_key", "type": "CONCEALED", "value": "pem"},
                    {"label": "key_size", "type": "STRING", "value": "2048",
                     "section": {"id": "diffie-hellman", "label": "diffie-hellman"}},
                ],
                "sections": [{"id": "diffie-hellman", "label": "diffie-hellman"}],
            })
        );
    }

    #[test]
    fn a_template_cannot_delete() {
        assert!(matches!(
            template(&[Assignment::delete("x")]),
            Err(Error::InvalidAssignment(_))
        ));
    }
}
