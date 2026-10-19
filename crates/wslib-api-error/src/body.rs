use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// The body of every error answer: a sentence for a person, an optional
/// `snake_case` code for a program, and any fields of the app's own beside them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
pub struct ApiErrorBody {
    pub error: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts", ts(optional))]
    pub code: Option<String>,
    #[serde(flatten)]
    #[cfg_attr(feature = "ts", ts(flatten))]
    pub extra: Map<String, Value>,
}

impl ApiErrorBody {
    pub fn new(error: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            code: None,
            extra: Map::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn a_bare_body_is_the_sentence_alone() {
        assert_eq!(
            serde_json::to_value(ApiErrorBody::new("no such user")).unwrap(),
            json!({ "error": "no such user" })
        );
    }

    #[test]
    fn extra_fields_sit_beside_the_sentence_and_code_and_read_back() {
        let wire = json!({ "error": "the clocks disagree", "code": "clock_skew", "minutes": -7 });
        let body: ApiErrorBody = serde_json::from_value(wire.clone()).unwrap();
        assert_eq!(body.code.as_deref(), Some("clock_skew"));
        assert_eq!(body.extra["minutes"], -7);
        assert_eq!(serde_json::to_value(&body).unwrap(), wire);
    }

    #[cfg(feature = "ts")]
    #[test]
    fn typescript_names_the_sentence_the_optional_code_and_open_extras() {
        use ts_rs::TS;
        assert_eq!(
            ApiErrorBody::decl(),
            "type ApiErrorBody = { error: string, code?: string, } & ({ [key in string]?: number | string | boolean | Array<JsonValue> | { [key in string]?: JsonValue } | null });"
        );
    }
}
