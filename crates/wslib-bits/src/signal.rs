#[cfg(feature = "display")]
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// A signal's non-numeric format; absent, a signal is a plain scaled number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum SignalFormat {
    Ascii,
    Utf8,
    Hex,
    Enum,
    UnixTime,
    #[serde(other)]
    Other,
}

/// A signal's `display` value: a name, or a table giving one as `widget` with
/// its other keys kept as authored; none is interpreted here.
#[cfg(feature = "display")]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(
    feature = "ts",
    ts(type = "{ widget: string, [option: string]: unknown }")
)]
pub struct DisplayHint {
    pub widget: String,
    #[serde(flatten)]
    pub options: BTreeMap<String, serde_json::Value>,
}

#[cfg(feature = "display")]
impl DisplayHint {
    /// A widget name, or a table with a non-empty one as `widget`; `None` for
    /// anything else.
    pub fn from_authored(value: serde_json::Value) -> Option<Self> {
        let hint = match value {
            serde_json::Value::String(widget) => Self {
                widget,
                options: BTreeMap::new(),
            },
            serde_json::Value::Object(mut table) => match table.remove("widget") {
                Some(serde_json::Value::String(widget)) => Self {
                    widget,
                    options: table.into_iter().collect(),
                },
                _ => return None,
            },
            _ => return None,
        };
        (!hint.widget.is_empty()).then_some(hint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[cfg(feature = "display")]
    #[test]
    fn a_hint_is_a_widget_name_or_a_table_naming_one() {
        assert_eq!(
            DisplayHint::from_authored(json!("rotary")),
            Some(DisplayHint {
                widget: "rotary".into(),
                options: BTreeMap::new(),
            })
        );
        let table =
            DisplayHint::from_authored(json!({ "widget": "level-bar", "orientation": "vertical" }))
                .unwrap();
        assert_eq!(table.widget, "level-bar");
        assert_eq!(table.options["orientation"], json!("vertical"));
        for bad in [
            json!(""),
            json!(3),
            json!({ "orientation": "vertical" }),
            json!({ "widget": 3 }),
        ] {
            assert_eq!(DisplayHint::from_authored(bad.clone()), None, "{bad}");
        }
    }

    #[test]
    fn an_unknown_format_reads_as_other() {
        assert_eq!(
            serde_json::from_value::<SignalFormat>(json!("bcd")).unwrap(),
            SignalFormat::Other
        );
        assert_eq!(
            serde_json::to_value(SignalFormat::UnixTime).unwrap(),
            json!("unix_time")
        );
    }
}
