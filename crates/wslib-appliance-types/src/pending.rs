//! A change that is applied and not yet known to have taken: the one envelope
//! the appliance and a product answer it in, so one component renders both.

use serde::{Deserialize, Serialize};

/// A change, where it stands, and when to look again; `change` is what was
/// asked for while pending, and what the device reports once settled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
#[non_exhaustive]
pub struct Pending<T> {
    pub change: T,
    #[serde(flatten)]
    pub state: PendingState,
    /// Milliseconds to wait before re-reading, a hint; `None` once terminal.
    pub check_after_ms: Option<u32>,
    /// Present only where not confirming undoes the change.
    pub rollback: Option<Rollback>,
    pub warnings: Vec<Warning>,
}

impl<T> Pending<T> {
    /// `change`, pending, with no hint, no rollback and no warnings.
    pub fn new(change: T) -> Self {
        Self {
            change,
            state: PendingState::Pending,
            check_after_ms: None,
            rollback: None,
            warnings: Vec::new(),
        }
    }
}

/// How long until the box undoes the change by itself, in milliseconds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
#[non_exhaustive]
pub struct Rollback {
    pub in_ms: u32,
}

/// Where a change stands. Every state but `pending` is terminal, though an
/// `expired` change may later read `settled`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(tag = "state", rename_all = "snake_case")]
#[cfg_attr(feature = "ts", ts(export))]
#[non_exhaustive]
pub enum PendingState {
    Pending,
    Settled {
        by: SettledBy,
    },
    RolledBack,
    /// The server's verdict at a deadline on the box's clock.
    Expired,
}

/// Who or what settled a change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "ts", ts(export))]
#[non_exhaustive]
pub enum SettledBy {
    /// Somebody confirmed it.
    Operator,
    /// Reading the device back showed it had taken.
    ReadBack,
}

/// A sentence about a change, never a refusal.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
#[non_exhaustive]
pub struct Warning {
    pub text: String,
    pub scope: WarningScope,
}

/// Whether a warning goes when its change reaches a terminal state.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "ts", ts(export))]
#[non_exhaustive]
pub enum WarningScope {
    #[default]
    ThisChange,
    Standing,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_state_is_flattened_beside_the_change() {
        let mut settled = Pending::new(json!({ "name": "pump" }));
        settled.state = PendingState::Settled {
            by: SettledBy::ReadBack,
        };
        settled.warnings.push(Warning {
            text: "The pump restarts.".to_string(),
            scope: WarningScope::Standing,
        });
        let wire = json!({
            "change": { "name": "pump" },
            "state": "settled",
            "by": "read_back",
            "check_after_ms": null,
            "rollback": null,
            "warnings": [{ "text": "The pump restarts.", "scope": "standing" }],
        });
        assert_eq!(serde_json::to_value(&settled).unwrap(), wire);
        assert_eq!(
            serde_json::from_value::<Pending<serde_json::Value>>(wire).unwrap(),
            settled
        );
    }
}
