//! A product builds every `Pending` state from outside the crate that defines it.

use wslib_appliance_types::pending::{
    Pending, PendingState, Rollback, SettledBy, Warning, WarningScope,
};

#[test]
fn a_product_can_build_every_state_a_rollback_and_a_warning() {
    for (state, tag) in [
        (PendingState::Pending, "pending"),
        (
            PendingState::Settled {
                by: SettledBy::Operator,
            },
            "settled",
        ),
        (
            PendingState::Settled {
                by: SettledBy::ReadBack,
            },
            "settled",
        ),
        (PendingState::RolledBack, "rolled_back"),
        (PendingState::Expired, "expired"),
    ] {
        let mut pending = Pending::new("pump".to_string());
        pending.state = state;
        pending.check_after_ms = Some(2_000);
        let mut rollback = Rollback::default();
        rollback.in_ms = 180_000;
        pending.rollback = Some(rollback);
        let mut warning = Warning::default();
        warning.text = "The pump restarts.".to_string();
        warning.scope = WarningScope::Standing;
        pending.warnings.push(warning);

        let wire = serde_json::to_value(&pending).unwrap();
        assert_eq!(wire["state"], tag);
        assert_eq!(wire["rollback"]["in_ms"], 180_000);
        assert_eq!(
            serde_json::from_value::<Pending<String>>(wire).unwrap(),
            pending
        );
    }
}

#[test]
fn a_warning_is_about_this_change_unless_it_says_otherwise() {
    assert_eq!(Warning::default().scope, WarningScope::ThisChange);
}
