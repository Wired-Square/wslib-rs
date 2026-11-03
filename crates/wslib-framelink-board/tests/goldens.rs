//! Every serialised shape and written TOML, against what the source this
//! crate was moved from produced for the same inputs. `IndicatorConfig`'s
//! `colour` keeps the name `color`. A frame definition's signal carries the
//! device's `quantity` byte.

use wslib_framelink_board as b;
use wslib_framelink_protocol as p;

include!("fixtures/golden_inputs.rs");

#[test]
fn every_golden_is_unchanged() {
    let fixtures: std::collections::BTreeMap<String, String> =
        serde_json::from_str(include_str!("fixtures/goldens.json")).unwrap();
    let goldens = board_goldens();
    assert_eq!(goldens.len(), fixtures.len());
    for (name, produced) in goldens {
        assert_eq!(produced, fixtures[name], "{name}");
    }
}

#[test]
fn indicator_colour_is_serialised_as_color() {
    let config: b::IndicatorConfig = serde_json::from_str(INDICATOR_CONFIG).unwrap();
    assert_eq!(config.colour, 0xFF00_FF00);
    assert_eq!(serde_json::to_string(&config).unwrap(), INDICATOR_CONFIG);
}
