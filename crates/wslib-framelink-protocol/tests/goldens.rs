//! Every serialised shape, wire payload and message, against what the source
//! this crate was moved from produced for the same inputs.

use wslib_framelink_protocol as p;

include!("fixtures/golden_inputs.rs");

#[test]
fn every_golden_is_unchanged() {
    let fixtures: std::collections::BTreeMap<String, String> =
        serde_json::from_str(include_str!("fixtures/goldens.json")).unwrap();
    let goldens = protocol_goldens();
    assert_eq!(goldens.len(), fixtures.len());
    for (name, produced) in goldens {
        assert_eq!(produced, fixtures[name], "{name}");
    }
}
