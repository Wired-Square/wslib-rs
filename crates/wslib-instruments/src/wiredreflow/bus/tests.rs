use wslib_can_bus::BusKind;

use super::feature;
use crate::uri::CAN_KINDS;

#[test]
fn the_kinds_offered_are_those_whose_feature_is_on() {
    let enabled: Vec<BusKind> = BusKind::ALL
        .into_iter()
        .filter(|kind| feature(*kind).1)
        .collect();
    assert_eq!(CAN_KINDS, enabled.as_slice());
}
