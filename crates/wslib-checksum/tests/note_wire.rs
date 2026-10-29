//! Every note code's values on the wire, against `fixtures/note_wire.json`:
//! counts as numbers, positions as negative numbers, `value` as a string.

use std::path::PathBuf;

use wslib_checksum::{ALL_NOTES, ChecksumNote, NoteValue};

#[test]
fn every_note_serialises_as_pinned() {
    let notes: Vec<ChecksumNote> = ALL_NOTES
        .iter()
        .map(|spec| {
            let values: Vec<(&str, NoteValue)> = spec
                .values
                .iter()
                .enumerate()
                .map(|(i, &name)| {
                    let value = match name {
                        "value" => format!("0x{:02X}", 0xA0 + i).into(),
                        "byte" | "from" | "to" | "position" => (-(i as i32) - 2).into(),
                        _ => (usize::MAX / 4 + i).into(),
                    };
                    (name, value)
                })
                .collect();
            ChecksumNote::new(spec.code, &values)
        })
        .collect();
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/note_wire.json");
    let pinned: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(serde_json::to_value(&notes).unwrap(), pinned);
    assert_eq!(
        serde_json::to_string_pretty(&notes).unwrap(),
        serde_json::to_string_pretty(&pinned).unwrap()
    );
}
