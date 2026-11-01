//! The shared Magnitude vectors, which a TypeScript port tests against too.

use std::path::PathBuf;

use rust_decimal::Decimal;
use serde_json::Value;
use wslib_quantity::{Precision, format_decimal};

#[test]
fn every_magnitude_vector_formats_to_its_output() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/magnitude.json");
    let vectors: Vec<Value> =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert!(vectors.len() >= 20);
    for case in &vectors {
        let input = case["input"].as_str().unwrap();
        let value: Decimal = input.parse().unwrap();
        assert_eq!(
            format_decimal(value, Precision::Magnitude),
            case["output"].as_str().unwrap(),
            "input {input}"
        );
    }
}
