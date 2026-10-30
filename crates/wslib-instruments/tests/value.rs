use wslib_instruments::value::Value;

const MILLI: i8 = -3;
const TENTHS: i8 = -1;
const UNITS: i8 = 0;
const HUNDREDS: i8 = 2;
const ROOM_TENTHS: i64 = 210;
const ROOM_MILLI: i64 = 21_000;
const LARGEST_SHIFT_UP: i8 = i8::MAX;
const SMALLEST_EXPONENT: i8 = i8::MIN;

#[test]
fn rescaling_to_a_finer_exponent_multiplies_exactly() {
    assert_eq!(
        Value::new(ROOM_TENTHS, TENTHS).rescale(MILLI),
        Some(ROOM_MILLI),
        "21.0 °C is 21 000 m°C"
    );
}

#[test]
fn rescaling_to_a_coarser_exponent_divides_only_when_no_digits_are_lost() {
    assert_eq!(
        Value::new(ROOM_MILLI, MILLI).rescale(TENTHS),
        Some(ROOM_TENTHS)
    );
    assert_eq!(
        Value::new(ROOM_MILLI + 1, MILLI).rescale(TENTHS),
        None,
        "21.001 has no exact tenths"
    );
}

#[test]
fn a_rescale_that_overflows_is_none_not_a_wrapped_number() {
    assert_eq!(Value::new(i64::MAX, UNITS).rescale(TENTHS), None);
    assert_eq!(
        Value::new(1, LARGEST_SHIFT_UP).rescale(SMALLEST_EXPONENT),
        None
    );
}

#[test]
fn zero_rescales_to_zero_at_any_exponent() {
    assert_eq!(
        Value::new(0, LARGEST_SHIFT_UP).rescale(SMALLEST_EXPONENT),
        Some(0)
    );
}

#[test]
fn negative_values_rescale_with_their_sign() {
    assert_eq!(
        Value::new(-ROOM_TENTHS, TENTHS).rescale(MILLI),
        Some(-ROOM_MILLI)
    );
}

#[test]
fn display_places_the_decimal_point_from_the_exponent() {
    assert_eq!(Value::new(ROOM_TENTHS, TENTHS).to_string(), "21.0");
    assert_eq!(
        Value::new(-5, MILLI).to_string(),
        "-0.005",
        "a sub-unit negative keeps its sign and leading zero"
    );
    assert_eq!(Value::new(0, TENTHS).to_string(), "0.0");
    assert_eq!(Value::new(-10, HUNDREDS).to_string(), "-1000");
    assert_eq!(
        Value::new(0, HUNDREDS).to_string(),
        "0",
        "zero has no trailing zeros to scale"
    );
}
