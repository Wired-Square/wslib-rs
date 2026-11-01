use rust_decimal::Decimal;
use rust_decimal_macros::dec;
use wslib_quantity::{ConvertError, Dimension, Precision, Quantity, Unit, format_decimal};

fn fmt(value: Decimal, precision: Precision) -> String {
    format_decimal(value, precision)
}

fn q(value: Decimal, unit: Unit) -> Quantity {
    Quantity::new(value, unit)
}

#[test]
fn exact_normalises_without_rounding() {
    assert_eq!(fmt(dec!(55.50), Precision::Exact), "55.5");
    assert_eq!(fmt(dec!(0.0001), Precision::Exact), "0.0001");
    assert_eq!(
        fmt(dec!(27.4710502624512), Precision::Exact),
        "27.4710502624512"
    );
    assert_eq!(fmt(dec!(100), Precision::Exact), "100");
}

#[test]
fn fixed_rounds_half_away_from_zero_and_pads() {
    assert_eq!(fmt(dec!(0.125), Precision::Fixed(2)), "0.13");
    assert_eq!(fmt(dec!(5), Precision::Fixed(1)), "5.0");
    assert_eq!(fmt(dec!(27.4710502624512), Precision::Fixed(2)), "27.47");
    assert_eq!(fmt(dec!(6.11326265335083), Precision::Fixed(0)), "6");
    assert_eq!(fmt(dec!(-1.256), Precision::Fixed(1)), "-1.3");
}

#[test]
fn fixed_pads_past_decimals_scale_limit() {
    assert_eq!(
        fmt(dec!(1), Precision::Fixed(30)),
        format!("1.{}", "0".repeat(30))
    );
}

#[test]
fn at_most_rounds_and_drops_trailing_zeros() {
    assert_eq!(fmt(dec!(0.0), Precision::AtMost(3)), "0");
    assert_eq!(fmt(dec!(27.4710502624512), Precision::AtMost(3)), "27.471");
    assert_eq!(fmt(dec!(1.5), Precision::AtMost(3)), "1.5");
}

#[test]
fn magnitude_takes_its_places_from_the_unrounded_value() {
    assert_eq!(fmt(dec!(5), Precision::Magnitude), "5.000");
    assert_eq!(fmt(dec!(99.9995), Precision::Magnitude), "100.000");
    assert_eq!(fmt(dec!(100), Precision::Magnitude), "100.00");
    assert_eq!(fmt(dec!(9999.95), Precision::Magnitude), "10000.0");
    assert_eq!(fmt(dec!(10000), Precision::Magnitude), "10000");
}

#[test]
fn a_value_that_rounds_to_zero_never_prints_negative_zero() {
    assert_eq!(fmt(dec!(-0.001), Precision::Fixed(2)), "0.00");
    assert_eq!(fmt(dec!(-0.001), Precision::AtMost(2)), "0");
    assert_eq!(fmt(dec!(-0.0001), Precision::Magnitude), "0.000");
    assert_eq!(fmt(-Decimal::ZERO, Precision::Exact), "0");
}

#[test]
fn no_thousands_separators() {
    assert_eq!(fmt(dec!(1234567.5), Precision::Fixed(1)), "1234567.5");
    assert_eq!(fmt(dec!(1234567), Precision::Magnitude), "1234567");
}

#[test]
fn ha_precision_is_fixed_when_set_else_at_most_three() {
    assert_eq!(Precision::ha(Some(2)), Precision::Fixed(2));
    assert_eq!(Precision::ha(None), Precision::AtMost(3));
}

#[test]
fn units_parse_from_canonical_and_unambiguous_tolerant_spellings() {
    let table = [
        ("W", Unit::W),
        ("w", Unit::W),
        ("watt", Unit::W),
        ("watts", Unit::W),
        ("kW", Unit::KiloW),
        ("kw", Unit::KiloW),
        ("KW", Unit::KiloW),
        ("kilowatt", Unit::KiloW),
        ("kilowatts", Unit::KiloW),
        ("MW", Unit::MegaW),
        ("Wh", Unit::Wh),
        ("watt-hours", Unit::Wh),
        ("kWh", Unit::KiloWh),
        ("kwh", Unit::KiloWh),
        ("kilowatt-hour", Unit::KiloWh),
        ("kilowatt-hours", Unit::KiloWh),
        ("MWh", Unit::MegaWh),
        ("°C", Unit::Celsius),
        ("C", Unit::Celsius),
        ("degC", Unit::Celsius),
        ("deg C", Unit::Celsius),
        ("℃", Unit::Celsius),
        ("°F", Unit::Fahrenheit),
        ("F", Unit::Fahrenheit),
        ("degF", Unit::Fahrenheit),
        ("deg F", Unit::Fahrenheit),
        ("℉", Unit::Fahrenheit),
        ("K", Unit::Kelvin),
        ("A", Unit::A),
        ("mA", Unit::MilliA),
        ("V", Unit::V),
        ("mV", Unit::MilliV),
        ("kV", Unit::KiloV),
        ("Ah", Unit::Ah),
        ("mAh", Unit::MilliAh),
        ("%", Unit::Percent),
        ("Hz", Unit::Hz),
        ("VA", Unit::VA),
        ("kVA", Unit::KiloVA),
        ("var", Unit::Var),
        ("VAr", Unit::Var),
        ("kvar", Unit::KiloVar),
        ("kVAr", Unit::KiloVar),
        ("c/kWh", Unit::CentsPerKWh),
        ("¢/kWh", Unit::CentsPerKWh),
        ("$/kWh", Unit::DollarsPerKWh),
        (" kW ", Unit::KiloW),
    ];
    for (text, unit) in table {
        assert_eq!(Unit::parse(text), unit, "{text:?}");
        assert_eq!(text.parse::<Unit>(), Ok(unit), "{text:?}");
    }
}

#[test]
fn ambiguous_or_unknown_spellings_are_other_and_display_unchanged() {
    for text in [
        "deg", "mw", "Mw", "mW", "mwh", "MWH", "ma", "c", "k", "Module #", "rpm", "",
    ] {
        let unit = Unit::parse(text);
        assert_eq!(unit, Unit::Other(text.to_string()), "{text:?}");
        assert_eq!(unit.to_string(), text);
        assert_eq!(unit.dimension(), None);
    }
}

#[test]
fn units_display_in_home_assistant_spelling() {
    let table = [
        (Unit::KiloW, "kW"),
        (Unit::Celsius, "°C"),
        (Unit::Var, "var"),
        (Unit::KiloVar, "kvar"),
        (Unit::CentsPerKWh, "c/kWh"),
        (Unit::DollarsPerKWh, "$/kWh"),
        (Unit::MilliAh, "mAh"),
    ];
    for (unit, text) in table {
        assert_eq!(unit.to_string(), text);
        assert_eq!(Unit::parse(text), unit);
    }
}

#[test]
fn units_know_their_dimension() {
    assert_eq!(Unit::KiloWh.dimension(), Some(Dimension::Energy));
    assert_eq!(Unit::MilliAh.dimension(), Some(Dimension::Charge));
    assert_eq!(Unit::Percent.dimension(), Some(Dimension::Ratio));
    assert_eq!(
        Unit::CentsPerKWh.dimension(),
        Some(Dimension::PricePerEnergy)
    );
}

#[test]
fn quantity_parses_plain_and_scientific_states_trimmed() {
    assert_eq!(
        Quantity::parse(" 1234.5 ", Some("W")),
        Some(q(dec!(1234.5), Unit::W))
    );
    assert_eq!(
        Quantity::parse("1.5e3", Some("kW")),
        Some(q(dec!(1500), Unit::KiloW))
    );
    assert_eq!(
        Quantity::parse("9.7E-7", None).map(|q| q.value),
        Some(dec!(0.00000097))
    );
    assert_eq!(
        Quantity::parse("-3", None),
        Some(q(dec!(-3), Unit::Other(String::new())))
    );
    for bad in [
        "unavailable",
        "unknown",
        "",
        "nan",
        "inf",
        "1_000",
        "1e",
        "1,5",
    ] {
        assert_eq!(Quantity::parse(bad, Some("W")), None, "{bad:?}");
    }
}

#[test]
fn conversion_within_a_dimension_is_exact() {
    let cases = [
        (q(dec!(1500), Unit::W), Unit::KiloW, dec!(1.5)),
        (q(dec!(2.5), Unit::MegaW), Unit::W, dec!(2500000)),
        (q(dec!(1234), Unit::Wh), Unit::KiloWh, dec!(1.234)),
        (q(dec!(3), Unit::MegaWh), Unit::KiloWh, dec!(3000)),
        (q(dec!(100), Unit::Celsius), Unit::Fahrenheit, dec!(212)),
        (q(dec!(0), Unit::Celsius), Unit::Kelvin, dec!(273.15)),
        (q(dec!(212), Unit::Fahrenheit), Unit::Celsius, dec!(100)),
        (q(dec!(273.15), Unit::Kelvin), Unit::Fahrenheit, dec!(32)),
        (q(dec!(250), Unit::MilliA), Unit::A, dec!(0.25)),
        (q(dec!(3.3), Unit::V), Unit::MilliV, dec!(3300)),
        (q(dec!(11), Unit::KiloV), Unit::V, dec!(11000)),
        (q(dec!(2600), Unit::MilliAh), Unit::Ah, dec!(2.6)),
        (
            q(dec!(28.5), Unit::CentsPerKWh),
            Unit::DollarsPerKWh,
            dec!(0.285),
        ),
        (
            q(dec!(1.2), Unit::DollarsPerKWh),
            Unit::CentsPerKWh,
            dec!(120),
        ),
    ];
    for (from, to, value) in cases {
        let got = from.to(to.clone()).unwrap();
        assert_eq!((got.value, got.unit), (value, to), "{from:?}");
    }
}

#[test]
fn conversion_across_dimensions_or_from_other_is_incompatible() {
    assert_eq!(
        q(dec!(1), Unit::KiloW).to(Unit::KiloWh),
        Err(ConvertError::Incompatible {
            from: Unit::KiloW,
            to: Unit::KiloWh
        })
    );
    let rpm = Unit::Other("rpm".into());
    assert!(matches!(
        q(dec!(1), rpm.clone()).to(Unit::Hz),
        Err(ConvertError::Incompatible { .. })
    ));
    assert!(q(dec!(1), rpm.clone()).to(rpm).is_ok());
    assert!(matches!(
        q(dec!(1), Unit::Other("x".into())).to(Unit::Other("y".into())),
        Err(ConvertError::Incompatible { .. })
    ));
}

#[test]
fn conversion_out_of_range_is_overflow() {
    assert_eq!(
        q(Decimal::MAX, Unit::MegaW).to(Unit::W),
        Err(ConvertError::Overflow)
    );
    assert_eq!(
        q(Decimal::MAX, Unit::Fahrenheit).to(Unit::Celsius),
        Err(ConvertError::Overflow)
    );
}

#[test]
fn auto_scale_takes_the_largest_prefix_keeping_at_least_one() {
    let cases = [
        (q(dec!(999), Unit::W), dec!(999), Unit::W),
        (q(dec!(1234), Unit::W), dec!(1.234), Unit::KiloW),
        (q(dec!(-2500000), Unit::W), dec!(-2.5), Unit::MegaW),
        (q(dec!(0.5), Unit::KiloWh), dec!(500), Unit::Wh),
        (q(dec!(0.25), Unit::A), dec!(250), Unit::MilliA),
        (q(dec!(0.0005), Unit::A), dec!(0.5), Unit::MilliA),
        (q(dec!(0.5), Unit::W), dec!(0.5), Unit::W),
        (q(dec!(11000), Unit::V), dec!(11), Unit::KiloV),
        (q(dec!(0.8), Unit::Ah), dec!(800), Unit::MilliAh),
        (q(dec!(1500), Unit::VA), dec!(1.5), Unit::KiloVA),
        (q(dec!(2000), Unit::Var), dec!(2), Unit::KiloVar),
    ];
    for (from, value, unit) in cases {
        let got = from.auto_scaled();
        assert_eq!((got.value, got.unit), (value, unit), "{from:?}");
    }
    assert_eq!(
        q(dec!(1234), Unit::W)
            .auto_scaled()
            .display(Precision::Fixed(2)),
        "1.23 kW"
    );
}

#[test]
fn auto_scale_shows_dollars_only_above_one() {
    let dollars = q(dec!(150), Unit::CentsPerKWh).auto_scaled();
    assert_eq!(
        (dollars.value, dollars.unit),
        (dec!(1.5), Unit::DollarsPerKWh)
    );
    let cents = q(dec!(1), Unit::DollarsPerKWh).auto_scaled();
    assert_eq!((cents.value, cents.unit), (dec!(100), Unit::CentsPerKWh));
    let cents = q(dec!(28), Unit::CentsPerKWh).auto_scaled();
    assert_eq!((cents.value, cents.unit), (dec!(28), Unit::CentsPerKWh));
}

#[test]
fn auto_scale_leaves_temperature_ratio_frequency_other_and_zero_alone() {
    for unchanged in [
        q(dec!(1500), Unit::Celsius),
        q(dec!(1500), Unit::Kelvin),
        q(dec!(1500), Unit::Percent),
        q(dec!(1500), Unit::Hz),
        q(dec!(1500), Unit::Other("rpm".into())),
        q(dec!(0), Unit::KiloW),
        q(dec!(0), Unit::CentsPerKWh),
    ] {
        assert_eq!(unchanged.auto_scaled(), unchanged);
    }
}

#[test]
fn display_spaces_every_unit_but_percent() {
    assert_eq!(
        q(dec!(1.234), Unit::KiloW).display(Precision::Fixed(2)),
        "1.23 kW"
    );
    assert_eq!(
        q(dec!(21.5), Unit::Celsius).display(Precision::Exact),
        "21.5 °C"
    );
    assert_eq!(q(dec!(87), Unit::Percent).display(Precision::Exact), "87%");
    assert_eq!(
        q(dec!(90), Unit::Other("°".into())).display(Precision::Exact),
        "90°"
    );
    assert_eq!(
        q(dec!(3), Unit::Other("Module #".into())).display(Precision::Exact),
        "3 Module #"
    );
    assert_eq!(
        q(dec!(3), Unit::Other(String::new())).display(Precision::Exact),
        "3"
    );
    assert_eq!(
        q(dec!(1.2), Unit::KiloW).format(Precision::Fixed(3)),
        "1.200"
    );
}
