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
        ("cents/kWh", Unit::CentsPerKWh),
        ("$/kWh", Unit::DollarsPerKWh),
        ("AUD/kWh", Unit::DollarsPerKWh),
        ("ms", Unit::Millisecond),
        ("millisecond", Unit::Millisecond),
        ("Milliseconds", Unit::Millisecond),
        ("s", Unit::Second),
        ("sec", Unit::Second),
        ("secs", Unit::Second),
        ("second", Unit::Second),
        ("Seconds", Unit::Second),
        ("min", Unit::Minute),
        ("mins", Unit::Minute),
        ("MINUTE", Unit::Minute),
        ("minutes", Unit::Minute),
        ("h", Unit::Hour),
        ("hr", Unit::Hour),
        ("Hrs", Unit::Hour),
        ("hour", Unit::Hour),
        ("hours", Unit::Hour),
        ("d", Unit::Day),
        ("day", Unit::Day),
        ("Days", Unit::Day),
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
        "deg", "mw", "Mw", "mW", "mwh", "MWH", "ma", "c", "k", "S", "H", "MS", "Min", "D", "m",
        "Module #", "rpm", "",
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
        (Unit::Millisecond, "ms"),
        (Unit::Second, "s"),
        (Unit::Minute, "min"),
        (Unit::Hour, "h"),
        (Unit::Day, "d"),
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
    assert_eq!(Unit::Day.dimension(), Some(Dimension::Time));
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
        (q(dec!(90), Unit::Minute), Unit::Second, dec!(5400)),
        (q(dec!(1), Unit::Day), Unit::Hour, dec!(24)),
        (q(dec!(1), Unit::Hour), Unit::Millisecond, dec!(3600000)),
        (q(dec!(90), Unit::Second), Unit::Minute, dec!(1.5)),
    ];
    for (from, to, value) in cases {
        let got = from.to(to.clone()).unwrap();
        assert_eq!((got.value, got.unit), (value, to), "{from:?}");
    }
}

#[test]
fn conversion_that_does_not_terminate_rounds_rather_than_failing() {
    let got = q(dec!(100), Unit::Second).to(Unit::Minute).unwrap();
    assert_eq!(got.unit, Unit::Minute);
    assert_eq!(got.format(Precision::Fixed(4)), "1.6667");
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
    assert_eq!(
        q(dec!(1), Unit::Millisecond).to(Unit::W),
        Err(ConvertError::Incompatible {
            from: Unit::Millisecond,
            to: Unit::W
        })
    );
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
    assert_eq!(
        q(Decimal::MAX, Unit::Day).to(Unit::Millisecond),
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
fn auto_scale_moves_time_between_ms_s_min_and_h() {
    let cases = [
        ("60000", "ms", "1 min"),
        ("600000", "ms", "10 min"),
        ("1500", "ms", "1.5 s"),
        ("24000", "ms", "24 s"),
        ("500", "ms", "500 ms"),
        ("3600000", "ms", "1 h"),
        ("90000000", "ms", "25 h"),
        ("90", "min", "1.5 h"),
        ("0.5", "s", "500 ms"),
    ];
    for (state, unit, shown) in cases {
        let scaled = Quantity::parse(state, Some(unit)).unwrap().auto_scaled();
        assert_eq!(scaled.display(Precision::Exact), shown, "{state} {unit}");
    }
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
    let free = q(dec!(0), Unit::DollarsPerKWh).auto_scaled();
    assert_eq!(free.display(Precision::Fixed(1)), "0.0 c/kWh");
}

#[test]
fn auto_scale_leaves_temperature_ratio_frequency_days_other_and_zero_alone() {
    for unchanged in [
        q(dec!(1500), Unit::Celsius),
        q(dec!(2), Unit::Day),
        q(dec!(0.5), Unit::Day),
        q(dec!(0), Unit::Second),
        q(dec!(1500), Unit::Kelvin),
        q(dec!(1500), Unit::Percent),
        q(dec!(1500), Unit::Hz),
        q(dec!(1500), Unit::Other("rpm".into())),
        q(dec!(0), Unit::KiloW),
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

fn assert_shown_at(cases: &[(Quantity, Quantity, &str)]) {
    for (value, resolution, shown) in cases {
        assert_eq!(
            value.display_at(resolution).as_deref(),
            Ok(*shown),
            "{value:?} at {resolution:?}"
        );
    }
}

#[test]
fn display_at_shows_to_the_steps_first_significant_place_in_the_scaled_unit() {
    let rpm = Unit::Other("rpm".into());
    let unitless = Unit::Other(String::new());
    assert_shown_at(&[
        (q(dec!(6408), Unit::W), q(dec!(1), Unit::W), "6.408 kW"),
        (q(dec!(6400), Unit::W), q(dec!(1), Unit::W), "6.4 kW"),
        (q(dec!(12994), Unit::W), q(dec!(10), Unit::W), "12.99 kW"),
        (
            q(dec!(43238300), Unit::Wh),
            q(dec!(100), Unit::Wh),
            "43.2383 MWh",
        ),
        (
            q(dec!(66.312), Unit::Percent),
            q(dec!(0.1), Unit::Percent),
            "66.3%",
        ),
        (
            q(dec!(21.0956), Unit::CentsPerKWh),
            q(dec!(0.1), Unit::CentsPerKWh),
            "21.1 c/kWh",
        ),
        (
            q(dec!(121.0956), Unit::CentsPerKWh),
            q(dec!(0.1), Unit::CentsPerKWh),
            "1.211 $/kWh",
        ),
        (
            q(dec!(21.46), Unit::Celsius),
            q(dec!(0.1), Unit::Celsius),
            "21.5 °C",
        ),
        (
            q(dec!(21.46), Unit::Celsius),
            q(dec!(0.5), Unit::Celsius),
            "21.5 °C",
        ),
        (
            q(dec!(21.2), Unit::Celsius),
            q(dec!(0.5), Unit::Celsius),
            "21 °C",
        ),
        (
            q(dec!(3), unitless.clone()),
            q(dec!(1), unitless.clone()),
            "3",
        ),
        (
            q(dec!(0.03), unitless.clone()),
            q(dec!(0.03), unitless.clone()),
            "0.03",
        ),
        (
            q(dec!(21.25), unitless.clone()),
            q(dec!(0.25), unitless),
            "21.3",
        ),
        (q(dec!(1234.4), rpm.clone()), q(dec!(1), rpm), "1234 rpm"),
    ]);
}

#[test]
fn display_at_rounds_durations_half_away_from_zero_in_any_unit_of_time() {
    assert_shown_at(&[
        (
            q(dec!(33194), Unit::Millisecond),
            q(dec!(1000), Unit::Millisecond),
            "33 s",
        ),
        (
            q(dec!(33194), Unit::Millisecond),
            q(dec!(1), Unit::Second),
            "33 s",
        ),
        (
            q(dec!(68044), Unit::Millisecond),
            q(dec!(1000), Unit::Millisecond),
            "1.13 min",
        ),
        (
            q(dec!(3598), Unit::Second),
            q(dec!(1), Unit::Second),
            "59.97 min",
        ),
        (
            q(dec!(500), Unit::Millisecond),
            q(dec!(1000), Unit::Millisecond),
            "1 s",
        ),
        (
            q(dec!(-500), Unit::Millisecond),
            q(dec!(1000), Unit::Millisecond),
            "-1 s",
        ),
    ]);
}

#[test]
fn display_at_carries_into_the_next_unit_when_rounding_reaches_it() {
    assert_shown_at(&[
        (q(dec!(999.6), Unit::W), q(dec!(1), Unit::W), "1 kW"),
        (
            q(dec!(60000), Unit::Millisecond),
            q(dec!(1000), Unit::Millisecond),
            "1 min",
        ),
        (q(dec!(3598), Unit::Second), q(dec!(7), Unit::Second), "1 h"),
    ]);
}

#[test]
fn display_at_shows_a_rounded_zero_in_the_unit_one_step_scales_to() {
    assert_shown_at(&[
        (
            q(dec!(400), Unit::Millisecond),
            q(dec!(1000), Unit::Millisecond),
            "0 s",
        ),
        (
            q(dec!(-400), Unit::Millisecond),
            q(dec!(1000), Unit::Millisecond),
            "0 s",
        ),
    ]);
}

#[test]
fn display_at_leaves_days_in_days_at_the_steps_first_significant_place_there() {
    assert_shown_at(&[
        (q(dec!(2.26), Unit::Day), q(dec!(1), Unit::Hour), "2.25 d"),
        (q(dec!(0.04), Unit::Day), q(dec!(1), Unit::Hour), "0.04 d"),
    ]);
}

#[test]
fn a_zero_resolution_shows_every_digit_and_a_negative_one_acts_as_its_magnitude() {
    assert_shown_at(&[
        (
            q(dec!(6408.125), Unit::W),
            q(dec!(0), Unit::W),
            "6.408125 kW",
        ),
        (q(dec!(6408), Unit::W), q(dec!(-1), Unit::W), "6.408 kW"),
        (q(dec!(12994), Unit::W), q(dec!(-10), Unit::W), "12.99 kW"),
    ]);
}

#[test]
fn a_resolution_converts_only_by_ratio_within_the_values_dimension() {
    let incompatible = |value: Quantity, resolution: Quantity| {
        assert_eq!(
            value.display_at(&resolution),
            Err(ConvertError::Incompatible {
                from: value.unit.clone(),
                to: resolution.unit.clone(),
            })
        );
    };
    incompatible(
        q(dec!(21.46), Unit::Celsius),
        q(dec!(0.1), Unit::Fahrenheit),
    );
    incompatible(q(dec!(6408), Unit::W), q(dec!(1), Unit::Wh));
    incompatible(q(dec!(6408), Unit::W), q(dec!(0), Unit::Wh));
    incompatible(
        q(dec!(3), Unit::Other("rpm".into())),
        q(dec!(1), Unit::Other(String::new())),
    );
}

#[test]
fn rounded_to_keeps_the_values_unit() {
    let got = q(dec!(68044), Unit::Millisecond)
        .rounded_to(&q(dec!(1), Unit::Second))
        .unwrap();
    assert_eq!((got.value, got.unit), (dec!(68000), Unit::Millisecond));
    let got = q(dec!(1.2345), Unit::KiloW)
        .rounded_to(&q(dec!(10), Unit::W))
        .unwrap();
    assert_eq!((got.value, got.unit), (dec!(1.23), Unit::KiloW));
}

#[test]
fn rounded_to_out_of_range_is_overflow() {
    assert_eq!(
        q(Decimal::MAX, Unit::W).rounded_to(&q(dec!(0.5), Unit::W)),
        Err(ConvertError::Overflow)
    );
    assert_eq!(
        q(Decimal::MAX, Unit::MegaW).rounded_to(&q(dec!(1), Unit::W)),
        Err(ConvertError::Overflow)
    );
}
