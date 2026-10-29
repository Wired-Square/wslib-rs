use serde::{Deserialize, Serialize};
use toml::{Table, Value};

use crate::manifest::layout_fits;
use crate::{DisplayHint, ManifestError, ModbusManifest, RegisterType};

/// One finding: the path of the field at fault and what is wrong with it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(rename = "ValidationError"))]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub field: String,
    pub message: String,
}

fn finding(field: impl Into<String>, message: impl Into<String>) -> Finding {
    Finding {
        field: field.into(),
        message: message.into(),
    }
}

/// Every finding in a catalogue's `[meta]` and `[frame.modbus]` sections, empty
/// when they are valid; other frame sections are not read. A TOML syntax error
/// is the one finding, on `toml`.
pub fn validate(content: &str) -> Vec<Finding> {
    let table: Table = match toml::from_str(content) {
        Ok(table) => table,
        Err(e) => return vec![finding("toml", format!("TOML syntax error: {e}"))],
    };
    let mut findings = Vec::new();
    validate_meta(&table, &mut findings);
    let frames = table
        .get("frame")
        .and_then(|f| f.get("modbus"))
        .and_then(Value::as_table);
    if frames.is_some()
        && let Err(ManifestError::BadRegister(name)) = ModbusManifest::parse(content)
    {
        findings.push(finding(
            format!("frame.modbus.{name}"),
            format!(
                "frame '{name}' has no register_number and its name is not a register address (decimal or 0x-hex)"
            ),
        ));
    }
    for (key, frame) in frames.into_iter().flatten() {
        let prefix = format!("frame.modbus.{key}");
        require_finite_scale(&prefix, frame, &mut findings);
        validate_signals(&prefix, frame, &mut findings);
        validate_layouts(&prefix, frame, &mut findings);
    }
    findings
}

fn validate_meta(table: &Table, findings: &mut Vec<Finding>) {
    let Some(meta) = table.get("meta").and_then(Value::as_table) else {
        findings.push(finding("meta", "Missing [meta] section"));
        return;
    };
    match meta.get("name") {
        None => findings.push(finding(
            "meta.name",
            "Catalogue name is required in [meta] section",
        )),
        Some(name) if !name.is_str() => {
            findings.push(finding("meta.name", "Catalogue name must be a string"))
        }
        Some(_) => {}
    }
    if meta
        .get("version")
        .and_then(Value::as_integer)
        .is_some_and(|v| v < 1)
    {
        findings.push(finding("meta.version", "Version must be at least 1"));
    }
    if let Some(e) = meta.get("default_endianness").and_then(Value::as_str)
        && e != "little"
        && e != "big"
    {
        findings.push(finding(
            "meta.default_endianness",
            format!("Invalid endianness '{e}'. Must be 'little' or 'big'"),
        ));
    }
    if let Some(codes) = meta.get("modbus").and_then(|m| m.get("function_code")) {
        validate_function_codes(codes, findings);
    }
}

/// A rule an RTU line can't read is dropped, which leaves its code to the
/// shortest-CRC search: the truncation the rule was written to prevent.
fn validate_function_codes(codes: &Value, findings: &mut Vec<Finding>) {
    let prefix = "meta.modbus.function_code";
    let Some(codes) = codes.as_table() else {
        findings.push(finding(
            prefix,
            "Function codes must be a table keyed by code",
        ));
        return;
    };
    for (key, body) in codes {
        let field = format!("{prefix}.{key}");
        match function_code(key) {
            None | Some(0) => findings.push(finding(
                &field,
                format!("Function code '{key}' must be 0x01 to 0x7F"),
            )),
            Some(code) if has_own_length_rules(code) => findings.push(finding(
                &field,
                format!(
                    "Function code {code:#04x} is standard Modbus, framed by its own length rules, so declaring it has no effect"
                ),
            )),
            Some(_) => {}
        }
        let Some(body) = body.as_table() else {
            findings.push(finding(field, "A function code must be a table"));
            continue;
        };
        let Some(rules) = body.get("lengths") else {
            continue;
        };
        let Some(rules) = rules.as_array() else {
            findings.push(finding(
                format!("{field}.lengths"),
                "Lengths must be an array of rules",
            ));
            continue;
        };
        for (i, rule) in rules.iter().enumerate() {
            if !is_length_rule(rule) {
                findings.push(finding(
                    format!("{field}.lengths[{i}]"),
                    "A length rule needs a len of { fixed } or { count_at, overhead }, \
                     and optionally a when of { offset, value }",
                ));
            }
        }
    }
}

/// `0x60` or `96`.
fn function_code(key: &str) -> Option<u8> {
    let key = key.trim();
    let code = match key.strip_prefix("0x").or_else(|| key.strip_prefix("0X")) {
        Some(hex) => u32::from_str_radix(hex, 16).ok()?,
        None if !key.is_empty() && key.chars().all(|c| c.is_ascii_digit()) => key.parse().ok()?,
        None => return None,
    };
    u8::try_from(code).ok()
}

/// The codes an RTU line frames without a declared rule: the reads, the writes,
/// and every exception.
fn has_own_length_rules(code: u8) -> bool {
    code & 0x80 != 0 || matches!(code, 0x01..=0x06 | 0x0F | 0x10)
}

/// `{ len = { fixed } }` or `{ len = { count_at, overhead } }`, optionally with
/// `when = { offset, value }`.
fn is_length_rule(rule: &Value) -> bool {
    let int = |v: &Value, key: &str| v.get(key).and_then(Value::as_integer);
    let byte = |v: &Value, key: &str| int(v, key).and_then(|i| u8::try_from(i).ok());
    let word = |v: &Value, key: &str| int(v, key).and_then(|i| u16::try_from(i).ok());
    let when_ok = rule
        .get("when")
        .is_none_or(|w| byte(w, "offset").is_some() && byte(w, "value").is_some());
    let len_ok = rule.get("len").is_some_and(|len| {
        matches!(
            (
                word(len, "fixed"),
                byte(len, "count_at"),
                word(len, "overhead")
            ),
            (Some(_), None, None) | (None, Some(_), Some(_))
        )
    });
    when_ok && len_ok
}

/// A malformed `display` parses as no hint and a non-finite scale decodes as out
/// of range, so this is where either shows.
fn validate_signals(prefix: &str, frame: &Value, findings: &mut Vec<Finding>) {
    let signals = frame
        .get("signal")
        .or_else(|| frame.get("signals"))
        .and_then(Value::as_array);
    for (idx, signal) in signals.into_iter().flatten().enumerate() {
        let signal_prefix = format!("{prefix}.signal[{idx}]");
        let malformed_display = signal.get("display").is_some_and(|d| {
            serde_json::to_value(d)
                .ok()
                .and_then(DisplayHint::from_authored)
                .is_none()
        });
        if malformed_display {
            findings.push(finding(
                format!("{signal_prefix}.display"),
                "display must be a widget name, or a table with one as `widget`",
            ));
        }
        require_finite_scale(&signal_prefix, signal, findings);
    }
    for (key, case) in frame
        .get("mux")
        .and_then(Value::as_table)
        .into_iter()
        .flatten()
    {
        validate_signals(&format!("{prefix}.mux.{key}"), case, findings);
    }
}

/// The parser skips a signal that fails this, so it is neither read nor written.
fn validate_layouts(prefix: &str, frame: &Value, findings: &mut Vec<Finding>) {
    let bank: RegisterType = frame
        .get("register_type")
        .and_then(Value::as_str)
        .and_then(|t| t.parse().ok())
        .unwrap_or_default();
    let signals = frame
        .get("signal")
        .or_else(|| frame.get("signals"))
        .and_then(Value::as_array);
    for (idx, signal) in signals.into_iter().flatten().enumerate() {
        let int = |key| signal.get(key).and_then(Value::as_integer);
        let numeric = signal
            .get("format")
            .and_then(Value::as_str)
            .is_none_or(|format| format == "enum");
        if let (Some(start), Some(len)) = (int("start_bit"), int("bit_length"))
            && !layout_fits(bank, numeric, start, len)
        {
            findings.push(finding(
                format!("{prefix}.signal[{idx}]"),
                "A signal needs a bit_length of at least 1, at most 64 if numeric, \
                 and must end within the bank's 65536 addresses; it is skipped",
            ));
        }
    }
}

fn require_finite_scale(prefix: &str, table: &Value, findings: &mut Vec<Finding>) {
    for key in ["factor", "offset"] {
        if let Some(value) = table
            .get(key)
            .and_then(Value::as_float)
            .filter(|v| !v.is_finite())
        {
            findings.push(finding(
                format!("{prefix}.{key}"),
                format!("{key} must be a finite number, not {value}"),
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|f| f.field.as_str()).collect()
    }

    #[test]
    fn a_valid_catalogue_has_no_findings() {
        let toml = r#"
[meta]
name = "ok"
version = 1
[meta.modbus]
register_base = 1
[frame.modbus.battery]
register_number = 13019
register_type = "input"
length = 1
[[ frame.modbus.battery.signals ]]
name = "SoC"
start_bit = 0
bit_length = 16
factor = 0.1
display = "level-bar"
"#;
        assert!(validate(toml).is_empty());
    }

    #[test]
    fn a_toml_syntax_error_is_the_single_finding() {
        let findings = validate("not = valid = toml =");
        assert_eq!(fields(&findings), ["toml"]);
        assert!(findings[0].message.starts_with("TOML syntax error: "));
    }

    #[test]
    fn missing_meta_and_name() {
        assert_eq!(
            fields(&validate("[frame.modbus.1]\nlength = 1\n")),
            vec!["meta"]
        );
        assert_eq!(fields(&validate("[meta]\nversion=1\n")), vec!["meta.name"]);
    }

    #[test]
    fn a_name_that_is_not_a_string_is_refused() {
        let findings = validate("[meta]\nname = 5\n");
        assert_eq!(fields(&findings), vec!["meta.name"]);
        assert_eq!(findings[0].message, "Catalogue name must be a string");
    }

    #[test]
    fn an_empty_name_is_accepted() {
        assert!(validate("[meta]\nname = \"\"\n").is_empty());
    }

    #[test]
    fn a_version_below_one_and_an_unknown_endianness_are_refused() {
        let findings =
            validate("[meta]\nname = \"x\"\nversion = 0\ndefault_endianness = \"middle\"\n");
        assert_eq!(
            fields(&findings),
            ["meta.version", "meta.default_endianness"]
        );
    }

    #[test]
    fn a_frame_with_no_register_is_reported() {
        let toml = r#"
[meta]
name = "x"
[frame.modbus.not_a_register]
register_type = "input"
length = 1
[[ frame.modbus.not_a_register.signals ]]
name = "A"
start_bit = 0
bit_length = 16
"#;
        assert_eq!(fields(&validate(toml)), vec!["frame.modbus.not_a_register"]);
    }

    #[test]
    fn function_code_rules() {
        let case = |body: &str| {
            let toml = format!("[meta]\nname = \"x\"\n{body}");
            validate(&toml)
                .into_iter()
                .map(|f| f.field)
                .collect::<Vec<_>>()
        };

        assert!(
            case(
                "[meta.modbus.function_code.0x60]\n\
                 name = \"Dispatch\"\n\
                 lengths = [{ len = { count_at = 6, overhead = 9 } }]\n\
                 [meta.modbus.function_code.0x20]\n\
                 lengths = [{ when = { offset = 4, value = 3 }, len = { fixed = 11 } }]\n\
                 [meta.modbus.function_code.0x65]\n"
            )
            .is_empty()
        );
        for bad in [
            "{ when = { offset = 4, value = 3 } }",
            "{ len = { count_at = 6 } }",
            "{ len = { fixed = 11, overhead = 9 } }",
            "{ when = { offset = 4 }, len = { fixed = 11 } }",
            "{ len = { fixed = 70000 } }",
        ] {
            assert_eq!(
                case(&format!(
                    "[meta.modbus.function_code.0x60]\nlengths = [{bad}]\n"
                )),
                vec!["meta.modbus.function_code.0x60.lengths[0]"],
                "{bad}"
            );
        }
        assert_eq!(
            case("[meta.modbus.function_code.0x60]\nlengths = 1\n"),
            vec!["meta.modbus.function_code.0x60.lengths"]
        );
        for code in ["0x03", "0x10", "0x83", "0x0", "0x100", "dispatch"] {
            assert_eq!(
                case(&format!("[meta.modbus.function_code.{code}]\n")),
                vec![format!("meta.modbus.function_code.{code}")],
                "{code}"
            );
        }
        assert_eq!(
            case("[meta.modbus]\nfunction_code = 96\n"),
            vec!["meta.modbus.function_code"]
        );
    }

    #[test]
    fn the_standard_codes_are_exactly_the_ones_with_their_own_length_rules() {
        let own: Vec<u8> = (0..=0x7F).filter(|&c| has_own_length_rules(c)).collect();
        assert_eq!(own, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0F, 0x10]);
        assert!((0x80..=0xFF).all(has_own_length_rules));
    }

    #[test]
    fn a_malformed_display_hint_is_a_finding_in_every_section() {
        let toml = r#"
[meta]
name = "x"
[frame.modbus.battery]
register_number = 13019
[[ frame.modbus.battery.signals ]]
name = "Bare"
start_bit = 0
bit_length = 16
display = "no-such-widget"
[[ frame.modbus.battery.signals ]]
name = "Number"
start_bit = 16
bit_length = 16
display = 5
[[ frame.modbus.battery.signals ]]
name = "NoWidget"
start_bit = 32
bit_length = 16
display = { orientation = "vertical" }
[frame.modbus.battery.mux]
name = "Sel"
start_bit = 48
bit_length = 8
[[ frame.modbus.battery.mux.1.signals ]]
name = "Empty"
start_bit = 56
bit_length = 8
display = ""
"#;
        assert_eq!(
            fields(&validate(toml)),
            vec![
                "frame.modbus.battery.signal[1].display",
                "frame.modbus.battery.signal[2].display",
                "frame.modbus.battery.mux.1.signal[0].display",
            ]
        );
    }

    fn catalogue_scaled_everywhere(scale: &str) -> String {
        format!(
            r#"
[meta]
name = "x"
[frame.modbus.battery]
register_number = 13019
[[ frame.modbus.battery.signals ]]
name = "Plain"
start_bit = 0
bit_length = 16
[[ frame.modbus.battery.signals ]]
name = "SoC"
start_bit = 16
bit_length = 16
{scale}
[frame.modbus.13020]
{scale}
"#
        )
    }

    #[test]
    fn a_non_finite_factor_or_offset_is_a_finding_on_a_frame_and_a_signal() {
        for key in ["factor", "offset"] {
            for value in ["nan", "inf", "-inf"] {
                let findings = validate(&catalogue_scaled_everywhere(&format!("{key} = {value}")));
                assert_eq!(
                    fields(&findings),
                    vec![
                        format!("frame.modbus.13020.{key}"),
                        format!("frame.modbus.battery.signal[1].{key}"),
                    ],
                    "{key} = {value}"
                );
            }
        }
    }

    #[test]
    fn a_finite_factor_and_offset_are_not_findings() {
        for scale in ["factor = 0.1\noffset = -40", "factor = 10\noffset = 1e15"] {
            assert!(
                validate(&catalogue_scaled_everywhere(scale)).is_empty(),
                "{scale}"
            );
        }
    }

    #[test]
    fn other_frame_sections_are_not_read() {
        let toml = "[meta]\nname = \"x\"\n[frame.can.not_an_id]\nlength = 99\n";
        assert!(validate(toml).is_empty());
    }

    #[test]
    fn a_finding_serialises_as_field_and_message() {
        let json = serde_json::to_value(finding("meta.name", "no name")).unwrap();
        assert_eq!(
            json,
            serde_json::json!({ "field": "meta.name", "message": "no name" })
        );
    }

    #[test]
    fn a_signal_that_cannot_be_laid_out_is_a_finding() {
        let toml = r#"
[meta]
name = "x"
[frame.modbus.0x10]
register_type = "holding"
length = 10
[[ frame.modbus.0x10.signals ]]
name = "Empty"
start_bit = 0
bit_length = 0
[[ frame.modbus.0x10.signals ]]
name = "Wide"
start_bit = 0
bit_length = 65
[[ frame.modbus.0x10.signals ]]
name = "Serial"
start_bit = 0
bit_length = 160
format = "ascii"
[[ frame.modbus.0x10.signals ]]
name = "Mode"
start_bit = 0
bit_length = 80
format = "enum"
[frame.modbus.0]
register_type = "coil"
[[ frame.modbus.0.signals ]]
name = "PastTheEnd"
start_bit = 65535
bit_length = 2
"#;
        assert_eq!(
            fields(&validate(toml)),
            vec![
                "frame.modbus.0.signal[0]",
                "frame.modbus.0x10.signal[0]",
                "frame.modbus.0x10.signal[1]",
                "frame.modbus.0x10.signal[3]",
            ]
        );
    }
}
