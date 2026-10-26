/// RFC 1035 §3.3: a character-string's length is one octet.
const MAX_STRING_LEN: usize = 255;

/// Splits `value` into the character-strings of a TXT record, each at most 255
/// octets, only between characters. An empty value is one empty string, since
/// a TXT record holds at least one (RFC 1035 §3.3.14).
pub fn split(value: &str) -> Vec<&str> {
    let mut strings = Vec::new();
    let mut rest = value;
    while rest.len() > MAX_STRING_LEN {
        let mut at = MAX_STRING_LEN;
        while !rest.is_char_boundary(at) {
            at -= 1;
        }
        let (string, after) = rest.split_at(at);
        strings.push(string);
        rest = after;
    }
    strings.push(rest);
    strings
}

/// The strings in zone file form, as Route 53 also takes them: `"a" "b"`, with
/// `"` and `\` escaped by a backslash.
pub fn quote<S: AsRef<str>>(strings: impl IntoIterator<Item = S>) -> String {
    let mut out = String::new();
    for string in strings {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push('"');
        for c in string.as_ref().chars() {
            if matches!(c, '"' | '\\') {
                out.push('\\');
            }
            out.push(c);
        }
        out.push('"');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_splits_after_255_octets() {
        let exact = "a".repeat(255);
        assert_eq!(split(&exact), [exact.as_str()]);
        let over = "a".repeat(256);
        assert_eq!(split(&over), [&over[..255], "a"]);
        let lengths: Vec<_> = split(&"a".repeat(600)).iter().map(|s| s.len()).collect();
        assert_eq!(lengths, [255, 255, 90]);
    }

    #[test]
    fn a_character_across_the_limit_goes_whole_into_the_next_string() {
        let value = format!("{}é{}", "a".repeat(254), "b");
        let strings = split(&value);
        assert_eq!(strings, ["a".repeat(254), "éb".to_string()]);
        assert_eq!(strings.concat(), value);
    }

    #[test]
    fn an_empty_value_is_one_empty_string() {
        assert_eq!(split(""), [""]);
        assert_eq!(quote(split("")), r#""""#);
    }

    #[test]
    fn quotes_and_backslashes_are_escaped() {
        assert_eq!(quote(["v=spf1 -all"]), r#""v=spf1 -all""#);
        assert_eq!(quote(["a\"b", "c\\d"]), r#""a\"b" "c\\d""#);
        assert_eq!(quote(["", "x"]), r#""" "x""#);
    }
}
