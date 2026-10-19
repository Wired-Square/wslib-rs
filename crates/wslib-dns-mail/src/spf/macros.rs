use std::fmt;

/// A domain-spec or explanation string (RFC 7208 §7.1), as written and as
/// parsed into literals and macros.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MacroString {
    pub raw: String,
    pub tokens: Vec<MacroToken>,
}

impl MacroString {
    pub fn has_macros(&self) -> bool {
        self.tokens
            .iter()
            .any(|token| !matches!(token, MacroToken::Literal(_)))
    }

    /// The text itself when it has no macros: a plain domain name.
    pub fn literal(&self) -> Option<&str> {
        (!self.has_macros()).then_some(self.raw.as_str())
    }
}

impl fmt::Display for MacroString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum MacroToken {
    Literal(String),
    Macro(Macro),
    /// `%%`
    Percent,
    /// `%_`
    Space,
    /// `%-`, a URL-encoded space.
    UrlSpace,
}

/// `%{` letter transformers delimiters `}`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Macro {
    pub letter: MacroLetter,
    /// The letter was uppercase: URL-escape the expansion.
    pub url_escape: bool,
    /// Keep this many right-hand parts.
    pub keep: Option<u32>,
    pub reverse: bool,
    /// Split on these; `.` when empty.
    pub delimiters: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum MacroLetter {
    /// `s`
    Sender,
    /// `l`
    LocalPart,
    /// `o`
    SenderDomain,
    /// `d`
    Domain,
    /// `i`
    Ip,
    /// `p`
    ValidatedDomain,
    /// `v`: `in-addr` or `ip6`.
    IpVersion,
    /// `h`
    Helo,
    /// `c`, explanations only.
    ClientIp,
    /// `r`, explanations only.
    ReceivingDomain,
    /// `t`, explanations only.
    Timestamp,
}

impl MacroLetter {
    fn from_char(c: char) -> Option<Self> {
        Some(match c.to_ascii_lowercase() {
            's' => Self::Sender,
            'l' => Self::LocalPart,
            'o' => Self::SenderDomain,
            'd' => Self::Domain,
            'i' => Self::Ip,
            'p' => Self::ValidatedDomain,
            'v' => Self::IpVersion,
            'h' => Self::Helo,
            'c' => Self::ClientIp,
            'r' => Self::ReceivingDomain,
            't' => Self::Timestamp,
            _ => return None,
        })
    }

    fn explanation_only(self) -> bool {
        matches!(
            self,
            Self::ClientIp | Self::ReceivingDomain | Self::Timestamp
        )
    }
}

/// Parses a macro-string. `explanation` admits `c`, `r` and `t` and spaces, as
/// an `exp=` TXT record may use. Errors are byte offsets into `raw`.
pub(crate) fn parse(raw: &str, explanation: bool) -> Result<MacroString, usize> {
    let mut tokens = Vec::new();
    let mut literal = String::new();
    let mut chars = raw.char_indices().peekable();
    while let Some((at, c)) = chars.next() {
        if c != '%' {
            let printable = matches!(c, '\x21'..='\x7e') || (explanation && c == ' ');
            if !printable {
                return Err(at);
            }
            literal.push(c);
            continue;
        }
        let token = match chars.next().map(|(_, c)| c) {
            Some('%') => MacroToken::Percent,
            Some('_') => MacroToken::Space,
            Some('-') => MacroToken::UrlSpace,
            Some('{') => MacroToken::Macro(parse_macro(&mut chars, explanation).ok_or(at)?),
            _ => return Err(at),
        };
        if !literal.is_empty() {
            tokens.push(MacroToken::Literal(std::mem::take(&mut literal)));
        }
        tokens.push(token);
    }
    if !literal.is_empty() {
        tokens.push(MacroToken::Literal(literal));
    }
    Ok(MacroString {
        raw: raw.to_owned(),
        tokens,
    })
}

fn parse_macro(
    chars: &mut std::iter::Peekable<std::str::CharIndices<'_>>,
    explanation: bool,
) -> Option<Macro> {
    let (_, c) = chars.next()?;
    let letter = MacroLetter::from_char(c)?;
    if letter.explanation_only() && !explanation {
        return None;
    }
    let mut digits = String::new();
    while let Some(&(_, d)) = chars.peek().filter(|(_, d)| d.is_ascii_digit()) {
        digits.push(d);
        chars.next();
    }
    let keep = match digits.as_str() {
        "" => None,
        digits => Some(digits.parse::<u32>().ok().filter(|&n| n > 0)?),
    };
    let reverse = chars
        .next_if(|&(_, r)| r.eq_ignore_ascii_case(&'r'))
        .is_some();
    let mut delimiters = String::new();
    loop {
        match chars.next()?.1 {
            '}' => break,
            d @ ('.' | '-' | '+' | ',' | '/' | '_' | '=') => delimiters.push(d),
            _ => return None,
        }
    }
    Some(Macro {
        letter,
        url_escape: c.is_ascii_uppercase(),
        keep,
        reverse,
        delimiters,
    })
}

/// Whether a domain-spec ends the way RFC 7208 §7.1 requires: a top label
/// that isn't all digits, or a macro.
pub(crate) fn has_domain_end(spec: &MacroString) -> bool {
    if matches!(spec.tokens.last(), Some(MacroToken::Macro(_))) {
        return true;
    }
    let text = spec.raw.strip_suffix('.').unwrap_or(&spec.raw);
    let Some((_, top)) = text.rsplit_once('.') else {
        return false;
    };
    !top.is_empty()
        && top.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && !top.starts_with('-')
        && !top.ends_with('-')
        && !top.bytes().all(|b| b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literals_and_escapes() {
        let spec = parse("a%%b%_c%-d", false).unwrap();
        assert_eq!(
            spec.tokens,
            [
                MacroToken::Literal("a".into()),
                MacroToken::Percent,
                MacroToken::Literal("b".into()),
                MacroToken::Space,
                MacroToken::Literal("c".into()),
                MacroToken::UrlSpace,
                MacroToken::Literal("d".into()),
            ]
        );
        assert!(spec.has_macros());
        assert_eq!(
            parse("_spf.example.com", false).unwrap().literal(),
            Some("_spf.example.com")
        );
    }

    #[test]
    fn macros_carry_their_transformers() {
        let spec = parse("%{ir}.%{V}._spf.%{d2}", false).unwrap();
        let macros: Vec<&Macro> = spec
            .tokens
            .iter()
            .filter_map(|t| match t {
                MacroToken::Macro(m) => Some(m),
                _ => None,
            })
            .collect();
        assert_eq!(macros[0].letter, MacroLetter::Ip);
        assert!(macros[0].reverse);
        assert!(macros[1].url_escape);
        assert_eq!(macros[2].keep, Some(2));
        let spec = parse("%{l1r-+}", false).unwrap();
        assert!(
            matches!(&spec.tokens[0], MacroToken::Macro(m) if m.delimiters == "-+" && m.keep == Some(1))
        );
    }

    #[test]
    fn malformed_macros_are_rejected_at_their_offset() {
        assert_eq!(parse("a%{x}", false), Err(1));
        assert_eq!(parse("%{d0}", false), Err(0));
        assert_eq!(parse("%{d", false), Err(0));
        assert_eq!(parse("ab%", false), Err(2));
        assert_eq!(parse("%{d;}", false), Err(0));
        assert_eq!(parse("%{c}", false), Err(0));
        assert!(parse("%{c} at %{t}", true).is_ok());
        assert_eq!(parse("a b", false), Err(1));
    }

    #[test]
    fn domain_end_needs_a_top_label_or_a_macro() {
        let end = |raw| has_domain_end(&parse(raw, false).unwrap());
        assert!(end("example.com"));
        assert!(end("example.com."));
        assert!(end("%{d}"));
        assert!(end("%{i}.%{d}"));
        assert!(!end("localhost"));
        assert!(!end("192.0.2.1"));
        assert!(!end("example.-com"));
        assert!(!end("example."));
    }
}
