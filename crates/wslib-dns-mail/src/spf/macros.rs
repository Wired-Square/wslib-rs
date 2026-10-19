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

/// What macros expand from (RFC 7208 §7.3). A letter whose value isn't known
/// makes [`MacroString::expand`] return `None`, which is how a walk without a
/// sender skips `exists:%{i}…`.
#[derive(Clone, Debug, Default)]
pub struct MacroContext {
    /// `<local-part>@<domain>`.
    pub sender: Option<String>,
    /// The domain being evaluated, `%{d}`.
    pub domain: String,
    pub ip: Option<std::net::IpAddr>,
    pub helo: Option<String>,
    /// `%{p}`, looked up by the caller when a string uses it.
    pub validated_domain: Option<String>,
    /// `%{r}`, the receiving host; `unknown` when unset.
    pub receiver: Option<String>,
    /// `%{t}`, seconds since the epoch.
    pub timestamp: Option<u64>,
}

impl MacroString {
    /// Whether expanding it needs `%{p}`, which costs DNS queries.
    pub fn uses_validated_domain(&self) -> bool {
        self.tokens
            .iter()
            .any(|token| matches!(token, MacroToken::Macro(m) if m.letter == MacroLetter::ValidatedDomain))
    }

    /// The expansion, or `None` when a letter's value isn't in `context`.
    pub fn expand(&self, context: &MacroContext) -> Option<String> {
        let mut out = String::new();
        for token in &self.tokens {
            match token {
                MacroToken::Literal(text) => out.push_str(text),
                MacroToken::Percent => out.push('%'),
                MacroToken::Space => out.push(' '),
                MacroToken::UrlSpace => out.push_str("%20"),
                MacroToken::Macro(m) => out.push_str(&expand_macro(m, context)?),
            }
        }
        Some(out)
    }

    /// The expansion as a domain to query: trailing dot dropped, and labels
    /// removed from the left until it fits in 253 octets (§7.3).
    pub fn expand_domain(&self, context: &MacroContext) -> Option<String> {
        let expanded = self.expand(context)?;
        let mut name = expanded.trim_end_matches('.');
        while name.len() > 253 {
            name = name.split_once('.')?.1;
        }
        Some(name.to_ascii_lowercase())
    }
}

fn expand_macro(m: &Macro, context: &MacroContext) -> Option<String> {
    use std::net::IpAddr;
    let sender = || context.sender.as_deref();
    let value = match m.letter {
        MacroLetter::Sender => sender()?.to_owned(),
        MacroLetter::LocalPart => sender()?
            .rsplit_once('@')
            .map_or("postmaster", |(local, _)| local)
            .to_owned(),
        MacroLetter::SenderDomain => sender()?
            .rsplit_once('@')
            .map_or(sender()?, |(_, domain)| domain)
            .to_owned(),
        MacroLetter::Domain => context.domain.clone(),
        MacroLetter::Ip => match context.ip? {
            IpAddr::V4(v4) => v4.to_string(),
            IpAddr::V6(v6) => v6
                .octets()
                .iter()
                .flat_map(|byte| [byte >> 4, byte & 0x0f])
                .map(|nibble| format!("{nibble:x}"))
                .collect::<Vec<_>>()
                .join("."),
        },
        MacroLetter::ValidatedDomain => context
            .validated_domain
            .clone()
            .unwrap_or_else(|| "unknown".into()),
        MacroLetter::IpVersion => match context.ip? {
            IpAddr::V4(_) => "in-addr".into(),
            IpAddr::V6(_) => "ip6".into(),
        },
        MacroLetter::Helo => context.helo.clone()?,
        MacroLetter::ClientIp => context.ip?.to_string(),
        MacroLetter::ReceivingDomain => {
            context.receiver.clone().unwrap_or_else(|| "unknown".into())
        }
        MacroLetter::Timestamp => context.timestamp?.to_string(),
    };
    let delimiters: &[char] = &if m.delimiters.is_empty() {
        vec!['.']
    } else {
        m.delimiters.chars().collect()
    };
    let mut parts: Vec<&str> = value.split(delimiters).collect();
    if m.reverse {
        parts.reverse();
    }
    if let Some(keep) = m.keep {
        let keep = usize::try_from(keep).unwrap_or(usize::MAX).min(parts.len());
        parts.drain(..parts.len() - keep);
    }
    let joined = parts.join(".");
    Some(if m.url_escape {
        url_escape(&joined)
    } else {
        joined
    })
}

/// Percent-encodes everything but RFC 3986's unreserved characters.
fn url_escape(text: &str) -> String {
    text.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
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

    /// RFC 7208 §7.4.
    fn rfc_context() -> MacroContext {
        MacroContext {
            sender: Some("strong-bad@email.example.com".into()),
            domain: "email.example.com".into(),
            ip: Some("192.0.2.3".parse().unwrap()),
            helo: Some("mx.example.org".into()),
            ..MacroContext::default()
        }
    }

    #[test]
    fn expansions_from_rfc_7208_section_7_4() {
        let context = rfc_context();
        for (raw, expected) in [
            ("%{s}", "strong-bad@email.example.com"),
            ("%{o}", "email.example.com"),
            ("%{d}", "email.example.com"),
            ("%{d4}", "email.example.com"),
            ("%{d3}", "email.example.com"),
            ("%{d2}", "example.com"),
            ("%{d1}", "com"),
            ("%{dr}", "com.example.email"),
            ("%{d2r}", "example.email"),
            ("%{l}", "strong-bad"),
            ("%{l-}", "strong.bad"),
            ("%{lr}", "strong-bad"),
            ("%{lr-}", "bad.strong"),
            ("%{l1r-}", "strong"),
            (
                "%{ir}.%{v}._spf.%{d2}",
                "3.2.0.192.in-addr._spf.example.com",
            ),
            ("%{lr-}.lp._spf.%{d2}", "bad.strong.lp._spf.example.com"),
            (
                "%{lr-}.lp.%{ir}.%{v}._spf.%{d2}",
                "bad.strong.lp.3.2.0.192.in-addr._spf.example.com",
            ),
            (
                "%{ir}.%{v}.%{l1r-}.lp._spf.%{d2}",
                "3.2.0.192.in-addr.strong.lp._spf.example.com",
            ),
            (
                "%{d2}.trusted-domains.example.net",
                "example.com.trusted-domains.example.net",
            ),
        ] {
            assert_eq!(
                parse(raw, false).unwrap().expand(&context).as_deref(),
                Some(expected),
                "{raw}"
            );
        }
        let v6 = MacroContext {
            ip: Some("2001:db8::cb01".parse().unwrap()),
            ..rfc_context()
        };
        assert_eq!(
            parse("%{ir}.%{v}._spf.%{d2}", false)
                .unwrap()
                .expand(&v6)
                .as_deref(),
            Some(
                "1.0.b.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6._spf.example.com"
            )
        );
    }

    #[test]
    fn uppercase_letters_url_escape_and_escapes_expand() {
        let context = rfc_context();
        assert_eq!(
            parse("%{S}", false).unwrap().expand(&context).as_deref(),
            Some("strong-bad%40email.example.com")
        );
        assert_eq!(
            parse("a%%b%_c%-d", false)
                .unwrap()
                .expand(&context)
                .as_deref(),
            Some("a%b c%20d")
        );
        assert_eq!(
            parse("%{p}", false).unwrap().expand(&context).as_deref(),
            Some("unknown")
        );
    }

    #[test]
    fn missing_values_and_long_names() {
        let domain_only = MacroContext {
            domain: "example.com".into(),
            ..MacroContext::default()
        };
        assert_eq!(
            parse("_spf.%{d}", false)
                .unwrap()
                .expand(&domain_only)
                .as_deref(),
            Some("_spf.example.com")
        );
        assert_eq!(
            parse("%{i}._spf.%{d}", false).unwrap().expand(&domain_only),
            None
        );
        let long = MacroContext {
            domain: format!("{}.example.com", vec!["a".repeat(60); 5].join(".")),
            ..MacroContext::default()
        };
        let name = parse("%{d}", false).unwrap().expand_domain(&long).unwrap();
        assert!(
            name.len() <= 253 && name.ends_with(".example.com"),
            "{name}"
        );
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
