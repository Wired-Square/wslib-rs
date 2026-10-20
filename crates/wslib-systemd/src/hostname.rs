use std::fmt;

/// The longest hostname [`clean_hostname`] accepts, in bytes.
///
/// The kernel takes 64 (`HOST_NAME_MAX`), but a one-label name is a DNS
/// label, which RFC 1035 caps at 63.
pub const MAX_HOSTNAME_LEN: usize = 63;

/// The rule a refused hostname broke.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HostnameError {
    Empty,
    /// Longer than [`MAX_HOSTNAME_LEN`] bytes.
    TooLong,
    EndsWithDot,
    EmptyLabel,
    /// Anything but ASCII letters, digits, hyphens and dots.
    BadCharacter,
    HyphenAtEdge,
}

impl fmt::Display for HostnameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("a hostname is required"),
            Self::TooLong => write!(f, "a hostname may be at most {MAX_HOSTNAME_LEN} bytes"),
            Self::EndsWithDot => f.write_str("a hostname may not end with a dot"),
            Self::EmptyLabel => f.write_str("a hostname may not contain an empty part"),
            Self::BadCharacter => {
                f.write_str("a hostname may contain only letters, digits, hyphens and dots")
            }
            Self::HyphenAtEdge => {
                f.write_str("no part of a hostname may start or end with a hyphen")
            }
        }
    }
}

impl std::error::Error for HostnameError {}

/// Trims `raw` and accepts it if every dot-separated label is an RFC 1123
/// label: stricter than hostnamed, since the name lands in certificates, mDNS
/// and URLs.
pub fn clean_hostname(raw: &str) -> Result<&str, HostnameError> {
    let name = raw.trim();
    if name.is_empty() {
        return Err(HostnameError::Empty);
    }
    // Bytes, as the kernel counts them.
    if name.len() > MAX_HOSTNAME_LEN {
        return Err(HostnameError::TooLong);
    }
    if name.ends_with('.') {
        return Err(HostnameError::EndsWithDot);
    }
    for label in name.split('.') {
        if label.is_empty() {
            return Err(HostnameError::EmptyLabel);
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(HostnameError::BadCharacter);
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(HostnameError::HyphenAtEdge);
        }
    }
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use HostnameError::*;

    #[test]
    fn an_ordinary_name_is_accepted_and_trimmed() {
        assert_eq!(clean_hostname("  widget-01  "), Ok("widget-01"));
        assert_eq!(clean_hostname("widget-01.example"), Ok("widget-01.example"));
        assert_eq!(clean_hostname("pi4"), Ok("pi4"));
    }

    #[test]
    fn every_refusal_names_the_rule_it_broke() {
        for (raw, rule) in [
            ("", Empty),
            ("   ", Empty),
            ("widget-01.", EndsWithDot),
            ("widget..01", EmptyLabel),
            ("-widget", HyphenAtEdge),
            ("widget-", HyphenAtEdge),
            ("widget.-01", HyphenAtEdge),
            ("widget_01", BadCharacter),
            ("widget 01", BadCharacter),
            ("widget/01", BadCharacter),
        ] {
            assert_eq!(clean_hostname(raw), Err(rule), "{raw:?}");
        }
        let long = "a".repeat(MAX_HOSTNAME_LEN + 1);
        assert_eq!(clean_hostname(&long), Err(TooLong));
        assert_eq!(TooLong.to_string(), "a hostname may be at most 63 bytes");
    }

    #[test]
    fn a_name_that_would_forge_a_log_line_is_refused() {
        assert_eq!(clean_hostname("widget\n01"), Err(BadCharacter));
        assert_eq!(clean_hostname("widget\u{0}01"), Err(BadCharacter));
    }

    #[test]
    fn the_length_is_counted_in_bytes() {
        let wide = "é".repeat(MAX_HOSTNAME_LEN / 2 + 1);
        assert!(wide.chars().count() <= MAX_HOSTNAME_LEN);
        assert_eq!(clean_hostname(&wide), Err(TooLong));
    }

    #[test]
    fn a_name_of_exactly_the_limit_is_accepted() {
        let longest = "a".repeat(MAX_HOSTNAME_LEN);
        assert_eq!(clean_hostname(&longest), Ok(longest.as_str()));
    }
}
