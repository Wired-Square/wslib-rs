//! The path an appliance serves everything under, so one build runs at `/` or
//! behind a proxy that forwards `/apps/<name>/` unchanged.

use std::fmt;
use std::str::FromStr;

/// `/`, or `/` and slash-separated segments ending in `/`: `/apps/hello/`.
///
/// A segment is letters, digits, `-`, `.`, `_` and `~`, and is not `.` or `..`,
/// so the path needs no escaping in a URL, a cookie or an HTML attribute.
/// Parsed with or without its slashes at either end.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(try_from = "String")]
pub struct BasePath(String);

impl BasePath {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The path without its trailing slash, `""` at the root: what a router
    /// nests under.
    pub fn prefix(&self) -> &str {
        self.0.trim_end_matches('/')
    }

    /// Whether `segment` is one segment of a base path.
    pub fn is_segment(segment: &str) -> bool {
        !segment.is_empty()
            && segment != "."
            && segment != ".."
            && segment
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
    }
}

impl Default for BasePath {
    fn default() -> Self {
        Self("/".to_string())
    }
}

impl fmt::Display for BasePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for BasePath {
    type Err = String;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let segments: Vec<&str> = raw.trim().trim_matches('/').split('/').collect();
        if segments == [""] {
            return Ok(Self::default());
        }
        if !segments.iter().all(|segment| Self::is_segment(segment)) {
            return Err(
                "expected a path like /apps/name/: segments of letters, digits, '-', '.', '_' \
                 and '~', none of them '.' or '..'"
                    .to_string(),
            );
        }
        Ok(Self(format!("/{}/", segments.join("/"))))
    }
}

impl TryFrom<String> for BasePath {
    type Error = String;

    fn try_from(raw: String) -> Result<Self, Self::Error> {
        raw.parse()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_base_path_is_normalised_to_slashes_at_both_ends() {
        for (raw, base) in [
            ("", "/"),
            ("/", "/"),
            ("apps/hello", "/apps/hello/"),
            ("/apps/hello", "/apps/hello/"),
            (" /apps/hello/ ", "/apps/hello/"),
            ("/a.b_c~d-e/", "/a.b_c~d-e/"),
        ] {
            assert_eq!(raw.parse::<BasePath>().unwrap().as_str(), base, "{raw:?}");
        }
        assert_eq!(
            "/apps/hello/".parse::<BasePath>().unwrap().prefix(),
            "/apps/hello"
        );
        assert_eq!(BasePath::default().prefix(), "");
    }

    #[test]
    fn a_base_path_that_would_need_escaping_or_climb_is_refused() {
        for raw in [
            "/apps//hello/",
            "/apps/../hello",
            "/./",
            "/apps/he llo/",
            "/apps/\"x\"/",
            "/apps/%2e%2e/",
            "/apps/hé/",
            "/apps?x/",
        ] {
            assert!(raw.parse::<BasePath>().is_err(), "{raw:?}");
        }
    }
}
