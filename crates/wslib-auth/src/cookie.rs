use chrono::TimeDelta;
use http::header::COOKIE;
use http::{HeaderMap, HeaderValue};

use crate::token::SessionToken;

/// The cookie's `SameSite` attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SameSite {
    Strict,
    Lax,
    /// Sent cross-site too; browsers require `Secure` with it.
    None,
}

/// The session cookie as the caller names and scopes it; always `HttpOnly`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionCookie {
    name: String,
    path: String,
    same_site: SameSite,
    secure: bool,
    max_age: Option<TimeDelta>,
}

impl SessionCookie {
    /// A cookie called `name` at path `/`, `SameSite=Strict`, `Secure`, lasting the browser session.
    ///
    /// # Panics
    ///
    /// If `name` is not an RFC 6265 cookie name.
    pub fn new(name: impl Into<String>) -> Self {
        let name = name.into();
        assert!(is_cookie_name(&name), "{name:?} is not a cookie name");
        Self {
            name,
            path: "/".into(),
            same_site: SameSite::Strict,
            secure: true,
            max_age: None,
        }
    }

    /// # Panics
    ///
    /// If `path` holds a `;` or a character a header cannot carry.
    pub fn path(self, path: impl Into<String>) -> Self {
        let path = path.into();
        assert!(
            path.bytes().all(|b| b.is_ascii_graphic() && b != b';'),
            "{path:?} is not a cookie path"
        );
        Self { path, ..self }
    }

    pub fn same_site(self, same_site: SameSite) -> Self {
        Self { same_site, ..self }
    }

    pub fn secure(self, secure: bool) -> Self {
        Self { secure, ..self }
    }

    /// Keeps the cookie past the browser session, for `max_age`.
    pub fn max_age(self, max_age: TimeDelta) -> Self {
        Self {
            max_age: Some(max_age),
            ..self
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// The `Set-Cookie` value carrying `token`.
    ///
    /// # Panics
    ///
    /// If a token from [`SessionToken::from_presented`] holds a control character.
    pub fn set(&self, token: &SessionToken) -> HeaderValue {
        self.header(token.expose(), self.max_age.map(|age| age.num_seconds()))
    }

    /// The `Set-Cookie` value that removes the cookie, at the same path.
    pub fn clear(&self) -> HeaderValue {
        self.header("", Some(0))
    }

    fn header(&self, value: &str, max_age: Option<i64>) -> HeaderValue {
        let same_site = match self.same_site {
            SameSite::Strict => "Strict",
            SameSite::Lax => "Lax",
            SameSite::None => "None",
        };
        let mut cookie = format!(
            "{}={value}; Path={}; HttpOnly; SameSite={same_site}",
            self.name, self.path
        );
        if self.secure {
            cookie.push_str("; Secure");
        }
        if let Some(seconds) = max_age {
            cookie.push_str(&format!("; Max-Age={}", seconds.max(0)));
        }
        HeaderValue::try_from(cookie)
            .expect("a validated name and path, and a token a header can carry")
    }

    /// The first non-empty value of this cookie across every `Cookie` header.
    ///
    /// Browsers send the cookie with the longest path first, so a duplicate
    /// from a broader path set elsewhere comes after this one.
    pub fn token_in(&self, headers: &HeaderMap) -> Option<SessionToken> {
        headers
            .get_all(COOKIE)
            .iter()
            .filter_map(|header| header.to_str().ok())
            .flat_map(|header| header.split(';'))
            .filter_map(|pair| pair.trim().split_once('='))
            .map(|(name, value)| (name, value.trim_matches('"')))
            .find(|(name, value)| *name == self.name && !value.is_empty())
            .map(|(_, value)| SessionToken::from_presented(value))
    }
}

fn is_cookie_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_graphic() && !b"()<>@,;:\\\"/[]?={}".contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(cookies: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for cookie in cookies {
            headers.append(COOKIE, HeaderValue::from_str(cookie).unwrap());
        }
        headers
    }

    #[test]
    fn set_and_clear_carry_the_callers_attributes() {
        let token = SessionToken::from_presented("abc");
        assert_eq!(
            SessionCookie::new("app_session").set(&token),
            "app_session=abc; Path=/; HttpOnly; SameSite=Strict; Secure"
        );
        let lax = SessionCookie::new("app_session")
            .path("/app")
            .same_site(SameSite::Lax)
            .secure(false)
            .max_age(TimeDelta::hours(12));
        assert_eq!(
            lax.set(&token),
            "app_session=abc; Path=/app; HttpOnly; SameSite=Lax; Max-Age=43200"
        );
        assert_eq!(
            lax.clear(),
            "app_session=; Path=/app; HttpOnly; SameSite=Lax; Max-Age=0"
        );
    }

    #[test]
    #[should_panic(expected = "is not a cookie name")]
    fn a_name_with_a_separator_is_refused() {
        let _ = SessionCookie::new("app;session");
    }

    #[test]
    #[should_panic(expected = "is not a cookie path")]
    fn a_path_with_a_semicolon_is_refused() {
        let _ = SessionCookie::new("app_session").path("/; Domain=evil");
    }

    #[test]
    fn the_token_is_found_among_other_cookies_and_headers() {
        let cookie = SessionCookie::new("s");
        let found = |cookies: &[&str]| {
            cookie
                .token_in(&headers(cookies))
                .map(|t| t.expose().to_owned())
        };

        assert_eq!(found(&[]), None);
        assert_eq!(found(&["other=1"]), None);
        assert_eq!(found(&["other=1; s=abc; more=2"]), Some("abc".into()));
        assert_eq!(
            found(&["other=1", "s=abc"]),
            Some("abc".into()),
            "a second header"
        );
        assert_eq!(found(&["s=first; s=second"]), Some("first".into()));
        assert_eq!(
            found(&["s=", "s=abc"]),
            Some("abc".into()),
            "an empty one skipped"
        );
        assert_eq!(found(&["ss=abc; s_=x"]), None, "names match exactly");
        assert_eq!(found(&["s=\"abc\""]), Some("abc".into()));
        assert_eq!(found(&["s=\"\"; s=abc"]), Some("abc".into()));
    }
}
