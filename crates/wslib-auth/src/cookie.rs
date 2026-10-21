use std::borrow::Cow;

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
    name: &'static str,
    path: Cow<'static, str>,
    same_site: SameSite,
    secure: bool,
    max_age: Option<TimeDelta>,
}

impl SessionCookie {
    /// A cookie called `name` at path `/`, `SameSite=Strict`, `Secure`, lasting the browser session.
    ///
    /// # Panics
    ///
    /// If `name` is not an RFC 6265 cookie name; in a `const`, at compile time.
    pub const fn new(name: &'static str) -> Self {
        assert!(is_cookie_name(name), "not a cookie name");
        Self {
            name,
            path: Cow::Borrowed("/"),
            same_site: SameSite::Strict,
            secure: true,
            max_age: None,
        }
    }

    /// # Panics
    ///
    /// If `path` holds a `;` or a character a header cannot carry.
    pub fn path(self, path: impl Into<Cow<'static, str>>) -> Self {
        let path = path.into();
        assert!(
            path.bytes().all(|b| b.is_ascii_graphic() && b != b';'),
            "{path:?} is not a cookie path"
        );
        Self { path, ..self }
    }

    pub const fn same_site(mut self, same_site: SameSite) -> Self {
        self.same_site = same_site;
        self
    }

    pub const fn secure(mut self, secure: bool) -> Self {
        self.secure = secure;
        self
    }

    /// Keeps the cookie past the browser session, for `max_age`.
    pub fn max_age(self, max_age: TimeDelta) -> Self {
        Self {
            max_age: Some(max_age),
            ..self
        }
    }

    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// The `Set-Cookie` value carrying `token`.
    ///
    /// # Panics
    ///
    /// If a token from [`SessionToken::from_presented`] holds a control character.
    pub fn set(&self, token: &SessionToken) -> HeaderValue {
        let max_age = self
            .max_age
            .map(|age| format!("Max-Age={}", age.num_seconds().max(0)));
        self.header(token.expose(), max_age.as_deref())
    }

    /// The `Set-Cookie` value that removes the cookie, at the same path.
    pub fn clear(&self) -> HeaderValue {
        self.header("", Some("Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT"))
    }

    fn header(&self, value: &str, lifetime: Option<&str>) -> HeaderValue {
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
        if let Some(lifetime) = lifetime {
            cookie.push_str("; ");
            cookie.push_str(lifetime);
        }
        HeaderValue::try_from(cookie)
            .expect("a validated name and path, and a token a header can carry")
    }

    /// The last non-empty value of this cookie across every `Cookie` header.
    ///
    /// Browsers send longer paths first, so a same-name cookie a script planted
    /// at a deeper path comes before this one and cannot shadow it.
    pub fn token_in(&self, headers: &HeaderMap) -> Option<SessionToken> {
        headers
            .get_all(COOKIE)
            .iter()
            .filter_map(|header| header.to_str().ok())
            .flat_map(|header| header.split(';'))
            .filter_map(|pair| pair.trim().split_once('='))
            .map(|(name, value)| (name, value.trim_matches('"')))
            .rfind(|(name, value)| *name == self.name && !value.is_empty())
            .map(|(_, value)| SessionToken::from_presented(value))
    }
}

const fn is_cookie_name(name: &str) -> bool {
    const SEPARATORS: &[u8] = b"()<>@,;:\\\"/[]?={}";
    let bytes = name.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if !b.is_ascii_graphic() {
            return false;
        }
        let mut j = 0;
        while j < SEPARATORS.len() {
            if b == SEPARATORS[j] {
                return false;
            }
            j += 1;
        }
        i += 1;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    const LAX: SessionCookie = SessionCookie::new("app_session").same_site(SameSite::Lax);

    #[test]
    fn a_cookie_can_be_a_const() {
        assert_eq!(LAX.name(), "app_session");
        assert!(
            LAX.set(&SessionToken::generate().unwrap())
                .to_str()
                .unwrap()
                .contains("SameSite=Lax")
        );
    }

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
            "app_session=; Path=/app; HttpOnly; SameSite=Lax; Max-Age=0; \
             Expires=Thu, 01 Jan 1970 00:00:00 GMT"
        );
    }

    #[test]
    #[should_panic(expected = "not a cookie name")]
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
        assert_eq!(
            found(&["s=planted; s=abc"]),
            Some("abc".into()),
            "a deeper path's cookie comes first and is passed over"
        );
        assert_eq!(found(&["s=planted", "s=abc"]), Some("abc".into()));
        assert_eq!(
            found(&["s=abc", "s="]),
            Some("abc".into()),
            "an empty one skipped"
        );
        assert_eq!(found(&["ss=abc; s_=x"]), None, "names match exactly");
        assert_eq!(found(&["s=\"abc\""]), Some("abc".into()));
        assert_eq!(found(&["s=abc; s=\"\""]), Some("abc".into()));
    }
}
