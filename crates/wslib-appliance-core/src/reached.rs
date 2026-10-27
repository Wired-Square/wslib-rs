//! The name a browser reached the box by, which a passkey ceremony runs as.
//!
//! Read from `:authority` or `Host`, **never `Forwarded` or `X-Forwarded-Host`**,
//! which any client may write. The port must be the listener's [`ServingPort`]:
//! another HTTPS service on the same name is another origin.

use axum::extract::FromRequestParts;
use axum::http::header;
use axum::http::request::Parts;
use axum::http::uri::Authority;
use wslib_appliance_auth::{AuthError, RelyingParty};

use crate::ApiError;

/// A request extension the listener inserts: the port a browser's address for
/// it carries. An address with no port reads as 443.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServingPort(pub u16);

/// Extracting it never refuses; [`relying_party`](Self::relying_party) does.
#[derive(Debug, Clone, Default)]
pub struct Reached {
    authority: Option<Authority>,
    serving: Option<ServingPort>,
}

impl Reached {
    /// Refused for no name, an IP address, or a port the listener does not serve.
    pub fn relying_party(&self) -> Result<RelyingParty, ApiError> {
        let authority = self.authority.as_ref().ok_or(AuthError::BadHost)?;
        let port = authority.port_u16().unwrap_or(443);
        if self.serving != Some(ServingPort(port)) {
            tracing::warn!(
                port,
                serving = ?self.serving,
                "passkey refused: reached on a port this listener does not serve"
            );
            return Err(AuthError::BadHost.into());
        }
        Ok(
            RelyingParty::for_host(&format!("{}:{port}", authority.host()))
                .map_err(AuthError::from)?,
        )
    }

    #[cfg(test)]
    pub(crate) fn at(authority: &str, serving: u16) -> Self {
        Self {
            authority: authority.parse().ok(),
            serving: Some(ServingPort(serving)),
        }
    }
}

impl<S: Send + Sync> FromRequestParts<S> for Reached {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        let authority = parts.uri.authority().cloned().or_else(|| {
            parts
                .headers
                .get(header::HOST)
                .and_then(|host| host.to_str().ok()?.parse().ok())
        });
        let serving = parts.extensions.get::<ServingPort>().copied();
        Ok(Self { authority, serving })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refused(reached: Reached) -> String {
        reached.relying_party().expect_err("refused").to_string()
    }

    #[test]
    fn the_port_is_the_listeners_whatever_host_says() {
        assert!(Reached::at("box.local:8443", 8443).relying_party().is_ok());
        assert!(Reached::at("box.local", 443).relying_party().is_ok());
        let bad_host = AuthError::BadHost.to_string();
        for (authority, serving) in [
            ("box.local:9443", 8443),
            ("box.local", 8443),
            ("box.local:443", 8443),
        ] {
            assert_eq!(
                refused(Reached::at(authority, serving)),
                bad_host,
                "{authority}"
            );
        }
        let unmarked = Reached {
            serving: None,
            ..Reached::at("box.local:8443", 8443)
        };
        assert_eq!(refused(unmarked), bad_host, "no listener said");
    }

    #[test]
    fn no_name_or_an_address_runs_no_ceremony() {
        assert_eq!(refused(Reached::default()), AuthError::BadHost.to_string());
        for address in ["192.168.1.20:8443", "[fe80::1]:8443"] {
            assert_eq!(
                refused(Reached::at(address, 8443)),
                AuthError::NotOnAnIpAddress.to_string(),
                "{address}"
            );
        }
    }
}
