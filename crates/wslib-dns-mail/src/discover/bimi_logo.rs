use super::fetch::FetchFailure;
#[cfg(feature = "http")]
use super::fetch::{HttpClients, Reach, get};
use crate::bimi::LogoValidation;

/// Logos longer than this as sent are cut off: twice the BIMI Group's
/// guidance, so a logo just over it is still checked.
pub const LOGO_FETCH_LIMIT: usize = 64 * 1024;

/// A compressed logo is refused once it inflates past this, so a small file
/// can't expand into a large one.
pub const LOGO_INFLATE_LIMIT: usize = 256 * 1024;

/// The outcome of fetching a BIMI logo.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case", tag = "kind"))]
pub enum LogoFetch {
    /// `body` is the SVG, decompressed when it was sent gzipped (`gzip`).
    Fetched {
        url: String,
        content_type: Option<String>,
        gzip: bool,
        body: Vec<u8>,
        validation: LogoValidation,
    },
    Unreachable {
        url: String,
        failure: FetchFailure,
    },
}

/// Fetches the logo at `url`, a BIMI record's `l=`, and checks it against
/// SVG Tiny PS. The URL's host is resolved through `resolver` and refused
/// unless every address is globally routable; the connection is pinned to
/// those addresses. A `.svgz` or gzip-encoded body is inflated first.
#[cfg(feature = "http")]
pub async fn bimi_logo(
    resolver: &impl wslib_dns::Resolver,
    clients: &HttpClients,
    url: &str,
    timeout: Option<std::time::Duration>,
) -> LogoFetch {
    fetch(resolver, clients, url, timeout, Reach::GlobalOnly).await
}

#[cfg(feature = "http")]
pub(crate) async fn fetch(
    resolver: &impl wslib_dns::Resolver,
    clients: &HttpClients,
    url: &str,
    timeout: Option<std::time::Duration>,
    reach: Reach,
) -> LogoFetch {
    let unreachable = |failure| LogoFetch::Unreachable {
        url: url.to_owned(),
        failure,
    };
    let got = match get(resolver, clients, url, timeout, reach, LOGO_FETCH_LIMIT).await {
        Ok(got) => got,
        Err(failure) => return unreachable(failure),
    };
    let gzip = got.gzip || crate::inflate::is_gzip(&got.body);
    let body = if gzip {
        match crate::inflate::gunzip(&got.body, LOGO_INFLATE_LIMIT) {
            Ok(body) => body,
            Err(crate::inflate::InflateError::TooLarge) => {
                return unreachable(FetchFailure::TooLarge {
                    limit: LOGO_INFLATE_LIMIT,
                    decompressed: true,
                });
            }
            Err(crate::inflate::InflateError::Corrupt) => {
                return unreachable(FetchFailure::Undecodable);
            }
        }
    } else {
        got.body
    };
    LogoFetch::Fetched {
        url: url.to_owned(),
        content_type: got.content_type,
        gzip,
        validation: crate::bimi::validate_logo(&body),
        body,
    }
}

#[cfg(all(test, feature = "http"))]
mod tests;
