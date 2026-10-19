use crate::Parsed;
use crate::mta_sts::MtaStsPolicy;

use super::fetch::FetchFailure;
#[cfg(feature = "http")]
use super::fetch::{HttpClients, Reach, get, media_type};

/// The outcome of fetching a domain's MTA-STS policy file (RFC 8461 §3.3).
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case", tag = "kind"))]
#[non_exhaustive]
pub enum PolicyFetch {
    /// `body` is the file as served, which the policy's spans index.
    Fetched {
        url: String,
        body: String,
        policy: Parsed<MtaStsPolicy>,
    },
    Unreachable {
        url: String,
        failure: FetchFailure,
    },
}

/// Policy files longer than this are refused, as senders may (§3.3).
pub const POLICY_SIZE_LIMIT: usize = 64 * 1024;

/// Where a domain's policy is served from.
pub fn policy_url(domain: &str) -> String {
    format!(
        "https://mta-sts.{}/.well-known/mta-sts.txt",
        super::ascii(domain)
    )
}

/// Fetches and parses the MTA-STS policy of `domain`. The policy host is
/// resolved through `resolver`, refused unless every address is globally
/// routable, and connected to only at those addresses, so a domain can't
/// steer the request into a private network. `timeout` bounds the request.
#[cfg(feature = "http")]
pub async fn mta_sts_policy(
    resolver: &impl wslib_dns::Resolver,
    clients: &HttpClients,
    domain: &str,
    timeout: Option<std::time::Duration>,
) -> PolicyFetch {
    fetch(
        resolver,
        clients,
        policy_url(domain),
        timeout,
        Reach::GlobalOnly,
    )
    .await
}

#[cfg(feature = "http")]
pub(crate) async fn fetch(
    resolver: &impl wslib_dns::Resolver,
    clients: &HttpClients,
    url: String,
    timeout: Option<std::time::Duration>,
    reach: Reach,
) -> PolicyFetch {
    match read(resolver, clients, &url, timeout, reach).await {
        Ok(body) => PolicyFetch::Fetched {
            policy: crate::mta_sts::parse_policy(&body),
            url,
            body,
        },
        Err(failure) => PolicyFetch::Unreachable { url, failure },
    }
}

/// §3.3 asks for `text/plain`, and the policy is text.
#[cfg(feature = "http")]
async fn read(
    resolver: &impl wslib_dns::Resolver,
    clients: &HttpClients,
    url: &str,
    timeout: Option<std::time::Duration>,
    reach: Reach,
) -> Result<String, FetchFailure> {
    let got = get(
        resolver,
        clients,
        url,
        timeout,
        reach,
        POLICY_SIZE_LIMIT,
        "text/plain",
    )
    .await?;
    if media_type(got.content_type.as_deref()).as_deref() != Some("text/plain") {
        return Err(FetchFailure::ContentType {
            content_type: got.content_type,
        });
    }
    String::from_utf8(got.body).map_err(|_| FetchFailure::NotUtf8)
}

#[cfg(all(test, feature = "http"))]
mod tests {
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    use wslib_dns::FakeResolver;

    use super::*;
    use crate::discover::fetch::testing::{clients, response, serve};

    const HOST: &str = "mta-sts.example.com";

    fn loopback() -> FakeResolver {
        FakeResolver::new().with_ip(HOST, ["127.0.0.1".parse().unwrap()])
    }

    async fn local_fetch(raw: Vec<u8>) -> PolicyFetch {
        let (port, _) = serve(raw).await;
        let url = format!("http://{HOST}:{port}/.well-known/mta-sts.txt");
        fetch(&loopback(), &clients(), url, None, Reach::Anywhere).await
    }

    async fn failure(raw: Vec<u8>) -> FetchFailure {
        match local_fetch(raw).await {
            PolicyFetch::Unreachable { failure, .. } => failure,
            fetched => panic!("expected a failure, got {fetched:?}"),
        }
    }

    const POLICY: &str =
        "version: STSv1\r\nmode: enforce\r\nmx: mail.example.com\r\nmax_age: 86400\r\n";

    #[test]
    fn the_url_is_under_the_mta_sts_host() {
        assert_eq!(
            policy_url("Example.COM."),
            "https://mta-sts.example.com/.well-known/mta-sts.txt"
        );
    }

    #[tokio::test]
    async fn a_plain_text_policy_is_fetched_and_parsed() {
        let fetched = local_fetch(response(
            "200 OK",
            &["Content-Type: text/plain; charset=utf-8"],
            POLICY.as_bytes(),
        ))
        .await;
        let PolicyFetch::Fetched { body, policy, .. } = fetched else {
            panic!("the policy is served");
        };
        assert_eq!(body, POLICY);
        assert!(policy.is_usable());
    }

    #[tokio::test]
    async fn anything_but_a_plain_200_is_refused() {
        assert_eq!(
            failure(response(
                "404 Not Found",
                &["Content-Type: text/plain"],
                b""
            ))
            .await,
            FetchFailure::Status { status: 404 }
        );
        assert_eq!(
            failure(response(
                "302 Found",
                &["Location: https://example.com/policy"],
                b""
            ))
            .await,
            FetchFailure::Redirect {
                location: Some("https://example.com/policy".into())
            }
        );
        assert_eq!(
            failure(response(
                "200 OK",
                &["Content-Type: text/html"],
                POLICY.as_bytes()
            ))
            .await,
            FetchFailure::ContentType {
                content_type: Some("text/html".into())
            }
        );
        assert_eq!(
            failure(response("200 OK", &[], POLICY.as_bytes())).await,
            FetchFailure::ContentType { content_type: None }
        );
        assert_eq!(
            failure(response(
                "200 OK",
                &["Content-Type: text/plain"],
                &[0xff, 0xfe]
            ))
            .await,
            FetchFailure::NotUtf8
        );
        let body = vec![b'#'; POLICY_SIZE_LIMIT + 1];
        assert_eq!(
            failure(response("200 OK", &["Content-Type: text/plain"], &body)).await,
            FetchFailure::TooLarge {
                limit: POLICY_SIZE_LIMIT,
                decompressed: false
            }
        );
    }

    #[tokio::test]
    async fn a_policy_host_on_a_private_or_local_address_is_never_contacted() {
        let (port, connections) = serve(response(
            "200 OK",
            &["Content-Type: text/plain"],
            POLICY.as_bytes(),
        ))
        .await;
        for addresses in [
            vec!["127.0.0.1"],
            vec!["10.0.3.7"],
            vec!["169.254.169.254"],
            vec!["198.51.100.7", "::1"],
        ] {
            let dns =
                FakeResolver::new().with_ip(HOST, addresses.iter().map(|a| a.parse().unwrap()));
            let fetched = mta_sts_policy(&dns, &clients(), "example.com", None).await;
            assert!(
                matches!(
                    fetched,
                    PolicyFetch::Unreachable {
                        failure: FetchFailure::NonGlobalAddress { .. },
                        ..
                    }
                ),
                "{addresses:?}: {fetched:?}"
            );
        }
        let url = format!("https://{HOST}:{port}/.well-known/mta-sts.txt");
        let fetched = fetch(&loopback(), &clients(), url, None, Reach::GlobalOnly).await;
        assert!(matches!(
            fetched,
            PolicyFetch::Unreachable {
                failure: FetchFailure::NonGlobalAddress { .. },
                ..
            }
        ));
        assert_eq!(connections.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn lookup_failures_and_no_time_left_send_nothing() {
        let dns = FakeResolver::new().with_error(
            HOST,
            wslib_dns::RecordType::A,
            wslib_dns::LookupError::ServFail,
        );
        let PolicyFetch::Unreachable { failure, .. } =
            mta_sts_policy(&dns, &clients(), "example.com", None).await
        else {
            panic!("a failed lookup fetches nothing");
        };
        assert!(matches!(failure, FetchFailure::Lookup { .. }));
        let PolicyFetch::Unreachable { failure, .. } =
            mta_sts_policy(&loopback(), &clients(), "example.com", Some(Duration::ZERO)).await
        else {
            panic!("nothing is sent");
        };
        assert_eq!(failure, FetchFailure::NotSent);
    }
}
