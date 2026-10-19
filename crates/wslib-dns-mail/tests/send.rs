use wslib_dns::Resolver;
use wslib_dns_mail::check::{self, CheckOptions};
use wslib_dns_mail::discover::{self, DmarcDiscoveryMode};
use wslib_dns_mail::spf;

fn assert_send<T: Send>(_: T) {}

// A Lambda handler or `tokio::spawn` needs every discovery future to be Send.
#[allow(dead_code)]
fn discovery_futures_are_send<R: Resolver>(dns: &R, uri: &wslib_dns_mail::ReportUri) {
    assert_send(discover::spf(dns, "example.com"));
    assert_send(discover::dmarc(
        dns,
        "example.com",
        DmarcDiscoveryMode::Rfc7489,
    ));
    assert_send(discover::dmarc_report_authorisation(
        dns,
        "example.com",
        uri,
    ));
    assert_send(discover::dkim(dns, "s1", "example.com"));
    assert_send(discover::probe_dkim(
        dns,
        "example.com",
        discover::COMMON_SELECTORS.iter().copied(),
    ));
    assert_send(discover::mx(dns, "example.com"));
    assert_send(discover::bimi(dns, "example.com", "default"));
    assert_send(discover::mta_sts(dns, "example.com"));
    assert_send(discover::tls_rpt(dns, "example.com"));
    assert_send(discover::dnsbl(
        dns,
        "192.0.2.1".parse().unwrap(),
        "bl.example.org",
    ));
    assert_send(spf::tree::walk(
        dns,
        "example.com",
        spf::tree::WalkLimits::default(),
    ));
    assert_send(spf::check_host(
        dns,
        "192.0.2.1".parse().unwrap(),
        "mx.example.com",
        "a@example.com",
    ));
    assert_send(check::check_domain(
        dns,
        "example.com",
        &CheckOptions::default(),
    ));
    #[cfg(feature = "http")]
    assert_send(discover::mta_sts_policy(
        dns,
        &discover::HttpClients::new(reqwest::Client::builder),
        "example.com",
        None,
    ));
}

#[test]
fn compiles() {}
