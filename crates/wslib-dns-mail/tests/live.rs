//! Against the real DNS: `cargo test -p wslib-dns-mail --test live -- --ignored`.

use wslib_dns::{HickoryOptions, HickoryResolver};
use wslib_dns_mail::check::{self, CheckOptions};
use wslib_dns_mail::discover::{self, DmarcDiscoveryMode, PolicyTag};
use wslib_dns_mail::spf;

#[tokio::test]
#[ignore = "needs the network"]
async fn example_com_publishes_spf_dmarc_and_a_null_mx() {
    let dns = HickoryResolver::from_system(HickoryOptions::default()).unwrap();
    let spf = discover::spf(&dns, "example.com").await;
    assert!(spf.single().is_some_and(|record| record.parsed.is_usable()));
    let dmarc = discover::dmarc(&dns, "example.com", DmarcDiscoveryMode::Rfc7489).await;
    assert_eq!(dmarc.applies.map(|applied| applied.tag), Some(PolicyTag::P));
    let inherited = discover::dmarc(&dns, "www.example.com", DmarcDiscoveryMode::Rfc7489).await;
    assert_eq!(inherited.records.inherited_from(), Some("example.com"));
    assert!(discover::mx(&dns, "example.com").await.is_null());
    let tree = spf::tree::walk(&dns, "example.com", spf::tree::WalkLimits::default()).await;
    assert_eq!(tree.accounting.lookups, 0);
    let checked = spf::check_host(
        &dns,
        "192.0.2.1".parse().unwrap(),
        "mx.example.org",
        "a@example.com",
    )
    .await;
    assert_eq!(checked.result, spf::SpfResult::Fail);
}

#[tokio::test]
#[ignore = "needs the network"]
async fn check_domain_reports_on_example_com_within_its_budget() {
    let dns = HickoryResolver::from_system(HickoryOptions::default()).unwrap();
    let mut options = CheckOptions::default();
    options.query_log = true;
    let report = check::check_domain(&dns, "example.com", &options).await;
    assert!(report.queries_sent <= 200);
    assert!(
        report
            .findings
            .iter()
            .all(|f| f.code != check::FindingCode::Incomplete)
    );
    assert!(
        report
            .findings
            .iter()
            .all(|f| f.code != check::FindingCode::SpfMissing)
    );
    assert!(report.queries.is_some_and(|log| !log.is_empty()));
}

#[cfg(feature = "http")]
#[tokio::test]
#[ignore = "needs the network"]
async fn a_published_mta_sts_policy_is_fetched_over_https() {
    use wslib_dns_mail::discover::PolicyFetch;
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dns = HickoryResolver::from_system(HickoryOptions::default()).unwrap();
    let clients = discover::HttpClients::new(reqwest::Client::builder);
    let PolicyFetch::Fetched { policy, .. } =
        discover::mta_sts_policy(&dns, &clients, "google.com", None).await
    else {
        panic!("google.com serves an MTA-STS policy");
    };
    assert!(policy.is_usable());
}

#[cfg(feature = "http")]
#[tokio::test]
#[ignore = "needs the network"]
async fn a_published_bimi_logo_is_fetched_and_checked() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dns = HickoryResolver::from_system(HickoryOptions::default()).unwrap();
    let mut options = CheckOptions::default();
    options.bimi_http = Some(discover::HttpClients::new(reqwest::Client::builder));
    let report = check::check_domain(&dns, "bimigroup.org", &options).await;
    let Some(discover::LogoFetch::Fetched { validation, .. }) = report.bimi_logo else {
        panic!("bimigroup.org serves a logo: {:?}", report.bimi_logo);
    };
    assert!(validation.size > 0);
}

#[cfg(feature = "http")]
#[tokio::test]
#[ignore = "needs the network"]
async fn a_published_mark_certificate_verifies_through_check_domain() {
    use wslib_dns_mail::bimi::{VmcOptions, VmcTrustAnchors};
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dns = HickoryResolver::from_system(HickoryOptions::default()).unwrap();
    let clients = discover::HttpClients::new(reqwest::Client::builder);
    let records = discover::bimi(&dns, "cnn.com", "default").await;
    let authority = records
        .found()
        .and_then(|found| found.parsed.record.authority.clone())
        .unwrap();
    let discover::CertificateFetch::Fetched { pem, .. } =
        discover::bimi_certificate(&dns, &clients, &authority, None).await
    else {
        panic!("cnn.com serves its mark certificate");
    };
    // No roots are built in; anchor on the chain's own root to check the rest.
    let text = String::from_utf8(pem).unwrap();
    let root = text
        .split_inclusive("-----END CERTIFICATE-----")
        .filter(|b| b.contains("BEGIN"))
        .last()
        .unwrap();
    let mut options = CheckOptions::default();
    options.bimi_http = Some(clients);
    options.bimi_vmc = Some(VmcOptions::new(
        VmcTrustAnchors::from_pem(root.as_bytes()).unwrap(),
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .all,
    ));
    let report = check::check_domain(&dns, "cnn.com", &options).await;
    let vmc = report.bimi_vmc.expect("the certificate is verified");
    assert!(vmc.is_valid(), "{:?}", vmc.problems);
}

/// Through the system's resolvers. Behind a validating upstream the broken
/// zone SERVFAILs, so the DS heuristic flags it rather than `dnssec_bogus`.
#[tokio::test]
#[ignore = "needs the network"]
async fn validation_reports_dnssec_and_dane() {
    use wslib_dns::DnssecStatus;
    use wslib_dns_mail::check::FindingCode;

    let mut options = HickoryOptions::default();
    options.validate = true;
    let dns = HickoryResolver::from_system(options).unwrap();
    let report = check::check_domain(&dns, "example.com", &CheckOptions::default()).await;
    assert_eq!(
        report.dnssec,
        Some(DnssecStatus::Secure),
        "{:?}",
        report.findings
    );

    let posteo = check::check_mx(&dns, "posteo.de", &[]).await;
    assert_eq!(posteo.mx.dnssec, Some(DnssecStatus::Secure));
    assert!(
        posteo
            .mx
            .hosts
            .iter()
            .any(|host| host.tlsa.as_ref().is_some_and(|tlsa| {
                tlsa.dnssec == Some(DnssecStatus::Secure) && !tlsa.records.is_empty()
            })),
        "{:?}",
        posteo.mx.hosts
    );

    let broken = check::check_domain(&dns, "dnssec-failed.org", &CheckOptions::default()).await;
    assert!(
        broken.findings.iter().any(|finding| matches!(
            finding.code,
            FindingCode::DnssecBogus | FindingCode::DnssecSuspectedBogus
        )),
        "{:?}",
        broken.findings
    );
}
