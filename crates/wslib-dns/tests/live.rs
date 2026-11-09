//! Against the real DNS: `cargo test -p wslib-dns --features hickory -- --ignored`.

use wslib_dns::{
    AuthoritativeOptions, AuthoritativeResolver, HickoryOptions, HickoryResolver, LookupError,
    Resolver,
};

fn resolver() -> HickoryResolver {
    HickoryResolver::from_system(HickoryOptions::default()).unwrap()
}

#[tokio::test]
#[ignore = "needs the network"]
async fn authoritative_servers_answer_from_the_root_down() {
    let dns = AuthoritativeResolver::new(AuthoritativeOptions::default());
    let spf = dns.txt("example.com").await.unwrap();
    assert!(
        spf.records
            .iter()
            .any(|txt| txt.joined().starts_with("v=spf1"))
    );
    assert!(!dns.ns("example.com").await.unwrap().records.is_empty());
    assert!(
        !dns.delegation("example.com")
            .await
            .unwrap()
            .records
            .is_empty()
    );
    assert_eq!(
        dns.txt("nothing.example.invalid").await,
        Err(LookupError::NxDomain)
    );
    assert_eq!(
        dns.delegation("www.example.com").await,
        Err(LookupError::NoData)
    );
}

#[tokio::test]
#[ignore = "needs the network"]
async fn example_com_answers_and_reports_absence_precisely() {
    let dns = resolver();
    assert!(!dns.a("example.com").await.unwrap().records.is_empty());
    assert!(!dns.ns("example.com").await.unwrap().records.is_empty());
    let spf = dns.txt("example.com").await.unwrap();
    assert!(
        spf.records
            .iter()
            .any(|txt| txt.joined().starts_with("v=spf1"))
    );
    assert!(spf.ttl.is_some());
    assert_eq!(dns.cname("example.com").await, Err(LookupError::NoData));
    assert_eq!(
        dns.txt("nothing.example.invalid").await,
        Err(LookupError::NxDomain)
    );
}

#[tokio::test]
#[ignore = "needs the network"]
async fn explicit_nameservers_resolve() {
    let dns = HickoryResolver::from_nameservers(
        ["1.1.1.1:53".parse().unwrap()],
        HickoryOptions::default(),
    )
    .unwrap();
    let mx = dns.mx("example.com").await.unwrap();
    assert!(
        mx.records
            .iter()
            .all(|mx| mx.exchange == "." || !mx.exchange.ends_with('.'))
    );
}

#[tokio::test]
#[ignore = "needs the network"]
async fn a_validation_failure_is_servfail() {
    let dns = HickoryResolver::from_nameservers(
        ["1.1.1.1:53".parse().unwrap()],
        HickoryOptions::default(),
    )
    .unwrap();
    assert_eq!(
        dns.txt("dnssec-failed.org").await,
        Err(LookupError::ServFail)
    );
}

#[tokio::test]
#[ignore = "needs the network"]
async fn internationalised_names_are_sent_as_a_labels() {
    let error = resolver().txt("bücher.example.invalid").await.unwrap_err();
    assert_eq!(error, LookupError::NxDomain);
}

/// Through the system's resolvers, as a deployment would be: a resolver that
/// strips RRSIGs fails here even when a public one passes.
#[cfg(feature = "__dnssec")]
#[tokio::test]
#[ignore = "needs the network"]
async fn validation_tells_signed_unsigned_and_broken_zones_apart() {
    use wslib_dns::DnssecStatus;
    let mut options = HickoryOptions::default();
    options.validate = true;
    let dns = HickoryResolver::from_system(options).unwrap();
    assert_eq!(
        dns.a("example.com").await.unwrap().dnssec,
        Some(DnssecStatus::Secure)
    );
    assert_eq!(
        dns.a("google.com").await.unwrap().dnssec,
        Some(DnssecStatus::Insecure)
    );
    // hickory can't set CD, so an upstream that validates answers SERVFAIL
    // for a bogus zone before hickory sees it; only a non-validating upstream
    // lets it report Bogus.
    let broken = dns.a("dnssec-failed.org").await;
    assert!(
        matches!(broken, Err(LookupError::Bogus | LookupError::ServFail)),
        "{broken:?}"
    );
    let unvalidated = resolver().a("example.com").await.unwrap();
    assert_eq!(unvalidated.dnssec, None);
}
