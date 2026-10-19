//! Against the real DNS: `cargo test -p wslib-dns --features hickory -- --ignored`.

use wslib_dns::{HickoryOptions, HickoryResolver, LookupError, Resolver};

fn resolver() -> HickoryResolver {
    HickoryResolver::from_system(HickoryOptions::default()).unwrap()
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
    let dns =
        HickoryResolver::from_nameservers(["1.1.1.1".parse().unwrap()], HickoryOptions::default())
            .unwrap();
    let mx = dns.mx("example.com").await.unwrap();
    assert!(
        mx.records
            .iter()
            .all(|mx| mx.exchange == "." || !mx.exchange.ends_with('.'))
    );
}
