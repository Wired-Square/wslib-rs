//! Against the real DNS: `cargo test -p wslib-dns-mail --test live -- --ignored`.

use wslib_dns::{HickoryOptions, HickoryResolver};
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
