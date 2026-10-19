//! Against the real DNS: `cargo test -p wslib-dns-mail --test live -- --ignored`.

use wslib_dns::{HickoryOptions, HickoryResolver};
use wslib_dns_mail::discover::{self, DmarcDiscoveryMode, PolicyTag};

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
}
