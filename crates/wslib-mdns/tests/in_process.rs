use std::time::Duration;

use wslib_mdns::{
    AdvertState, BrowseEvent, Error, Host, InProcess, Interfaces, Options, Service, ServiceType,
};

fn on_loopback(host: &str) -> InProcess {
    InProcess::new(Options {
        interfaces: Interfaces::Loopback,
        host: Host::Named(host.parse().unwrap()),
    })
    .unwrap()
}

#[tokio::test]
#[ignore = "binds UDP 5353 on loopback, where this machine's own responder sees it"]
async fn an_advert_on_loopback_is_resolved_and_removed_when_withdrawn() {
    let kind: ServiceType = "_wslib-test._tcp".parse().unwrap();
    let browser = on_loopback("wslib-mdns-browser");
    let mut browse = browser.browse(&kind).unwrap();
    assert!(matches!(browser.browse(&kind), Err(Error::Unsupported(_))));

    let mut service = Service::new(kind.clone(), "Loopback test".parse().unwrap(), 18080);
    service.txt.push("product=widget".parse().unwrap());
    let advert = on_loopback("wslib-mdns-test")
        .advertise(&service)
        .await
        .unwrap();

    let found = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(BrowseEvent::Resolved(found)) = browse.next().await {
                break found;
            }
        }
    })
    .await
    .expect("resolved on loopback");
    assert_eq!(found.instance.as_str(), "Loopback test");
    assert_eq!(found.host, "wslib-mdns-test.local");
    assert_eq!(found.port, 18080);
    assert!(
        found.addrs.iter().all(|a| a.is_loopback()),
        "{:?}",
        found.addrs
    );
    assert!(!found.addrs.is_empty(), "the advert carries no addresses");
    assert_eq!(found.txt("product"), Some("widget"));
    tokio::time::timeout(
        Duration::from_secs(10),
        advert.state().wait_for(|s| *s == AdvertState::Established),
    )
    .await
    .expect("announced on loopback")
    .unwrap();

    advert.withdraw().await.unwrap();
    let removed = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(BrowseEvent::Removed(instance)) = browse.next().await {
                break instance;
            }
        }
    })
    .await
    .expect("removed on loopback");
    assert_eq!(removed.as_str(), "Loopback test");
}
