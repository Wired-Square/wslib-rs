use std::net::UdpSocket;
use std::time::Duration;

use wslib_dns::{HickoryOptions, HickoryResolver, LookupError, Resolver};

#[tokio::test]
async fn a_server_that_never_answers_is_a_timeout() {
    let silent = UdpSocket::bind("127.0.0.1:0").unwrap();
    let dns = HickoryResolver::from_nameservers(
        [silent.local_addr().unwrap()],
        HickoryOptions {
            timeout: Duration::from_millis(200),
            attempts: 1,
        },
    )
    .unwrap();
    assert_eq!(dns.a("example.com").await, Err(LookupError::Timeout));
    assert_eq!(dns.txt("example.com").await, Err(LookupError::Timeout));
}

#[tokio::test]
async fn debug_shows_the_options_not_the_internals() {
    let dns = HickoryResolver::from_nameservers(
        ["192.0.2.53:53".parse().unwrap()],
        HickoryOptions::default(),
    )
    .unwrap();
    assert!(format!("{dns:?}").starts_with("HickoryResolver { options:"));
}
