use wslib_dns::{DEFAULT_MAX_CNAME_HOPS, LoggingResolver, Resolver};

fn assert_send<T: Send>(_: T) {}

// Lambda handlers and `tokio::spawn` need every future a check awaits to be Send.
#[allow(dead_code)]
fn futures_are_send<R: Resolver>(dns: &R) {
    assert_send(dns.txt("example.com"));
    assert_send(dns.ip("example.com"));
    assert_send(dns.cname_chain("example.com", DEFAULT_MAX_CNAME_HOPS));
    let logged = LoggingResolver::new(dns);
    assert_send(logged.ip("example.com"));
    assert_send(by_value(logged));
}

async fn by_value<R: Resolver>(dns: R) {
    dns.mx("example.com").await.ok();
}

#[test]
fn compiles() {}

#[allow(dead_code)]
fn shared_resolvers_are_resolvers<R: Resolver>(dns: std::sync::Arc<R>) {
    assert_send(by_value(dns));
}
