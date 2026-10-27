//! Serving with no rustls provider installed, in a process of its own: the
//! default provider is process-wide, and the unit tests install one.

use wslib_appliance_server::{Ingress, ServeError, Server, logs};
use wslib_appliance_store::Store;
use wslib_appliance_types::Branding;

#[tokio::test]
async fn serving_with_no_crypto_provider_is_refused_and_fires_the_handle() {
    let store = Store::open_in_memory(None).await.expect("store");
    let server = Server::new(store, Branding::unbranded(), "0.0.0", logs(&[]));
    let stopped = server.shutdown();
    let ingress = Ingress::new("127.0.0.1:0".parse().unwrap(), |_| None);

    let refused = server
        .serve_ingress(ingress, std::future::pending())
        .await
        .expect_err("refused");

    assert!(matches!(refused, ServeError::NoCryptoProvider), "{refused}");
    assert!(stopped.is_cancelled());
}
