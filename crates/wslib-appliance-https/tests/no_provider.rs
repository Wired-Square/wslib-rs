//! Serving with no rustls provider installed, in a process of its own: the
//! default provider is process-wide, and the unit tests install one.

use std::net::Ipv4Addr;
use std::time::Duration;

use wslib_appliance_config::{ApplianceArgs, Resolver, ServingArgs, Tls};
use wslib_appliance_https::{ServeError, Server, logs};
use wslib_appliance_store::Store;
use wslib_appliance_types::Branding;

#[tokio::test]
async fn serving_with_no_crypto_provider_is_refused_and_fires_the_handle() {
    let dir = tempfile::TempDir::new().expect("a directory");
    let config = dir.path().join("config.toml");
    std::fs::write(&config, "").expect("write");
    let pair = Tls::default_in(dir.path());
    let run = dir.path().join("run");
    let bootstrap = Resolver::new("test", "APPLIANCE_HTTPS_TEST_ONLY")
        .serving(&ServingArgs {
            bind_address: Some(Ipv4Addr::LOCALHOST.into()),
            https_port: Some(0),
            redirect_port: Some(0),
            tls_cert: Some(pair.cert.clone()),
            tls_key: Some(pair.key),
        })
        .resolve(&ApplianceArgs {
            config: Some(config),
            db: Some(dir.path().join("db")),
            socket: Some(run.join("control.sock")),
            ..Default::default()
        })
        .expect("resolves");
    let store = Store::open_in_memory(None).await.expect("store");
    let server = Server::new(store, Branding::unbranded(), "0.0.0", logs(&[]));
    let stopped = server.shutdown();

    let serving = server.serve(&bootstrap, std::future::pending());
    let refused = tokio::time::timeout(Duration::from_secs(5), serving)
        .await
        .expect("refused at once, not serving")
        .expect_err("refused");

    assert!(matches!(refused, ServeError::NoCryptoProvider), "{refused}");
    assert!(stopped.is_cancelled());
    assert!(!pair.cert.exists(), "no pair is minted without a provider");
    assert!(!run.exists(), "serving never began");
}
