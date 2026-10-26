use wslib_crypto::{Error, random_default};

// The default provider is process-global, so this file holds one test to keep it alone in its process.
#[test]
fn random_default_needs_an_installed_provider() {
    assert!(matches!(random_default::<32>(), Err(Error::NoProvider)));

    rustls::crypto::ring::default_provider()
        .install_default()
        .unwrap();
    let bytes = random_default::<32>().unwrap();
    assert_ne!(bytes, [0; 32]);
}
