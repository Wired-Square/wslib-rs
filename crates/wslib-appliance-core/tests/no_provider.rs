//! Each entry point with no rustls provider installed, in a process of its own:
//! the default provider is process-wide, and the unit tests install one.

use std::sync::Arc;

use wslib_appliance_core::backend::{Callers, LogsRung, load_or_mint, no_tls};
use wslib_appliance_core::tls::{TlsError, pair_at};
use wslib_appliance_core::{AboveAdmin, Backend, Chassis, ServeError, logs};
use wslib_appliance_store::Store;
use wslib_appliance_types::Branding;

#[tokio::test]
async fn building_with_no_crypto_provider_is_refused_with_a_sentence() {
    let store = Store::open_in_memory(None).await.expect("store");
    let refused = Chassis::new(store, Branding::unbranded(), "0.0.0", logs(&[]))
        .build(Backend {
            callers: Callers::nobody(),
            logs: LogsRung::Admin,
            tls: Arc::new(no_tls()),
            listening: None,
            onboarding: false,
            names_the_box: false,
            above_admin: AboveAdmin::Absent,
            routes: Vec::new(),
            control_routes: Vec::new(),
        })
        .await
        .err()
        .expect("refused");

    assert!(matches!(refused, ServeError::NoCryptoProvider));
    assert!(refused.to_string().contains("install one"), "{refused}");
}

#[tokio::test]
async fn loading_or_minting_the_pair_with_no_crypto_provider_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let refused = load_or_mint(&wslib_appliance_config::Tls::default_in(dir.path()), None)
        .await
        .expect_err("refused");
    assert!(matches!(refused, ServeError::NoCryptoProvider));
}

const CERT: &str = "-----BEGIN CERTIFICATE-----
MIIBGTCBwAIJAJtp0qHMxGXCMAoGCCqGSM49BAMCMBQxEjAQBgNVBAMMCWxvY2Fs
aG9zdDAgFw0yNjEwMjcwMTE4MzhaGA8yMTI2MTAwMzAxMTgzOFowFDESMBAGA1UE
AwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8TCWNzFSXFQ+
lteo342XpvYKanrnIW1shMG5PaLEz/hYM68Q1cpQnWR0g/ZRw1DvIi249dADx/bU
EYZtVHM54TAKBggqhkjOPQQDAgNIADBFAiEA9spi9lRmBwPRahQN7VCfqa1ZBZlD
FH2AmjXgr0If1pgCIHqmEpoAa8KCeqK/dOBtXGySphgJ2+UpvRuCQfiJTSSM
-----END CERTIFICATE-----
";

const KEY: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg82zlyCsKFXj42Xdv
aAgHXt7gbNCis7P1STcKvVqHMxqhRANCAATxMJY3MVJcVD6W16jfjZem9gpqeuch
bWyEwbk9osTP+FgzrxDVylCdZHSD9lHDUO8iLbj10APH9tQRhm1Ucznh
-----END PRIVATE KEY-----
";

#[test]
fn reading_a_pair_offline_with_no_crypto_provider_is_an_internal_error() {
    let dir = tempfile::tempdir().unwrap();
    let settings = wslib_appliance_config::Tls::default_in(dir.path());
    std::fs::write(&settings.cert, CERT).unwrap();
    std::fs::write(&settings.key, KEY).unwrap();

    let refused = pair_at(&settings).expect_err("refused");
    assert!(matches!(refused, TlsError::Internal(_)), "{refused:?}");
    assert!(refused.to_string().contains("install one"), "{refused}");
}
