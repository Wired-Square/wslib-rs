use std::error::Error;
use std::time::Duration;

use wslib_ble::{Address, AddressParseError, ForgetError, PairError, Refusal};

const OCTETS: [u8; 6] = [0xAA, 0xBB, 0xCC, 0x0D, 0xEE, 0xFF];
const LIMIT: Duration = Duration::from_secs(1);

#[test]
fn an_address_parses_in_either_case_and_prints_upper_case() {
    let upper: Address = "AA:BB:CC:0D:EE:FF".parse().unwrap();
    let lower: Address = "aa:bb:cc:0d:ee:ff".parse().unwrap();
    assert_eq!(upper, lower);
    assert_eq!(upper.octets(), OCTETS);
    assert_eq!(lower.to_string(), "AA:BB:CC:0D:EE:FF");
    assert_eq!(Address::new(OCTETS), upper);
}

#[test]
fn a_malformed_address_is_refused() {
    for text in [
        "",
        "AA:BB:CC:DD:EE",
        "AA:BB:CC:DD:EE:FF:00",
        "AA:BB:CC:DD:EE:F",
        "AA:BB:CC:DD:EE:FFF",
        "AA:BB:CC:DD:EE:GG",
        "AA:BB:CC:DD:EE:+F",
        "AA-BB-CC-DD-EE-FF",
        "AABBCCDDEEFF",
        " AA:BB:CC:DD:EE:FF",
    ] {
        let refused: Result<Address, AddressParseError> = text.parse();
        let error = refused.expect_err(text);
        assert_eq!(error.text(), text);
        assert!(error.source().is_none());
    }
}

#[test]
fn an_error_with_no_cause_has_no_source() {
    let address = Address::new(OCTETS);
    let errors = [
        PairError::NoAdapter {
            adapter: "hci0".into(),
        },
        PairError::UnknownDevice {
            adapter: "hci0".into(),
            address,
        },
        PairError::TimedOut { limit: LIMIT },
    ];
    for error in errors {
        assert!(error.source().is_none(), "{error}");
        assert!(!error.to_string().is_empty());
    }
    assert!(ForgetError::Unsupported.source().is_none());
}

#[test]
fn a_refusal_keeps_the_name_bluez_gave() {
    for (reason, name) in [
        (
            Refusal::AuthenticationFailed,
            "org.bluez.Error.AuthenticationFailed",
        ),
        (
            Refusal::AuthenticationRejected,
            "org.bluez.Error.AuthenticationRejected",
        ),
        (
            Refusal::AuthenticationCanceled,
            "org.bluez.Error.AuthenticationCanceled",
        ),
        (
            Refusal::AuthenticationTimeout,
            "org.bluez.Error.AuthenticationTimeout",
        ),
        (
            Refusal::ConnectionAttemptFailed,
            "org.bluez.Error.ConnectionAttemptFailed",
        ),
    ] {
        assert_eq!(reason.name(), name);
        assert_eq!(Refusal::from_name(name), Some(reason));
    }
    assert_eq!(Refusal::from_name("org.bluez.Error.AlreadyExists"), None);
}

#[cfg(not(target_os = "linux"))]
mod off_linux {
    use wslib_ble::{Address, ForgetError, Paired, Pairing, forget};

    use super::{LIMIT, OCTETS};

    #[tokio::test]
    async fn the_system_pairs() {
        let pairing = Pairing::confirm("hci0", &Address::new(OCTETS))
            .await
            .unwrap();
        assert_eq!(pairing.pair(LIMIT).await.unwrap(), Paired::ByTheSystem);
        pairing.close().await.unwrap();
    }

    #[tokio::test]
    async fn a_bond_cannot_be_forgotten() {
        let refused = forget("hci0", &Address::new(OCTETS)).await;
        assert!(matches!(refused, Err(ForgetError::Unsupported)));
    }
}
