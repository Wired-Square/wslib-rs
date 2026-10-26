use std::sync::{Arc, OnceLock};

use rustls::crypto::{CryptoProvider, GetRandomFailed, KeyProvider, SecureRandom};
use rustls::sign::SigningKey;
use rustls::{SignatureAlgorithm, SignatureScheme};
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer};
use wslib_crypto::{
    Error, KeyAlgorithm, Signer, key_identifier, key_matches, random, random_serial,
};

fn providers() -> [(&'static str, Arc<CryptoProvider>); 2] {
    [
        ("ring", Arc::new(rustls::crypto::ring::default_provider())),
        (
            "aws-lc-rs",
            Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        ),
    ]
}

fn key(algorithm: KeyAlgorithm) -> PrivateKeyDer<'static> {
    static KEYS: OnceLock<Vec<PrivatePkcs8KeyDer<'static>>> = OnceLock::new();
    let keys = KEYS.get_or_init(|| {
        KeyAlgorithm::ALL
            .iter()
            .map(|algorithm| algorithm.generate().expect("generates"))
            .collect()
    });
    let index = KeyAlgorithm::ALL
        .iter()
        .position(|a| *a == algorithm)
        .unwrap();
    keys[index].clone_key().into()
}

/// A provider that never says what a key's public half is, as some may not.
fn without_public_keys(provider: &CryptoProvider) -> Arc<CryptoProvider> {
    #[derive(Debug)]
    struct Hiding(&'static dyn KeyProvider);
    #[derive(Debug)]
    struct Hidden(Arc<dyn SigningKey>);

    impl KeyProvider for Hiding {
        fn load_private_key(
            &self,
            key: PrivateKeyDer<'static>,
        ) -> Result<Arc<dyn SigningKey>, rustls::Error> {
            Ok(Arc::new(Hidden(self.0.load_private_key(key)?)))
        }
    }
    impl SigningKey for Hidden {
        fn choose_scheme(
            &self,
            offered: &[SignatureScheme],
        ) -> Option<Box<dyn rustls::sign::Signer>> {
            self.0.choose_scheme(offered)
        }
        fn algorithm(&self) -> SignatureAlgorithm {
            self.0.algorithm()
        }
    }

    Arc::new(CryptoProvider {
        key_provider: Box::leak(Box::new(Hiding(provider.key_provider))),
        ..provider.clone()
    })
}

#[test]
fn every_generated_key_signs_in_both_providers_with_its_one_scheme() {
    for (name, provider) in providers() {
        for algorithm in KeyAlgorithm::ALL {
            let signer = Signer::new(provider.clone(), &key(algorithm))
                .unwrap_or_else(|e| panic!("{name} {algorithm}: {e}"));
            assert_eq!(signer.algorithm(), algorithm, "{name}");
            assert_eq!(KeyAlgorithm::of_spki(signer.spki()), Some(algorithm));

            let signature = rcgen::SigningKey::sign(&signer, b"message").expect("signs");
            let (_, verifiers) = provider
                .signature_verification_algorithms
                .mapping
                .iter()
                .find(|(scheme, _)| *scheme == algorithm.signature_scheme())
                .expect("the provider verifies the scheme");
            let public_key = rcgen::PublicKeyData::der_bytes(&signer);
            assert!(
                verifiers.iter().any(|v| v
                    .verify_signature(public_key, b"message", &signature)
                    .is_ok()),
                "{name} {algorithm}: the signature does not verify"
            );
        }
    }
}

#[test]
fn the_public_key_from_pkcs8_is_the_one_the_provider_gives() {
    for (name, provider) in providers() {
        for algorithm in KeyAlgorithm::ALL {
            let theirs = Signer::new(provider.clone(), &key(algorithm)).unwrap();
            let ours = Signer::new(without_public_keys(&provider), &key(algorithm))
                .unwrap_or_else(|e| panic!("{name} {algorithm}: {e}"));
            assert_eq!(ours.spki(), theirs.spki(), "{name} {algorithm}");
        }
    }
}

#[test]
fn a_foreign_key_with_no_public_key_is_refused_clearly() {
    let sec1 = p256::SecretKey::random(&mut rand_core::OsRng)
        .to_sec1_der()
        .unwrap();
    let key = PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(sec1.to_vec()));
    for (name, provider) in providers() {
        Signer::new(provider.clone(), &key).unwrap_or_else(|e| panic!("{name}: {e}"));
        let refused = Signer::new(without_public_keys(&provider), &key);
        assert!(
            matches!(refused, Err(Error::NoPublicKey)),
            "{name}: {refused:?}"
        );
    }
}

#[test]
fn a_key_matches_its_own_public_key_and_no_other() {
    for (name, provider) in providers() {
        let p256 = Signer::new(provider.clone(), &key(KeyAlgorithm::EcP256)).unwrap();
        let rsa = Signer::new(provider.clone(), &key(KeyAlgorithm::Rsa2048)).unwrap();
        assert!(
            key_matches(&provider, &key(KeyAlgorithm::EcP256), p256.spki()).unwrap(),
            "{name}"
        );
        assert!(
            !key_matches(&provider, &key(KeyAlgorithm::EcP256), rsa.spki()).unwrap(),
            "{name}"
        );
        assert!(
            key_matches(&provider, &key(KeyAlgorithm::Rsa2048), rsa.spki()).unwrap(),
            "{name}"
        );
    }
}

#[test]
fn key_identifiers_and_serials_come_out_the_size_certificates_want() {
    let (_, provider) = &providers()[0];
    let signer = Signer::new(provider.clone(), &key(KeyAlgorithm::EcP384)).unwrap();
    assert_eq!(signer.key_identifier(), key_identifier(signer.spki()));

    let serials: Vec<[u8; 16]> = (0..64).map(|_| random_serial(provider).unwrap()).collect();
    assert!(
        serials
            .iter()
            .all(|serial| (0x40..0x80).contains(&serial[0]))
    );
    assert!(serials.windows(2).all(|pair| pair[0] != pair[1]));
}

#[test]
fn both_providers_give_distinct_non_zero_random_bytes() {
    for (name, provider) in providers() {
        let [first, second] = [(); 2].map(|_| random::<32>(&provider).unwrap());
        assert_ne!(first, [0; 32], "{name}");
        assert_ne!(first, second, "{name}");
    }
}

#[test]
fn a_failing_random_number_generator_is_an_error() {
    #[derive(Debug)]
    struct Failing;
    impl SecureRandom for Failing {
        fn fill(&self, _: &mut [u8]) -> Result<(), GetRandomFailed> {
            Err(GetRandomFailed)
        }
    }

    let (_, provider) = &providers()[0];
    let failing = CryptoProvider {
        secure_random: &Failing,
        ..CryptoProvider::clone(provider)
    };
    assert!(matches!(random::<32>(&failing), Err(Error::Random)));
    assert!(matches!(random_serial(&failing), Err(Error::Random)));
}
