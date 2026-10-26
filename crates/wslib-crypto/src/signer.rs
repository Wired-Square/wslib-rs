use std::sync::Arc;

use pkcs8::der::Decode;
use pkcs8::spki::SubjectPublicKeyInfoRef;
use pkcs8::{DecodePrivateKey, EncodePublicKey};
use rustls::crypto::CryptoProvider;
use rustls::sign::SigningKey;
use rustls_pki_types::PrivateKeyDer;
use sha2::{Digest, Sha256};

use crate::{Error, KeyAlgorithm};

/// A private key loaded into a provider, signing for rcgen with its algorithm's one scheme.
#[derive(Debug)]
pub struct Signer {
    provider: Arc<CryptoProvider>,
    signer: Box<dyn rustls::sign::Signer>,
    algorithm: KeyAlgorithm,
    spki: Vec<u8>,
    public_key: Vec<u8>,
}

impl Signer {
    /// Loads `key` through the provider, reading its algorithm from its public key.
    ///
    /// The public key is the provider's; when it gives none, a PKCS#8 P-256,
    /// P-384 or RSA key's is computed here, and any other key is refused.
    pub fn new(provider: Arc<CryptoProvider>, key: &PrivateKeyDer<'_>) -> Result<Self, Error> {
        let (signing, spki) = load(&provider, key)?;
        let algorithm = KeyAlgorithm::of_spki(&spki).ok_or(Error::Unsupported)?;
        let signer = signing
            .choose_scheme(&[algorithm.signature_scheme()])
            .ok_or(Error::NoScheme(algorithm))?;
        let public_key = SubjectPublicKeyInfoRef::from_der(&spki)
            .ok()
            .and_then(|info| info.subject_public_key.as_bytes().map(<[u8]>::to_vec))
            .ok_or(Error::Unsupported)?;
        Ok(Self {
            provider,
            signer,
            algorithm,
            spki,
            public_key,
        })
    }

    pub fn algorithm(&self) -> KeyAlgorithm {
        self.algorithm
    }

    /// The DER SubjectPublicKeyInfo.
    pub fn spki(&self) -> &[u8] {
        &self.spki
    }

    pub fn key_identifier(&self) -> [u8; 20] {
        key_identifier(&self.spki)
    }

    pub fn provider(&self) -> &Arc<CryptoProvider> {
        &self.provider
    }
}

impl rcgen::PublicKeyData for Signer {
    fn der_bytes(&self) -> &[u8] {
        &self.public_key
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        self.algorithm.rcgen()
    }
}

impl rcgen::SigningKey for Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        self.signer
            .sign(message)
            .map_err(|_| rcgen::Error::RemoteKeyError)
    }
}

fn load(
    provider: &CryptoProvider,
    key: &PrivateKeyDer<'_>,
) -> Result<(Arc<dyn SigningKey>, Vec<u8>), Error> {
    let signing = provider
        .key_provider
        .load_private_key(key.clone_key())
        .map_err(Error::Load)?;
    let spki = match (signing.public_key(), key) {
        (Some(spki), _) => spki.to_vec(),
        (None, PrivateKeyDer::Pkcs8(der)) => {
            spki_of_pkcs8(der.secret_pkcs8_der()).ok_or(Error::NoPublicKey)?
        }
        (None, _) => return Err(Error::NoPublicKey),
    };
    Ok((signing, spki))
}

fn spki_of_pkcs8(der: &[u8]) -> Option<Vec<u8>> {
    let encoded = if let Ok(key) = p256::SecretKey::from_pkcs8_der(der) {
        key.public_key().to_public_key_der()
    } else if let Ok(key) = p384::SecretKey::from_pkcs8_der(der) {
        key.public_key().to_public_key_der()
    } else {
        rsa::RsaPrivateKey::from_pkcs8_der(der)
            .ok()?
            .to_public_key()
            .to_public_key_der()
    };
    encoded.ok().map(|document| document.into_vec())
}

/// Whether `key`, loaded through the provider, is the private half of `spki`.
pub fn key_matches(
    provider: &CryptoProvider,
    key: &PrivateKeyDer<'_>,
    spki: &[u8],
) -> Result<bool, Error> {
    Ok(load(provider, key)?.1 == spki)
}

/// RFC 7093 method 1: the first 20 bytes of the SHA-256 of a DER SubjectPublicKeyInfo.
pub fn key_identifier(spki: &[u8]) -> [u8; 20] {
    let mut identifier = [0; 20];
    identifier.copy_from_slice(&Sha256::digest(spki)[..20]);
    identifier
}
