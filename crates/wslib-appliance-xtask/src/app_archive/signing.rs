//! The index's detached CMS signature, the check that its signer is a
//! code-signing leaf of a root, and throwaway keys to sign with.

use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use cms::cert::x509::Certificate;
use cms::cert::x509::der::asn1::{ObjectIdentifier, OctetString, SetOfVec, UtcTime};
use cms::cert::x509::der::{Any, Decode, Encode};
use cms::cert::x509::spki::AlgorithmIdentifierOwned;
use cms::cert::x509::time::Time;
use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use cms::content_info::{CmsVersion, ContentInfo};
use cms::signed_data::{
    CertificateSet, EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo, SignerInfos,
};
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::pkcs8::{DecodePrivateKey, EncodePublicKey};
use rsa::Pkcs1v15Sign;
use rsa::traits::PublicKeyParts;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use wslib_crypto::{KeyAlgorithm, Signer, to_pkcs8};
use wslib_crypto_ca::{
    Authority, BasicConstraints, Csr, Extension, KeyIdentifierMethod, Profile, Serial, Subject,
    Validity, build_csr,
};
use wslib_crypto_x509::chain::{self, Purpose};
use wslib_crypto_x509::{ExtendedKeyUsage, KeyUsage, pem};
use zeroize::Zeroizing;

use super::Failed;

const WIRED_SQUARE_ROOT: &str = "WIRED_SQUARE_APPS_ROOT";

const ID_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
const ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
const CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
const MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
const SIGNING_TIME: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.5");
const SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");

const DAY: Duration = Duration::from_secs(24 * 60 * 60);

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

pub(super) enum Root {
    File(PathBuf),
    Pem(String),
}

impl Root {
    pub(super) fn given_or_wired_square(given: Option<PathBuf>) -> Result<Self, String> {
        given
            .map(Self::File)
            .or_else(|| {
                std::env::var(WIRED_SQUARE_ROOT)
                    .ok()
                    .filter(|pem| !pem.trim().is_empty())
                    .map(Self::Pem)
            })
            .ok_or_else(|| {
                format!(
                    "no root to check the signer against: give --root, or the Wired Square Apps \
                     root's PEM in {WIRED_SQUARE_ROOT}"
                )
            })
    }

    fn certificate(&self) -> Result<(CertificateDer<'static>, String), String> {
        let (pem, named) = match self {
            Self::File(path) => (
                fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?,
                path.display().to_string(),
            ),
            Self::Pem(pem) => (pem.clone(), format!("the root in {WIRED_SQUARE_ROOT}")),
        };
        let mut certificates =
            pem::certificates(&pem).map_err(|e| format!("{named}: {}", crate::chain(&e)))?;
        Ok((certificates.swap_remove(0), named))
    }
}

/// A signer's certificate, then any intermediates, as one PEM file holds them.
pub(super) struct Chain {
    path: PathBuf,
    certificates: Vec<CertificateDer<'static>>,
}

impl Chain {
    pub(super) fn read(path: &Path) -> Result<Self, String> {
        fs::read_to_string(path)
            .map_err(|e| e.to_string())
            .and_then(|pem| pem::certificates(&pem).map_err(|e| crate::chain(&e)))
            .map(|certificates| Self {
                path: path.to_path_buf(),
                certificates,
            })
            .map_err(|e| format!("{}: {e}", path.display()))
    }

    /// Why its leaf is not a code-signing leaf of `root` now, if it is not.
    pub(super) fn refusal(&self, root: &Root) -> Result<Option<String>, String> {
        let (root, named) = root.certificate()?;
        let anchor =
            chain::trust_anchor(&root).map_err(|e| format!("{named}: {}", crate::chain(&e)))?;
        let [leaf, intermediates @ ..] = self.certificates.as_slice() else {
            unreachable!("pem::certificates gives at least one");
        };
        Ok(chain::verify(
            leaf,
            intermediates,
            &[anchor],
            Purpose::CODE_SIGNING,
            SystemTime::now(),
            provider().signature_verification_algorithms.all,
        )
        .err()
        .map(|e| {
            format!(
                "{} is not a code-signing leaf of {named}: {}",
                self.path.display(),
                crate::chain(&e)
            )
        }))
    }

    /// A detached RFC 5652 SignedData over `content`, carrying every certificate.
    pub(super) fn sign(&self, key: &Path, content: &[u8]) -> Result<Vec<u8>, Failed> {
        let certificates = self
            .certificates
            .iter()
            .map(|der| Certificate::from_der(der))
            .collect::<Result<Vec<_>, _>>()?;
        let leaf = &certificates[0].tbs_certificate;
        let signer = Key::read(key)?;
        if leaf.subject_public_key_info.to_der()? != signer.spki()? {
            return Err(format!("the key is not that of {}", self.path.display()).into());
        }

        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?;
        let attributes = SetOfVec::try_from(vec![
            attribute(CONTENT_TYPE, Any::encode_from(&ID_DATA)?)?,
            attribute(
                SIGNING_TIME,
                Any::encode_from(&Time::UtcTime(UtcTime::from_unix_duration(now)?))?,
            )?,
            attribute(
                MESSAGE_DIGEST,
                Any::encode_from(&OctetString::new(Sha256::digest(content).to_vec())?)?,
            )?,
        ])?;
        let signature = signer.sign(&attributes.to_der()?)?;
        let sha256 = AlgorithmIdentifierOwned {
            oid: SHA256,
            parameters: None,
        };
        let signer_info = SignerInfo {
            version: CmsVersion::V1,
            sid: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
                issuer: leaf.issuer.clone(),
                serial_number: leaf.serial_number.clone(),
            }),
            digest_alg: sha256.clone(),
            signed_attrs: Some(attributes),
            signature_algorithm: signer.algorithm(),
            signature: OctetString::new(signature)?,
            unsigned_attrs: None,
        };
        let signed = SignedData {
            version: CmsVersion::V1,
            digest_algorithms: SetOfVec::try_from(vec![sha256])?,
            encap_content_info: EncapsulatedContentInfo {
                econtent_type: ID_DATA,
                econtent: None,
            },
            certificates: Some(CertificateSet(SetOfVec::try_from(
                certificates
                    .into_iter()
                    .map(CertificateChoices::Certificate)
                    .collect::<Vec<_>>(),
            )?)),
            crls: None,
            signer_infos: SignerInfos(SetOfVec::try_from(vec![signer_info])?),
        };
        Ok(ContentInfo {
            content_type: ID_SIGNED_DATA,
            content: Any::encode_from(&signed)?,
        }
        .to_der()?)
    }
}

fn attribute(
    oid: ObjectIdentifier,
    value: Any,
) -> Result<cms::cert::x509::attr::Attribute, cms::cert::x509::der::Error> {
    Ok(cms::cert::x509::attr::Attribute {
        oid,
        values: SetOfVec::try_from(vec![value])?,
    })
}

/// A signing key whose signature is over SHA-256 whatever its size, as the
/// SignerInfo's digest algorithm says; a P-384 key signs a SHA-256 prehash.
enum Key {
    P256(p256::ecdsa::SigningKey),
    P384(p384::ecdsa::SigningKey),
    Rsa(rsa::RsaPrivateKey),
}

impl Key {
    /// The key at `path`, or on stdin for `-`: PKCS#8, SEC1 or PKCS#1 PEM.
    fn read(path: &Path) -> Result<Self, String> {
        let mut text = Zeroizing::new(String::new());
        match path == Path::new("-") {
            true => io::stdin().read_to_string(&mut text),
            false => fs::File::open(path).and_then(|mut file| file.read_to_string(&mut text)),
        }
        .map_err(|e| e.to_string())
        .and_then(|_| pem::private_key(&text).map_err(|e| crate::chain(&e)))
        .and_then(|key| to_pkcs8(&key).map_err(|e| crate::chain(&e)))
        .and_then(|key| Self::from_pkcs8(key.secret_pkcs8_der()))
        .map_err(|e| format!("{}: {e}", path.display()))
    }

    fn from_pkcs8(der: &[u8]) -> Result<Self, String> {
        if let Ok(key) = p256::ecdsa::SigningKey::from_pkcs8_der(der) {
            return Ok(Self::P256(key));
        }
        if let Ok(key) = p384::ecdsa::SigningKey::from_pkcs8_der(der) {
            return Ok(Self::P384(key));
        }
        match rsa::RsaPrivateKey::from_pkcs8_der(der) {
            Ok(key) if key.size() >= 256 => Ok(Self::Rsa(key)),
            Ok(_) => Err("an RSA key under 2048 bits".into()),
            Err(_) => Err("not a P-256, P-384 or RSA key".into()),
        }
    }

    fn spki(&self) -> Result<Vec<u8>, Failed> {
        let document = match self {
            Self::P256(key) => p256::PublicKey::from(key.verifying_key()).to_public_key_der()?,
            Self::P384(key) => p384::PublicKey::from(key.verifying_key()).to_public_key_der()?,
            Self::Rsa(key) => key.to_public_key().to_public_key_der()?,
        };
        Ok(document.into_vec())
    }

    fn algorithm(&self) -> AlgorithmIdentifierOwned {
        match self {
            Self::P256(_) | Self::P384(_) => AlgorithmIdentifierOwned {
                oid: ECDSA_WITH_SHA256,
                parameters: None,
            },
            Self::Rsa(_) => AlgorithmIdentifierOwned {
                oid: SHA256_WITH_RSA,
                parameters: Some(Any::null()),
            },
        }
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Failed> {
        let digest = Sha256::digest(message);
        Ok(match self {
            Self::P256(key) => {
                let signature: p256::ecdsa::Signature = key.sign_prehash(&digest)?;
                signature.to_der().as_bytes().to_vec()
            }
            Self::P384(key) => {
                let signature: p384::ecdsa::Signature = key.sign_prehash(&digest)?;
                signature.to_der().as_bytes().to_vec()
            }
            Self::Rsa(key) => key.sign(Pkcs1v15Sign::new::<Sha256>(), &digest)?,
        })
    }
}

/// Test keys only: a P-256 root and a code-signing leaf under it, each file `0600`.
pub(super) fn keys(dir: &Path) -> Result<(), Failed> {
    let paths = ["root.key", "root.pem", "leaf.key", "leaf.pem"].map(|name| dir.join(name));
    if paths.iter().any(|path| path.exists()) {
        return Err(format!("{} already holds keys", dir.display()).into());
    }
    let provider = provider();
    let validity = |days: u32| Validity {
        not_before: SystemTime::now(),
        not_after: SystemTime::now() + DAY * days,
    };
    let subject = |common_name: &str| Subject {
        organisation: Some("Wired Square".into()),
        ..Subject::new(common_name)
    };

    let load = |key: &PrivatePkcs8KeyDer<'_>| {
        Signer::new(provider.clone(), &PrivateKeyDer::Pkcs8(key.clone_key()))
    };

    let root_key = KeyAlgorithm::EcP256.generate()?;
    let root = Authority::self_signed(
        load(&root_key)?,
        &subject("Throwaway app source root").to_der()?,
        &Profile {
            basic_constraints: Some(Extension::critical(BasicConstraints::Authority {
                path_length: None,
            })),
            key_usage: Some(Extension::critical(vec![
                KeyUsage::KeyCertSign,
                KeyUsage::CrlSign,
            ])),
            ..Profile::default()
        },
        &Serial::random(&provider)?,
        validity(3650),
        KeyIdentifierMethod::Sha1,
    )?;
    let leaf_key = KeyAlgorithm::EcP256.generate()?;
    let request = build_csr(
        &load(&leaf_key)?,
        &subject("Throwaway app source signing"),
        &[],
    )?;
    let leaf = root.issue(
        &Csr::from_der(&request, provider.signature_verification_algorithms.all)?,
        &Profile {
            basic_constraints: Some(Extension::critical(BasicConstraints::EndEntity)),
            key_usage: Some(Extension::critical(vec![KeyUsage::DigitalSignature])),
            extended_key_usage: Some(Extension::critical(vec![ExtendedKeyUsage::CodeSigning])),
            ..Profile::default()
        },
        &Serial::random(&provider)?,
        validity(825),
    )?;

    fs::create_dir_all(dir)?;
    let [root_key_path, root_path, leaf_key_path, leaf_path] = &paths;
    for (path, body) in [
        (root_key_path, pem::encode_private_key(&root_key)),
        (
            root_path,
            pem::encode(pem::CERTIFICATE, root.certificate()).into(),
        ),
        (leaf_key_path, pem::encode_private_key(&leaf_key)),
        (leaf_path, pem::encode(pem::CERTIFICATE, &leaf).into()),
    ] {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?
            .write_all(body.as_bytes())?;
    }
    println!(
        "root: {} (add it in Apps › Sources); leaf: {}",
        root_path.display(),
        leaf_path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const UNDECODABLE: &str = "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n";

    #[test]
    fn a_chain_that_does_not_read_says_what_the_decoder_said() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chain.pem");
        fs::write(&path, UNDECODABLE).unwrap();
        let decoder = pem::certificates(UNDECODABLE).unwrap_err();
        let decoder = std::error::Error::source(&decoder).expect("the decoder's error");
        let refused = Chain::read(&path).err().expect("refused");
        assert!(refused.ends_with(&format!(": {decoder}")), "{refused}");
    }

    #[test]
    fn a_key_that_does_not_convert_says_what_the_decoder_said() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key.pem");
        fs::write(
            &path,
            "-----BEGIN EC PRIVATE KEY-----\nMAA=\n-----END EC PRIVATE KEY-----\n",
        )
        .unwrap();
        let refused = Key::read(&path).err().expect("refused");
        assert!(
            refused.contains("the private key is malformed: "),
            "{refused}"
        );
    }

    #[test]
    fn a_leaf_of_another_root_says_what_the_verifier_said() {
        let (ours, theirs) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        keys(ours.path()).unwrap();
        keys(theirs.path()).unwrap();
        let chain = Chain::read(&ours.path().join("leaf.pem")).unwrap();
        let root = Root::File(theirs.path().join("root.pem"));
        let refused = chain.refusal(&root).unwrap().expect("not their leaf");
        assert!(
            refused.contains("the certificate is not issued under a trusted anchor: "),
            "{refused}"
        );
    }
}
