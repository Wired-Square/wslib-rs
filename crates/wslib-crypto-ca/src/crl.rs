use std::time::{Duration, SystemTime};

use rcgen::{
    CertificateParams, CertificateRevocationListParams, Issuer, KeyIdMethod, RevocationReason,
    RevokedCertParams, SerialNumber,
};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{
    CertificateDer, CertificateRevocationListDer, SignatureVerificationAlgorithm,
};
use wslib_crypto_x509::signature;
use x509_parser::prelude::{
    ASN1Time, CertificateRevocationList, FromDer, ParsedExtension, X509Certificate,
};
use x509_parser::x509::ReasonCode;

use crate::der::{self, Draft};
use crate::{Authority, Error, Serial};

/// The PEM label of a certificate revocation list.
pub const X509_CRL: &str = "X509 CRL";

/// RFC 5280 5.3.1's reasons; an unspecified reason is no reason at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    KeyCompromise,
    CaCompromise,
    AffiliationChanged,
    Superseded,
    CessationOfOperation,
    CertificateHold,
    RemoveFromCrl,
    PrivilegeWithdrawn,
    AaCompromise,
}

const REASONS: [(Reason, RevocationReason); 9] = [
    (Reason::KeyCompromise, RevocationReason::KeyCompromise),
    (Reason::CaCompromise, RevocationReason::CaCompromise),
    (
        Reason::AffiliationChanged,
        RevocationReason::AffiliationChanged,
    ),
    (Reason::Superseded, RevocationReason::Superseded),
    (
        Reason::CessationOfOperation,
        RevocationReason::CessationOfOperation,
    ),
    (Reason::CertificateHold, RevocationReason::CertificateHold),
    (Reason::RemoveFromCrl, RevocationReason::RemoveFromCrl),
    (
        Reason::PrivilegeWithdrawn,
        RevocationReason::PrivilegeWithdrawn,
    ),
    (Reason::AaCompromise, RevocationReason::AaCompromise),
];

impl Reason {
    fn rcgen(self) -> RevocationReason {
        REASONS
            .iter()
            .find(|(reason, _)| *reason == self)
            .unwrap()
            .1
    }

    fn of_code(code: ReasonCode) -> Option<Self> {
        REASONS
            .iter()
            .find(|(_, rcgen)| *rcgen as u8 == code.0)
            .map(|(reason, _)| *reason)
    }
}

/// One revoked certificate in a list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Revocation {
    pub serial: Serial,
    pub revoked_at: SystemTime,
    pub reason: Option<Reason>,
    /// When the key is known or suspected to have been compromised.
    pub invalid_since: Option<SystemTime>,
}

impl Revocation {
    pub fn new(serial: Serial, revoked_at: SystemTime) -> Self {
        Self {
            serial,
            revoked_at,
            reason: None,
            invalid_since: None,
        }
    }
}

/// TBSCertList positions: version, signature, issuer, thisUpdate, nextUpdate, revoked, extensions.
const ISSUER: usize = 2;
const NEXT_UPDATE: usize = 4;

impl Authority {
    /// A v2 CRL with its number and authority key identifier, the entries in serial order.
    pub fn revocation_list(
        &self,
        number: u64,
        this_update: SystemTime,
        next_update: SystemTime,
        revoked: &[Revocation],
    ) -> Result<CertificateRevocationListDer<'static>, Error> {
        if next_update < this_update {
            return Err(Error::CrlValidity);
        }
        let mut revoked = revoked.to_vec();
        revoked.sort_by(|a, b| a.serial.cmp(&b.serial));
        let params = CertificateRevocationListParams {
            this_update: this_update.into(),
            // rcgen refuses a nextUpdate equal to thisUpdate, which RFC 5280 allows; the real one is copied in.
            next_update: (this_update + Duration::from_secs(1)).into(),
            crl_number: SerialNumber::from(number),
            issuing_distribution_point: None,
            revoked_certs: revoked
                .iter()
                .map(|entry| RevokedCertParams {
                    serial_number: SerialNumber::from_slice(entry.serial.as_bytes()),
                    revocation_time: entry.revoked_at.into(),
                    reason_code: entry.reason.map(Reason::rcgen),
                    invalidity_date: entry.invalid_since.map(Into::into),
                })
                .collect(),
            key_identifier_method: KeyIdMethod::PreSpecified(self.key_identifier.clone()),
        };
        let issuer = Issuer::new(CertificateParams::default(), Draft(&self.signer));
        let draft = params.signed_by(&issuer).map_err(der::encode)?;
        der::signed(
            &self.signer,
            draft.der(),
            &[(ISSUER, &self.subject), (NEXT_UPDATE, &time(next_update))],
        )
        .map(Into::into)
    }
}

/// What a CRL says, read without trusting it; [`CrlView::verify`] checks it against its issuer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrlView {
    /// The issuer's name, as DER.
    pub issuer: Vec<u8>,
    /// The issuer's name in RFC 4514 form, as `wslib_crypto_x509::rfc_4514` writes it.
    pub issuer_text: String,
    pub number: Option<u64>,
    pub this_update: SystemTime,
    pub next_update: Option<SystemTime>,
    pub authority_key_identifier: Option<Vec<u8>>,
    pub revoked: Vec<Revocation>,
    signed: Vec<u8>,
    signature_algorithm: Vec<u8>,
    signature_algorithm_name: String,
    signature: Vec<u8>,
}

impl CrlView {
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let crl = der::whole(CertificateRevocationList::from_der(der))?;
        let [signed, signature_algorithm, _] = der::elements(der)?[..] else {
            return Err(Error::Malformed("not a CRL".into()));
        };
        let number = crl
            .crl_number()
            .map(|number| match number.to_bytes_be() {
                bytes if bytes.len() <= 8 => {
                    Ok(bytes.iter().fold(0, |n, &b| n << 8 | u64::from(b)))
                }
                _ => Err(Error::Malformed("a CRL number over 64 bits".into())),
            })
            .transpose()?;
        let authority_key_identifier =
            crl.extensions()
                .iter()
                .find_map(|extension| match extension.parsed_extension() {
                    ParsedExtension::AuthorityKeyIdentifier(aki) => {
                        aki.key_identifier.as_ref().map(|id| id.0.to_vec())
                    }
                    _ => None,
                });
        let revoked = crl
            .iter_revoked_certificates()
            .map(|entry| Revocation {
                serial: Serial::unchecked(entry.raw_serial()),
                revoked_at: instant(entry.revocation_date),
                reason: entry
                    .reason_code()
                    .and_then(|(_, code)| Reason::of_code(code)),
                invalid_since: entry.invalidity_date().map(|(_, at)| instant(at)),
            })
            .collect();
        Ok(Self {
            issuer: crl.issuer().as_raw().to_vec(),
            issuer_text: wslib_crypto_x509::rfc_4514(crl.issuer().as_raw())
                .map_err(der::malformed)?,
            number,
            this_update: instant(crl.last_update()),
            next_update: crl.next_update().map(instant),
            authority_key_identifier,
            revoked,
            signed: signed.to_vec(),
            signature_algorithm: signature_algorithm.to_vec(),
            signature_algorithm_name: signature::algorithm_name(
                &crl.signature_algorithm.algorithm.to_id_string(),
            ),
            signature: crl.signature_value.data.to_vec(),
        })
    }

    /// The one `X509 CRL` section of `pem`.
    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        let der = CertificateRevocationListDer::from_pem_slice(pem.as_bytes())
            .map_err(|e| Error::Malformed(e.to_string()))?;
        Self::from_der(&der)
    }

    /// As [`signature::algorithm_name`] spells it.
    pub fn signature_algorithm(&self) -> &str {
        &self.signature_algorithm_name
    }

    /// Checks that `issuer` issued this CRL: its subject is the CRL's issuer byte for byte, and its key signed it.
    pub fn verify(
        &self,
        issuer: &CertificateDer<'_>,
        algorithms: &[&dyn SignatureVerificationAlgorithm],
    ) -> Result<(), Error> {
        let (_, certificate) =
            X509Certificate::from_der(issuer).map_err(|e| Error::Malformed(e.to_string()))?;
        if certificate.subject().as_raw() != self.issuer {
            return Err(Error::IssuerMismatch);
        }
        signature::verify(
            certificate.public_key().raw,
            &self.signature_algorithm,
            &self.signed,
            &self.signature,
            algorithms,
        )?;
        Ok(())
    }
}

/// UTCTime from 1950 to 2049 and GeneralizedTime otherwise, to the second, as RFC 5280 5.1.2.4 has it.
fn time(at: SystemTime) -> Vec<u8> {
    let at = time::OffsetDateTime::from(at);
    let (tag, year) = match at.year() {
        year @ 1950..2050 => (0x17, format!("{:02}", year % 100)),
        year => (0x18, format!("{year:04}")),
    };
    let text = format!(
        "{year}{:02}{:02}{:02}{:02}{:02}Z",
        u8::from(at.month()),
        at.day(),
        at.hour(),
        at.minute(),
        at.second()
    );
    der::tlv(tag, text.as_bytes())
}

fn instant(time: ASN1Time) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(time.timestamp().max(0) as u64)
}
