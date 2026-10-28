use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyIdMethod,
    KeyUsagePurpose, SanType, SerialNumber,
};
use rustls_pki_types::CertificateDer;
use wslib_crypto::{Signer, random_serial};

use crate::{Error, SubjectAltName};

/// A self-signed serving certificate for `names`, the first of which is also its common name.
///
/// Valid from 1975 into the year 4096, so that a clock running fast or slow
/// never invalidates it and Safari's 825-day cap, which starts in 2019, never
/// applies; `CA:FALSE`, digital signatures and server authentication, each
/// stated.
pub fn mint(signer: &Signer, names: &[SubjectAltName]) -> Result<CertificateDer<'static>, Error> {
    let first = names.first().ok_or(Error::NoNames)?;
    let mut params = CertificateParams::default();
    params.subject_alt_names = names.iter().map(san).collect::<Result<_, _>>()?;
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, first.to_string());
    params.not_before = rcgen::date_time_ymd(1975, 1, 1);
    params.not_after = rcgen::date_time_ymd(4096, 1, 1);
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let serial = random_serial(signer.provider()).map_err(|e| Error::Mint(e.to_string()))?;
    params.serial_number = Some(SerialNumber::from_slice(&serial));
    params.key_identifier_method = KeyIdMethod::PreSpecified(signer.key_identifier().to_vec());
    let certificate = params
        .self_signed(signer)
        .map_err(|e| Error::Mint(e.to_string()))?;
    Ok(certificate.der().clone())
}

fn san(name: &SubjectAltName) -> Result<SanType, Error> {
    let ia5 = |value: &str| {
        value.try_into().map_err(|_| Error::Name {
            name: value.to_string(),
            reason: "not ASCII",
        })
    };
    Ok(match name {
        SubjectAltName::Dns(dns) => SanType::DnsName(ia5(dns)?),
        SubjectAltName::Ip(ip) => SanType::IpAddress(*ip),
        SubjectAltName::Email(email) => SanType::Rfc822Name(ia5(email)?),
        SubjectAltName::Uri(uri) => SanType::URI(ia5(uri)?),
    })
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use super::*;
    use crate::testing::signer;
    use crate::{ExtendedKeyUsage, KeyUsage, examine, inspect};
    use wslib_crypto::KeyAlgorithm;

    #[test]
    fn a_minted_certificate_has_the_serving_profile_and_no_warnings() {
        let names: Vec<SubjectAltName> = ["widget-01", "widget-01.local", "127.0.0.1", "::1"]
            .iter()
            .map(|name| name.parse().unwrap())
            .collect();
        let signer = signer(KeyAlgorithm::EcP256);
        let view = inspect(&mint(&signer, &names).expect("mints")).expect("reads");

        assert_eq!(view.sans, names);
        assert_eq!(view.subject, "CN=widget-01");
        assert!(view.self_signed);
        assert!(!view.ca);
        assert_eq!(view.key_usages, Some(vec![KeyUsage::DigitalSignature]));
        assert_eq!(
            view.extended_key_usages,
            Some(vec![ExtendedKeyUsage::ServerAuth])
        );
        assert_eq!(
            view.not_before,
            SystemTime::UNIX_EPOCH + Duration::from_secs(157_766_400)
        );
        assert_eq!(view.spki, signer.spki());

        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        for host in ["widget-01.local", "[::1]", "127.0.0.1"] {
            assert_eq!(
                examine(view.clone(), Some(host), now).warnings,
                [],
                "{host}"
            );
        }
    }

    #[test]
    fn a_minted_certificate_predates_the_825_day_cap() {
        let names = ["localhost".parse().unwrap()];
        let view = inspect(&mint(&signer(KeyAlgorithm::EcP256), &names).unwrap()).unwrap();
        let cap_starts = SystemTime::UNIX_EPOCH + Duration::from_secs(1_561_939_200);
        assert!(view.not_before < cap_starts, "{:?}", view.not_before);
    }

    #[test]
    fn two_mints_get_different_serials() {
        let signer = signer(KeyAlgorithm::EcP256);
        let names = ["localhost".parse().unwrap()];
        let serial = || inspect(&mint(&signer, &names).unwrap()).unwrap().serial;
        assert_ne!(serial(), serial());
    }

    #[test]
    fn a_certificate_without_names_is_refused() {
        assert_eq!(
            mint(&signer(KeyAlgorithm::EcP256), &[]),
            Err(Error::NoNames)
        );
    }
}
