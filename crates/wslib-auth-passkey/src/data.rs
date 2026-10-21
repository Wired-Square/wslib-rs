//! What the browser and the authenticator hand back: the client data (§5.8.1)
//! and the authenticator data (§6.1), parsed and nothing more.

use serde::Deserialize;

use super::cbor::{self, Malformed, Value};
use super::cose::PublicKey;

const RP_ID_HASH: usize = 32;
const HEADER: usize = RP_ID_HASH + 1 + 4;
const AAGUID: usize = 16;
pub(crate) const MAX_CREDENTIAL_ID: usize = 1023;

const UP: u8 = 0x01;
const UV: u8 = 0x04;
const BE: u8 = 0x08;
const BS: u8 = 0x10;
const AT: u8 = 0x40;
const ED: u8 = 0x80;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ClientData {
    #[serde(rename = "type")]
    pub(crate) kind: String,
    pub(crate) challenge: String,
    pub(crate) origin: String,
    pub(crate) cross_origin: Option<bool>,
    pub(crate) top_origin: Option<String>,
}

impl ClientData {
    /// Step 5's UTF-8 decode, a leading byte order mark stripped, then JSON;
    /// a repeated field is refused.
    pub(crate) fn parse(json: &[u8]) -> Result<Self, Malformed> {
        let json = json.strip_prefix(b"\xef\xbb\xbf").unwrap_or(json);
        serde_json::from_slice(json).map_err(|_| Malformed("client data that is not its JSON"))
    }
}

#[derive(Debug)]
pub(crate) struct AuthenticatorData<'a> {
    pub(crate) rp_id_hash: &'a [u8],
    flags: u8,
    pub(crate) sign_count: u32,
    pub(crate) credential: Option<AttestedCredential<'a>>,
}

#[derive(Debug)]
pub(crate) struct AttestedCredential<'a> {
    pub(crate) id: &'a [u8],
    /// The COSE_Key as the authenticator wrote it, already checked to be a
    /// key of an algorithm offered.
    pub(crate) cose: &'a [u8],
}

impl<'a> AuthenticatorData<'a> {
    /// The whole of `data`: attested credential data exactly when AT is set,
    /// an extensions map exactly when ED is, and nothing after either.
    pub(crate) fn parse(data: &'a [u8]) -> Result<Self, Malformed> {
        if data.len() < HEADER {
            return Err(Malformed("authenticator data too short"));
        }
        let (header, mut rest) = data.split_at(HEADER);
        let flags = header[RP_ID_HASH];
        let sign_count = u32::from_be_bytes(header[RP_ID_HASH + 1..].try_into().expect("4 bytes"));

        let credential = match flags & AT {
            0 => None,
            _ => {
                let (credential, after) = attested(rest)?;
                rest = after;
                Some(credential)
            }
        };
        match (flags & ED, rest) {
            (0, []) => {}
            (0, _) => return Err(Malformed("bytes after the authenticator data")),
            (_, extensions) => {
                if !matches!(cbor::decode(extensions)?, Value::Map(_)) {
                    return Err(Malformed("extensions that are not a map"));
                }
            }
        }
        Ok(Self {
            rp_id_hash: &header[..RP_ID_HASH],
            flags,
            sign_count,
            credential,
        })
    }

    pub(crate) fn user_present(&self) -> bool {
        self.flags & UP != 0
    }

    pub(crate) fn user_verified(&self) -> bool {
        self.flags & UV != 0
    }

    /// BS set only where BE is (§7.1 step 17, §7.2 step 18).
    pub(crate) fn backup_flags_agree(&self) -> bool {
        self.flags & BE != 0 || self.flags & BS == 0
    }
}

fn attested(data: &[u8]) -> Result<(AttestedCredential<'_>, &[u8]), Malformed> {
    if data.len() < AAGUID + 2 {
        return Err(Malformed("attested credential data too short"));
    }
    let length = usize::from(u16::from_be_bytes([data[AAGUID], data[AAGUID + 1]]));
    if length > MAX_CREDENTIAL_ID {
        return Err(Malformed("a credential ID over 1023 bytes"));
    }
    let rest = &data[AAGUID + 2..];
    if rest.len() < length {
        return Err(Malformed("attested credential data too short"));
    }
    let (id, rest) = rest.split_at(length);
    let (cose, after) = cbor::decode_prefix(rest)?;
    PublicKey::from_cose(&cose)?;
    let cose = &rest[..rest.len() - after.len()];
    Ok((AttestedCredential { id, cose }, after))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::super::cbor::encode;
    use super::super::cose::tests::ED25519_BASE;
    use super::*;

    pub(crate) fn header(rp_id: &str, flags: u8, sign_count: u32) -> Vec<u8> {
        [
            &crate::sha256(rp_id.as_bytes())[..],
            &[flags],
            &sign_count.to_be_bytes(),
        ]
        .concat()
    }

    pub(crate) fn okp_key(x: &[u8]) -> Vec<u8> {
        encode::map(&[
            (encode::int(1), encode::int(1)),
            (encode::int(3), encode::int(-8)),
            (encode::int(-1), encode::int(6)),
            (encode::int(-2), encode::bytes(x)),
        ])
    }

    pub(crate) fn attested_data(id: &[u8], cose: &[u8]) -> Vec<u8> {
        [
            &[0u8; AAGUID][..],
            &(id.len() as u16).to_be_bytes(),
            id,
            cose,
        ]
        .concat()
    }

    fn refused(data: &[u8]) -> &'static str {
        AuthenticatorData::parse(data).expect_err("refused").0
    }

    #[test]
    fn the_flags_read_as_the_bits_they_are() {
        let data = header("example.org", UP | UV | BE | BS, 7);
        let parsed = AuthenticatorData::parse(&data).expect("parses");
        assert!(parsed.user_present() && parsed.user_verified() && parsed.backup_flags_agree());
        assert_eq!(parsed.sign_count, 7);
        assert!(parsed.credential.is_none());

        let data = header("example.org", BS, 0);
        let parsed = AuthenticatorData::parse(&data).expect("parses");
        assert!(!parsed.user_present() && !parsed.user_verified());
        assert!(!parsed.backup_flags_agree(), "BS without BE");
    }

    #[test]
    fn attested_data_carries_the_id_and_the_key_bytes_as_written() {
        let cose = okp_key(&ED25519_BASE);
        let data = [
            header("example.org", UP | AT, 0),
            attested_data(&[1, 2, 3], &cose),
        ]
        .concat();
        let parsed = AuthenticatorData::parse(&data).expect("parses");
        let credential = parsed.credential.expect("attested");
        assert_eq!(credential.id, [1, 2, 3]);
        assert_eq!(credential.cose, cose);

        let es384 = encode::map(&[
            (encode::int(1), encode::int(2)),
            (encode::int(3), encode::int(-35)),
            (encode::int(-1), encode::int(2)),
        ]);
        let data = [
            header("example.org", UP | AT, 0),
            attested_data(&[1, 2, 3], &es384),
        ]
        .concat();
        assert_eq!(
            refused(&data),
            "a key that is neither ES256 on P-256 nor EdDSA on Ed25519",
            "§7.1 step 20"
        );
    }

    #[test]
    fn extensions_are_read_only_where_ed_says_and_nothing_trails() {
        let cose = okp_key(&ED25519_BASE);
        let attested = attested_data(&[1], &cose);
        let with = |flags, tail: &[u8]| {
            [
                header("example.org", flags, 0),
                attested.clone(),
                tail.to_vec(),
            ]
            .concat()
        };
        AuthenticatorData::parse(&with(UP | AT | ED, &[0xa1, 0x61, b'x', 0xf5]))
            .expect("an extensions map");
        assert_eq!(
            refused(&with(UP | AT, &[0xa0])),
            "bytes after the authenticator data"
        );
        assert_eq!(
            refused(&with(UP | AT | ED, &[0x01])),
            "extensions that are not a map"
        );
        assert_eq!(
            refused(&with(UP | AT | ED, &[0xa0, 0x00])),
            "bytes after the item"
        );
        assert_eq!(
            refused(&[header("example.org", UP, 0), vec![0]].concat()),
            "bytes after the authenticator data"
        );
    }

    #[test]
    fn short_data_and_a_long_credential_id_are_refused() {
        assert_eq!(refused(&[0; HEADER - 1]), "authenticator data too short");
        let short = [header("example.org", AT, 0), vec![0; AAGUID + 1]].concat();
        assert_eq!(refused(&short), "attested credential data too short");
        let mut cut = [header("example.org", AT, 0), attested_data(&[1; 10], &[])].concat();
        cut.truncate(cut.len() - 1);
        assert_eq!(refused(&cut), "attested credential data too short");

        let cose = okp_key(&ED25519_BASE);
        let at_limit = [
            header("example.org", AT, 0),
            attested_data(&[1; MAX_CREDENTIAL_ID], &cose),
        ]
        .concat();
        AuthenticatorData::parse(&at_limit).expect("1023 bytes");
        let over = [
            header("example.org", AT, 0),
            attested_data(&[1; MAX_CREDENTIAL_ID + 1], &cose),
        ]
        .concat();
        assert_eq!(refused(&over), "a credential ID over 1023 bytes");
    }

    #[test]
    fn client_data_refuses_a_repeated_field_and_takes_a_bom() {
        let json = br#"{"type":"webauthn.get","challenge":"AA","origin":"https://x","crossOrigin":false,"other":1}"#;
        let parsed = ClientData::parse(json).expect("parses");
        assert_eq!(parsed.kind, "webauthn.get");
        assert_eq!(parsed.cross_origin, Some(false));
        ClientData::parse(&[b"\xef\xbb\xbf".as_slice(), json].concat()).expect("a BOM");

        let twice = br#"{"type":"webauthn.get","type":"webauthn.create","challenge":"AA","origin":"https://x"}"#;
        assert!(ClientData::parse(twice).is_err());
        let a_string = br#"{"type":"webauthn.get","challenge":"AA","origin":"https://x","crossOrigin":"false"}"#;
        assert!(ClientData::parse(a_string).is_err());
    }
}
