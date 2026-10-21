//! A passkey a test can hold, answering a ceremony's options as a browser's
//! would.

use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::Signer as _;

use crate::cbor::encode;
use crate::ceremonies::{b64, random_bytes, sha256};
use crate::{
    AssertionCredential, AssertionResponse, AttestationResponse, CreationOptions,
    RegistrationCredential, RequestOptions,
};

/// An ES256 passkey that verifies its user, keeping a count unless it is
/// [`Self::counterless`].
pub struct SoftPasskey {
    key: SigningKey,
    credential_id: Vec<u8>,
    user_handle: Option<String>,
    count: u32,
    counts: bool,
}

impl Default for SoftPasskey {
    fn default() -> Self {
        Self::new()
    }
}

impl SoftPasskey {
    pub fn new() -> Self {
        let key = std::iter::repeat_with(|| {
            random_bytes::<32>()
                .ok()
                .and_then(|bytes| SigningKey::from_slice(&bytes).ok())
        })
        .find_map(|key| key)
        .expect("a key");
        let credential_id =
            sha256(key.verifying_key().to_encoded_point(false).as_bytes())[..16].to_vec();
        Self {
            key,
            credential_id,
            user_handle: None,
            count: 0,
            counts: true,
        }
    }

    /// One that signs every answer with a count of zero, as many synced
    /// passkeys do.
    pub fn counterless() -> Self {
        Self {
            counts: false,
            ..Self::new()
        }
    }

    pub fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }

    /// Make this passkey for `options`, as a page at `origin` asked.
    pub fn register(&mut self, options: &CreationOptions, origin: &str) -> RegistrationCredential {
        self.user_handle = Some(options.user.id.clone());
        let point = self.key.verifying_key().to_encoded_point(false);
        let point = point.as_bytes();
        let cose = encode::map(&[
            (encode::int(1), encode::int(2)),
            (encode::int(3), encode::int(-7)),
            (encode::int(-1), encode::int(1)),
            (encode::int(-2), encode::bytes(&point[1..33])),
            (encode::int(-3), encode::bytes(&point[33..])),
        ]);
        let length = u16::try_from(self.credential_id.len()).expect("short");
        let auth_data = [
            self.header(&options.rp.id, 0x45),
            vec![0; 16],
            length.to_be_bytes().to_vec(),
            self.credential_id.clone(),
            cose,
        ]
        .concat();
        let object = encode::map(&[
            (encode::text("fmt"), encode::text("none")),
            (encode::text("attStmt"), encode::map(&[])),
            (encode::text("authData"), encode::bytes(&auth_data)),
        ]);
        let id = b64(&self.credential_id);
        RegistrationCredential {
            id: id.clone(),
            raw_id: id,
            kind: "public-key".into(),
            response: AttestationResponse {
                client_data_json: b64(&client_data("webauthn.create", &options.challenge, origin)),
                attestation_object: b64(&object),
            },
        }
    }

    /// Answer `options` as a page at `origin` asked, a step further on the
    /// count if it keeps one.
    pub fn answer(&mut self, options: &RequestOptions, origin: &str) -> AssertionCredential {
        if self.counts {
            self.count += 1;
        }
        let auth_data = self.header(&options.rp_id, 0x05);
        let client = client_data("webauthn.get", &options.challenge, origin);
        let signed = [auth_data.as_slice(), &sha256(&client)].concat();
        let signature: p256::ecdsa::Signature = self.key.sign(&signed);
        let id = b64(&self.credential_id);
        AssertionCredential {
            id: id.clone(),
            raw_id: id,
            kind: "public-key".into(),
            response: AssertionResponse {
                client_data_json: b64(&client),
                authenticator_data: b64(&auth_data),
                signature: b64(signature.to_der().as_bytes()),
                user_handle: self.user_handle.clone(),
            },
        }
    }

    fn header(&self, rp_id: &str, flags: u8) -> Vec<u8> {
        [
            &sha256(rp_id.as_bytes())[..],
            &[flags],
            &self.count.to_be_bytes(),
        ]
        .concat()
    }
}

fn client_data(kind: &str, challenge: &str, origin: &str) -> Vec<u8> {
    format!(
        r#"{{"type":"{kind}","challenge":"{challenge}","origin":"{origin}","crossOrigin":false}}"#
    )
    .into_bytes()
}
