//! Passkeys: the WebAuthn registration (§7.1) and authentication (§7.2)
//! ceremonies. `none` attestation only; ES256 and EdDSA keys; the user
//! verified (a PIN or a biometric) every time. The caller keeps the passkeys.
//!
//! ```no_run
//! # fn run(
//! #     ceremonies: &wslib_auth_passkey::Ceremonies,
//! #     host: &str,
//! #     options_answered: wslib_auth_passkey::AssertionCredential,
//! # ) -> Result<(), Box<dyn std::error::Error>> {
//! use wslib_auth_passkey::{RelyingParty, StoredPasskey};
//!
//! let rp = RelyingParty::for_host(host)?;
//! let options = ceremonies.begin_sign_in(&rp)?; // to navigator.credentials.get()
//! let assertion = ceremonies.read_sign_in(&rp, &options_answered)?;
//! // Look up the passkey by `assertion.credential_id()`, then:
//! # let (user_id, rp_id, public_key, stored_count) = ("", "", &[][..], 0);
//! let sign_count = assertion.verify(&StoredPasskey { user_id, rp_id, public_key })?;
//! if !wslib_auth_passkey::sign_count_moved(stored_count, sign_count) {
//!     // refuse: a counter that did not move may be a cloned authenticator
//! }
//! # Ok(())
//! # }
//! ```
//!
//! **The RP ID is the host the browser reached the server by**, so a passkey
//! signs in on the name it was made on and no other. WebAuthn will not run on
//! an IP address, which [`RelyingParty::for_host`] refuses, nor behind a
//! certificate the browser does not trust, which the server cannot see: the
//! browser refuses that itself, with a `SecurityError`.
//!
//! A refusal names the check that failed, for the log; show users a fixed
//! message.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

use challenges::{Challenges, Purpose};
use cose::PublicKey;
use data::{AuthenticatorData, ClientData};

pub use json::{
    AssertionCredential, AssertionResponse, AttestationResponse, AuthenticatorSelection,
    CreationOptions, CredentialDescriptor, CredentialParameters, RegistrationCredential,
    RelyingPartyEntity, RequestOptions, UserEntity,
};

mod cbor;
mod challenges;
mod cose;
mod data;
mod json;
#[cfg(any(test, feature = "testing"))]
pub mod testing;
#[cfg(test)]
mod tests;

const PUBLIC_KEY: &str = "public-key";
const REQUIRED: &str = "required";

/// The host a ceremony runs on, and the origin the browser reports for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelyingParty {
    id: String,
    origin: String,
}

impl RelyingParty {
    /// From the `Host` the browser sent, `name[:port]`, over https.
    pub fn for_host(host: &str) -> Result<Self, HostError> {
        let (name, port) = match host.rsplit_once(':') {
            _ if host.starts_with('[') || host.parse::<std::net::Ipv6Addr>().is_ok() => {
                return Err(HostError::IpAddress);
            }
            Some((name, port)) => (
                name,
                Some(port.parse::<u16>().map_err(|_| HostError::NotAName)?),
            ),
            None => (host, None),
        };
        let name = name.to_ascii_lowercase();
        let labels: Vec<&str> = name.split('.').collect();
        let valid = name.len() <= 253
            && labels.iter().all(|label| {
                (1..=63).contains(&label.len())
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                    && !label.starts_with('-')
                    && !label.ends_with('-')
            });
        if !valid {
            return Err(HostError::NotAName);
        }
        // As a browser reads a host: a decimal or hex last label is IPv4.
        let last = labels.last().expect("split yields one");
        let hex = last
            .strip_prefix("0x")
            .is_some_and(|digits| digits.bytes().all(|b| b.is_ascii_hexdigit()));
        if hex || last.bytes().all(|b| b.is_ascii_digit()) {
            return Err(HostError::IpAddress);
        }
        let origin = match port {
            None | Some(443) => format!("https://{name}"),
            Some(port) => format!("https://{name}:{port}"),
        };
        Ok(Self { id: name, origin })
    }

    /// The RP ID: the name a passkey made here binds to.
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn origin(&self) -> &str {
        &self.origin
    }
}

/// Why a host can't be a relying party.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostError {
    /// Passkeys don't work at an IP address: the browser refuses them.
    IpAddress,
    NotAName,
}

impl fmt::Display for HostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::IpAddress => "passkeys don't work at an IP address",
            Self::NotAName => "the host is not a name a passkey can be made on",
        })
    }
}

impl std::error::Error for HostError {}

/// A new passkey, verified, for the caller to keep: the RP ID it was made on is
/// [`RelyingParty::id`]. A credential ID already registered, to anybody, must
/// be refused (§7.1 step 26).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewPasskey {
    pub credential_id: Vec<u8>,
    /// The COSE_Key as the authenticator wrote it, for [`StoredPasskey`].
    pub public_key: Vec<u8>,
    pub sign_count: u32,
}

/// A passkey the caller kept from [`NewPasskey`], found by an assertion's
/// [`Assertion::credential_id`].
#[derive(Debug, Clone, Copy)]
pub struct StoredPasskey<'a> {
    /// The account it was registered for.
    pub user_id: &'a str,
    pub rp_id: &'a str,
    pub public_key: &'a [u8],
}

/// The ceremonies under way. Share one per process across every route that
/// runs one; `Clone` shares it.
#[derive(Debug, Clone, Default)]
pub struct Ceremonies {
    challenges: Challenges,
}

impl Ceremonies {
    /// Options to make a passkey for the account `user_id`, called `username`,
    /// on `rp`, which `rp_name` names to the person making it. `exclude` is the
    /// credential IDs the account already has.
    pub fn begin_registration<I>(
        &self,
        rp: &RelyingParty,
        rp_name: &str,
        user_id: &str,
        username: &str,
        exclude: I,
    ) -> Result<CreationOptions, getrandom::Error>
    where
        I: IntoIterator<Item: AsRef<[u8]>>,
    {
        let purpose = Purpose::Register {
            user_id: user_id.to_owned(),
        };
        let timeout = timeout_ms(&purpose);
        let challenge = self.challenges.issue(purpose, &rp.id)?;
        Ok(CreationOptions {
            challenge: b64(&challenge),
            rp: RelyingPartyEntity {
                id: rp.id.clone(),
                name: rp_name.to_owned(),
            },
            user: UserEntity {
                id: b64(user_id.as_bytes()),
                name: username.to_owned(),
                display_name: username.to_owned(),
            },
            pub_key_cred_params: [cose::ES256, cose::EDDSA]
                .map(|alg| CredentialParameters {
                    kind: PUBLIC_KEY.into(),
                    alg,
                })
                .into(),
            timeout,
            exclude_credentials: descriptors(exclude),
            authenticator_selection: AuthenticatorSelection {
                resident_key: REQUIRED.into(),
                require_resident_key: true,
                user_verification: REQUIRED.into(),
            },
            attestation: "none".into(),
        })
    }

    /// Verify a new passkey for `user_id`, answering [`Self::begin_registration`].
    pub fn finish_registration(
        &self,
        rp: &RelyingParty,
        user_id: &str,
        credential: &RegistrationCredential,
    ) -> Result<NewPasskey, Refused> {
        let raw_id = credential_id(&credential.kind, &credential.id, &credential.raw_id)?;
        let client_data = field(&credential.response.client_data_json)?;
        let attestation = field(&credential.response.attestation_object)?;

        let purpose = Purpose::Register {
            user_id: user_id.to_owned(),
        };
        self.client_data(&client_data, "webauthn.create", &purpose, rp)?;

        let attestation = cbor::decode(&attestation)?;
        let (fmt, statement, auth_data) = attestation_parts(&attestation)?;
        let auth_data = AuthenticatorData::parse(auth_data)?;
        check_flags(&auth_data, rp)?;
        let attested = auth_data
            .credential
            .ok_or(Refused::Response("no attested credential data"))?;
        if fmt != "none" || statement != &cbor::Value::Map(vec![]) {
            return Err(Refused::Response("an attestation other than none"));
        }
        if attested.id != raw_id {
            return Err(Refused::Response(
                "the credential ID is not the one attested",
            ));
        }
        Ok(NewPasskey {
            credential_id: raw_id,
            public_key: attested.cose.to_vec(),
            sign_count: auth_data.sign_count,
        })
    }

    /// Options for a sign-in on `rp` with whichever passkey the person picks,
    /// which names its account.
    pub fn begin_sign_in(&self, rp: &RelyingParty) -> Result<RequestOptions, getrandom::Error> {
        self.request_options(Purpose::SignIn, rp, Vec::new())
    }

    /// The answer to [`Self::begin_sign_in`], its challenge spent, for the
    /// caller to find the passkey it names and [`Assertion::verify`] it.
    pub fn read_sign_in(
        &self,
        rp: &RelyingParty,
        credential: &AssertionCredential,
    ) -> Result<Assertion, Refused> {
        self.read_assertion(rp, Purpose::SignIn, credential)
    }

    /// Options for the account `user_id` to prove itself again with one of
    /// `allow`, its credential IDs made on `rp`.
    pub fn begin_reauthentication<I>(
        &self,
        rp: &RelyingParty,
        user_id: &str,
        allow: I,
    ) -> Result<RequestOptions, getrandom::Error>
    where
        I: IntoIterator<Item: AsRef<[u8]>>,
    {
        let purpose = Purpose::Reauthenticate {
            user_id: user_id.to_owned(),
        };
        self.request_options(purpose, rp, descriptors(allow))
    }

    /// The answer to [`Self::begin_reauthentication`]; its
    /// [`Assertion::verify`] takes only a passkey of `user_id`'s.
    pub fn read_reauthentication(
        &self,
        rp: &RelyingParty,
        user_id: &str,
        credential: &AssertionCredential,
    ) -> Result<Assertion, Refused> {
        let purpose = Purpose::Reauthenticate {
            user_id: user_id.to_owned(),
        };
        self.read_assertion(rp, purpose, credential)
    }

    fn request_options(
        &self,
        purpose: Purpose,
        rp: &RelyingParty,
        allow: Vec<CredentialDescriptor>,
    ) -> Result<RequestOptions, getrandom::Error> {
        let timeout = timeout_ms(&purpose);
        let challenge = self.challenges.issue(purpose, &rp.id)?;
        Ok(RequestOptions {
            challenge: b64(&challenge),
            rp_id: rp.id.clone(),
            timeout,
            allow_credentials: allow,
            user_verification: REQUIRED.into(),
        })
    }

    /// §7.2 steps 3–14.
    fn read_assertion(
        &self,
        rp: &RelyingParty,
        purpose: Purpose,
        credential: &AssertionCredential,
    ) -> Result<Assertion, Refused> {
        let response = &credential.response;
        let credential_id = credential_id(&credential.kind, &credential.id, &credential.raw_id)?;
        let client_data = field(&response.client_data_json)?;
        let authenticator_data = field(&response.authenticator_data)?;
        let signature = field(&response.signature)?;
        let user_handle = response.user_handle.as_deref().map(field).transpose()?;
        self.client_data(&client_data, "webauthn.get", &purpose, rp)?;
        Ok(Assertion {
            rp: rp.clone(),
            account: match purpose {
                Purpose::Reauthenticate { user_id } => Some(user_id),
                _ => None,
            },
            credential_id,
            client_data,
            authenticator_data,
            signature,
            user_handle,
        })
    }

    /// §7.1 steps 5–11 and §7.2 steps 8–14: the client data, and the challenge
    /// spent whatever they then say.
    fn client_data(
        &self,
        json: &[u8],
        kind: &str,
        purpose: &Purpose,
        rp: &RelyingParty,
    ) -> Result<(), Refused> {
        let client = ClientData::parse(json)?;
        let fresh = unb64(&client.challenge)
            .is_some_and(|challenge| self.challenges.take(&challenge, purpose, &rp.id));
        if client.kind != kind {
            return Err(Refused::Response("the client data is for another ceremony"));
        }
        if !fresh {
            return Err(Refused::Response(
                "the challenge is unknown, spent, expired or someone else's",
            ));
        }
        if client.origin != rp.origin {
            return Err(Refused::Response("the origin is not the host's"));
        }
        if client.cross_origin == Some(true) || client.top_origin.is_some() {
            return Err(Refused::Response("made inside a frame of another origin"));
        }
        Ok(())
    }
}

/// A passkey's answer whose client data checked out, waiting for the passkey
/// it names.
pub struct Assertion {
    rp: RelyingParty,
    account: Option<String>,
    credential_id: Vec<u8>,
    client_data: Vec<u8>,
    authenticator_data: Vec<u8>,
    signature: Vec<u8>,
    user_handle: Option<Vec<u8>>,
}

impl Assertion {
    pub fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }

    /// §7.2 steps 5–21: the count `passkey` signed with, once it is the one
    /// the answer claims and its signature verifies. The caller then checks
    /// the count with [`sign_count_moved`] and keeps it.
    pub fn verify(&self, passkey: &StoredPasskey<'_>) -> Result<u32, Refused> {
        if self
            .account
            .as_deref()
            .is_some_and(|id| id != passkey.user_id)
        {
            return Err(Refused::Response("another account's passkey"));
        }
        match &self.user_handle {
            Some(handle) if handle != passkey.user_id.as_bytes() => {
                return Err(Refused::Response(
                    "the user handle is not the passkey's account",
                ));
            }
            None if self.account.is_none() => return Err(Refused::Response("no user handle")),
            _ => {}
        }
        if passkey.rp_id != self.rp.id {
            return Err(Refused::Response("the passkey was made on another host"));
        }

        let auth_data = AuthenticatorData::parse(&self.authenticator_data)?;
        if auth_data.credential.is_some() {
            return Err(Refused::Response(
                "attested credential data in an assertion",
            ));
        }
        check_flags(&auth_data, &self.rp)?;

        let key = cbor::decode(passkey.public_key)
            .and_then(|cose| PublicKey::from_cose(&cose))
            .map_err(|e| Refused::StoredKey(e.0))?;
        let signed = [
            self.authenticator_data.as_slice(),
            &sha256(&self.client_data),
        ]
        .concat();
        if !key.verify(&signed, &self.signature) {
            return Err(Refused::Response("the signature does not verify"));
        }
        Ok(auth_data.sign_count)
    }
}

impl fmt::Debug for Assertion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Assertion")
            .field("rp", &self.rp.id)
            .finish_non_exhaustive()
    }
}

/// §7.2 step 22: whether a passkey's count moved past the one kept. An
/// authenticator that keeps no count signs zero every time, which passes; one
/// that does and repeats a count may have been cloned.
pub fn sign_count_moved(stored: u32, signed: u32) -> bool {
    (stored == 0 && signed == 0) || signed > stored
}

/// The account id an assertion's `userHandle` claims, unverified: for naming
/// a refused sign-in in an audit log.
pub fn claimed_user_id(credential: &AssertionCredential) -> Option<String> {
    let handle = unb64(credential.response.user_handle.as_deref()?)?;
    String::from_utf8(handle).ok()
}

/// Why a ceremony's answer was refused. Both name the check for the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Refused {
    /// The browser's or the authenticator's answer failed a check.
    Response(&'static str),
    /// The stored passkey's public key is unreadable: the caller's data, not
    /// the answer, is at fault.
    StoredKey(&'static str),
}

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Response(why) => write!(f, "passkey refused: {why}"),
            Self::StoredKey(why) => write!(f, "a stored passkey's key is unreadable: {why}"),
        }
    }
}

impl std::error::Error for Refused {}

impl From<cbor::Malformed> for Refused {
    fn from(malformed: cbor::Malformed) -> Self {
        Self::Response(malformed.0)
    }
}

/// §7.1 steps 14–17 and §7.2 steps 15–18.
fn check_flags(auth_data: &AuthenticatorData<'_>, rp: &RelyingParty) -> Result<(), Refused> {
    let refuse = |why| Err(Refused::Response(why));
    if auth_data.rp_id_hash != sha256(rp.id.as_bytes()) {
        return refuse("the RP ID hash is not the host's");
    }
    if !auth_data.user_present() {
        return refuse("the user was not present");
    }
    if !auth_data.user_verified() {
        return refuse("the user was not verified");
    }
    if !auth_data.backup_flags_agree() {
        return refuse("backed up but not backup eligible");
    }
    Ok(())
}

/// `{fmt, attStmt, authData}` and nothing else (§6.5.4).
fn attestation_parts<'v, 'a>(
    object: &'v cbor::Value<'a>,
) -> Result<(&'a str, &'v cbor::Value<'a>, &'a [u8]), cbor::Malformed> {
    use cbor::Value;
    let malformed = cbor::Malformed("an attestation object not of fmt, attStmt and authData");
    let Value::Map(entries) = object else {
        return Err(malformed);
    };
    match (
        entries.len(),
        object.get(&Value::Text("fmt")),
        object.get(&Value::Text("attStmt")),
        object.get(&Value::Text("authData")),
    ) {
        (3, Some(Value::Text(fmt)), Some(statement @ Value::Map(_)), Some(Value::Bytes(data))) => {
            Ok((fmt, statement, data))
        }
        _ => Err(malformed),
    }
}

/// The raw id of a `public-key` credential whose `id` is that same id.
fn credential_id(kind: &str, id: &str, raw_id: &str) -> Result<Vec<u8>, Refused> {
    (kind == PUBLIC_KEY && id == raw_id)
        .then(|| unb64(raw_id))
        .flatten()
        .ok_or(Refused::Response("not a public-key credential with its id"))
}

fn field(text: &str) -> Result<Vec<u8>, Refused> {
    unb64(text).ok_or(Refused::Response("a field not base64url"))
}

fn descriptors<I>(credential_ids: I) -> Vec<CredentialDescriptor>
where
    I: IntoIterator<Item: AsRef<[u8]>>,
{
    credential_ids
        .into_iter()
        .map(|id| CredentialDescriptor {
            kind: PUBLIC_KEY.into(),
            id: b64(id.as_ref()),
        })
        .collect()
}

/// Short of the lifetime, which starts at issue, so an answer at the end of
/// the browser's window still finds its challenge.
fn timeout_ms(purpose: &Purpose) -> u32 {
    const MARGIN: std::time::Duration = std::time::Duration::from_secs(10);
    u32::try_from((purpose.lifetime() - MARGIN).as_millis()).expect("minutes fit")
}

fn random_bytes<const N: usize>() -> Result<[u8; N], getrandom::Error> {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes)?;
    Ok(bytes)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn unb64(text: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(text).ok()
}
