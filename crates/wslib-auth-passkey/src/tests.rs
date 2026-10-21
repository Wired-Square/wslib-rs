//! The ceremonies end to end: the published vectors, authenticators made here,
//! and each check refusing a response that differs from a good one in that one
//! respect.

use std::cell::RefCell;
use std::collections::HashMap;
use std::time::Duration;

use ed25519_dalek::Signer as _;

use super::cbor::encode;
use super::data::tests::{attested_data, header, okp_key};
use super::*;

const HOST: &str = "box.local:8443";
const ORIGIN: &str = "https://box.local:8443";
const ADMIN: &str = "u-admin";
const OPERATOR: &str = "u-operator";
const UP: u8 = 0x01;
const UV: u8 = 0x04;
const BE: u8 = 0x08;
const BS: u8 = 0x10;
const AT: u8 = 0x40;

/// A spec step, a change to a good response, and the check that refuses it.
type Case<T> = (u8, fn(&mut T), &'static str);

fn rp() -> RelyingParty {
    RelyingParty::for_host(HOST).expect("a name")
}

fn reason<T: fmt::Debug>(result: Result<T, Refused>) -> &'static str {
    match result {
        Err(Refused::Response(why)) => why,
        other => panic!("{other:?}"),
    }
}

#[derive(Clone)]
struct Client {
    kind: String,
    challenge: String,
    origin: String,
    extra: String,
}

impl Client {
    fn new(kind: &str, challenge: &str) -> Self {
        Self {
            kind: kind.into(),
            challenge: challenge.into(),
            origin: ORIGIN.into(),
            extra: r#","crossOrigin":false"#.into(),
        }
    }

    fn json(&self) -> Vec<u8> {
        format!(
            r#"{{"type":"{}","challenge":"{}","origin":"{}"{}}}"#,
            self.kind, self.challenge, self.origin, self.extra
        )
        .into_bytes()
    }
}

enum Key {
    Es256(p256::ecdsa::SigningKey),
    Ed25519(ed25519_dalek::SigningKey),
}

/// A passkey's authenticator, as far as a server can tell one apart.
struct Authenticator {
    key: Key,
    credential_id: Vec<u8>,
    counter: u32,
}

impl Authenticator {
    fn es256(credential: u8) -> Self {
        let key = std::iter::repeat_with(|| random_bytes::<32>().expect("random"))
            .find_map(|bytes| p256::ecdsa::SigningKey::from_slice(&bytes).ok())
            .expect("a key");
        Self::new(Key::Es256(key), credential)
    }

    fn ed25519(credential: u8) -> Self {
        let key = ed25519_dalek::SigningKey::from_bytes(&random_bytes().expect("random"));
        Self::new(Key::Ed25519(key), credential)
    }

    fn new(key: Key, credential: u8) -> Self {
        Self {
            key,
            credential_id: vec![credential; 16],
            counter: 0,
        }
    }

    fn cose(&self) -> Vec<u8> {
        match &self.key {
            Key::Es256(key) => {
                let point = key.verifying_key().to_encoded_point(false);
                let point = point.as_bytes();
                encode::map(&[
                    (encode::int(1), encode::int(2)),
                    (encode::int(3), encode::int(-7)),
                    (encode::int(-1), encode::int(1)),
                    (encode::int(-2), encode::bytes(&point[1..33])),
                    (encode::int(-3), encode::bytes(&point[33..])),
                ])
            }
            Key::Ed25519(key) => okp_key(key.verifying_key().as_bytes()),
        }
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        match &self.key {
            Key::Es256(key) => {
                let signature: p256::ecdsa::Signature = key.sign(message);
                signature.to_der().as_bytes().to_vec()
            }
            Key::Ed25519(key) => key.sign(message).to_bytes().to_vec(),
        }
    }
}

/// A registration response, in parts a test changes one of.
struct Registration {
    client: Client,
    rp_id: String,
    flags: u8,
    cose: Vec<u8>,
    attested_id: Vec<u8>,
    raw_id: Vec<u8>,
    fmt: String,
    statement: Vec<u8>,
    object: Option<Vec<u8>>,
}

impl Registration {
    fn good(authenticator: &Authenticator, challenge: &str) -> Self {
        Self {
            client: Client::new("webauthn.create", challenge),
            rp_id: "box.local".into(),
            flags: UP | UV | AT,
            cose: authenticator.cose(),
            attested_id: authenticator.credential_id.clone(),
            raw_id: authenticator.credential_id.clone(),
            fmt: "none".into(),
            statement: encode::map(&[]),
            object: None,
        }
    }

    fn auth_data(&self) -> Vec<u8> {
        [
            header(&self.rp_id, self.flags, 0),
            attested_data(&self.attested_id, &self.cose),
        ]
        .concat()
    }

    fn credential(&self) -> RegistrationCredential {
        let object = self.object.clone().unwrap_or_else(|| {
            encode::map(&[
                (encode::text("fmt"), encode::text(&self.fmt)),
                (encode::text("attStmt"), self.statement.clone()),
                (encode::text("authData"), encode::bytes(&self.auth_data())),
            ])
        });
        RegistrationCredential {
            id: b64(&self.raw_id),
            raw_id: b64(&self.raw_id),
            kind: "public-key".into(),
            response: AttestationResponse {
                client_data_json: b64(&self.client.json()),
                attestation_object: b64(&object),
            },
        }
    }
}

/// An assertion, in parts a test changes one of.
struct Answer {
    client: Client,
    rp_id: String,
    flags: u8,
    counter: u32,
    raw_id: Vec<u8>,
    user_handle: Option<Vec<u8>>,
    tamper: bool,
}

impl Answer {
    fn good(authenticator: &mut Authenticator, challenge: &str, user_id: &str) -> Self {
        authenticator.counter += 1;
        Self {
            client: Client::new("webauthn.get", challenge),
            rp_id: "box.local".into(),
            flags: UP | UV,
            counter: authenticator.counter,
            raw_id: authenticator.credential_id.clone(),
            user_handle: Some(user_id.as_bytes().to_vec()),
            tamper: false,
        }
    }

    fn credential(&self, authenticator: &Authenticator) -> AssertionCredential {
        let auth_data = header(&self.rp_id, self.flags, self.counter);
        let client = self.client.json();
        let signed = [auth_data.as_slice(), &sha256(&client)].concat();
        let mut signature = authenticator.sign(&signed);
        if self.tamper {
            signature[10] ^= 1;
        }
        AssertionCredential {
            id: b64(&self.raw_id),
            raw_id: b64(&self.raw_id),
            kind: "public-key".into(),
            response: AssertionResponse {
                client_data_json: b64(&client),
                authenticator_data: b64(&auth_data),
                signature: b64(&signature),
                user_handle: self.user_handle.as_deref().map(b64),
            },
        }
    }
}

struct Kept {
    user_id: String,
    rp_id: String,
    public_key: Vec<u8>,
    sign_count: u32,
}

/// What a caller does around the ceremonies: keeps passkeys by credential ID.
#[derive(Default)]
struct Server {
    ceremonies: Ceremonies,
    kept: RefCell<HashMap<Vec<u8>, Kept>>,
}

impl Server {
    fn keep(&self, user_id: &str, rp_id: &str, passkey: NewPasskey) {
        self.kept.borrow_mut().insert(
            passkey.credential_id,
            Kept {
                user_id: user_id.into(),
                rp_id: rp_id.into(),
                public_key: passkey.public_key,
                sign_count: passkey.sign_count,
            },
        );
    }

    fn begin_registration(&self, user_id: &str) -> CreationOptions {
        let exclude: Vec<Vec<u8>> = self
            .kept
            .borrow()
            .iter()
            .filter(|(_, kept)| kept.user_id == user_id)
            .map(|(id, _)| id.clone())
            .collect();
        self.ceremonies
            .begin_registration(&rp(), "Widget", user_id, "admin", exclude)
            .expect("options")
    }

    fn finish_registration(&self, registration: &Registration) -> Result<NewPasskey, Refused> {
        let passkey =
            self.ceremonies
                .finish_registration(&rp(), ADMIN, &registration.credential())?;
        self.keep(ADMIN, "box.local", passkey.clone());
        Ok(passkey)
    }

    fn register(&self, authenticator: &Authenticator) -> NewPasskey {
        let challenge = self.begin_registration(ADMIN).challenge;
        self.finish_registration(&Registration::good(authenticator, &challenge))
            .expect("registered")
    }

    fn refused_registration(&self, change: impl FnOnce(&mut Registration)) -> &'static str {
        let challenge = self.begin_registration(ADMIN).challenge;
        let mut registration = Registration::good(&Authenticator::es256(7), &challenge);
        change(&mut registration);
        reason(self.finish_registration(&registration))
    }

    fn begin_sign_in(&self) -> String {
        self.ceremonies
            .begin_sign_in(&rp())
            .expect("options")
            .challenge
    }

    /// The count signed, once the assertion verifies for the passkey it names.
    fn verify(&self, assertion: Result<Assertion, Refused>) -> Result<u32, Refused> {
        let assertion = assertion?;
        let kept = self.kept.borrow();
        let passkey = kept
            .get(assertion.credential_id())
            .expect("a passkey kept here");
        let signed = assertion.verify(&StoredPasskey {
            user_id: &passkey.user_id,
            rp_id: &passkey.rp_id,
            public_key: &passkey.public_key,
        })?;
        assert!(sign_count_moved(passkey.sign_count, signed));
        Ok(signed)
    }

    fn sign_in(&self, authenticator: &Authenticator, answer: &Answer) -> Result<u32, Refused> {
        let credential = answer.credential(authenticator);
        let signed = self.verify(self.ceremonies.read_sign_in(&rp(), &credential))?;
        self.kept
            .borrow_mut()
            .get_mut(&answer.raw_id)
            .expect("kept")
            .sign_count = signed;
        Ok(signed)
    }

    /// A sign-in with a passkey registered on a server of its own, changed by
    /// `change`, and what refused it.
    fn refused_sign_in(change: impl FnOnce(&mut Answer)) -> &'static str {
        let ours = Self::default();
        let mut authenticator = Authenticator::es256(1);
        ours.register(&authenticator);
        let challenge = ours.begin_sign_in();
        let mut answer = Answer::good(&mut authenticator, &challenge, ADMIN);
        change(&mut answer);
        reason(ours.sign_in(&authenticator, &answer))
    }

    fn reauthenticate(
        &self,
        user_id: &str,
        authenticator: &Authenticator,
        answer: &Answer,
    ) -> Result<u32, Refused> {
        let credential = answer.credential(authenticator);
        self.verify(
            self.ceremonies
                .read_reauthentication(&rp(), user_id, &credential),
        )
    }
}

#[test]
fn an_es256_and_an_ed25519_passkey_register_and_sign_in_without_a_username() {
    let ours = Server::default();
    for mut authenticator in [Authenticator::es256(1), Authenticator::ed25519(2)] {
        let passkey = ours.register(&authenticator);
        assert_eq!(passkey.credential_id, authenticator.credential_id);
        assert_eq!(passkey.public_key, authenticator.cose());
        assert_eq!(passkey.sign_count, 0);

        for expected in 1..=2 {
            let challenge = ours.begin_sign_in();
            let answer = Answer::good(&mut authenticator, &challenge, ADMIN);
            assert_eq!(ours.sign_in(&authenticator, &answer), Ok(expected));
        }
    }
}

#[test]
fn registration_options_bind_the_account_and_leave_out_its_passkeys() {
    let ours = Server::default();
    ours.register(&Authenticator::es256(1));
    let options = ours.begin_registration(ADMIN);

    assert_eq!(unb64(&options.challenge).expect("base64url").len(), 32);
    assert_eq!(
        (options.rp.id.as_str(), options.rp.name.as_str()),
        ("box.local", "Widget")
    );
    assert_eq!(unb64(&options.user.id).unwrap(), ADMIN.as_bytes());
    assert_eq!(options.user.name, "admin");
    let algs: Vec<i32> = options.pub_key_cred_params.iter().map(|p| p.alg).collect();
    assert_eq!(algs, [-7, -8]);
    assert_eq!(options.exclude_credentials.len(), 1);
    assert_eq!(unb64(&options.exclude_credentials[0].id).unwrap(), [1; 16]);
    assert_eq!(options.authenticator_selection.resident_key, "required");
    assert_eq!(
        options.authenticator_selection.user_verification,
        "required"
    );
    assert_eq!(options.attestation, "none");
    assert_eq!(options.timeout, 290_000, "ten seconds inside the lifetime");

    let sign_in = ours.ceremonies.begin_sign_in(&rp()).expect("options");
    assert!(sign_in.allow_credentials.is_empty());
    assert_eq!(sign_in.rp_id, "box.local");
    assert_eq!(sign_in.user_verification, "required");
    assert_eq!(sign_in.timeout, 110_000);
    let reauth = ours
        .ceremonies
        .begin_reauthentication(&rp(), ADMIN, [[1; 16]])
        .expect("options");
    assert_eq!(reauth.timeout, 290_000);
}

#[test]
fn registration_refuses_client_data_for_another_ceremony_challenge_or_origin() {
    let ours = Server::default();
    let cases: [Case<Registration>; 6] = [
        (
            7,
            |r| r.client.kind = "webauthn.get".into(),
            "the client data is for another ceremony",
        ),
        (
            8,
            |r| r.client.challenge = b64(&[7; 32]),
            "the challenge is unknown, spent, expired or someone else's",
        ),
        (
            9,
            |r| r.client.origin = "https://box.local".into(),
            "the origin is not the host's",
        ),
        (
            9,
            |r| r.client.origin = "http://box.local:8443".into(),
            "the origin is not the host's",
        ),
        (
            10,
            |r| r.client.extra = r#","crossOrigin":true"#.into(),
            "made inside a frame of another origin",
        ),
        (
            11,
            |r| r.client.extra = r#","topOrigin":"https://evil.example""#.into(),
            "made inside a frame of another origin",
        ),
    ];
    for (n, change, expected) in cases {
        assert_eq!(ours.refused_registration(change), expected, "§7.1 step {n}");
    }
    assert!(ours.kept.borrow().is_empty());
}

#[test]
fn registration_refuses_an_authenticator_that_did_not_sign_for_this_host_or_user() {
    let ours = Server::default();
    let cases: [Case<Registration>; 5] = [
        (
            14,
            |r| r.rp_id = "other.local".into(),
            "the RP ID hash is not the host's",
        ),
        (15, |r| r.flags &= !UP, "the user was not present"),
        (16, |r| r.flags &= !UV, "the user was not verified"),
        (17, |r| r.flags |= BS, "backed up but not backup eligible"),
        (
            13,
            |r| {
                r.object = Some(encode::map(&[
                    (encode::text("fmt"), encode::text("none")),
                    (encode::text("attStmt"), encode::map(&[])),
                    (
                        encode::text("authData"),
                        encode::bytes(&header(&r.rp_id, UP | UV, 0)),
                    ),
                ]));
            },
            "no attested credential data",
        ),
    ];
    for (n, change, expected) in cases {
        assert_eq!(ours.refused_registration(change), expected, "§7.1 step {n}");
    }
    let challenge = ours.begin_registration(ADMIN).challenge;
    let mut synced = Registration::good(&Authenticator::es256(8), &challenge);
    synced.flags |= BE | BS;
    ours.finish_registration(&synced).expect("a synced passkey");
}

#[test]
fn registration_refuses_another_attestation_algorithm_or_credential_id() {
    let ours = Server::default();
    let cases: [Case<Registration>; 5] = [
        (
            20,
            |r| {
                r.cose = encode::map(&[
                    (encode::int(1), encode::int(2)),
                    (encode::int(3), encode::int(-35)),
                    (encode::int(-1), encode::int(2)),
                    (encode::int(-2), encode::bytes(&[1; 48])),
                    (encode::int(-3), encode::bytes(&[1; 48])),
                ]);
            },
            "a key that is neither ES256 on P-256 nor EdDSA on Ed25519",
        ),
        (
            21,
            |r| r.fmt = "packed".into(),
            "an attestation other than none",
        ),
        (
            22,
            |r| r.statement = encode::map(&[(encode::text("alg"), encode::int(-7))]),
            "an attestation other than none",
        ),
        (
            27,
            |r| r.attested_id = vec![9; 16],
            "the credential ID is not the one attested",
        ),
        (
            27,
            |r| r.raw_id = vec![],
            "the credential ID is not the one attested",
        ),
    ];
    for (n, change, expected) in cases {
        assert_eq!(ours.refused_registration(change), expected, "§7.1 step {n}");
    }
}

#[test]
fn registration_refuses_malformed_cbor_in_the_attestation_object() {
    let ours = Server::default();
    let good = |r: &Registration| {
        vec![
            (encode::text("fmt"), encode::text("none")),
            (encode::text("attStmt"), encode::map(&[])),
            (encode::text("authData"), encode::bytes(&r.auth_data())),
        ]
    };
    type Object = fn(&Registration, Vec<(Vec<u8>, Vec<u8>)>) -> Vec<u8>;
    let cases: [(Object, &str); 5] = [
        (
            |_, entries| [encode::map(&entries), vec![0x00]].concat(),
            "bytes after the item",
        ),
        (
            |_, mut entries| {
                entries.push((encode::text("extra"), encode::int(1)));
                encode::map(&entries)
            },
            "an attestation object not of fmt, attStmt and authData",
        ),
        (
            |_, mut entries| {
                entries[1] = (encode::text("fmt"), encode::text("none"));
                encode::map(&entries)
            },
            "a repeated map key",
        ),
        (
            |_, entries| {
                let mut object = encode::map(&entries);
                object[0] = 0xbf;
                object.push(0xff);
                object
            },
            "an indefinite length",
        ),
        (
            |r, _| {
                let mut data = r.auth_data();
                data.push(0x00);
                encode::map(&[
                    (encode::text("fmt"), encode::text("none")),
                    (encode::text("attStmt"), encode::map(&[])),
                    (encode::text("authData"), encode::bytes(&data)),
                ])
            },
            "bytes after the authenticator data",
        ),
    ];
    for (object, expected) in cases {
        let refused = ours.refused_registration(|r| r.object = Some(object(r, good(r))));
        assert_eq!(refused, expected, "§7.1 step 13");
    }
}

#[test]
fn a_challenge_registers_once_and_not_after_five_minutes() {
    let ours = Server::default();
    let authenticator = Authenticator::es256(1);
    let challenge = ours.begin_registration(ADMIN).challenge;
    let registration = Registration::good(&authenticator, &challenge);
    ours.finish_registration(&registration).expect("registered");
    assert_eq!(
        reason(ours.finish_registration(&registration)),
        "the challenge is unknown, spent, expired or someone else's"
    );

    let challenge = ours.begin_registration(ADMIN).challenge;
    ours.ceremonies.challenges.age(Duration::from_secs(300));
    let late = Registration::good(&Authenticator::es256(2), &challenge);
    assert_eq!(
        reason(ours.finish_registration(&late)),
        "the challenge is unknown, spent, expired or someone else's"
    );
}

#[test]
fn a_challenge_no_answer_reached_still_registers_for_as_long_as_the_browser_waits() {
    let ours = Server::default();
    let options = ours.begin_registration(ADMIN);
    ours.ceremonies
        .challenges
        .age(Duration::from_millis(options.timeout.into()));
    let retried = Registration::good(&Authenticator::es256(1), &options.challenge);
    ours.finish_registration(&retried)
        .expect("a retry with the same options");
}

#[test]
fn a_failed_registration_spends_its_challenge() {
    let ours = Server::default();
    let challenge = ours.begin_registration(ADMIN).challenge;
    let mut registration = Registration::good(&Authenticator::es256(1), &challenge);
    registration.flags &= !UV;
    assert!(ours.finish_registration(&registration).is_err());
    registration.flags |= UV;
    assert_eq!(
        reason(ours.finish_registration(&registration)),
        "the challenge is unknown, spent, expired or someone else's"
    );
}

#[test]
fn another_accounts_registration_challenge_is_refused() {
    let ours = Server::default();
    let theirs = ours.begin_registration(OPERATOR).challenge;
    let refused = ours.finish_registration(&Registration::good(&Authenticator::es256(1), &theirs));
    assert_eq!(
        reason(refused),
        "the challenge is unknown, spent, expired or someone else's"
    );
}

#[test]
fn sign_in_refuses_client_data_for_another_ceremony_challenge_or_origin() {
    let cases: [Case<Answer>; 5] = [
        (
            10,
            |a| a.client.kind = "webauthn.create".into(),
            "the client data is for another ceremony",
        ),
        (
            11,
            |a| a.client.challenge = b64(&[7; 32]),
            "the challenge is unknown, spent, expired or someone else's",
        ),
        (
            12,
            |a| a.client.origin = "https://box.local".into(),
            "the origin is not the host's",
        ),
        (
            13,
            |a| a.client.extra = r#","crossOrigin":true"#.into(),
            "made inside a frame of another origin",
        ),
        (
            14,
            |a| a.client.extra = r#","topOrigin":"https://evil.example""#.into(),
            "made inside a frame of another origin",
        ),
    ];
    for (n, change, expected) in cases {
        assert_eq!(Server::refused_sign_in(change), expected, "§7.2 step {n}");
    }
}

#[test]
fn sign_in_refuses_an_authenticator_that_did_not_sign_for_this_host_or_user() {
    let cases: [Case<Answer>; 5] = [
        (
            15,
            |a| a.rp_id = "other.local".into(),
            "the RP ID hash is not the host's",
        ),
        (16, |a| a.flags &= !UP, "the user was not present"),
        (17, |a| a.flags &= !UV, "the user was not verified"),
        (18, |a| a.flags |= BS, "backed up but not backup eligible"),
        (21, |a| a.tamper = true, "the signature does not verify"),
    ];
    for (n, change, expected) in cases {
        assert_eq!(Server::refused_sign_in(change), expected, "§7.2 step {n}");
    }
}

#[test]
fn sign_in_refuses_a_user_handle_that_is_not_its_account() {
    let cases: [Case<Answer>; 3] = [
        (
            6,
            |a| a.user_handle = Some(b"someone else".to_vec()),
            "the user handle is not the passkey's account",
        ),
        (6, |a| a.user_handle = None, "no user handle"),
        (15, |a| a.flags |= AT, "attested credential data too short"),
    ];
    for (n, change, expected) in cases {
        assert_eq!(Server::refused_sign_in(change), expected, "§7.2 step {n}");
    }
}

#[test]
fn a_sign_in_challenge_is_spent_by_its_first_answer_and_expires() {
    let ours = Server::default();
    let mut authenticator = Authenticator::es256(1);
    ours.register(&authenticator);

    let challenge = ours.begin_sign_in();
    let mut answer = Answer::good(&mut authenticator, &challenge, ADMIN);
    answer.tamper = true;
    assert!(ours.sign_in(&authenticator, &answer).is_err());
    answer.tamper = false;
    answer.counter += 1;
    assert_eq!(
        reason(ours.sign_in(&authenticator, &answer)),
        "the challenge is unknown, spent, expired or someone else's",
        "replayed after a failure"
    );

    let challenge = ours.begin_sign_in();
    ours.ceremonies.challenges.age(Duration::from_secs(120));
    let late = Answer::good(&mut authenticator, &challenge, ADMIN);
    assert_eq!(
        reason(ours.sign_in(&authenticator, &late)),
        "the challenge is unknown, spent, expired or someone else's"
    );
}

#[test]
fn a_count_moves_forward_or_stays_at_zero() {
    assert!(sign_count_moved(0, 1));
    assert!(sign_count_moved(4, 5));
    assert!(
        sign_count_moved(0, 0),
        "an authenticator that keeps no count"
    );
    assert!(!sign_count_moved(5, 5), "a possible clone");
    assert!(!sign_count_moved(5, 4));
    assert!(!sign_count_moved(5, 0));
}

#[test]
fn a_passkey_made_on_another_name_does_not_sign_in_here() {
    let ours = Server::default();
    let mut authenticator = Authenticator::es256(1);
    ours.keep(
        ADMIN,
        "widget-01.local",
        NewPasskey {
            credential_id: authenticator.credential_id.clone(),
            public_key: authenticator.cose(),
            sign_count: 0,
        },
    );
    let challenge = ours.begin_sign_in();
    let answer = Answer::good(&mut authenticator, &challenge, ADMIN);
    assert_eq!(
        reason(ours.sign_in(&authenticator, &answer)),
        "the passkey was made on another host",
        "§7.2 step 15"
    );
}

#[test]
fn an_unreadable_stored_key_is_the_callers_fault_not_the_answers() {
    let ours = Server::default();
    let mut authenticator = Authenticator::es256(1);
    ours.keep(
        ADMIN,
        "box.local",
        NewPasskey {
            credential_id: authenticator.credential_id.clone(),
            public_key: okp_key(&[0; 31]),
            sign_count: 0,
        },
    );
    let challenge = ours.begin_sign_in();
    let answer = Answer::good(&mut authenticator, &challenge, ADMIN);
    assert_eq!(
        ours.sign_in(&authenticator, &answer),
        Err(Refused::StoredKey("a COSE coordinate that is not 32 bytes"))
    );
}

#[test]
fn reauthentication_asks_for_this_accounts_passkeys_and_takes_no_other() {
    let ours = Server::default();
    let mut mine = Authenticator::es256(1);
    ours.register(&mine);

    let options = ours
        .ceremonies
        .begin_reauthentication(&rp(), ADMIN, [&mine.credential_id])
        .expect("options");
    assert_eq!(options.allow_credentials.len(), 1);
    assert_eq!(
        unb64(&options.allow_credentials[0].id).unwrap(),
        mine.credential_id
    );
    let mut answer = Answer::good(&mut mine, &options.challenge, ADMIN);
    answer.user_handle = None;
    ours.reauthenticate(ADMIN, &mine, &answer).expect("proved");

    let options = ours
        .ceremonies
        .begin_reauthentication(&rp(), ADMIN, [&mine.credential_id])
        .unwrap();
    let answer = Answer::good(&mut mine, &options.challenge, ADMIN);
    assert_eq!(
        reason(ours.reauthenticate(OPERATOR, &mine, &answer)),
        "the challenge is unknown, spent, expired or someone else's",
        "the admin's challenge is not the operator's"
    );
}

#[test]
fn reauthentication_refuses_another_accounts_passkey() {
    let ours = Server::default();
    let mut admins = Authenticator::es256(1);
    ours.register(&admins);
    let options = ours
        .ceremonies
        .begin_reauthentication(&rp(), OPERATOR, [[2; 16]])
        .unwrap();
    let answer = Answer::good(&mut admins, &options.challenge, ADMIN);
    assert_eq!(
        reason(ours.reauthenticate(OPERATOR, &admins, &answer)),
        "another account's passkey",
        "§7.2 step 5"
    );
}

#[test]
fn a_soft_passkey_registers_and_signs_in() {
    let ours = Server::default();
    let mut passkey = testing::SoftPasskey::new();
    let options = ours.begin_registration(ADMIN);
    let registered = ours
        .ceremonies
        .finish_registration(&rp(), ADMIN, &passkey.register(&options, ORIGIN))
        .expect("registered");
    assert_eq!(registered.credential_id, passkey.credential_id());
    ours.keep(ADMIN, "box.local", registered);

    let options = ours.ceremonies.begin_sign_in(&rp()).unwrap();
    let answer = passkey.answer(&options, ORIGIN);
    assert_eq!(claimed_user_id(&answer).as_deref(), Some(ADMIN));
    assert_eq!(
        ours.verify(ours.ceremonies.read_sign_in(&rp(), &answer)),
        Ok(1)
    );
}

#[test]
fn an_ip_address_is_refused_and_a_name_becomes_its_origin() {
    for ip in [
        "192.168.1.20",
        "192.168.1.20:8443",
        "[fe80::1]",
        "[::1]:8443",
        "::1",
        "fe80::1",
        "127.1",
        "0x7f.0.0.1",
        "box.10",
        "box.0x1f",
        "box.0x",
    ] {
        assert_eq!(
            RelyingParty::for_host(ip),
            Err(HostError::IpAddress),
            "{ip}"
        );
    }
    for bad in [
        "",
        "box.local:",
        "box.local:x",
        "box..local",
        "-box.local",
        "box local",
        "box.local/x",
        "a@b",
    ] {
        assert_eq!(
            RelyingParty::for_host(bad),
            Err(HostError::NotAName),
            "{bad:?}"
        );
    }
    for (host, id, origin) in [
        (
            "Widget-01.LOCAL",
            "widget-01.local",
            "https://widget-01.local",
        ),
        ("widget.lan:443", "widget.lan", "https://widget.lan"),
        ("widget.lan:8443", "widget.lan", "https://widget.lan:8443"),
        ("localhost:3000", "localhost", "https://localhost:3000"),
        ("box.0xygen", "box.0xygen", "https://box.0xygen"),
        ("box.10a", "box.10a", "https://box.10a"),
    ] {
        let rp = RelyingParty::for_host(host).expect("a name");
        assert_eq!((rp.id(), rp.origin()), (id, origin), "{host}");
    }
}

/// One section of `vectors.txt`, by name.
fn vector(section: &str) -> HashMap<String, Vec<u8>> {
    let text = include_str!("vectors.txt");
    let start = text.find(&format!("[{section}]")).expect("a section");
    let mut values = HashMap::new();
    let mut part = "";
    for line in text[start..].lines().skip(1) {
        match line {
            "" => break,
            "Registration:" | "Authentication:" => part = line.trim_end_matches(':'),
            _ => {
                let (name, value) = line.split_once(" = h'").expect("name = h'…'");
                let hex = value.trim_end_matches('\'');
                let bytes = (0..hex.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
                    .collect();
                values.insert(format!("{part}.{name}"), bytes);
            }
        }
    }
    values
}

fn example_org() -> RelyingParty {
    RelyingParty::for_host("example.org").expect("a name")
}

/// A section's registration as published, or with the UV flag set in its
/// authenticator data, which a `none` attestation leaves unsigned.
fn published_registration(v: &HashMap<String, Vec<u8>>, verified: bool) -> RegistrationCredential {
    let mut object = v["Registration.attestationObject"].clone();
    if verified {
        let rp_id_hash = sha256(b"example.org");
        let at = object
            .windows(32)
            .position(|w| w == rp_id_hash)
            .expect("the authenticator data");
        object[at + 32] |= UV;
    }
    let attestation = cbor::decode(&object).expect("CBOR");
    let (_, _, auth_data) = attestation_parts(&attestation).expect("parts");
    let id = AuthenticatorData::parse(auth_data)
        .expect("authenticator data")
        .credential
        .expect("attested")
        .id
        .to_vec();
    RegistrationCredential {
        id: b64(&id),
        raw_id: b64(&id),
        kind: "public-key".into(),
        response: AttestationResponse {
            client_data_json: b64(&v["Registration.clientDataJSON"]),
            attestation_object: b64(&object),
        },
    }
}

fn register_published(
    ours: &Server,
    v: &HashMap<String, Vec<u8>>,
    verified: bool,
) -> Result<NewPasskey, Refused> {
    let purpose = Purpose::Register {
        user_id: ADMIN.into(),
    };
    published_challenge(ours, v, "Registration", purpose);
    ours.ceremonies
        .finish_registration(&example_org(), ADMIN, &published_registration(v, verified))
}

fn published_challenge(ours: &Server, v: &HashMap<String, Vec<u8>>, part: &str, purpose: Purpose) {
    let challenge = v[&format!("{part}.challenge")]
        .clone()
        .try_into()
        .expect("32 bytes");
    ours.ceremonies
        .challenges
        .insert(challenge, purpose, "example.org");
}

#[test]
fn the_published_none_registrations_are_refused_only_where_they_differ_from_our_policy() {
    for section in ["none-es256", "none-es256-long-credential-id"] {
        let ours = Server::default();
        let v = vector(section);
        assert_eq!(
            reason(register_published(&ours, &v, false)),
            "the user was not verified",
            "{section}, as published"
        );
        register_published(&ours, &v, true)
            .unwrap_or_else(|e| panic!("{section}, user verified: {e:?}"));
    }
    for section in ["none-es256-crossOrigin", "none-es256-topOrigin"] {
        let ours = Server::default();
        assert_eq!(
            reason(register_published(&ours, &vector(section), true)),
            "made inside a frame of another origin",
            "{section}"
        );
    }
}

#[test]
fn the_published_es256_assertion_with_a_1023_byte_credential_id_verifies() {
    let ours = Server::default();
    let v = vector("none-es256-long-credential-id");
    let registered = published_registration(&v, true);
    assert_eq!(unb64(&registered.raw_id).unwrap().len(), 1023);
    let passkey = register_published(&ours, &v, true).expect("registered");
    ours.keep(ADMIN, "example.org", passkey);

    let purpose = Purpose::Reauthenticate {
        user_id: ADMIN.into(),
    };
    published_challenge(&ours, &v, "Authentication", purpose);
    let credential = AssertionCredential {
        id: registered.id,
        raw_id: registered.raw_id,
        kind: "public-key".into(),
        response: AssertionResponse {
            client_data_json: b64(&v["Authentication.clientDataJSON"]),
            authenticator_data: b64(&v["Authentication.authenticatorData"]),
            signature: b64(&v["Authentication.signature"]),
            user_handle: None,
        },
    };
    let assertion = ours
        .ceremonies
        .read_reauthentication(&example_org(), ADMIN, &credential);
    ours.verify(assertion).expect("the published assertion");
}

#[test]
fn the_published_es256_and_ed25519_signatures_verify_and_a_changed_byte_does_not() {
    for section in [
        "none-es256",
        "none-es256-crossOrigin",
        "none-es256-topOrigin",
        "packed-eddsa",
    ] {
        let v = vector(section);
        let attestation = cbor::decode(&v["Registration.attestationObject"]).unwrap();
        let (fmt, _, auth_data) = attestation_parts(&attestation).unwrap();
        let cose = AuthenticatorData::parse(auth_data)
            .unwrap()
            .credential
            .unwrap()
            .cose;
        let key = PublicKey::from_cose(&cbor::decode(cose).unwrap()).expect("a key");
        assert_eq!(
            matches!(key, PublicKey::Ed25519(_)),
            fmt == "packed",
            "{section}"
        );

        let auth = AuthenticatorData::parse(&v["Authentication.authenticatorData"]).unwrap();
        assert_eq!(auth.rp_id_hash, sha256(b"example.org"));
        let signed = [
            v["Authentication.authenticatorData"].as_slice(),
            &sha256(&v["Authentication.clientDataJSON"]),
        ]
        .concat();
        assert!(
            key.verify(&signed, &v["Authentication.signature"]),
            "{section}"
        );
        let mut changed = signed.clone();
        changed[32] ^= 0x04;
        assert!(
            !key.verify(&changed, &v["Authentication.signature"]),
            "{section}"
        );
    }
}
