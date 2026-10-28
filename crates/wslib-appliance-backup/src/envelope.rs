//! The file format: a plaintext header, and one sealed ciphertext.
//!
//! ```json
//! { "header": { … }, "kdf": { … }, "nonce": "…", "commitment": "…", "sealed": "…" }
//! ```
//!
//! There is no plaintext mode. The header is a hint a person chooses files by:
//! `Bundle::open` recomputes `contains`. The seal's associated data covers every
//! header field but `contains`, so the header can grow without breaking a seal.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq as _;
use wslib_appliance_types::backup::{BundleHeader, Contains, MAX_BUNDLE_LEN};
use zeroize::Zeroizing;

use crate::BackupError;

/// What the `format` field must say.
pub const FORMAT: &str = "appliance-backup";

pub const FORMAT_VERSION: u32 = 2;

/// The first version whose seal covers the box id.
const BOX_ID_SINCE: u32 = 2;

const KEY_LEN: usize = 32;

/// XChaCha20-Poly1305 is not key-committing, so the KDF derives this beside the
/// key and it is compared in constant time before anything is decrypted:
/// otherwise one crafted file tests many passphrases per restore attempt.
const COMMITMENT_LEN: usize = 32;

const NONCE_LEN: usize = 24;
const SALT_LEN: usize = 16;

/// Argon2id cost, dearer than a password's, since a bundle is ground offline.
/// Each header carries its own, so raising these leaves old bundles openable.
const M_COST: u32 = 64 * 1024;
const T_COST: u32 = 3;
const P_COST: u32 = 1;

const P_COST_CEILING: u32 = 16;

/// The dearest KDF a header may ask for, by who is asking: `m_cost` is
/// attacker-chosen and allocated up front, and a failed allocation aborts.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Ceiling {
    /// A caller with a session: four times what this module writes.
    General,
    /// A caller with no session, before the first account exists: twice what
    /// this module writes. A bundle between the two is refused by name, and
    /// still opens at [`Ceiling::General`].
    Unauthenticated,
}

impl Ceiling {
    /// `(m_cost, t_cost)` this caller will pay.
    const fn bounds(self) -> (u32, u32) {
        match self {
            Self::General => (M_COST * 4, T_COST * 4),
            Self::Unauthenticated => (M_COST * 2, T_COST * 2),
        }
    }

    fn refusal(self) -> BackupError {
        match self {
            Self::General => BackupError::malformed(
                "this backup asks for more work to open than any real one would",
            ),
            Self::Unauthenticated => BackupError::TooDearWithoutASession,
        }
    }
}

const _: () = assert!(
    Ceiling::Unauthenticated.bounds().0 >= M_COST
        && Ceiling::Unauthenticated.bounds().1 >= T_COST
        && Ceiling::Unauthenticated.bounds().0 <= Ceiling::General.bounds().0
        && Ceiling::Unauthenticated.bounds().1 <= Ceiling::General.bounds().1
        && P_COST_CEILING >= P_COST,
    "a bundle this module writes must open at either ceiling, and the lower must stay under the general"
);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Kdf {
    /// Always `argon2id`, and checked.
    pub algorithm: String,
    pub salt: String,
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub header: BundleHeader,
    pub kdf: Kdf,
    pub nonce: String,
    pub commitment: String,
    pub sealed: String,
}

/// What the header says of where a bundle came from, supplied by the caller.
#[derive(Debug, Clone)]
pub struct Provenance {
    pub source_host: String,
    pub box_id: Option<String>,
    pub app_version: String,
    /// The newest migration in the product's own chain, `0` with none.
    pub app_schema_version: u32,
}

/// The bytes the seal authenticates beside the ciphertext. From format 2 a JSON
/// array, so no value can shift into another's position; format 1's
/// newline-joined text is kept byte for byte.
fn aad(h: &BundleHeader, commitment: &str) -> Vec<u8> {
    // Fixed-width, where `to_rfc3339` drops the fraction on a whole second.
    let created = wslib_appliance_store::stamp(h.created_at);
    if h.version >= BOX_ID_SINCE {
        return serde_json::to_vec(&(
            FORMAT,
            h.version,
            h.app_schema_version,
            created,
            &h.source_host,
            &h.box_id,
            &h.app_version,
            commitment,
        ))
        .expect("strings and numbers serialise");
    }
    format!(
        "{FORMAT}\nversion={}\nschema={}\ncreated={created}\nhost={}\napp={}\ncommit={commitment}",
        h.version, h.app_schema_version, h.source_host, h.app_version,
    )
    .into_bytes()
}

/// A hyphenated lowercase UUID, as `wslib_appliance_core::box_id` writes one.
fn is_box_id(id: &str) -> bool {
    id.len() == 36
        && id.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => matches!(b, b'0'..=b'9' | b'a'..=b'f'),
        })
}

type Derived = (Zeroizing<[u8; KEY_LEN]>, [u8; COMMITMENT_LEN]);

fn derive(passphrase: &str, kdf: &Kdf, ceiling: Ceiling) -> Result<Derived, BackupError> {
    use argon2::{Algorithm, Argon2, Block, Params, Version};

    if passphrase.is_empty() {
        return Err(BackupError::Passphrase(
            "a backup needs a passphrase".to_string(),
        ));
    }
    if kdf.algorithm != "argon2id" {
        return Err(BackupError::malformed(
            "this backup was sealed with a key derivation this build does not know",
        ));
    }

    let salt = B64
        .decode(&kdf.salt)
        .map_err(|_| BackupError::malformed("the KDF salt is not valid base64"))?;
    if salt.len() < 8 {
        return Err(BackupError::malformed("the KDF salt is too short"));
    }

    // Before `Params::new`, which hands these to an allocator. The general bound
    // first: above it no session would open the file either.
    let (m_general, t_general) = Ceiling::General.bounds();
    if kdf.m_cost > m_general || kdf.t_cost > t_general || kdf.p_cost > P_COST_CEILING {
        return Err(Ceiling::General.refusal());
    }
    let (m_ceiling, t_ceiling) = ceiling.bounds();
    if kdf.m_cost > m_ceiling || kdf.t_cost > t_ceiling {
        return Err(ceiling.refusal());
    }

    let params = Params::new(
        kdf.m_cost,
        kdf.t_cost,
        kdf.p_cost,
        Some(KEY_LEN + COMMITMENT_LEN),
    )
    .map_err(|e| BackupError::Malformed(format!("unusable KDF parameters — {e}")))?;

    // argon2 frees the memory it allocates itself unwiped, zeroize feature or not.
    let mut memory = Zeroizing::new(vec![Block::default(); params.block_count()]);
    let mut material = Zeroizing::new([0u8; KEY_LEN + COMMITMENT_LEN]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into_with_memory(passphrase.as_bytes(), &salt, &mut *material, &mut **memory)
        .map_err(|e| BackupError::Passphrase(format!("could not derive a key — {e}")))?;

    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    key.copy_from_slice(&material[..KEY_LEN]);
    let commitment = material[KEY_LEN..]
        .try_into()
        .expect("COMMITMENT_LEN bytes");
    Ok((key, commitment))
}

/// A buffer that wipes what it held, and each one it outgrew.
#[derive(Default)]
pub(crate) struct Wiping(pub(crate) Zeroizing<Vec<u8>>);

impl std::io::Write for Wiping {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let needed = self.0.len() + bytes.len();
        if needed > self.0.capacity() {
            let mut grown = Vec::with_capacity(needed.max(2 * self.0.capacity()));
            grown.extend_from_slice(&self.0);
            self.0 = Zeroizing::new(grown);
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn random<const N: usize>() -> Result<[u8; N], BackupError> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).map_err(BackupError::internal)?;
    Ok(bytes)
}

/// Seal a snapshot's JSON, compressed, into the text a bundle file holds. A
/// plaintext or a sealed text [`open`] would refuse is refused as `TooLarge`.
pub(crate) fn seal(
    plaintext: &[u8],
    contains: Contains,
    passphrase: &str,
    provenance: &Provenance,
) -> Result<String, BackupError> {
    seal_at(plaintext, contains, passphrase, provenance, M_COST, T_COST)
}

/// [`seal`] at a chosen cost.
fn seal_at(
    plaintext: &[u8],
    contains: Contains,
    passphrase: &str,
    provenance: &Provenance,
    m_cost: u32,
    t_cost: u32,
) -> Result<String, BackupError> {
    use flate2::{Compression, bufread::GzEncoder};

    within_the_cap(plaintext.len())?;
    let kdf = Kdf {
        algorithm: "argon2id".to_string(),
        salt: B64.encode(random::<SALT_LEN>()?),
        m_cost,
        t_cost,
        p_cost: P_COST,
    };
    let mut header = BundleHeader::default();
    header.format = FORMAT.to_string();
    header.version = FORMAT_VERSION;
    header.created_at = Utc::now();
    header.source_host = provenance.source_host.clone();
    header.box_id = provenance.box_id.clone();
    header.app_version = provenance.app_version.clone();
    header.app_schema_version = provenance.app_schema_version;
    header.contains = contains;

    let mut compressed = Wiping::default();
    std::io::copy(
        &mut GzEncoder::new(plaintext, Compression::default()),
        &mut compressed,
    )
    .map_err(BackupError::internal)?;

    let (key, commitment) = derive(passphrase, &kdf, Ceiling::General)?;
    let commitment = B64.encode(commitment);
    let nonce = random::<NONCE_LEN>()?;
    let sealed = XChaCha20Poly1305::new((&*key).into())
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &compressed.0,
                aad: &aad(&header, &commitment),
            },
        )
        .map_err(|_| BackupError::internal("the snapshot could not be sealed"))?;

    let envelope = Envelope {
        header,
        kdf,
        nonce: B64.encode(nonce),
        commitment,
        sealed: B64.encode(sealed),
    };
    let text = serde_json::to_string(&envelope).map_err(BackupError::internal)?;
    within_the_cap(text.len())?;
    Ok(text)
}

fn within_the_cap(actual: usize) -> Result<(), BackupError> {
    match actual > MAX_BUNDLE_LEN {
        true => Err(BackupError::TooLarge {
            limit: MAX_BUNDLE_LEN,
            actual,
        }),
        false => Ok(()),
    }
}

/// Open a bundle, returning its header and the plaintext inside it. `ours` is
/// this build's schema version. The version and schema are checked before the
/// `ceiling`, and the ceiling before the key is derived.
pub(crate) fn open(
    text: &str,
    passphrase: &str,
    ours: u32,
    ceiling: Ceiling,
) -> Result<(BundleHeader, Zeroizing<Vec<u8>>), BackupError> {
    use flate2::bufread::GzDecoder;
    use std::io::Read as _;

    within_the_cap(text.len())?;

    let envelope: Envelope = serde_json::from_str(text).map_err(|_| BackupError::NotABundle)?;
    if envelope.header.format != FORMAT {
        return Err(BackupError::NotABundle);
    }
    if envelope.header.version > FORMAT_VERSION {
        return Err(BackupError::FormatTooNew {
            theirs: envelope.header.version,
            ours: FORMAT_VERSION,
        });
    }
    // Format 1's seal does not cover one, and no box writes one of another shape.
    if envelope
        .header
        .box_id
        .as_deref()
        .is_some_and(|id| envelope.header.version < BOX_ID_SINCE || !is_box_id(id))
    {
        return Err(BackupError::malformed(
            "it names the box it came from in a way no box would",
        ));
    }
    if envelope.header.app_schema_version > ours {
        return Err(BackupError::SchemaTooNew {
            theirs: envelope.header.app_schema_version,
            ours,
        });
    }

    let (key, commitment) = derive(passphrase, &envelope.kdf, ceiling)?;

    let claimed = B64
        .decode(&envelope.commitment)
        .map_err(|_| BackupError::malformed("the commitment is not valid base64"))?;
    if claimed.len() != COMMITMENT_LEN || !bool::from(commitment.as_slice().ct_eq(&claimed)) {
        return Err(BackupError::WrongPassphrase);
    }

    let nonce = B64
        .decode(&envelope.nonce)
        .map_err(|_| BackupError::malformed("the nonce is not valid base64"))?;
    let sealed = B64
        .decode(&envelope.sealed)
        .map_err(|_| BackupError::malformed("the sealed body is not valid base64"))?;

    let compressed = XChaCha20Poly1305::new((&*key).into())
        .decrypt(
            &XNonce::try_from(&nonce[..])
                .map_err(|_| BackupError::malformed("the nonce is the wrong length"))?,
            Payload {
                msg: &sealed,
                aad: &aad(&envelope.header, &envelope.commitment),
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| BackupError::malformed("the sealed body did not verify"))?;

    // The cap above bounds the input; `take` bounds what the gzip expands to.
    let mut plaintext = Wiping::default();
    std::io::copy(
        &mut GzDecoder::new(&compressed[..]).take(MAX_BUNDLE_LEN as u64 + 1),
        &mut plaintext,
    )
    .map_err(BackupError::internal)?;
    within_the_cap(plaintext.0.len())?;

    Ok((envelope.header, plaintext.0))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn open(
        text: &str,
        passphrase: &str,
        ours: u32,
    ) -> Result<(BundleHeader, Zeroizing<Vec<u8>>), BackupError> {
        super::open(text, passphrase, ours, Ceiling::General)
    }

    pub(crate) fn provenance() -> Provenance {
        Provenance {
            source_host: "widget-01".to_string(),
            box_id: Some(BOX.to_string()),
            app_version: "0.1.0".to_string(),
            app_schema_version: 1,
        }
    }

    const BOX: &str = "6f1c1e5a-3d52-4c1e-9d0b-6a8f2b7e4c10";

    /// A sealed format-1 envelope: `{"users":[]}` under "correct horse battery".
    const FORMAT_1: &str = r#"{"header":{"format":"appliance-backup","version":1,"created_at":"2026-09-24T15:43:02.569425Z","source_host":"widget-01","app_version":"0.2.2","app_schema_version":1,"contains":{"accounts":0,"settings":0,"trusted_certs":0,"trusted_cas":0,"serving_certificate":false,"ssh_keys":0,"host":false,"app":{}}},"kdf":{"algorithm":"argon2id","salt":"mFTLNSbTgsqj/rOHqrhm/g==","m_cost":65536,"t_cost":3,"p_cost":1},"nonce":"wToSkKG9DRgBKVj14yj8HT2ltpJQcdcv","commitment":"XmyczwZUkZrf3S7rSVrWHiQ7eQ2BgaYn6gsk5sekC5M=","sealed":"wm8sQZ8ZTQ7tZLxFRBwthjMRit+6fBHzKiaAM+eoQgQFA9PeCyPGbMzZFNckfnjR"}"#;

    fn sealed(body: &[u8]) -> String {
        seal(
            body,
            Contains::default(),
            "correct horse battery",
            &provenance(),
        )
        .expect("seal")
    }

    fn incompressible() -> Vec<u8> {
        let mut bytes = vec![0u8; 64 * 1024];
        getrandom::fill(&mut bytes).expect("random bytes");
        bytes
    }

    fn cheaply_sealed(plaintext: &[u8]) -> String {
        seal_at(
            plaintext,
            Contains::default(),
            "correct horse battery",
            &provenance(),
            64,
            1,
        )
        .expect("seal")
    }

    /// Before deflate's last 32 KiB window: the compression library's own
    /// state is not wiped, and not checked here.
    fn early(plaintext: &[u8]) -> &[u8] {
        &plaintext[..32]
    }

    #[test]
    fn opening_a_bundle_leaves_no_plaintext_in_the_crates_own_buffers() {
        let plaintext = incompressible();
        let text = cheaply_sealed(&plaintext);
        let ((), freed) = crate::watching::freed_during(|| {
            open(&text, "correct horse battery", 1).expect("open");
        });
        assert!(
            !freed.holds(early(&plaintext)),
            "a freed buffer held the plaintext"
        );
    }

    #[test]
    fn sealing_leaves_no_plaintext_in_the_crates_own_buffers() {
        let plaintext = incompressible();
        let (_text, freed) = crate::watching::freed_during(|| cheaply_sealed(&plaintext));
        assert!(
            !freed.holds(early(&plaintext)),
            "a freed buffer held the plaintext"
        );
    }

    #[test]
    fn deriving_a_key_wipes_the_argon2_memory() {
        let kdf = Kdf {
            algorithm: "argon2id".to_string(),
            salt: B64.encode([7u8; SALT_LEN]),
            m_cost: 64,
            t_cost: 1,
            p_cost: 1,
        };
        let (_derived, freed) = crate::watching::freed_during(|| {
            derive("correct horse battery", &kdf, Ceiling::General).expect("derives")
        });
        assert_eq!(freed.unwiped_argon2_memory, 0);
    }

    #[test]
    fn a_bundle_survives_the_round_trip() {
        let text = sealed(b"{\"users\":[]}");
        let (header, plaintext) = open(&text, "correct horse battery", 1).expect("open");

        assert_eq!(header.format, FORMAT);
        assert_eq!(header.version, FORMAT_VERSION);
        assert_eq!(header.source_host, "widget-01");
        assert_eq!(header.box_id.as_deref(), Some(BOX));
        assert_eq!(*plaintext, b"{\"users\":[]}");
    }

    #[test]
    fn a_format_1_bundle_still_opens_and_is_from_no_box_in_particular() {
        let (header, plaintext) = open(FORMAT_1, "correct horse battery", 1).expect("open");
        assert_eq!(header.version, 1);
        assert_eq!(header.box_id, None);
        assert_eq!(*plaintext, b"{\"users\":[]}");
    }

    #[test]
    fn a_box_id_no_box_would_write_is_refused_before_the_passphrase_is_judged() {
        let format_2 = sealed(b"x");
        for (text, id) in [
            (FORMAT_1, BOX),
            (format_2.as_str(), "not-a-uuid"),
            (format_2.as_str(), &BOX.to_uppercase()),
        ] {
            let mut envelope: Envelope = serde_json::from_str(text).unwrap();
            envelope.header.box_id = Some(id.to_string());
            assert!(
                matches!(
                    open(&serde_json::to_string(&envelope).unwrap(), "not it", 1),
                    Err(BackupError::Malformed(_))
                ),
                "{id} in format {}",
                envelope.header.version
            );
        }
    }

    fn format_2_header() -> BundleHeader {
        let mut header = BundleHeader::default();
        header.format = FORMAT.to_string();
        header.version = 2;
        header.app_schema_version = 7;
        header.created_at = "2026-09-25T01:02:03.456789Z".parse().unwrap();
        header.source_host = "a\"b\u{1}c é".to_string();
        header.box_id = Some(BOX.to_string());
        header.app_version = "0.3.0".to_string();
        header
    }

    #[test]
    fn format_2s_sealed_bytes_never_change() {
        assert_eq!(
            String::from_utf8(aad(&format_2_header(), "Q29tbWl0")).unwrap(),
            r#"["appliance-backup",2,7,"2026-09-25T01:02:03.456789Z","a\"b\u0001c é","6f1c1e5a-3d52-4c1e-9d0b-6a8f2b7e4c10","0.3.0","Q29tbWl0"]"#
        );
    }

    #[test]
    fn a_missing_box_id_and_an_empty_one_are_sealed_apart() {
        let mut missing = format_2_header();
        missing.box_id = None;
        let mut empty = format_2_header();
        empty.box_id = Some(String::new());
        assert_ne!(aad(&missing, "c"), aad(&empty, "c"));
    }

    #[test]
    fn a_hostname_cannot_shift_bytes_into_the_app_version() {
        let provenance = Provenance {
            source_host: "h\napp=X".to_string(),
            app_version: "Y".to_string(),
            ..provenance()
        };
        let text = seal(
            b"x",
            Contains::default(),
            "correct horse battery",
            &provenance,
        )
        .expect("seal");
        let sealed: Envelope = serde_json::from_str(&text).unwrap();
        let mut shifted = sealed.clone();
        shifted.header.source_host = "h".to_string();
        shifted.header.app_version = "X\napp=Y".to_string();

        assert_ne!(
            aad(&sealed.header, &sealed.commitment),
            aad(&shifted.header, &sealed.commitment)
        );
        assert!(matches!(
            open(
                &serde_json::to_string(&shifted).unwrap(),
                "correct horse battery",
                1
            ),
            Err(BackupError::Malformed(_))
        ));
    }

    #[test]
    fn the_wrong_passphrase_does_not_open_it() {
        let text = sealed(b"secrets");
        assert!(matches!(
            open(&text, "not the passphrase", 1),
            Err(BackupError::WrongPassphrase)
        ));
    }

    #[test]
    fn the_plaintext_is_not_in_the_file() {
        let text = sealed(b"argon2id$v=19$hunter2");
        assert!(!text.contains("hunter2"), "{text}");
        assert!(!text.contains("argon2id$"), "{text}");
    }

    #[test]
    fn the_header_a_person_reads_is_not_sealed_away_from_them() {
        let text = sealed(b"x");
        assert!(text.contains("widget-01"), "{text}");
        assert!(text.contains(FORMAT), "{text}");
    }

    #[test]
    fn the_provenance_a_person_reads_cannot_be_relabelled() {
        let text = sealed(b"x");
        for rewrite in [
            (|e: &mut Envelope| e.header.source_host = "widget-99".to_string())
                as fn(&mut Envelope),
            |e: &mut Envelope| e.header.app_version = "9.9.9".to_string(),
            |e: &mut Envelope| {
                e.header.box_id = Some("11111111-1111-4111-8111-111111111111".to_string())
            },
            |e: &mut Envelope| e.header.box_id = None,
            |e: &mut Envelope| {
                e.header.version = 1;
                e.header.box_id = None;
            },
        ] {
            let mut envelope: Envelope = serde_json::from_str(&text).unwrap();
            rewrite(&mut envelope);

            assert!(
                matches!(
                    open(
                        &serde_json::to_string(&envelope).unwrap(),
                        "correct horse battery",
                        1
                    ),
                    Err(BackupError::Malformed(_))
                ),
                "a rewritten header must not open"
            );
        }
    }

    #[test]
    fn a_wrong_passphrase_and_an_altered_file_are_now_different_answers() {
        let text = sealed(b"x");

        assert!(matches!(
            open(&text, "not the passphrase", 1),
            Err(BackupError::WrongPassphrase),
        ));

        let mut envelope: Envelope = serde_json::from_str(&text).unwrap();
        envelope.commitment = serde_json::from_str::<Envelope>(&sealed(b"other"))
            .unwrap()
            .commitment;
        assert!(matches!(
            open(
                &serde_json::to_string(&envelope).unwrap(),
                "correct horse battery",
                1
            ),
            Err(BackupError::WrongPassphrase),
        ));
    }

    #[test]
    fn rewriting_the_hint_does_not_break_the_seal() {
        // Stops the AAD being tidied to cover the whole header.
        let text = sealed(b"x");
        let mut envelope: Envelope = serde_json::from_str(&text).unwrap();
        envelope.header.contains.accounts = 41;

        let (header, _) = open(
            &serde_json::to_string(&envelope).unwrap(),
            "correct horse battery",
            1,
        )
        .expect("a rewritten hint still opens");
        assert_eq!(header.contains.accounts, 41, "and it is only ever a hint");
    }

    /// What a build with dearer constants writes.
    fn sealed_dear() -> String {
        seal_at(
            b"x",
            Contains::default(),
            "correct horse battery",
            &provenance(),
            Ceiling::Unauthenticated.bounds().0 + 1,
            T_COST,
        )
        .expect("seal")
    }

    #[test]
    fn a_bundle_sealed_dearer_than_this_build_writes_opens_signed_in_and_is_refused_unauthenticated()
     {
        let text = sealed_dear();
        open(&text, "correct horse battery", 1).expect("a session may pay the general ceiling");

        let refused = super::open(&text, "correct horse battery", 1, Ceiling::Unauthenticated)
            .expect_err("priced above what a public route will pay");
        assert!(
            matches!(refused, BackupError::TooDearWithoutASession),
            "{refused}"
        );
    }

    #[test]
    fn the_unauthenticated_ceiling_answers_before_the_passphrase_is_judged() {
        let text = sealed_dear();
        assert!(matches!(
            super::open(&text, "not it", 1, Ceiling::Unauthenticated),
            Err(BackupError::TooDearWithoutASession)
        ));
    }

    #[test]
    fn a_bundle_above_the_general_ceiling_is_damaged_to_every_caller() {
        let text = sealed(b"x");
        let mut envelope: Envelope = serde_json::from_str(&text).unwrap();
        envelope.kdf.m_cost = Ceiling::General.bounds().0 + 1;
        let text = serde_json::to_string(&envelope).unwrap();
        for ceiling in [Ceiling::General, Ceiling::Unauthenticated] {
            assert!(
                matches!(
                    super::open(&text, "correct horse battery", 1, ceiling),
                    Err(BackupError::Malformed(_))
                ),
                "{ceiling:?}"
            );
        }
    }

    #[test]
    fn a_bundle_from_a_newer_build_is_refused_by_name() {
        let text = sealed(b"x");
        let mut envelope: Envelope = serde_json::from_str(&text).unwrap();
        envelope.header.version = FORMAT_VERSION + 1;
        let refused = open(&serde_json::to_string(&envelope).unwrap(), "p", 1).unwrap_err();
        assert!(
            matches!(refused, BackupError::FormatTooNew { theirs, ours: FORMAT_VERSION }
                if theirs == FORMAT_VERSION + 1),
            "{refused:?}"
        );
        assert!(
            refused.to_string().contains(&format!(
                "format {}, and this build reads {FORMAT_VERSION}",
                FORMAT_VERSION + 1
            )),
            "{refused}"
        );

        let mut envelope: Envelope = serde_json::from_str(&text).unwrap();
        envelope.header.app_schema_version = 9;
        assert!(matches!(
            open(&serde_json::to_string(&envelope).unwrap(), "p", 1),
            Err(BackupError::SchemaTooNew { theirs: 9, ours: 1 })
        ));
    }

    #[test]
    fn a_header_asking_for_absurd_work_is_refused_before_it_is_paid() {
        // Without the ceiling this test allocates 4 TiB.
        let text = sealed(b"x");
        let mut envelope: Envelope = serde_json::from_str(&text).unwrap();
        envelope.kdf.m_cost = u32::MAX;

        assert!(matches!(
            open(
                &serde_json::to_string(&envelope).unwrap(),
                "correct horse battery",
                1
            ),
            Err(BackupError::Malformed(_))
        ));
    }

    #[test]
    fn something_that_is_not_a_bundle_says_so_rather_than_failing_to_parse() {
        for not_a_bundle in [
            "",
            "{}",
            "not json at all",
            r#"{"format":"something-else"}"#,
        ] {
            assert!(
                matches!(open(not_a_bundle, "p", 1), Err(BackupError::NotABundle)),
                "{not_a_bundle:?}"
            );
        }
    }

    #[test]
    fn an_empty_passphrase_is_refused_rather_than_used() {
        assert!(matches!(
            seal(b"x", Contains::default(), "", &provenance()),
            Err(BackupError::Passphrase(_))
        ));
    }

    #[test]
    fn two_bundles_of_the_same_thing_share_no_bytes() {
        let a = sealed(b"identical");
        let b = sealed(b"identical");
        let sealed_of = |t: &str| serde_json::from_str::<Envelope>(t).unwrap().sealed;
        assert_ne!(sealed_of(&a), sealed_of(&b));
    }

    #[test]
    fn a_file_larger_than_the_cap_is_refused_before_it_is_parsed() {
        let huge = "x".repeat(MAX_BUNDLE_LEN + 1);
        assert!(matches!(
            open(&huge, "p", 1),
            Err(BackupError::TooLarge { .. })
        ));
    }

    fn seal_refused(plaintext: &[u8]) -> usize {
        match seal(
            plaintext,
            Contains::default(),
            "correct horse battery",
            &provenance(),
        ) {
            Err(BackupError::TooLarge { limit, actual }) if limit == MAX_BUNDLE_LEN => actual,
            other => panic!(
                "sealed what open would refuse: {:?}",
                other.map(|t| t.len())
            ),
        }
    }

    #[test]
    fn a_plaintext_open_would_refuse_is_not_sealed() {
        let compressible = vec![b'x'; MAX_BUNDLE_LEN + 1];
        assert_eq!(seal_refused(&compressible), MAX_BUNDLE_LEN + 1);
    }

    #[test]
    fn a_sealed_text_open_would_refuse_is_not_written() {
        let mut incompressible = vec![0; MAX_BUNDLE_LEN * 3 / 4];
        getrandom::fill(&mut incompressible).unwrap();
        assert!(seal_refused(&incompressible) > MAX_BUNDLE_LEN);
    }
}
