//! `app-archive` through the process, on stand-in docker-load tarballs, with
//! each signature checked as an ApplianceOS console checks it.
#![cfg(unix)]

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::time::SystemTime;

use cms::cert::CertificateChoices;
use cms::cert::x509::Certificate;
use cms::cert::x509::der::asn1::{ObjectIdentifier, OctetString};
use cms::cert::x509::der::{Decode, Encode};
use cms::cert::x509::time::Time;
use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerIdentifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use wslib_crypto::{KeyAlgorithm, Signer};
use wslib_crypto_ca::{
    Authority, BasicConstraints, Csr, Extension, KeyIdentifierMethod, Profile, Serial, Subject,
    Validity, build_csr,
};
use wslib_crypto_x509::chain::{self, Purpose};
use wslib_crypto_x509::{ExtendedKeyUsage, pem, signature};

const EXE: &str = env!("CARGO_BIN_EXE_wslib-appliance-xtask");
const ROOT_VARIABLE: &str = "WIRED_SQUARE_APPS_ROOT";

const ID_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
const ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
const CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
const MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
const SIGNING_TIME: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.5");
const SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");

fn xtask(args: &[&dyn AsRef<std::ffi::OsStr>]) -> Command {
    let mut command = Command::new(EXE);
    command
        .arg("app-archive")
        .args(args.iter().map(|arg| arg.as_ref()))
        .env_remove(ROOT_VARIABLE)
        .stdin(Stdio::null());
    command
}

fn ran(command: &mut Command) -> (Option<i32>, String, String) {
    let Output {
        status,
        stdout,
        stderr,
    } = command.output().expect("runs");
    (
        status.code(),
        String::from_utf8_lossy(&stdout).into_owned(),
        String::from_utf8_lossy(&stderr).into_owned(),
    )
}

fn hex(n: u8) -> String {
    format!("{n:02x}").repeat(32)
}

struct StandIn {
    platform: Value,
    name: &'static str,
    label: Option<Value>,
    version: &'static str,
    manifests: usize,
}

impl Default for StandIn {
    fn default() -> Self {
        Self {
            platform: json!({ "architecture": "arm64" }),
            name: "ghcr.io/example/widget:0.0.1",
            label: Some(json!({ "name": "widget", "version": "0.0.1" })),
            version: "0.0.1",
            manifests: 1,
        }
    }
}

impl StandIn {
    /// A docker-load tarball: an OCI index, its manifest and its config, with no layers.
    fn write(&self, path: &Path) -> PathBuf {
        let mut labels = json!({ "org.opencontainers.image.version": self.version });
        if let Some(label) = &self.label {
            labels["com.wiredsquare.appliance.manifest"] = label.to_string().into();
        }
        let config = json!({ "config": { "Labels": labels } });
        let manifest = json!({ "config": { "digest": format!("sha256:{}", hex(0xc0)) } });
        let manifests: Vec<Value> = (0..self.manifests)
            .map(|_| {
                json!({
                    "digest": format!("sha256:{}", hex(0xa1)),
                    "platform": self.platform,
                    "annotations": { "io.containerd.image.name": self.name },
                })
            })
            .collect();
        let index = json!({ "manifests": manifests });

        let mut tar = tar::Builder::new(std::fs::File::create(path).expect("create"));
        for (name, value) in [
            ("index.json".to_string(), index),
            (format!("blobs/sha256/{}", hex(0xa1)), manifest),
            (format!("blobs/sha256/{}", hex(0xc0)), config),
        ] {
            let body = value.to_string();
            let mut header = tar::Header::new_ustar();
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            tar.append_data(&mut header, name, body.as_bytes())
                .expect("append");
        }
        tar.into_inner().expect("finish");
        path.to_path_buf()
    }
}

fn entry(image: &Path, registry: Option<&str>) -> (Option<i32>, Value, String) {
    let mut command = xtask(&[&"entry", &image]);
    if let Some(registry) = registry {
        command.args(["--registry", registry]);
    }
    let (code, out, err) = ran(&mut command);
    (code, serde_json::from_str(&out).unwrap_or(Value::Null), err)
}

#[test]
fn an_entry_pins_the_label_to_the_image() {
    let dir = TempDir::new().expect("tempdir");
    let image = StandIn::default().write(&dir.path().join("widget.tar"));
    let (code, said, err) = entry(&image, None);
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(
        said,
        json!({ "arch": "arm64", "manifest": {
            "name": "widget", "version": "0.0.1",
            "image": { "repository": "ghcr.io/example/widget", "digest": format!("sha256:{}", hex(0xa1)) },
        }})
    );
}

#[test]
fn an_arm_entry_names_its_variant_and_a_registry_takes_the_host() {
    let dir = TempDir::new().expect("tempdir");
    let image = StandIn {
        platform: json!({ "architecture": "arm", "variant": "v7" }),
        ..StandIn::default()
    }
    .write(&dir.path().join("widget.tar"));
    let (code, said, err) = entry(&image, Some("registry.example:5000"));
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(said["arch"], "arm/v7");
    assert_eq!(
        said["manifest"]["image"]["repository"],
        "registry.example:5000/example/widget"
    );

    let local = StandIn {
        name: "example/widget:0.0.1",
        ..StandIn::default()
    }
    .write(&dir.path().join("local.tar"));
    let (_, said, _) = entry(&local, Some("registry.example"));
    assert_eq!(
        said["manifest"]["image"]["repository"],
        "registry.example/example/widget"
    );
}

#[test]
fn an_entry_is_refused_for_two_images_a_disagreeing_version_or_no_label() {
    let dir = TempDir::new().expect("tempdir");
    for (stand_in, why) in [
        (
            StandIn {
                manifests: 2,
                ..StandIn::default()
            },
            "holds 2 images, not one",
        ),
        (
            StandIn {
                version: "0.0.2",
                ..StandIn::default()
            },
            "its label and its OCI version disagree",
        ),
        (
            StandIn {
                label: None,
                ..StandIn::default()
            },
            "the image carries no manifest label",
        ),
    ] {
        let image = stand_in.write(&dir.path().join("refused.tar"));
        let (code, _, err) = entry(&image, None);
        assert_eq!(code, Some(2), "{why}: {err}");
        assert!(err.contains(why), "{why}: {err}");
    }
}

fn keys(dir: &Path) -> PathBuf {
    let (code, said, err) = ran(&mut xtask(&[&"keys", &dir]));
    assert_eq!(code, Some(0), "{err}");
    assert!(said.contains("leaf.pem"), "{said}");
    dir.to_path_buf()
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).expect("read")
}

/// A leaf under `keys`' root with `profile`'s extensions, in `dir`.
fn odd_leaf(keys: &Path, dir: &Path, profile: &Profile) -> PathBuf {
    let provider = provider();
    let signer = |pem: &str| {
        let key = wslib_crypto::to_pkcs8(&pem::private_key(pem).expect("key")).expect("pkcs8");
        Signer::new(provider.clone(), &PrivateKeyDer::Pkcs8(key)).expect("loads")
    };
    let root = Authority::new(
        pem::certificates(&read(&keys.join("root.pem"))).expect("root")[0].clone(),
        signer(&read(&keys.join("root.key"))),
        KeyIdentifierMethod::Sha1,
    )
    .expect("authority");
    let key = wslib_crypto::KeyAlgorithm::EcP256
        .generate()
        .expect("generates");
    let key_pem = pem::encode_private_key(&key);
    let request =
        build_csr(&signer(&key_pem), &Subject::new("Not a code signer"), &[]).expect("request");
    let now = SystemTime::now();
    let leaf = root
        .issue(
            &Csr::from_der(&request, provider.signature_verification_algorithms.all)
                .expect("request"),
            profile,
            &Serial::random(&provider).expect("serial"),
            Validity {
                not_before: now,
                not_after: now + std::time::Duration::from_secs(86_400),
            },
        )
        .expect("issues");
    std::fs::create_dir_all(dir).expect("mkdir");
    std::fs::write(dir.join("leaf.key"), key_pem.as_bytes()).expect("write");
    std::fs::write(dir.join("leaf.pem"), pem::encode(pem::CERTIFICATE, &leaf)).expect("write");
    dir.to_path_buf()
}

fn pack(source: &str, keys: &Path, root: Option<&Path>, out: &Path, image: &Path) -> Command {
    let mut command = xtask(&[
        &"pack",
        &"--source",
        &source,
        &"--cert",
        &keys.join("leaf.pem"),
        &"--key",
        &keys.join("leaf.key"),
        &out,
        &image,
    ]);
    if let Some(root) = root {
        command.arg("--root").arg(root);
    }
    command
}

/// What `source.rs`'s `signed_by` checks: one signer with signed content
/// type, digest and time, chaining to `root` for code signing at that time.
fn reader_verifies(index: &[u8], signature: &[u8], root: &str) -> Result<(), String> {
    let e = |e: &dyn ToString| e.to_string();
    let info = ContentInfo::from_der(signature).map_err(|x| e(&x))?;
    assert_eq!(info.content_type, ID_SIGNED_DATA);
    let signed: SignedData = info.content.decode_as().map_err(|x| e(&x))?;
    assert_eq!(signed.encap_content_info.econtent_type, ID_DATA);
    assert!(signed.encap_content_info.econtent.is_none());
    let [signer] = signed.signer_infos.0.as_slice() else {
        return Err("not one signer".into());
    };
    assert_eq!(signer.digest_alg.oid, SHA256);
    let attributes = signer.signed_attrs.as_ref().ok_or("no signed attributes")?;
    let attribute = |oid| {
        let found = attributes.iter().find(|a| a.oid == oid).expect("attribute");
        assert_eq!(found.values.len(), 1);
        found.values.get(0).expect("value").clone()
    };
    let content_type: ObjectIdentifier = attribute(CONTENT_TYPE).decode_as().map_err(|x| e(&x))?;
    assert_eq!(content_type, ID_DATA);
    let digest: OctetString = attribute(MESSAGE_DIGEST).decode_as().map_err(|x| e(&x))?;
    if digest.as_bytes() != &Sha256::digest(index)[..] {
        return Err("tampered".into());
    }
    let at =
        Time::from_der(&attribute(SIGNING_TIME).to_der().map_err(|x| e(&x))?).map_err(|x| e(&x))?;

    let certificates: Vec<&Certificate> = signed
        .certificates
        .iter()
        .flat_map(|set| set.0.iter())
        .filter_map(|choice| match choice {
            CertificateChoices::Certificate(certificate) => Some(certificate),
            CertificateChoices::Other(_) => None,
        })
        .collect();
    let SignerIdentifier::IssuerAndSerialNumber(id) = &signer.sid else {
        return Err("not issuer and serial".into());
    };
    let leaf = certificates
        .iter()
        .find(|c| {
            c.tbs_certificate.issuer == id.issuer
                && c.tbs_certificate.serial_number == id.serial_number
        })
        .ok_or("no signer certificate")?;
    let others: Vec<_> = certificates
        .iter()
        .filter(|c| !std::ptr::eq(**c, *leaf))
        .map(|c| CertificateDer::from(c.to_der().expect("der")))
        .collect();
    let root = pem::certificates(root).map_err(|x| e(&x))?.remove(0);
    let algorithms = provider().signature_verification_algorithms.all;
    chain::verify(
        &CertificateDer::from(leaf.to_der().map_err(|x| e(&x))?),
        &others,
        &[chain::trust_anchor(&root).map_err(|x| e(&x))?],
        Purpose::CODE_SIGNING,
        SystemTime::UNIX_EPOCH + at.to_unix_duration(),
        algorithms,
    )
    .map_err(|x| e(&x))?;
    signature::verify(
        &leaf
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .map_err(|x| e(&x))?,
        &signer.signature_algorithm.to_der().map_err(|x| e(&x))?,
        &attributes.to_der().map_err(|x| e(&x))?,
        signer.signature.as_bytes(),
        algorithms,
    )
    .map_err(|x| e(&x))
}

/// Each member's path, whether its header is ustar, and its bytes.
fn members(archive: &Path) -> Vec<(String, bool, Vec<u8>)> {
    let mut archive = tar::Archive::new(std::fs::File::open(archive).expect("open"));
    archive
        .entries()
        .expect("entries")
        .map(|member| {
            let mut member = member.expect("member");
            let path = member.path().expect("path").display().to_string();
            let ustar = member.header().as_ustar().is_some();
            let mut bytes = Vec::new();
            member.read_to_end(&mut bytes).expect("read");
            (path, ustar, bytes)
        })
        .collect()
}

fn index_and_signature(archive: &Path) -> (Vec<u8>, Vec<u8>) {
    let members = members(archive);
    let body = |name: &str| {
        members
            .iter()
            .find(|(path, ..)| path == name)
            .map(|(.., bytes)| bytes.clone())
            .expect(name)
    };
    (body("index.json"), body("index.json.sig"))
}

#[test]
fn keys_are_private_and_made_once() {
    let dir = TempDir::new().expect("tempdir");
    let keys = keys(&dir.path().join("keys"));
    for file in ["root.key", "root.pem", "leaf.key", "leaf.pem"] {
        let mode = std::fs::metadata(keys.join(file))
            .expect("made")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "{file}");
    }
    let (code, _, err) = ran(&mut xtask(&[&"keys", &keys]));
    assert_eq!(code, Some(2), "{err}");
    assert!(err.contains("already holds keys"), "{err}");
}

#[test]
fn a_packed_archive_verifies_against_its_root_alone() {
    let dir = TempDir::new().expect("tempdir");
    let image = StandIn::default().write(&dir.path().join("widget.tar"));
    let keys = keys(&dir.path().join("keys"));
    let other = self::keys(&dir.path().join("other"));
    let root = keys.join("root.pem");
    let out = dir.path().join("widget-wired-square.tar");

    let (code, said, err) = ran(&mut pack("wired-square", &keys, Some(&root), &out, &image));
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(
        said,
        format!(
            "{}: widget 0.0.1 at ghcr.io/example/widget from wired-square\n",
            out.display()
        )
    );

    let members = members(&out);
    let tarball = format!("images/sha256-{}.tar", hex(0xa1));
    assert_eq!(
        members
            .iter()
            .map(|(path, ..)| path.as_str())
            .collect::<Vec<_>>(),
        ["index.json", "index.json.sig", "images/", tarball.as_str()]
    );
    assert!(members.iter().all(|(_, ustar, _)| *ustar));
    assert_eq!(members[3].2, std::fs::read(&image).expect("image"));

    let (index, signature) = index_and_signature(&out);
    let parsed: Value = serde_json::from_slice(&index).expect("json");
    assert_eq!(parsed["schema"], 1);
    assert_eq!(parsed["source"], "wired-square");
    assert_eq!(parsed["apps"][0]["manifest"]["name"], "widget");
    assert!(
        String::from_utf8_lossy(&index)
            .starts_with(r#"{"schema":1,"source":"wired-square","apps":["#)
    );
    reader_verifies(&index, &signature, &read(&root)).expect("verifies against its root");
    assert!(reader_verifies(&index, &signature, &read(&other.join("root.pem"))).is_err());
    let mut tampered = index.clone();
    tampered[1] ^= 1;
    assert!(reader_verifies(&tampered, &signature, &read(&root)).is_err());
}

#[test]
fn wired_square_refuses_a_leaf_that_is_not_its_roots_code_signer() {
    let dir = TempDir::new().expect("tempdir");
    let image = StandIn::default().write(&dir.path().join("widget.tar"));
    let keys = keys(&dir.path().join("keys"));
    let root = keys.join("root.pem");
    let end_entity = Some(Extension::critical(BasicConstraints::EndEntity));
    let leaves = [
        self::keys(&dir.path().join("other")),
        odd_leaf(
            &keys,
            &dir.path().join("server-auth"),
            &Profile {
                basic_constraints: end_entity.clone(),
                extended_key_usage: Some(Extension::non_critical(vec![
                    ExtendedKeyUsage::ServerAuth,
                ])),
                ..Profile::default()
            },
        ),
        odd_leaf(
            &keys,
            &dir.path().join("no-eku"),
            &Profile {
                basic_constraints: end_entity.clone(),
                ..Profile::default()
            },
        ),
    ];
    for leaf in leaves {
        let out = dir.path().join("refused.tar");
        let (code, _, err) = ran(&mut pack("wired-square", &leaf, Some(&root), &out, &image));
        assert_eq!(code, Some(1), "{}: {err}", leaf.display());
        assert!(err.contains("not a code-signing leaf"), "{err}");
        assert!(!out.exists(), "{}", leaf.display());

        let (code, _, err) = ran(&mut xtask(&[
            &"verify",
            &leaf.join("leaf.pem"),
            &"--root",
            &root,
        ]));
        assert_eq!(code, Some(1), "{err}");
        assert!(err.contains("not a code-signing leaf"), "{err}");
    }
    let (code, _, err) = ran(&mut xtask(&[
        &"verify",
        &keys.join("leaf.pem"),
        &"--root",
        &root,
    ]));
    assert_eq!(code, Some(0), "{err}");
}

#[test]
fn another_source_signs_unchecked_unless_given_a_root() {
    let dir = TempDir::new().expect("tempdir");
    let image = StandIn::default().write(&dir.path().join("widget.tar"));
    let keys = keys(&dir.path().join("keys"));
    let other = self::keys(&dir.path().join("other"));
    let out = dir.path().join("widget-test.tar");

    let (code, _, err) = ran(&mut pack("test-source", &other, None, &out, &image));
    assert_eq!(code, Some(0), "{err}");
    let (index, signature) = index_and_signature(&out);
    reader_verifies(&index, &signature, &read(&other.join("root.pem"))).expect("verifies");

    std::fs::remove_file(&out).expect("rm");
    let root = keys.join("root.pem");
    let (code, _, err) = ran(&mut pack("test-source", &other, Some(&root), &out, &image));
    assert_eq!(code, Some(1), "{err}");
    assert!(!out.exists());
}

#[test]
fn wired_square_takes_its_root_from_the_environment_or_refuses() {
    let dir = TempDir::new().expect("tempdir");
    let image = StandIn::default().write(&dir.path().join("widget.tar"));
    let keys = keys(&dir.path().join("keys"));
    let other = self::keys(&dir.path().join("other"));
    let out = dir.path().join("widget.tar.out");

    let (code, _, err) = ran(&mut pack("wired-square", &keys, None, &out, &image));
    assert_eq!(code, Some(2), "{err}");
    assert!(
        err.contains("--root") && err.contains(ROOT_VARIABLE),
        "{err}"
    );
    assert!(!out.exists());

    let root = read(&keys.join("root.pem"));
    let (code, _, err) =
        ran(pack("wired-square", &other, None, &out, &image).env(ROOT_VARIABLE, &root));
    assert_eq!(code, Some(1), "{err}");
    assert!(err.contains("not a code-signing leaf"), "{err}");
    assert!(!out.exists());

    let (code, _, err) =
        ran(pack("wired-square", &keys, None, &out, &image).env(ROOT_VARIABLE, &root));
    assert_eq!(code, Some(0), "{err}");
    let (index, signature) = index_and_signature(&out);
    reader_verifies(&index, &signature, &root).expect("verifies");

    let (code, _, err) = ran(xtask(&[&"verify", &keys.join("leaf.pem")]).env(ROOT_VARIABLE, &root));
    assert_eq!(code, Some(0), "{err}");
    let (code, _, err) = ran(&mut xtask(&[&"verify", &keys.join("leaf.pem")]));
    assert_eq!(code, Some(2), "{err}");
}

#[test]
fn the_key_can_come_on_stdin() {
    let dir = TempDir::new().expect("tempdir");
    let image = StandIn::default().write(&dir.path().join("widget.tar"));
    let keys = keys(&dir.path().join("keys"));
    let out = dir.path().join("widget-wired-square.tar");
    let mut child = xtask(&[
        &"pack",
        &"--source",
        &"wired-square",
        &"--cert",
        &keys.join("leaf.pem"),
        &"--key",
        &"-",
        &"--root",
        &keys.join("root.pem"),
        &out,
        &image,
    ])
    .stdin(Stdio::piped())
    .stderr(Stdio::piped())
    .stdout(Stdio::null())
    .spawn()
    .expect("runs");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(read(&keys.join("leaf.key")).as_bytes())
        .expect("key");
    let done = child.wait_with_output().expect("waits");
    assert!(
        done.status.success(),
        "{}",
        String::from_utf8_lossy(&done.stderr)
    );
    let (index, signature) = index_and_signature(&out);
    reader_verifies(&index, &signature, &read(&keys.join("root.pem"))).expect("verifies");
}

#[test]
fn entries_sign_with_their_images_found_by_digest_or_as_an_index_alone() {
    let dir = TempDir::new().expect("tempdir");
    let images = dir.path().join("images/arm64");
    std::fs::create_dir_all(&images).expect("mkdir");
    let image = StandIn::default().write(&images.join(format!("sha256-{}.tar", hex(0xa1))));
    let keys = keys(&dir.path().join("keys"));
    let root = keys.join("root.pem");
    let (_, derived, _) = entry(&image, None);
    let entry_file = dir.path().join("entry.json");
    std::fs::write(&entry_file, derived.to_string()).expect("write");
    let signing = |out: &Path| {
        let mut command = xtask(&[
            &"sign",
            &"--source",
            &"wired-square",
            &"--cert",
            &keys.join("leaf.pem"),
            &"--key",
            &keys.join("leaf.key"),
            &"--root",
            &root,
            &out,
            &entry_file,
        ]);
        command.env_remove(ROOT_VARIABLE);
        command
    };

    let out = dir.path().join("archive.tar");
    let (code, _, err) = ran(signing(&out).arg("--images").arg(dir.path().join("images")));
    assert_eq!(code, Some(0), "{err}");
    let names: Vec<_> = members(&out).into_iter().map(|(path, ..)| path).collect();
    assert_eq!(names[3], format!("images/sha256-{}.tar", hex(0xa1)));
    let (index, signature) = index_and_signature(&out);
    reader_verifies(&index, &signature, &read(&root)).expect("verifies");

    let (code, _, err) = ran(&mut signing(&dir.path().join("unpacked.tar")));
    assert_eq!(code, Some(2), "{err}");
    assert!(err.contains("--images"), "{err}");

    let served = dir.path().join("served");
    let (code, said, err) = ran(signing(&served).arg("--index"));
    assert_eq!(code, Some(0), "{err}");
    assert!(
        said.contains("serve index.json and index.json.sig"),
        "{said}"
    );
    let mut written: Vec<_> = std::fs::read_dir(&served)
        .expect("dir")
        .map(|f| f.expect("entry").file_name().into_string().expect("utf-8"))
        .collect();
    written.sort();
    assert_eq!(written, ["index.json", "index.json.sig"]);
    reader_verifies(
        &std::fs::read(served.join("index.json")).expect("index"),
        &std::fs::read(served.join("index.json.sig")).expect("signature"),
        &read(&root),
    )
    .expect("verifies");
}

#[test]
fn a_packed_index_names_its_registry() {
    let dir = TempDir::new().expect("tempdir");
    let image = StandIn::default().write(&dir.path().join("widget.tar"));
    let keys = keys(&dir.path().join("keys"));
    let served = dir.path().join("served");
    let (code, said, err) = ran(pack("test-source", &keys, None, &served, &image).args([
        "--index",
        "--registry",
        "registry.example",
    ]));
    assert_eq!(code, Some(0), "{err}");
    assert!(
        said.contains("at registry.example/example/widget"),
        "{said}"
    );
    let index: Value =
        serde_json::from_slice(&std::fs::read(served.join("index.json")).expect("index"))
            .expect("json");
    assert_eq!(
        index["apps"][0]["manifest"]["image"]["repository"],
        "registry.example/example/widget"
    );
}

/// The one use of OpenSSL left, as a cross-check: an OpenSSL 3 that knows `-purpose codesign`.
fn openssl() -> Option<PathBuf> {
    let found = std::env::var_os("OPENSSL")
        .map(PathBuf::from)
        .into_iter()
        .chain(
            [
                "openssl",
                "/opt/homebrew/opt/openssl@3/bin/openssl",
                "/usr/local/opt/openssl@3/bin/openssl",
                "/home/linuxbrew/.linuxbrew/opt/openssl@3/bin/openssl",
            ]
            .map(PathBuf::from),
        )
        .find(|candidate| {
            Command::new(candidate)
                .args(["verify", "-purpose", "codesign", "/dev/null"])
                .output()
                .is_ok_and(|said| {
                    !String::from_utf8_lossy(&[said.stdout, said.stderr].concat())
                        .to_lowercase()
                        .contains("purpose")
                })
        });
    if found.is_none() {
        eprintln!(
            "OpenSSL cross-check skipped: no OpenSSL 3 that knows -purpose codesign; set OPENSSL"
        );
    }
    found
}

fn openssl_verifies(openssl: &Path, archive: &Path, root: &Path) -> Result<(), String> {
    let dir = TempDir::new().expect("tempdir");
    let (index, signature) = index_and_signature(archive);
    std::fs::write(dir.path().join("index.json"), index).expect("write");
    std::fs::write(dir.path().join("index.json.sig"), signature).expect("write");
    let verified = Command::new(openssl)
        .args([
            "cms", "-verify", "-binary", "-inform", "DER", "-purpose", "codesign",
        ])
        .arg("-in")
        .arg(dir.path().join("index.json.sig"))
        .arg("-content")
        .arg(dir.path().join("index.json"))
        .arg("-CAfile")
        .arg(root)
        .args(["-out", "/dev/null"])
        .output()
        .expect("openssl runs");
    match verified.status.success() {
        true => Ok(()),
        false => Err(String::from_utf8_lossy(&verified.stderr).into_owned()),
    }
}

#[test]
fn openssl_verifies_a_packed_archive_too() {
    let Some(openssl) = openssl() else { return };
    let dir = TempDir::new().expect("tempdir");
    let image = StandIn::default().write(&dir.path().join("widget.tar"));
    let keys = keys(&dir.path().join("keys"));
    let root = keys.join("root.pem");
    let out = dir.path().join("widget-wired-square.tar");
    let (code, _, err) = ran(&mut pack("wired-square", &keys, Some(&root), &out, &image));
    assert_eq!(code, Some(0), "{err}");
    openssl_verifies(&openssl, &out, &root).expect("verifies");
    let other = self::keys(&dir.path().join("other"));
    assert!(openssl_verifies(&openssl, &out, &other.join("root.pem")).is_err());
}

struct RsaPublicKey(Vec<u8>);

impl rcgen::PublicKeyData for RsaPublicKey {
    fn der_bytes(&self) -> &[u8] {
        &self.0
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_RSA_SHA256
    }
}

/// A P-384 root, as the Wired Square Apps root is, and a code-signing leaf
/// under it for `leaf_key`, in `dir`.
fn p384_chain(
    dir: &Path,
    leaf_key: PrivatePkcs8KeyDer<'static>,
    leaf_public: &impl rcgen::PublicKeyData,
) -> PathBuf {
    use rcgen::{
        CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyIdMethod,
        KeyUsagePurpose, SerialNumber,
    };
    let provider = provider();
    let params = |common_name: &str| {
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params.serial_number = Some(SerialNumber::from_slice(
            &wslib_crypto::random_serial(&provider).expect("serial"),
        ));
        params
    };
    let root_signer = Signer::new(
        provider.clone(),
        &PrivateKeyDer::Pkcs8(
            KeyAlgorithm::EcP384
                .generate()
                .expect("generates")
                .clone_key(),
        ),
    )
    .expect("loads");
    let mut root = params("P-384 root");
    root.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    root.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    root.key_identifier_method = KeyIdMethod::PreSpecified(root_signer.key_identifier().to_vec());
    let root_pem = pem::encode(
        pem::CERTIFICATE,
        root.self_signed(&root_signer).expect("signs").der(),
    );
    let issuer = Issuer::new(root, root_signer);

    let mut leaf = params("signing");
    leaf.is_ca = IsCa::ExplicitNoCa;
    leaf.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::CodeSigning];
    leaf.key_identifier_method = KeyIdMethod::PreSpecified(vec![7; 20]);
    let leaf = leaf.signed_by(leaf_public, &issuer).expect("signs");

    std::fs::create_dir_all(dir).expect("mkdir");
    std::fs::write(dir.join("root.pem"), root_pem).expect("write");
    std::fs::write(
        dir.join("leaf.pem"),
        pem::encode(pem::CERTIFICATE, leaf.der()),
    )
    .expect("write");
    std::fs::write(
        dir.join("leaf.key"),
        pem::encode_private_key(&leaf_key).as_bytes(),
    )
    .expect("write");
    dir.to_path_buf()
}

fn packs_and_verifies(keys: &Path) {
    let dir = TempDir::new().expect("tempdir");
    let image = StandIn::default().write(&dir.path().join("widget.tar"));
    let root = keys.join("root.pem");
    let out = dir.path().join("widget-wired-square.tar");
    let (code, _, err) = ran(&mut pack("wired-square", keys, Some(&root), &out, &image));
    assert_eq!(code, Some(0), "{err}");
    let (index, signature) = index_and_signature(&out);
    reader_verifies(&index, &signature, &read(&root)).expect("the reader verifies");
    if let Some(openssl) = openssl() {
        openssl_verifies(&openssl, &out, &root).expect("OpenSSL verifies");
    }
}

#[test]
fn a_p384_leaf_signs_over_sha256() {
    let dir = TempDir::new().expect("tempdir");
    let key = KeyAlgorithm::EcP384.generate().expect("generates");
    let public = Signer::new(provider(), &PrivateKeyDer::Pkcs8(key.clone_key())).expect("loads");
    packs_and_verifies(&p384_chain(&dir.path().join("p384"), key, &public));
}

#[test]
fn an_rsa_3072_leaf_signs() {
    use rsa::pkcs1::EncodeRsaPublicKey;
    use rsa::pkcs8::EncodePrivateKey;
    let dir = TempDir::new().expect("tempdir");
    let key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 3072).expect("generates");
    let public = RsaPublicKey(
        key.to_public_key()
            .to_pkcs1_der()
            .expect("encodes")
            .into_vec(),
    );
    let pkcs8 = PrivatePkcs8KeyDer::from(key.to_pkcs8_der().expect("encodes").as_bytes().to_vec());
    packs_and_verifies(&p384_chain(&dir.path().join("rsa"), pkcs8, &public));
}
