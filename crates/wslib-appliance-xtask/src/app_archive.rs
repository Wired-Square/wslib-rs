//! An app source's signed index, alone or packed with its docker-load images,
//! as an ApplianceOS console's Apps › Install reads them.

mod signing;

use std::collections::HashSet;
use std::error::Error;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Args, Subcommand};
use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::FOUND;
use signing::{Chain, Root};

const WIRED_SQUARE: &str = "wired-square";
const MANIFEST_LABEL: &str = "com.wiredsquare.appliance.manifest";
const VERSION_LABEL: &str = "org.opencontainers.image.version";

type Failed = Box<dyn Error>;

#[derive(Debug, Subcommand)]
pub(crate) enum AppArchive {
    /// Make a throwaway root and code-signing leaf in DIR, for testing installs.
    Keys { dir: PathBuf },
    /// Print a docker-load tarball's index entry.
    Entry {
        image: PathBuf,
        /// Move its repository to this registry, keeping its path.
        #[arg(long, value_name = "HOST")]
        registry: Option<String>,
    },
    /// Exit 1 unless CERT is a code-signing leaf of the root.
    Verify {
        cert: PathBuf,
        /// The root [default: the PEM in WIRED_SQUARE_APPS_ROOT]
        #[arg(long, value_name = "PEM")]
        root: Option<PathBuf>,
    },
    /// Sign an index of the images and pack it with them into OUT.
    Pack {
        #[command(flatten)]
        signing: Signing,
        /// Move each image's repository to this registry, keeping its path.
        #[arg(long, value_name = "HOST")]
        registry: Option<String>,
        out: PathBuf,
        #[arg(required = true)]
        images: Vec<PathBuf>,
    },
    /// Sign the entries in the JSON files and pack each with its sha256-<hex>.tar found under --images.
    Sign {
        #[command(flatten)]
        signing: Signing,
        /// Where to look for the images, recursively.
        #[arg(long = "images", value_name = "DIR")]
        image_dirs: Vec<PathBuf>,
        out: PathBuf,
        #[arg(required = true)]
        entries: Vec<PathBuf>,
    },
}

#[derive(Debug, Args)]
pub(crate) struct Signing {
    /// The source the index names.
    #[arg(long)]
    source: String,
    /// The signer's certificate, then any intermediates.
    #[arg(long, value_name = "PEM")]
    cert: PathBuf,
    /// The signer's key, or - for stdin; it is never written out.
    #[arg(long, value_name = "PATH|-")]
    key: PathBuf,
    /// Refuse a signer that is not a code-signing leaf of this root; wired-square always checks, against the PEM in WIRED_SQUARE_APPS_ROOT by default.
    #[arg(long, value_name = "PEM")]
    root: Option<PathBuf>,
    /// Write OUT/index.json and OUT/index.json.sig alone, for a source with a URL.
    #[arg(long)]
    index: bool,
}

#[derive(Serialize)]
struct Index<'a> {
    schema: u32,
    source: &'a str,
    apps: &'a [Value],
}

pub(crate) fn run(command: AppArchive) -> Result<ExitCode, Failed> {
    match command {
        AppArchive::Keys { dir } => signing::keys(&dir)?,
        AppArchive::Entry { image, registry } => {
            println!("{}", entry(&image, registry.as_deref())?);
        }
        AppArchive::Verify { cert, root } => {
            let root = Root::given_or_wired_square(root)?;
            if let Some(why) = Chain::read(&cert)?.refusal(&root)? {
                eprintln!("error: {why}");
                return Ok(ExitCode::from(FOUND));
            }
        }
        AppArchive::Pack {
            signing,
            registry,
            out,
            images,
        } => {
            let entries = images
                .iter()
                .map(|image| entry(image, registry.as_deref()))
                .collect::<Result<Vec<_>, _>>()?;
            let images = entries
                .iter()
                .zip(images)
                .map(|(entry, image)| Ok((tarball(entry)?, image)))
                .collect::<Result<Vec<_>, String>>()?;
            return signing.write(&out, &entries, &images);
        }
        AppArchive::Sign {
            signing,
            image_dirs,
            out,
            entries: files,
        } => {
            let entries = files
                .iter()
                .map(|file| {
                    fs::read(file)
                        .map_err(Failed::from)
                        .and_then(|json| Ok(serde_json::from_slice::<Value>(&json)?))
                        .map_err(|e| format!("{}: {e}", file.display()))
                })
                .collect::<Result<Vec<_>, _>>()?;
            let images = match (signing.index, image_dirs.is_empty()) {
                (true, _) => Vec::new(),
                (false, true) => {
                    return Err("an archive carries its images: say where they are with \
                                --images, or write the index alone with --index"
                        .into());
                }
                (false, false) => entries
                    .iter()
                    .zip(&files)
                    .map(|(entry, file)| found_image(entry, file, &image_dirs))
                    .collect::<Result<Vec<_>, _>>()?,
            };
            return signing.write(&out, &entries, &images);
        }
    }
    Ok(ExitCode::SUCCESS)
}

impl Signing {
    /// Refuses before anything is written.
    fn write(
        &self,
        out: &Path,
        entries: &[Value],
        images: &[(String, PathBuf)],
    ) -> Result<ExitCode, Failed> {
        let root = match self.source == WIRED_SQUARE {
            true => Some(Root::given_or_wired_square(self.root.clone())?),
            false => self.root.clone().map(Root::File),
        };
        let chain = Chain::read(&self.cert)?;
        if let Some(root) = root
            && let Some(why) = chain.refusal(&root)?
        {
            eprintln!("error: {why}");
            return Ok(ExitCode::from(FOUND));
        }

        let index = serde_json::to_vec(&Index {
            schema: 1,
            source: &self.source,
            apps: entries,
        })?;
        let signature = chain.sign(&self.key, &index)?;
        let offered = format!(
            "{}: {} from {}",
            out.display(),
            offered(entries),
            self.source
        );
        if self.index {
            fs::create_dir_all(out)?;
            fs::write(out.join("index.json"), &index)?;
            fs::write(out.join("index.json.sig"), &signature)?;
            println!("{offered}; serve index.json and index.json.sig at the source's URL");
        } else {
            write_archive(out, &index, &signature, images)?;
            println!("{offered}");
        }
        Ok(ExitCode::SUCCESS)
    }
}

/// Its arch, and the manifest in its label pinned to its OCI manifest digest,
/// which is the image ID a containerd-store engine gives it.
fn entry(image: &Path, registry: Option<&str>) -> Result<Value, String> {
    let json = |name: &str| -> Result<Value, String> {
        serde_json::from_slice(&member(image, name)?).map_err(|e| format!("{name}: {e}"))
    };
    let blob = |digest: &str| json(&format!("blobs/sha256/{}", sha256_hex(digest)?));
    let field = |value: &Value, pointer: &str| -> Result<String, String> {
        value
            .pointer(pointer)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| format!("its index.json has no {pointer}"))
    };

    let derived = || -> Result<Value, String> {
        let index = json("index.json")?;
        let manifests = index["manifests"].as_array().map_or(&[][..], Vec::as_slice);
        let [manifest] = manifests else {
            return Err(format!("it holds {} images, not one", manifests.len()));
        };
        let digest = field(manifest, "/digest")?;
        let mut arch = field(manifest, "/platform/architecture")?;
        if arch == "arm" {
            arch = format!(
                "arm/{}",
                field(manifest, "/platform/variant").unwrap_or_default()
            );
        }
        let repository = rehomed(
            untagged(&field(manifest, "/annotations/io.containerd.image.name")?),
            registry,
        );

        let config = blob(&field(&blob(&digest)?, "/config/digest")?)?;
        let labels = &config["config"]["Labels"];
        let mut label: Map<String, Value> = labels[MANIFEST_LABEL]
            .as_str()
            .ok_or("the image carries no manifest label")
            .and_then(|label| {
                serde_json::from_str(label).map_err(|_| "its manifest label is not a JSON object")
            })?;
        if labels[VERSION_LABEL].as_str().map(Value::from).as_ref() != label.get("version") {
            return Err("its label and its OCI version disagree".into());
        }
        label.insert(
            "image".into(),
            json!({ "repository": repository, "digest": digest }),
        );
        Ok(json!({ "arch": arch, "manifest": label }))
    };
    derived().map_err(|e| format!("{}: {e}", image.display()))
}

fn member(image: &Path, name: &str) -> Result<Vec<u8>, String> {
    let read = || -> io::Result<Option<Vec<u8>>> {
        let mut archive = tar::Archive::new(File::open(image)?);
        for member in archive.entries()? {
            let mut member = member?;
            let path = member.path()?.into_owned();
            if path.strip_prefix(".").unwrap_or(&path) == Path::new(name) {
                let mut bytes = Vec::new();
                member.read_to_end(&mut bytes)?;
                return Ok(Some(bytes));
            }
        }
        Ok(None)
    };
    match read() {
        Ok(Some(bytes)) => Ok(bytes),
        Ok(None) => Err(format!("it holds no {name}")),
        Err(e) => Err(e.to_string()),
    }
}

fn untagged(name: &str) -> &str {
    match name.rsplit_once(':') {
        Some((repository, tag)) if !tag.contains('/') => repository,
        _ => name,
    }
}

/// With a registry, a first path component that names a host gives way to it.
fn rehomed(repository: &str, registry: Option<&str>) -> String {
    let Some(registry) = registry else {
        return repository.to_string();
    };
    let path = match repository.split_once('/') {
        Some((host, path)) if host.contains(['.', ':']) => path,
        _ => repository,
    };
    format!("{registry}/{path}")
}

fn sha256_hex(digest: &str) -> Result<&str, String> {
    digest
        .strip_prefix("sha256:")
        .filter(|hex| {
            hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        })
        .ok_or_else(|| format!("{digest:?} is not a sha256 digest"))
}

/// The name an archive carries an entry's image under.
fn tarball(entry: &Value) -> Result<String, String> {
    let digest = entry
        .pointer("/manifest/image/digest")
        .and_then(Value::as_str)
        .ok_or("an entry has no manifest.image.digest")?;
    Ok(format!("sha256-{}.tar", sha256_hex(digest)?))
}

fn found_image(entry: &Value, file: &Path, dirs: &[PathBuf]) -> Result<(String, PathBuf), Failed> {
    let name = tarball(entry).map_err(|e| format!("{}: {e}", file.display()))?;
    for dir in dirs {
        if let Some(image) = find(dir, &name)? {
            return Ok((name, image));
        }
    }
    let dirs: Vec<_> = dirs.iter().map(|d| d.display().to_string()).collect();
    Err(format!("no {name} for {} under {}", file.display(), dirs.join(" ")).into())
}

fn find(dir: &Path, name: &str) -> io::Result<Option<PathBuf>> {
    for found in fs::read_dir(dir)? {
        let found = found?;
        if found.file_name() == name {
            return Ok(Some(found.path()));
        }
        if found.file_type()?.is_dir()
            && let Some(image) = find(&found.path(), name)?
        {
            return Ok(Some(image));
        }
    }
    Ok(None)
}

fn offered(entries: &[Value]) -> String {
    let text = |value: &Value| {
        value
            .as_str()
            .map_or_else(|| value.to_string(), str::to_string)
    };
    entries
        .iter()
        .map(|entry| {
            let manifest = &entry["manifest"];
            format!(
                "{} {} at {}",
                text(&manifest["name"]),
                text(&manifest["version"]),
                text(&manifest["image"]["repository"])
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn write_archive(
    out: &Path,
    index: &[u8],
    signature: &[u8],
    images: &[(String, PathBuf)],
) -> io::Result<()> {
    let mtime = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    let header = |entry_type, mode, size| {
        let mut header = tar::Header::new_ustar();
        header.set_entry_type(entry_type);
        header.set_mode(mode);
        header.set_size(size);
        header.set_mtime(mtime);
        header
    };
    let file = |size| header(tar::EntryType::Regular, 0o644, size);

    let mut archive = tar::Builder::new(File::create(out)?);
    archive.append_data(&mut file(index.len() as u64), "index.json", index)?;
    archive.append_data(
        &mut file(signature.len() as u64),
        "index.json.sig",
        signature,
    )?;
    archive.append_data(
        &mut header(tar::EntryType::Directory, 0o755, 0),
        "images/",
        io::empty(),
    )?;
    let mut packed = HashSet::new();
    for (name, image) in images {
        if packed.insert(name) {
            let image = File::open(image)?;
            let mut header = file(image.metadata()?.len());
            archive.append_data(&mut header, format!("images/{name}"), image)?;
        }
    }
    archive.into_inner()?.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tag_goes_but_a_registry_port_stays() {
        assert_eq!(
            untagged("ghcr.io/example/widget:1.2"),
            "ghcr.io/example/widget"
        );
        assert_eq!(untagged("localhost:5000/widget"), "localhost:5000/widget");
        assert_eq!(untagged("localhost:5000/widget:1"), "localhost:5000/widget");
    }

    #[test]
    fn a_registry_replaces_only_a_host() {
        let to = Some("registry.example:5000");
        assert_eq!(
            rehomed("ghcr.io/example/widget", to),
            "registry.example:5000/example/widget"
        );
        assert_eq!(
            rehomed("localhost:5000/widget", to),
            "registry.example:5000/widget"
        );
        assert_eq!(
            rehomed("example/widget", to),
            "registry.example:5000/example/widget"
        );
        assert_eq!(rehomed("widget.io", to), "registry.example:5000/widget.io");
        assert_eq!(rehomed("example/widget", None), "example/widget");
    }

    #[test]
    fn only_a_sha256_digest_names_a_tarball() {
        let hex = "0123456789abcdef".repeat(4);
        let entry = |digest: &str| json!({ "manifest": { "image": { "digest": digest } } });
        assert_eq!(
            tarball(&entry(&format!("sha256:{hex}"))),
            Ok(format!("sha256-{hex}.tar"))
        );
        for digest in [
            format!("sha256:{}", hex.to_uppercase()),
            format!("sha512:{hex}"),
            "sha256:../x".into(),
        ] {
            assert!(tarball(&entry(&digest)).is_err(), "{digest}");
        }
    }
}
