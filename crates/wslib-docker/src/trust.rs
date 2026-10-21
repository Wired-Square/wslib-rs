//! The engine's trust in the registries it pulls from: one set of extra
//! authorities, written into `certs.d/<registry>/` for each registry, since the
//! engine reads a registry's authorities from there alone. Link
//! `/etc/docker/certs.d` to [`RegistryTrust::certs_d`].

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use wslib_file_atomic::replace_private;

const AUTHORITIES: &str = "authorities.pem";

/// Extra authorities for the engine, kept under a root directory.
#[derive(Debug, Clone)]
pub struct RegistryTrust {
    root: PathBuf,
    bundle: String,
}

impl RegistryTrust {
    /// Trust kept under `root`, written in each registry's directory as `bundle`,
    /// which must end `.crt` for the engine to read it.
    pub fn new(root: impl Into<PathBuf>, bundle: impl Into<String>) -> Self {
        Self {
            root: root.into(),
            bundle: bundle.into(),
        }
    }

    pub fn certs_d(&self) -> PathBuf {
        self.root.join("certs.d")
    }

    /// The authorities, replacing those before, in every registry added; none removes them.
    pub fn set_authorities(&self, authorities: &[String]) -> io::Result<()> {
        let certs_d = self.certs_d();
        fs::create_dir_all(&certs_d)?;
        let bundle = authorities.join("\n");
        write(&self.root.join(AUTHORITIES), &bundle)?;
        for entry in fs::read_dir(certs_d)? {
            write(&entry?.path().join(&self.bundle), &bundle)?;
        }
        Ok(())
    }

    /// Before a pull from `registry` ([`ImageReference::registry`](crate::ImageReference::registry)),
    /// so the engine finds the authorities there, and later ones follow.
    pub fn add_registry(&self, registry: &str) -> io::Result<()> {
        if registry.is_empty() || registry.starts_with('.') || registry.contains(['/', '\\']) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{registry:?} is not a registry"),
            ));
        }
        let bundle = match fs::read_to_string(self.root.join(AUTHORITIES)) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
            read => read?,
        };
        let dir = self.certs_d().join(registry);
        fs::create_dir_all(&dir)?;
        write(&dir.join(&self.bundle), &bundle)
    }
}

/// Readable by its owner alone, or gone when there is nothing to trust.
fn write(path: &Path, bundle: &str) -> io::Result<()> {
    if bundle.is_empty() {
        return match fs::remove_file(path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            removed => removed,
        };
    }
    replace_private(path, bundle.as_bytes())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    const CA: &str = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
    const OTHER: &str = "-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----\n";
    const BUNDLE: &str = "extra.crt";

    fn trust() -> RegistryTrust {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "wslib-docker-trust-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        RegistryTrust::new(root, BUNDLE)
    }

    fn bundle(trust: &RegistryTrust, registry: &str) -> Option<String> {
        fs::read_to_string(trust.certs_d().join(registry).join(BUNDLE)).ok()
    }

    #[test]
    fn a_registry_added_holds_the_authorities_and_follows_each_change() {
        let trust = trust();
        trust.add_registry("10.0.2.2:5443").unwrap();
        assert_eq!(bundle(&trust, "10.0.2.2:5443"), None);

        trust
            .set_authorities(&[CA.to_string(), OTHER.to_string()])
            .unwrap();
        assert_eq!(
            bundle(&trust, "10.0.2.2:5443").unwrap(),
            format!("{CA}\n{OTHER}")
        );
        trust.add_registry("ghcr.io").unwrap();
        assert_eq!(bundle(&trust, "ghcr.io"), bundle(&trust, "10.0.2.2:5443"));

        trust.set_authorities(&[OTHER.to_string()]).unwrap();
        assert_eq!(bundle(&trust, "ghcr.io").unwrap(), OTHER);
        trust.set_authorities(&[]).unwrap();
        assert_eq!(bundle(&trust, "ghcr.io"), None);
        assert_eq!(bundle(&trust, "10.0.2.2:5443"), None);
    }

    #[cfg(unix)]
    #[test]
    fn the_authorities_are_for_their_owner_alone() {
        use std::os::unix::fs::MetadataExt;
        let trust = trust();
        trust.add_registry("ghcr.io").unwrap();
        trust.set_authorities(&[CA.to_string()]).unwrap();
        for written in [
            trust.root.join(AUTHORITIES),
            trust.certs_d().join("ghcr.io").join(BUNDLE),
        ] {
            let mode = fs::metadata(&written).unwrap().mode();
            assert_eq!(mode & 0o777, 0o600, "{}", written.display());
        }
    }

    #[test]
    fn only_a_registry_is_a_directory_of_its_own() {
        let trust = trust();
        for refused in ["", "..", ".", "../etc", "a/b", "a\\b"] {
            assert!(trust.add_registry(refused).is_err(), "{refused:?}");
        }
    }
}
