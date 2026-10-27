//! What an app declares to the console that runs it as a container; the
//! console's supervisor decides everything it does not say.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{MAX_APP_LEN, is_app_name, is_segment};

/// The newest manifest schema this build reads and writes. Every field or
/// variant added raises it.
pub const MANIFEST_SCHEMA: u32 = 1;

const MAX_VOLUMES: usize = 32;
const MAX_LISTENERS: usize = 64;
const MAX_START_TIMEOUT_S: u32 = 3600;
const MAX_VERSION_LEN: usize = 64;
const MAX_REPOSITORY_LEN: usize = 255;
const MAX_PATH_LEN: usize = 255;
const RESERVED_PATHS: [&str; 5] = ["/proc", "/sys", "/dev", "/run/appliance", "/var/run"];

/// The one field of any manifest, read first: one newer than [`MANIFEST_SCHEMA`]
/// is kept and not run, never refused as corrupt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub struct ManifestSchema {
    pub schema: u32,
}

/// One app's manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct AppManifest {
    pub schema: u32,
    /// Also the app's base path, `/apps/<name>/`.
    pub name: String,
    pub version: String,
    pub image: AppImage,
    pub arches: Vec<AppArch>,
    #[serde(default)]
    pub sockets: AppSockets,
    #[serde(default)]
    pub network: AppNetwork,
    #[serde(default)]
    pub capabilities: Vec<AppCapability>,
    #[serde(default)]
    pub volumes: Vec<AppVolume>,
    #[serde(default)]
    pub listeners: Vec<AppListener>,
    #[serde(default)]
    pub health: AppHealth,
}

/// The OCI label a product's image carries its [`AppLabel`] in, as compact JSON.
pub const MANIFEST_LABEL: &str = "com.wiredsquare.appliance.manifest";

/// A manifest without its image; [`AppManifest::from_label`] adds the one loaded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct AppLabel {
    pub schema: u32,
    pub name: String,
    pub version: String,
    pub arches: Vec<AppArch>,
    #[serde(default)]
    pub sockets: AppSockets,
    #[serde(default)]
    pub network: AppNetwork,
    #[serde(default)]
    pub capabilities: Vec<AppCapability>,
    #[serde(default)]
    pub volumes: Vec<AppVolume>,
    #[serde(default)]
    pub listeners: Vec<AppListener>,
    #[serde(default)]
    pub health: AppHealth,
}

/// An image pinned by digest, never by tag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
#[serde(deny_unknown_fields)]
pub struct AppImage {
    /// `[registry[:port]/]path`, lowercase, with no tag or digest.
    pub repository: String,
    /// `sha256:` and 64 lowercase hex digits.
    pub digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
#[serde(rename_all = "snake_case")]
pub enum AppArch {
    Arm64,
    Amd64,
    #[serde(rename = "arm/v7")]
    ArmV7,
}

/// The sockets the manifest declares in the directory the console mounts into
/// the app. An image may also serve `hooks.sock` there, found by connecting.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct AppSockets {
    /// `app.sock`, the HTTP the console proxies `/apps/<name>/` to.
    #[serde(default)]
    pub app: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
#[serde(rename_all = "snake_case")]
pub enum AppNetwork {
    /// The console's bridge for apps.
    #[default]
    Bridge,
    Host,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum AppCapability {
    NetRaw,
    NetAdmin,
    NetBindService,
}

/// A directory the app keeps; the console decides where it lives on the host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
#[serde(deny_unknown_fields)]
pub struct AppVolume {
    pub name: String,
    /// Where it is mounted in the container, clear of `/proc`, `/sys`, `/dev`,
    /// `/run/appliance` and `/var/run`.
    pub at: String,
}

/// A port the app serves itself, outside the console's proxy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
#[serde(deny_unknown_fields)]
pub struct AppListener {
    pub name: String,
    pub protocol: ListenerProtocol,
    /// The default; the console decides who may move it.
    pub port: u16,
    /// A DNS-SD service type, `_name._tcp` or `_name._udp` to match `protocol`.
    pub dns_sd: Option<String>,
    /// Whether it starts on; the console decides who may turn it on or off.
    pub enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
#[serde(rename_all = "snake_case")]
pub enum ListenerProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct AppHealth {
    /// How long a new image may take to become healthy; `None` is the console's default.
    #[serde(default)]
    pub start_timeout_s: Option<u32>,
}

/// Why a manifest is refused; never names the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ManifestError {
    #[error("the manifest's schema is newer than this build reads")]
    NewerSchema,
    #[error("the manifest's schema is 0, which nothing writes")]
    NoSchema,
    #[error(
        "the app's name is not one path segment of at most {} bytes",
        MAX_APP_LEN
    )]
    Name,
    #[error(
        "the version is not 1 to {} letters, digits, '.', '+', '_', '~' or '-', starting \
         with a letter or digit",
        MAX_VERSION_LEN
    )]
    Version,
    #[error("the image's repository is not a lowercase repository with no tag or digest")]
    Repository,
    #[error("the image's digest is not sha256: and 64 lowercase hex digits")]
    Digest,
    #[error("the manifest names no architecture")]
    NoArch,
    #[error("an architecture is named twice")]
    RepeatedArch,
    #[error("a capability is named twice")]
    RepeatedCapability,
    #[error("the manifest declares more than {} volumes", MAX_VOLUMES)]
    TooManyVolumes,
    #[error(
        "a volume's name is not one path segment of at most {} bytes",
        MAX_APP_LEN
    )]
    VolumeName,
    #[error(
        "a volume's path is not an absolute path of plain segments clear of the paths the \
         console reserves"
    )]
    VolumePath,
    #[error("two volumes share a name or a path")]
    RepeatedVolume,
    #[error("the manifest declares more than {} listeners", MAX_LISTENERS)]
    TooManyListeners,
    #[error(
        "a listener's name is not one path segment of at most {} bytes",
        MAX_APP_LEN
    )]
    ListenerName,
    #[error("a listener's port is 0")]
    ListenerPort,
    #[error("a listener's DNS-SD type is not _name._tcp or _name._udp to match its protocol")]
    DnsSd,
    #[error("two listeners share a name, or a protocol and port")]
    RepeatedListener,
    #[error("the start timeout is 0")]
    StartTimeout,
    #[error("the start timeout is longer than {} seconds", MAX_START_TIMEOUT_S)]
    LongStartTimeout,
}

impl AppManifest {
    /// A manifest at [`MANIFEST_SCHEMA`] that serves, keeps and asks for nothing.
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        image: AppImage,
        arches: Vec<AppArch>,
    ) -> Self {
        Self {
            schema: MANIFEST_SCHEMA,
            name: name.into(),
            version: version.into(),
            image,
            arches,
            sockets: AppSockets::default(),
            network: AppNetwork::default(),
            capabilities: Vec::new(),
            volumes: Vec::new(),
            listeners: Vec::new(),
            health: AppHealth::default(),
        }
    }

    /// The manifest of the image whose label is `label`, unvalidated.
    pub fn from_label(label: AppLabel, image: AppImage) -> Self {
        // Built in full, so a field added to one struct alone does not compile.
        let AppLabel {
            schema,
            name,
            version,
            arches,
            sockets,
            network,
            capabilities,
            volumes,
            listeners,
            health,
        } = label;
        Self {
            schema,
            name,
            version,
            image,
            arches,
            sockets,
            network,
            capabilities,
            volumes,
            listeners,
            health,
        }
    }

    /// The manifest for an image nobody signed: `/data` and the image's `VOLUME`
    /// paths as volumes, and every exposed port a listener that starts off. One
    /// that fails [`validate`](Self::validate) refuses the image.
    pub fn generated(
        name: impl Into<String>,
        version: impl Into<String>,
        image: AppImage,
        arch: AppArch,
        volume_paths: impl IntoIterator<Item = impl AsRef<str>>,
        exposed: impl IntoIterator<Item = (ListenerProtocol, u16)>,
    ) -> Self {
        let mut manifest = Self::new(name, version, image, vec![arch]);
        let mut paths: BTreeSet<String> = volume_paths
            .into_iter()
            .map(|path| path.as_ref().trim_matches('/').to_string())
            .collect();
        paths.remove("data");
        manifest.volumes = std::iter::once("data".to_string())
            .chain(paths)
            .map(|inside| AppVolume {
                name: inside.replace('/', "-"),
                at: format!("/{inside}"),
            })
            .collect();
        manifest.listeners = exposed
            .into_iter()
            .map(|(protocol, port)| AppListener {
                name: format!("{}-{port}", protocol.as_str()),
                protocol,
                port,
                dns_sd: None,
                enabled: false,
            })
            .collect();
        manifest
    }

    /// The first rule this manifest breaks, if any. The supervisor still checks
    /// the image's symlinks, `host` network with `NET_ADMIN`, host-mode port
    /// clashes, the Docker names it derives, and the digest against `arches`.
    pub fn validate(&self) -> Result<(), ManifestError> {
        use ManifestError::*;
        let (volumes, listeners) = (&self.volumes, &self.listeners);
        // One at a time, in order: the caps bound every quadratic rule after them.
        require(self.schema <= MANIFEST_SCHEMA, NewerSchema)?;
        require(self.schema > 0, NoSchema)?;
        require(is_app_name(&self.name), Name)?;
        require(is_version(&self.version), Version)?;
        require(is_repository(&self.image.repository), Repository)?;
        require(is_digest(&self.image.digest), Digest)?;
        require(!self.arches.is_empty(), NoArch)?;
        require(distinct(&self.arches), RepeatedArch)?;
        require(distinct(&self.capabilities), RepeatedCapability)?;
        require(volumes.len() <= MAX_VOLUMES, TooManyVolumes)?;
        require(volumes.iter().all(|v| is_app_name(&v.name)), VolumeName)?;
        require(volumes.iter().all(|v| is_volume_path(&v.at)), VolumePath)?;
        require(
            distinct(volumes.iter().map(|v| &v.name)) && distinct(volumes.iter().map(|v| &v.at)),
            RepeatedVolume,
        )?;
        require(listeners.len() <= MAX_LISTENERS, TooManyListeners)?;
        require(listeners.iter().all(|l| is_app_name(&l.name)), ListenerName)?;
        require(listeners.iter().all(|l| l.port != 0), ListenerPort)?;
        require(listeners.iter().all(has_its_dns_sd_type), DnsSd)?;
        require(
            distinct(listeners.iter().map(|l| &l.name))
                && distinct(listeners.iter().map(|l| (l.protocol, l.port))),
            RepeatedListener,
        )?;
        require(self.health.start_timeout_s != Some(0), StartTimeout)?;
        require(
            self.health
                .start_timeout_s
                .is_none_or(|s| s <= MAX_START_TIMEOUT_S),
            LongStartTimeout,
        )
    }
}

impl ListenerProtocol {
    fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

fn require(holds: bool, refusal: ManifestError) -> Result<(), ManifestError> {
    if holds { Ok(()) } else { Err(refusal) }
}

fn distinct<T: PartialEq>(items: impl IntoIterator<Item = T>) -> bool {
    let items: Vec<T> = items.into_iter().collect();
    items
        .iter()
        .enumerate()
        .all(|(i, item)| !items[..i].contains(item))
}

fn is_version(version: &str) -> bool {
    version.len() <= MAX_VERSION_LEN
        && version.starts_with(|c: char| c.is_ascii_alphanumeric())
        && version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".+_~-".contains(&b))
}

fn is_repository(repository: &str) -> bool {
    let (first, rest) = repository.split_once('/').unwrap_or(("", repository));
    let first_holds = if !(first.contains(['.', ':']) || first == "localhost") {
        first.is_empty() || is_path_component(first)
    } else {
        match first.split_once(':') {
            None => is_domain(first),
            Some((host, port)) => {
                is_domain(host)
                    && port.bytes().all(|b| b.is_ascii_digit())
                    && port.parse::<u16>().is_ok_and(|port| port > 0)
            }
        }
    };
    repository.len() <= MAX_REPOSITORY_LEN && first_holds && rest.split('/').all(is_path_component)
}

/// Docker's, lowercase: labels of letters, digits and inner `-`, joined by `.`.
fn is_domain(host: &str) -> bool {
    host.split('.').all(|label| {
        let alphanumeric = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit();
        label.starts_with(alphanumeric)
            && label.ends_with(alphanumeric)
            && label.chars().all(|c| alphanumeric(c) || c == '-')
    })
}

/// Docker's: lowercase letters and digits, separated by `.`, `_`, `__` or `-`s.
fn is_path_component(part: &str) -> bool {
    let alphanumeric = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit();
    part.starts_with(alphanumeric)
        && part.ends_with(alphanumeric)
        && part.split(alphanumeric).all(|separator| {
            matches!(separator, "" | "." | "_" | "__") || separator.bytes().all(|b| b == b'-')
        })
}

fn is_digest(digest: &str) -> bool {
    digest.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

fn is_volume_path(at: &str) -> bool {
    let within = |path: &str, root: &str| {
        path.strip_prefix(root)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
    };
    at.len() <= MAX_PATH_LEN
        && at
            .strip_prefix('/')
            .is_some_and(|inside| inside.split('/').all(is_segment))
        && !RESERVED_PATHS
            .iter()
            .any(|reserved| within(at, reserved) || within(reserved, at))
}

fn has_its_dns_sd_type(listener: &AppListener) -> bool {
    let Some(kind) = &listener.dns_sd else {
        return true;
    };
    kind.strip_prefix('_')
        .and_then(|rest| rest.strip_suffix(listener.protocol.as_str()))
        .and_then(|rest| rest.strip_suffix("._"))
        .is_some_and(|service| {
            (1..=15).contains(&service.len())
                && !service.starts_with('-')
                && !service.ends_with('-')
                && !service.contains("--")
                && service.bytes().any(|b| b.is_ascii_lowercase())
                && service
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn image(repository: &str) -> AppImage {
        AppImage {
            repository: repository.to_string(),
            digest: DIGEST.to_string(),
        }
    }

    fn declared() -> AppManifest {
        let mut manifest = AppManifest::new(
            "hello",
            "1.2.3",
            image("ghcr.io/example/hello"),
            vec![AppArch::Arm64, AppArch::ArmV7],
        );
        manifest.sockets.app = true;
        manifest.capabilities = vec![AppCapability::NetRaw];
        manifest.volumes = vec![AppVolume {
            name: "data".to_string(),
            at: "/data".to_string(),
        }];
        manifest.listeners = vec![AppListener {
            name: "frames".to_string(),
            protocol: ListenerProtocol::Tcp,
            port: 120,
            dns_sd: Some("_frames._tcp".to_string()),
            enabled: true,
        }];
        manifest.health.start_timeout_s = Some(120);
        manifest
    }

    fn volume(i: usize) -> AppVolume {
        AppVolume {
            name: format!("v{i}"),
            at: format!("/v{i}"),
        }
    }

    fn listener(i: usize) -> AppListener {
        AppListener {
            name: format!("l{i}"),
            protocol: ListenerProtocol::Tcp,
            port: 1000 + i as u16,
            dns_sd: None,
            enabled: false,
        }
    }

    fn refusal(change: impl FnOnce(&mut AppManifest)) -> Result<(), ManifestError> {
        let mut manifest = declared();
        change(&mut manifest);
        manifest.validate()
    }

    #[test]
    fn a_declared_manifest_has_this_wire_shape() {
        let json = serde_json::json!({
            "schema": 1,
            "name": "hello",
            "version": "1.2.3",
            "image": {"repository": "ghcr.io/example/hello", "digest": DIGEST},
            "arches": ["arm64", "arm/v7"],
            "sockets": {"app": true},
            "network": "bridge",
            "capabilities": ["NET_RAW"],
            "volumes": [{"name": "data", "at": "/data"}],
            "listeners": [{
                "name": "frames", "protocol": "tcp", "port": 120,
                "dns_sd": "_frames._tcp", "enabled": true
            }],
            "health": {"start_timeout_s": 120},
        });
        assert_eq!(serde_json::to_value(declared()).unwrap(), json);
        assert_eq!(
            serde_json::from_value::<AppManifest>(json).unwrap(),
            declared()
        );
        assert_eq!(declared().validate(), Ok(()));
    }

    #[test]
    fn an_absent_optional_field_means_nothing_asked_for() {
        let read: AppManifest = serde_json::from_value(serde_json::json!({
            "schema": 1,
            "name": "hello",
            "version": "1",
            "image": {"repository": "hello", "digest": DIGEST},
            "arches": ["amd64"],
        }))
        .unwrap();
        assert_eq!(
            read,
            AppManifest::new("hello", "1", image("hello"), vec![AppArch::Amd64])
        );
    }

    #[test]
    fn a_field_this_build_does_not_know_is_refused_at_parse() {
        let mut json = serde_json::to_value(declared()).unwrap();
        json["privileged"] = true.into();
        assert!(serde_json::from_value::<AppManifest>(json).is_err());
        let mut json = serde_json::to_value(declared()).unwrap();
        json["sockets"]["hooks"] = true.into();
        assert!(serde_json::from_value::<AppManifest>(json).is_err());
    }

    #[test]
    fn a_label_is_the_manifest_without_its_image_and_round_trips() {
        let mut json = serde_json::to_value(declared()).unwrap();
        json.as_object_mut().unwrap().remove("image");
        let label: AppLabel = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(serde_json::to_value(&label).unwrap(), json);
        assert_eq!(AppManifest::from_label(label, declared().image), declared());
    }

    #[test]
    fn a_label_naming_an_image_is_refused_at_parse() {
        let json = serde_json::to_value(declared()).unwrap();
        let refused = serde_json::from_value::<AppLabel>(json).unwrap_err();
        assert!(refused.to_string().contains("image"), "{refused}");
    }

    #[test]
    fn a_newer_or_zero_schema_is_refused() {
        assert_eq!(
            refusal(|m| m.schema = MANIFEST_SCHEMA + 1),
            Err(ManifestError::NewerSchema)
        );
        assert_eq!(refusal(|m| m.schema = 0), Err(ManifestError::NoSchema));
    }

    #[test]
    fn a_newer_manifest_reads_its_schema_and_nothing_else() {
        let newer = r#"{"schema":2,"new":1}"#;
        let read: ManifestSchema = serde_json::from_str(newer).unwrap();
        assert_eq!(read.schema, 2);
        assert!(serde_json::from_str::<AppManifest>(newer).is_err());
        assert!(serde_json::from_str::<ManifestSchema>("{}").is_err());
    }

    #[test]
    fn a_name_or_version_out_of_shape_is_refused() {
        for name in ["", "..", "../x", "a/b", "a b", &"a".repeat(MAX_APP_LEN + 1)] {
            assert_eq!(
                refusal(|m| m.name = name.to_string()),
                Err(ManifestError::Name),
                "{name:?}"
            );
        }
        for version in [
            "",
            "1 2",
            "-1",
            ".1",
            "v1/2",
            "1:2",
            "1@2",
            "1\"",
            &"1".repeat(MAX_VERSION_LEN + 1),
        ] {
            assert_eq!(
                refusal(|m| m.version = version.to_string()),
                Err(ManifestError::Version),
                "{version:?}"
            );
        }
        for version in ["1", "v1.2.3-rc.1+build_7~x", &"1".repeat(MAX_VERSION_LEN)] {
            assert_eq!(
                refusal(|m| m.version = version.to_string()),
                Ok(()),
                "{version:?}"
            );
        }
    }

    #[test]
    fn an_image_is_pinned_by_digest_and_names_no_tag() {
        for digest in [
            "",
            "latest",
            "sha256:",
            "sha256:0123",
            &DIGEST.to_uppercase().replace("SHA256", "sha256"),
            &DIGEST.replace("sha256", "sha512"),
            &format!("{DIGEST}0"),
        ] {
            assert_eq!(
                refusal(|m| m.image.digest = digest.to_string()),
                Err(ManifestError::Digest),
                "{digest:?}"
            );
        }
        for repository in [
            "",
            "Hello",
            "hello:latest",
            "ghcr.io/example/hello:1",
            "a//b",
            "a/",
            "-a",
            "a@sha256",
            "localhost:port/a",
            "localhost:0/a",
            "localhost:65536/a",
            "localhost:/a",
            "my_reg.io:5000/a",
            "reg-.io/a",
            "reg..io/a",
            "localhost:+80/a",
            "a..b",
            "a___b",
            "a._b",
            "a-_b",
        ] {
            assert_eq!(
                refusal(|m| m.image.repository = repository.to_string()),
                Err(ManifestError::Repository),
                "{repository:?}"
            );
        }
        for repository in [
            "hello",
            "grafana/grafana",
            "localhost:5000/a/b",
            "registry.example.com/a.b_c-d",
            "localhost:65535/a__b---c",
            "my-reg.example.io:5000/a",
            "my_org/app",
        ] {
            assert_eq!(
                refusal(|m| m.image.repository = repository.to_string()),
                Ok(()),
                "{repository:?}"
            );
        }
    }

    #[test]
    fn arches_and_capabilities_are_named_once_and_arches_at_least_once() {
        assert_eq!(refusal(|m| m.arches.clear()), Err(ManifestError::NoArch));
        assert_eq!(
            refusal(|m| m.arches.push(AppArch::Arm64)),
            Err(ManifestError::RepeatedArch)
        );
        assert_eq!(
            refusal(|m| m.capabilities.push(AppCapability::NetRaw)),
            Err(ManifestError::RepeatedCapability)
        );
    }

    #[test]
    fn a_volume_is_a_plain_absolute_path_clear_of_the_hosts_own() {
        for at in [
            "data",
            "/",
            "/data/",
            "//data",
            "/data/../etc",
            "/a/./b",
            "/a b",
            "/proc",
            "/sys/x",
            "/dev",
            "/run",
            "/run/appliance/x",
            "/var",
            "/var/run",
            "/var/run/appliance",
        ] {
            assert_eq!(
                refusal(|m| m.volumes[0].at = at.to_string()),
                Err(ManifestError::VolumePath),
                "{at:?}"
            );
        }
        for at in ["/run/app", "/var/lib/x", "/var/running", "/var/run2"] {
            assert_eq!(
                refusal(|m| m.volumes[0].at = at.to_string()),
                Ok(()),
                "{at:?}"
            );
        }
        assert_eq!(
            refusal(|m| m.volumes[0].name = "a/b".to_string()),
            Err(ManifestError::VolumeName)
        );
        let twin = |name: &str, at: &str| AppVolume {
            name: name.to_string(),
            at: at.to_string(),
        };
        assert_eq!(
            refusal(|m| m.volumes.push(twin("data", "/other"))),
            Err(ManifestError::RepeatedVolume)
        );
        assert_eq!(
            refusal(|m| m.volumes.push(twin("other", "/data"))),
            Err(ManifestError::RepeatedVolume)
        );
    }

    #[test]
    fn a_listener_has_a_port_a_unique_name_and_a_type_matching_its_protocol() {
        assert_eq!(
            refusal(|m| m.listeners[0].port = 0),
            Err(ManifestError::ListenerPort)
        );
        assert_eq!(
            refusal(|m| m.listeners[0].name = "a b".to_string()),
            Err(ManifestError::ListenerName)
        );
        for kind in [
            "_frames._udp",
            "frames._tcp",
            "_._tcp",
            "_-frames._tcp",
            "_Frames._tcp",
            "_framesframesframes._tcp",
            "_frames.tcp",
            "_123._tcp",
            "_fr--ames._tcp",
        ] {
            assert_eq!(
                refusal(|m| m.listeners[0].dns_sd = Some(kind.to_string())),
                Err(ManifestError::DnsSd),
                "{kind:?}"
            );
        }
        let mut twin = declared().listeners[0].clone();
        twin.port = 121;
        assert_eq!(
            refusal(|m| m.listeners.push(twin)),
            Err(ManifestError::RepeatedListener)
        );
        let mut twin = declared().listeners[0].clone();
        twin.name = "other".to_string();
        assert_eq!(
            refusal(|m| m.listeners.push(twin.clone())),
            Err(ManifestError::RepeatedListener)
        );
        twin.protocol = ListenerProtocol::Udp;
        twin.dns_sd = None;
        assert_eq!(refusal(|m| m.listeners.push(twin)), Ok(()));
        assert_eq!(
            refusal(|m| m.listeners[0].dns_sd = Some("_abcdefghijklmn1._tcp".to_string())),
            Ok(())
        );
    }

    #[test]
    fn the_caps_are_checked_before_any_quadratic_rule() {
        let started = std::time::Instant::now();
        let many_volumes = refusal(|m| m.volumes = (0..MAX_VOLUMES * 1000).map(volume).collect());
        let many_listeners =
            refusal(|m| m.listeners = (0..MAX_LISTENERS * 1000).map(listener).collect());
        assert_eq!(many_volumes, Err(ManifestError::TooManyVolumes));
        assert_eq!(many_listeners, Err(ManifestError::TooManyListeners));
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }

    #[test]
    fn volumes_listeners_and_the_start_timeout_are_capped() {
        assert_eq!(
            refusal(|m| m.volumes = (0..MAX_VOLUMES).map(volume).collect()),
            Ok(())
        );
        assert_eq!(
            refusal(|m| m.volumes = (0..=MAX_VOLUMES).map(volume).collect()),
            Err(ManifestError::TooManyVolumes)
        );
        assert_eq!(
            refusal(|m| m.listeners = (0..MAX_LISTENERS).map(listener).collect()),
            Ok(())
        );
        assert_eq!(
            refusal(|m| m.listeners = (0..=MAX_LISTENERS).map(listener).collect()),
            Err(ManifestError::TooManyListeners)
        );
        assert_eq!(
            refusal(|m| m.health.start_timeout_s = Some(0)),
            Err(ManifestError::StartTimeout)
        );
        assert_eq!(
            refusal(|m| m.health.start_timeout_s = Some(MAX_START_TIMEOUT_S)),
            Ok(())
        );
        assert_eq!(
            refusal(|m| m.health.start_timeout_s = Some(MAX_START_TIMEOUT_S + 1)),
            Err(ManifestError::LongStartTimeout)
        );
    }

    #[test]
    fn a_generated_manifest_asks_for_nothing_and_starts_no_listener() {
        let manifest = AppManifest::generated(
            "grafana",
            "11.2.0",
            image("docker.io/grafana/grafana"),
            AppArch::Arm64,
            ["/var/lib/grafana/", "/data", "var/lib/grafana"],
            [(ListenerProtocol::Tcp, 3000), (ListenerProtocol::Udp, 3000)],
        );
        assert_eq!(manifest.validate(), Ok(()));
        assert_eq!(manifest.sockets, AppSockets::default());
        assert_eq!(manifest.network, AppNetwork::Bridge);
        assert!(manifest.capabilities.is_empty());
        assert_eq!(manifest.health, AppHealth::default());
        assert_eq!(
            manifest.volumes,
            [("data", "/data"), ("var-lib-grafana", "/var/lib/grafana")].map(|(name, at)| {
                AppVolume {
                    name: name.to_string(),
                    at: at.to_string(),
                }
            })
        );
        let listeners: Vec<_> = manifest
            .listeners
            .iter()
            .map(|l| (l.name.as_str(), l.port, l.enabled, l.dns_sd.is_none()))
            .collect();
        assert_eq!(
            listeners,
            [
                ("tcp-3000", 3000, false, true),
                ("udp-3000", 3000, false, true)
            ]
        );
    }

    #[test]
    fn a_generated_manifest_does_not_depend_on_the_order_of_volume_paths() {
        let generated = |paths: [&str; 3]| {
            AppManifest::generated("x", "1", image("x"), AppArch::Amd64, paths, [])
        };
        let manifest = generated(["/srv", "/data", "/etc/x"]);
        assert_eq!(manifest, generated(["/etc/x", "/srv", "/data"]));
        let ats: Vec<_> = manifest.volumes.iter().map(|v| v.at.as_str()).collect();
        assert_eq!(ats, ["/data", "/etc/x", "/srv"]);
    }
}
