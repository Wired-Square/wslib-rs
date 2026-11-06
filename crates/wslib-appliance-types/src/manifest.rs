//! What an app declares to the console that runs it as a container; the
//! console's supervisor decides everything it does not say.

use std::collections::BTreeSet;

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};

use crate::{MAX_APP_LEN, is_app_name, is_segment};

/// The newest manifest schema this build reads, raised by every field or variant
/// added; a manifest is written at its [`AppManifest::oldest_schema`].
pub const MANIFEST_SCHEMA: u32 = 4;

const MAX_VOLUMES: usize = 32;
const MAX_LISTENERS: usize = 64;
const MAX_OPTIONS: usize = 32;
const MAX_OPTION_LABEL_LEN: usize = 64;
const MAX_OPTION_DESCRIPTION_LEN: usize = 1024;
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub devices: Vec<AppDevice>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<AppOption>,
    /// The oldest ApplianceOS release that runs the app, `MAJOR.MINOR.PATCH`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_applianceos: Option<String>,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub devices: Vec<AppDevice>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<AppOption>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_applianceos: Option<String>,
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

/// A class of hotplugged device the console passes into the app.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
#[serde(deny_unknown_fields)]
pub struct AppDevice {
    pub class: DeviceClass,
    /// Only a USB class takes these; none means any vendor.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vids: Vec<UsbVendorId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum DeviceClass {
    /// `/dev/ttyACM*` and `/dev/ttyUSB*`.
    UsbSerial,
    /// `/dev/bus/usb`.
    UsbRaw,
    /// video4linux's `/dev/video*`.
    Video,
    /// The Bluetooth adapter, held by this app alone.
    Bluetooth,
}

/// A setting the app reads, its value given by the console.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct AppOption {
    pub name: String,
    pub kind: AppOptionKind,
    /// Must be given a value, so takes no default.
    #[serde(default, skip_serializing_if = "is_false")]
    pub required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AppOptionKind {
    String,
    /// A JSON number that fits an `i64`.
    Integer,
    Boolean,
    /// A list of strings.
    Strings,
}

/// Option values checked against a manifest's [`AppOption`]s.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
#[non_exhaustive]
pub struct CheckedOptions {
    /// Each value given or defaulted, by option name.
    pub values: Map<String, Value>,
    /// Required options with no value.
    pub missing: Vec<String>,
    /// Keys given that name no option, left out of `values`.
    pub dropped: Vec<String>,
}

/// Why option values are refused; never names the value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum OptionsError {
    #[error("the value of option {option} is not of its kind")]
    WrongKind { option: String },
}

/// A USB vendor ID, 4 hex digits, read in lowercase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
pub struct UsbVendorId(String);

/// Why a manifest is refused; never names the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ManifestError {
    #[error("the manifest's schema is newer than this build reads")]
    NewerSchema,
    #[error("the manifest's schema is 0, which nothing writes")]
    NoSchema,
    #[error("the manifest's schema is older than what it declares")]
    OldSchema,
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
    #[error("the minimum ApplianceOS release is not a plain MAJOR.MINOR.PATCH")]
    MinApplianceos,
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
    #[error("a device's vendor ID is not 4 hex digits")]
    VendorId,
    #[error("a device names vendor IDs, which only a USB class takes")]
    VendorIdNotUsb,
    #[error("a device class is named twice")]
    RepeatedDevice,
    #[error("the manifest declares more than {} options", MAX_OPTIONS)]
    TooManyOptions,
    #[error(
        "an option's name is not one path segment of at most {} bytes",
        MAX_APP_LEN
    )]
    OptionName,
    #[error("an option's default is not of its kind")]
    OptionDefault,
    #[error("an option is both required and given a default")]
    RequiredOptionDefault,
    #[error("an option's label is longer than {} bytes", MAX_OPTION_LABEL_LEN)]
    OptionLabel,
    #[error(
        "an option's description is longer than {} bytes",
        MAX_OPTION_DESCRIPTION_LEN
    )]
    OptionDescription,
    #[error("two options share a name")]
    RepeatedOption,
}

impl AppManifest {
    /// A manifest at schema 1 that serves, keeps and asks for nothing.
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        image: AppImage,
        arches: Vec<AppArch>,
    ) -> Self {
        Self {
            schema: 1,
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
            devices: Vec::new(),
            options: Vec::new(),
            min_applianceos: None,
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
            devices,
            options,
            min_applianceos,
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
            devices,
            options,
            min_applianceos,
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

    /// The oldest schema that carries everything this manifest declares, so an
    /// older console still runs one that declares nothing newer.
    pub fn oldest_schema(&self) -> u32 {
        if self.min_applianceos.is_some() {
            4
        } else if !self.options.is_empty() {
            3
        } else if !self.devices.is_empty() {
            2
        } else {
            1
        }
    }

    /// The first rule this manifest breaks, if any. The supervisor still checks
    /// the image's symlinks, `host` network with `NET_ADMIN`, host-mode port
    /// clashes, the Docker names it derives, and the digest against `arches`.
    pub fn validate(&self) -> Result<(), ManifestError> {
        use ManifestError::*;
        let (volumes, listeners, devices, options) =
            (&self.volumes, &self.listeners, &self.devices, &self.options);
        // One at a time, in order: the caps bound every quadratic rule after them.
        require(self.schema <= MANIFEST_SCHEMA, NewerSchema)?;
        require(self.schema > 0, NoSchema)?;
        require(self.schema >= self.oldest_schema(), OldSchema)?;
        require(is_app_name(&self.name), Name)?;
        require(is_version(&self.version), Version)?;
        require(
            self.min_applianceos
                .as_deref()
                .is_none_or(|r| release(r).is_some()),
            MinApplianceos,
        )?;
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
        )?;
        require(
            devices
                .iter()
                .flat_map(|d| &d.vids)
                .all(UsbVendorId::is_well_formed),
            VendorId,
        )?;
        require(
            devices
                .iter()
                .all(|d| d.vids.is_empty() || d.class.is_usb()),
            VendorIdNotUsb,
        )?;
        // Quadratic, but a repeat turns up within one entry more than there are classes.
        require(distinct(devices.iter().map(|d| d.class)), RepeatedDevice)?;
        require(options.len() <= MAX_OPTIONS, TooManyOptions)?;
        require(options.iter().all(|o| is_app_name(&o.name)), OptionName)?;
        require(
            options
                .iter()
                .all(|o| o.default.as_ref().is_none_or(|d| o.kind.admits(d))),
            OptionDefault,
        )?;
        require(
            options.iter().all(|o| !(o.required && o.default.is_some())),
            RequiredOptionDefault,
        )?;
        require(
            options
                .iter()
                .all(|o| has_at_most(&o.label, MAX_OPTION_LABEL_LEN)),
            OptionLabel,
        )?;
        require(
            options
                .iter()
                .all(|o| has_at_most(&o.description, MAX_OPTION_DESCRIPTION_LEN)),
            OptionDescription,
        )?;
        require(distinct(options.iter().map(|o| &o.name)), RepeatedOption)
    }

    /// `values` with each absent option's default filled in and keys naming no
    /// option dropped; a required option still absent is listed, not refused.
    pub fn check_options(
        &self,
        values: &Map<String, Value>,
    ) -> Result<CheckedOptions, OptionsError> {
        let mut checked = CheckedOptions::default();
        for option in &self.options {
            match values.get(&option.name).or(option.default.as_ref()) {
                Some(value) if option.kind.admits(value) => {
                    checked.values.insert(option.name.clone(), value.clone());
                }
                Some(_) => {
                    return Err(OptionsError::WrongKind {
                        option: option.name.clone(),
                    });
                }
                None if option.required => checked.missing.push(option.name.clone()),
                None => {}
            }
        }
        checked.dropped = values
            .keys()
            .filter(|key| !self.options.iter().any(|o| &o.name == *key))
            .cloned()
            .collect();
        Ok(checked)
    }

    /// The minimum ApplianceOS release, when a host running `running` is older
    /// or either release does not parse.
    pub fn needs_newer_host(&self, running: &str) -> Option<&str> {
        let required = self.min_applianceos.as_deref()?;
        let running = running.split_once('+').map_or(running, |(r, _)| r);
        let (running, pre) = running
            .split_once('-')
            .map_or((running, false), |(r, _)| (r, true));
        match (release(required), release(running)) {
            (Some(min), Some(at)) if at > min || (at == min && !pre) => None,
            _ => Some(required),
        }
    }
}

impl AppOption {
    /// An optional option with no default, label or description.
    pub fn new(name: impl Into<String>, kind: AppOptionKind) -> Self {
        Self {
            name: name.into(),
            kind,
            required: false,
            default: None,
            label: None,
            description: None,
        }
    }
}

impl AppOptionKind {
    fn admits(self, value: &Value) -> bool {
        match self {
            Self::String => value.is_string(),
            Self::Integer => value.is_i64(),
            Self::Boolean => value.is_boolean(),
            Self::Strings => value
                .as_array()
                .is_some_and(|items| items.iter().all(Value::is_string)),
        }
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

impl DeviceClass {
    fn is_usb(self) -> bool {
        matches!(self, Self::UsbSerial | Self::UsbRaw)
    }
}

impl UsbVendorId {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn is_well_formed(&self) -> bool {
        self.0.len() == 4 && self.0.bytes().all(|b| b.is_ascii_hexdigit())
    }
}

impl From<String> for UsbVendorId {
    fn from(mut id: String) -> Self {
        id.make_ascii_lowercase();
        Self(id)
    }
}

impl<'de> Deserialize<'de> for UsbVendorId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self::from)
    }
}

fn require(holds: bool, refusal: ManifestError) -> Result<(), ManifestError> {
    if holds { Ok(()) } else { Err(refusal) }
}

fn is_false(b: &bool) -> bool {
    !b
}

fn has_at_most(text: &Option<String>, max_len: usize) -> bool {
    text.as_ref().is_none_or(|t| t.len() <= max_len)
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

fn release(text: &str) -> Option<(u64, u64, u64)> {
    let mut numbers = text.split('.').map(|n| {
        let plain = n.bytes().all(|b| b.is_ascii_digit()) && (n == "0" || !n.starts_with('0'));
        n.parse().ok().filter(|_| plain)
    });
    let triple = (numbers.next()??, numbers.next()??, numbers.next()??);
    numbers.next().is_none().then_some(triple)
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
        let newer = r#"{"schema":5,"new":1}"#;
        let read: ManifestSchema = serde_json::from_str(newer).unwrap();
        assert_eq!(read.schema, 5);
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

    fn device(class: DeviceClass, vids: &[&str]) -> AppDevice {
        AppDevice {
            class,
            vids: vids
                .iter()
                .map(|v| UsbVendorId::from(v.to_string()))
                .collect(),
        }
    }

    fn with_devices(devices: Vec<AppDevice>) -> AppManifest {
        let mut manifest = declared();
        manifest.devices = devices;
        manifest.schema = manifest.oldest_schema();
        manifest
    }

    #[test]
    fn devices_have_a_kebab_case_class_and_lowercase_vids_on_the_wire() {
        let mut json = serde_json::to_value(declared()).unwrap();
        json["schema"] = 2.into();
        json["devices"] = serde_json::json!([
            {"class": "usb-serial", "vids": ["2FE3", "303a"]},
            {"class": "usb-raw"},
            {"class": "video"},
            {"class": "bluetooth"},
        ]);
        let read: AppManifest = serde_json::from_value(json.clone()).unwrap();
        let expected = with_devices(vec![
            device(DeviceClass::UsbSerial, &["2fe3", "303a"]),
            device(DeviceClass::UsbRaw, &[]),
            device(DeviceClass::Video, &[]),
            device(DeviceClass::Bluetooth, &[]),
        ]);
        assert_eq!(read, expected);
        assert_eq!(read.validate(), Ok(()));
        json["devices"][0]["vids"][0] = "2fe3".into();
        assert_eq!(serde_json::to_value(&read).unwrap(), json);
    }

    #[test]
    fn a_manifest_without_devices_is_written_at_schema_1_with_no_devices_key() {
        assert_eq!(declared().oldest_schema(), 1);
        let json = serde_json::to_value(declared()).unwrap();
        assert_eq!(json["schema"], 1);
        assert!(json.get("devices").is_none());
        assert_eq!(
            serde_json::from_value::<AppManifest>(json).unwrap(),
            declared()
        );
        assert_eq!(refusal(|m| m.schema = 2), Ok(()));
    }

    #[test]
    fn a_manifest_with_devices_needs_schema_2() {
        let manifest = with_devices(vec![device(DeviceClass::Video, &[])]);
        assert_eq!(manifest.schema, 2);
        assert_eq!(manifest.validate(), Ok(()));
        assert_eq!(
            refusal(|m| {
                m.devices = manifest.devices.clone();
                m.schema = 1;
            }),
            Err(ManifestError::OldSchema)
        );
    }

    #[test]
    fn a_vid_is_4_hex_digits() {
        for vid in ["", "2fe", "2fe3a", "2fg3", "0x2f", " 2fe"] {
            let manifest = with_devices(vec![device(DeviceClass::UsbSerial, &[vid])]);
            assert_eq!(manifest.validate(), Err(ManifestError::VendorId), "{vid:?}");
        }
        let manifest = with_devices(vec![device(DeviceClass::UsbRaw, &["ABCD", "0000"])]);
        assert_eq!(manifest.validate(), Ok(()));
        assert_eq!(manifest.devices[0].vids[0].as_str(), "abcd");
    }

    #[test]
    fn only_a_usb_class_takes_vids() {
        for class in [DeviceClass::Video, DeviceClass::Bluetooth] {
            let manifest = with_devices(vec![device(class, &["2fe3"])]);
            assert_eq!(
                manifest.validate(),
                Err(ManifestError::VendorIdNotUsb),
                "{class:?}"
            );
        }
    }

    #[test]
    fn a_device_class_is_named_once() {
        let manifest = with_devices(vec![
            device(DeviceClass::UsbSerial, &["2fe3"]),
            device(DeviceClass::UsbSerial, &["303a"]),
        ]);
        assert_eq!(manifest.validate(), Err(ManifestError::RepeatedDevice));
    }

    fn with_options(options: Vec<AppOption>) -> AppManifest {
        let mut manifest = declared();
        manifest.options = options;
        manifest.schema = manifest.oldest_schema();
        manifest
    }

    fn options_refusal(change: impl FnOnce(&mut AppOption)) -> Result<(), ManifestError> {
        let mut option = AppOption::new("o", AppOptionKind::String);
        change(&mut option);
        with_options(vec![option]).validate()
    }

    fn values(json: serde_json::Value) -> Map<String, Value> {
        json.as_object().unwrap().clone()
    }

    fn settings() -> AppManifest {
        let mut port = AppOption::new("port", AppOptionKind::Integer);
        port.default = Some(8080.into());
        let mut token = AppOption::new("token", AppOptionKind::String);
        token.required = true;
        with_options(vec![
            port,
            token,
            AppOption::new("verbose", AppOptionKind::Boolean),
            AppOption::new("hosts", AppOptionKind::Strings),
        ])
    }

    #[test]
    fn options_have_a_snake_case_kind_and_omit_what_they_leave_unset_on_the_wire() {
        let mut json = serde_json::to_value(declared()).unwrap();
        json["schema"] = 3.into();
        json["options"] = serde_json::json!([
            {"name": "port", "kind": "integer", "default": 8080},
            {
                "name": "token", "kind": "string", "required": true,
                "label": "Token", "description": "The upstream's API token."
            },
            {"name": "verbose", "kind": "boolean"},
            {"name": "hosts", "kind": "strings", "default": ["a", "b"]},
        ]);
        let read: AppManifest = serde_json::from_value(json.clone()).unwrap();
        let mut token = AppOption::new("token", AppOptionKind::String);
        token.required = true;
        token.label = Some("Token".to_string());
        token.description = Some("The upstream's API token.".to_string());
        let mut port = AppOption::new("port", AppOptionKind::Integer);
        port.default = Some(8080.into());
        let mut hosts = AppOption::new("hosts", AppOptionKind::Strings);
        hosts.default = Some(serde_json::json!(["a", "b"]));
        let expected = with_options(vec![
            port,
            token,
            AppOption::new("verbose", AppOptionKind::Boolean),
            hosts,
        ]);
        assert_eq!(read, expected);
        assert_eq!(read.validate(), Ok(()));
        assert_eq!(serde_json::to_value(&read).unwrap(), json);
    }

    #[test]
    fn a_label_carries_its_options_to_the_manifest() {
        let manifest = settings();
        let mut json = serde_json::to_value(&manifest).unwrap();
        json.as_object_mut().unwrap().remove("image");
        let label: AppLabel = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(serde_json::to_value(&label).unwrap(), json);
        assert_eq!(
            AppManifest::from_label(label, manifest.image.clone()),
            manifest
        );
    }

    #[test]
    fn a_manifest_with_options_needs_schema_3() {
        let manifest = settings();
        assert_eq!(manifest.schema, 3);
        assert_eq!(manifest.validate(), Ok(()));
        let mut both = with_devices(vec![device(DeviceClass::Video, &[])]);
        both.options = manifest.options.clone();
        assert_eq!(both.oldest_schema(), 3);
        for schema in [1, 2] {
            assert_eq!(
                refusal(|m| {
                    m.options = manifest.options.clone();
                    m.schema = schema;
                }),
                Err(ManifestError::OldSchema)
            );
        }
    }

    #[test]
    fn a_manifest_without_options_keeps_its_schema_and_has_no_options_key() {
        assert_eq!(declared().oldest_schema(), 1);
        assert!(
            serde_json::to_value(declared())
                .unwrap()
                .get("options")
                .is_none()
        );
        assert_eq!(
            with_devices(vec![device(DeviceClass::Video, &[])]).oldest_schema(),
            2
        );
        assert_eq!(refusal(|m| m.schema = 3), Ok(()));
    }

    #[test]
    fn an_option_is_named_like_a_listener() {
        for name in ["", "a b", "a/b", "..", &"a".repeat(MAX_APP_LEN + 1)] {
            assert_eq!(
                options_refusal(|o| o.name = name.to_string()),
                Err(ManifestError::OptionName),
                "{name:?}"
            );
        }
    }

    #[test]
    fn an_option_is_named_once() {
        let manifest = with_options(vec![
            AppOption::new("o", AppOptionKind::String),
            AppOption::new("o", AppOptionKind::Integer),
        ]);
        assert_eq!(manifest.validate(), Err(ManifestError::RepeatedOption));
    }

    #[test]
    fn options_are_capped_before_their_repeat_check() {
        let options = |n: usize| {
            (0..n)
                .map(|i| AppOption::new(format!("o{i}"), AppOptionKind::String))
                .collect()
        };
        assert_eq!(with_options(options(MAX_OPTIONS)).validate(), Ok(()));
        assert_eq!(
            with_options(options(MAX_OPTIONS + 1)).validate(),
            Err(ManifestError::TooManyOptions)
        );
        let started = std::time::Instant::now();
        assert_eq!(
            with_options(options(MAX_OPTIONS * 1000)).validate(),
            Err(ManifestError::TooManyOptions)
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }

    #[test]
    fn an_options_default_is_of_its_kind() {
        use AppOptionKind::*;
        use serde_json::json;
        for (kind, default) in [
            (String, json!(1)),
            (String, json!(null)),
            (Integer, json!("1")),
            (Integer, json!(1.5)),
            (Integer, json!(u64::MAX)),
            (Boolean, json!("true")),
            (Strings, json!("a")),
            (Strings, json!(["a", 1])),
        ] {
            assert_eq!(
                options_refusal(|o| {
                    o.kind = kind;
                    o.default = Some(default.clone());
                }),
                Err(ManifestError::OptionDefault),
                "{kind:?} {default}"
            );
        }
        for (kind, default) in [
            (String, json!("")),
            (Integer, json!(i64::MIN)),
            (Boolean, json!(false)),
            (Strings, json!([])),
        ] {
            assert_eq!(
                options_refusal(|o| {
                    o.kind = kind;
                    o.default = Some(default.clone());
                }),
                Ok(()),
                "{kind:?} {default}"
            );
        }
    }

    #[test]
    fn a_required_option_takes_no_default() {
        assert_eq!(
            options_refusal(|o| {
                o.required = true;
                o.default = Some("x".into());
            }),
            Err(ManifestError::RequiredOptionDefault)
        );
    }

    #[test]
    fn an_options_label_and_description_are_capped() {
        let text = |len: usize| Some("a".repeat(len));
        assert_eq!(
            options_refusal(|o| o.label = text(MAX_OPTION_LABEL_LEN)),
            Ok(())
        );
        assert_eq!(
            options_refusal(|o| o.label = text(MAX_OPTION_LABEL_LEN + 1)),
            Err(ManifestError::OptionLabel)
        );
        assert_eq!(
            options_refusal(|o| o.description = text(MAX_OPTION_DESCRIPTION_LEN)),
            Ok(())
        );
        assert_eq!(
            options_refusal(|o| o.description = text(MAX_OPTION_DESCRIPTION_LEN + 1)),
            Err(ManifestError::OptionDescription)
        );
    }

    #[test]
    fn checking_options_fills_defaults_and_lists_dropped_keys_and_missing_required_ones() {
        let checked = settings()
            .check_options(&values(
                serde_json::json!({"verbose": true, "colour": "red"}),
            ))
            .unwrap();
        assert_eq!(
            checked.values,
            values(serde_json::json!({"port": 8080, "verbose": true}))
        );
        assert_eq!(checked.missing, ["token"]);
        assert_eq!(checked.dropped, ["colour"]);
    }

    #[test]
    fn checking_options_accepts_a_value_of_each_kind_over_the_default() {
        let given = values(serde_json::json!({
            "port": -1, "token": "t", "verbose": false, "hosts": ["a"]
        }));
        let checked = settings().check_options(&given).unwrap();
        assert_eq!(checked.values, given);
        assert!(checked.missing.is_empty() && checked.dropped.is_empty());
    }

    #[test]
    fn checking_options_refuses_a_value_of_the_wrong_kind_naming_the_option() {
        for given in [
            serde_json::json!({"port": "80"}),
            serde_json::json!({"port": null}),
            serde_json::json!({"hosts": [1]}),
        ] {
            let refused = settings()
                .check_options(&values(given.clone()))
                .unwrap_err();
            let option = given.as_object().unwrap().keys().next().unwrap().clone();
            assert_eq!(
                refused,
                OptionsError::WrongKind {
                    option: option.clone()
                }
            );
            assert_eq!(
                refused.to_string(),
                format!("the value of option {option} is not of its kind")
            );
        }
    }

    fn needing(release: &str) -> AppManifest {
        let mut manifest = declared();
        manifest.min_applianceos = Some(release.to_string());
        manifest.schema = manifest.oldest_schema();
        manifest
    }

    #[test]
    fn a_manifest_with_a_minimum_release_needs_schema_4() {
        let manifest = needing("0.1.12");
        assert_eq!(manifest.schema, 4);
        assert_eq!(manifest.validate(), Ok(()));
        let mut json = serde_json::to_value(&manifest).unwrap();
        assert_eq!(json["min_applianceos"], "0.1.12");
        json["schema"] = 3.into();
        let older: AppManifest = serde_json::from_value(json).unwrap();
        assert_eq!(older.validate(), Err(ManifestError::OldSchema));
    }

    #[test]
    fn a_manifest_without_a_minimum_release_keeps_its_schema_and_has_no_key() {
        assert_eq!(settings().oldest_schema(), 3);
        assert!(
            serde_json::to_value(declared())
                .unwrap()
                .get("min_applianceos")
                .is_none()
        );
        assert_eq!(refusal(|m| m.schema = 4), Ok(()));
    }

    #[test]
    fn a_label_carries_its_minimum_release_to_the_manifest() {
        let manifest = needing("0.1.12");
        let mut json = serde_json::to_value(&manifest).unwrap();
        json.as_object_mut().unwrap().remove("image");
        let label: AppLabel = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(serde_json::to_value(&label).unwrap(), json);
        assert_eq!(
            AppManifest::from_label(label, manifest.image.clone()),
            manifest
        );
    }

    #[test]
    fn the_minimum_release_is_a_plain_major_minor_patch() {
        let overflowing = format!("1.{}0.0", u64::MAX);
        for release in [
            "",
            "1.2",
            "01.2.3",
            "1.02.3",
            "1.2.3-rc.1",
            "1.2.3+b",
            "v1.2.3",
            "1.2.3.4",
            "1..3",
            "1.2.-3",
            &overflowing,
        ] {
            assert_eq!(
                needing(release).validate(),
                Err(ManifestError::MinApplianceos),
                "{release:?}"
            );
        }
        for release in ["0.1.12", "0.0.0", "10.20.30"] {
            assert_eq!(needing(release).validate(), Ok(()), "{release:?}");
        }
    }

    #[test]
    fn a_host_older_than_the_minimum_release_needs_a_newer_one() {
        let manifest = needing("0.1.12");
        for running in [
            "0.1.11",
            "0.1.9",
            "0.0.99",
            "0.1.12-rc.1",
            "0.1.12-rc.1+abc",
        ] {
            assert_eq!(
                manifest.needs_newer_host(running),
                Some("0.1.12"),
                "{running}"
            );
        }
        for running in [
            "0.1.12",
            "0.1.13",
            "0.2.0",
            "1.0.0",
            "0.1.12+abc",
            "0.1.13-rc.1",
        ] {
            assert_eq!(manifest.needs_newer_host(running), None, "{running}");
        }
    }

    #[test]
    fn a_host_release_that_does_not_parse_needs_a_newer_one() {
        let manifest = needing("0.1.12");
        for running in ["", "0.1", "v0.1.12", "0.1.12.1", "unknown"] {
            assert_eq!(
                manifest.needs_newer_host(running),
                Some("0.1.12"),
                "{running:?}"
            );
        }
        assert_eq!(needing("0.1").needs_newer_host("9.9.9"), Some("0.1"));
    }

    #[test]
    fn a_manifest_without_a_minimum_release_runs_on_any_host() {
        for running in ["0.0.0", "0.1.12", "unknown"] {
            assert_eq!(declared().needs_newer_host(running), None, "{running:?}");
        }
    }
}
