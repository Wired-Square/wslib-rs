//! Devices pinned to an address or left to discovery, by name
//! ([`canonical_name`]), in one JSON file in the platform's config directory
//! that every program on the machine shares.

use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use wslib_framelink_protocol::types::FRAMELINK_DEFAULT_PORT;

use crate::{DeviceId, Error, Transport};

const CONFIG_SUBDIR: &str = "framelink";
const REGISTRY_FILE_NAME: &str = "framelink.json";

/// Zephyr mcumgr SMP-over-UDP default port (`CONFIG_MCUMGR_TRANSPORT_UDP_PORT`).
pub const MCUMGR_UDP_DEFAULT_PORT: u16 = 1337;

fn default_framelink_port() -> u16 {
    FRAMELINK_DEFAULT_PORT
}

fn default_smp_port() -> u16 {
    MCUMGR_UDP_DEFAULT_PORT
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Resolution {
    /// Found by mDNS when connecting.
    Auto,
    /// Always at the stored `host`, never discovered.
    Manual,
}

/// A `Manual` device is reached at `host` on every transport, at that
/// transport's port.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRecord {
    /// The key: the device's id with its prefix stripped by [`canonical_name`].
    pub name: String,
    pub resolution: Resolution,
    /// Required for `Manual`, ignored for `Auto`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<IpAddr>,
    #[serde(default = "default_framelink_port")]
    pub framelink_port: u16,
    #[serde(default = "default_smp_port")]
    pub smp_port: u16,
}

impl DeviceRecord {
    /// Pinned to `host` at the default ports.
    pub fn manual(name: impl Into<String>, host: IpAddr) -> Self {
        Self {
            name: name.into(),
            resolution: Resolution::Manual,
            host: Some(host),
            framelink_port: FRAMELINK_DEFAULT_PORT,
            smp_port: MCUMGR_UDP_DEFAULT_PORT,
        }
    }

    pub fn auto(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            resolution: Resolution::Auto,
            host: None,
            framelink_port: FRAMELINK_DEFAULT_PORT,
            smp_port: MCUMGR_UDP_DEFAULT_PORT,
        }
    }
}

/// A device id without its transport or selection prefix: the device's name.
pub fn canonical_name(raw: &str) -> &str {
    // `ip:` and `fl:` are prefixes callers put on ids they make, not ones
    // minted here; keep them. The longer `mdns:udp:` goes before `mdns:`.
    const PREFIXES: [&str; 6] = ["mdns:udp:", "mdns:", "ble:", "udp:", "ip:", "fl:"];
    for prefix in PREFIXES {
        if let Some(rest) = raw.strip_prefix(prefix) {
            return rest;
        }
    }
    raw
}

/// Standard registry file path: `<config>/framelink/framelink.json`, where
/// `<config>` is `$XDG_CONFIG_HOME` (if absolute) or `~/.config` on Unix
/// (including macOS), and `%APPDATA%` on Windows.
pub fn registry_path() -> PathBuf {
    registry_path_in(
        cfg!(windows),
        std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from),
        std::env::var_os("HOME").map(PathBuf::from),
        std::env::var_os("APPDATA").map(PathBuf::from),
    )
}

fn registry_path_in(
    windows: bool,
    xdg_config_home: Option<PathBuf>,
    home: Option<PathBuf>,
    appdata: Option<PathBuf>,
) -> PathBuf {
    let base = if windows {
        appdata.unwrap_or_else(|| PathBuf::from("."))
    } else {
        xdg_config_home
            .filter(|p| p.is_absolute())
            .or_else(|| home.map(|h| h.join(".config")))
            .unwrap_or_else(|| PathBuf::from(".config"))
    };
    base.join(CONFIG_SUBDIR).join(REGISTRY_FILE_NAME)
}

/// The registry file, read; [`save`](Self::save) writes it back.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DeviceRegistry {
    #[serde(default)]
    devices: BTreeMap<String, DeviceRecord>,
    #[serde(skip)]
    path: Option<PathBuf>,
}

impl DeviceRegistry {
    /// The registry at [`registry_path`], empty if there is no file yet.
    pub fn open() -> Result<Self, Error> {
        Self::open_at(registry_path())
    }

    pub fn open_at(path: impl Into<PathBuf>) -> Result<Self, Error> {
        let path = path.into();
        let mut registry = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice::<DeviceRegistry>(&bytes)?,
            Err(e) if e.kind() == ErrorKind::NotFound => DeviceRegistry::default(),
            Err(e) => return Err(e.into()),
        };
        registry.path = Some(path);
        Ok(registry)
    }

    /// Replaces the file whole or not at all, readable by its owner alone.
    pub fn save(&self) -> Result<(), Error> {
        let path = self
            .path
            .as_ref()
            .ok_or_else(|| std::io::Error::other("registry opened without a path"))?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_vec_pretty(self)?;
        wslib_file_atomic::replace_private(path, &json)?;
        Ok(())
    }

    pub fn get(&self, name: &str) -> Option<&DeviceRecord> {
        self.devices.get(canonical_name(name))
    }

    pub fn list(&self) -> impl Iterator<Item = &DeviceRecord> {
        self.devices.values()
    }

    /// Inserts or replaces the record under its [`canonical_name`], so
    /// `udp:Foo` and `Foo` are one entry.
    pub fn upsert(&mut self, mut record: DeviceRecord) {
        record.name = canonical_name(&record.name).to_string();
        self.devices.insert(record.name.clone(), record);
    }

    pub fn remove(&mut self, name: &str) -> Option<DeviceRecord> {
        self.devices.remove(canonical_name(name))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConnectTarget {
    Direct(SocketAddr),
    Discover,
}

/// `Direct` for a `Manual` record with a host, at the transport's port;
/// otherwise `Discover`, as BLE always is.
pub fn resolve_target(
    registry: &DeviceRegistry,
    id: &DeviceId,
    transport: Transport,
) -> ConnectTarget {
    let Some(rec) = registry.get(id.as_str()) else {
        return ConnectTarget::Discover;
    };
    if rec.resolution != Resolution::Manual {
        return ConnectTarget::Discover;
    }
    let Some(host) = rec.host else {
        return ConnectTarget::Discover;
    };
    let port = match transport {
        Transport::Tcp => rec.framelink_port,
        Transport::Udp => rec.smp_port,
        Transport::Ble => return ConnectTarget::Discover,
    };
    ConnectTarget::Direct(SocketAddr::new(host, port))
}

/// [`resolve_target`] against the registry file; one that cannot be read is
/// logged and taken as empty.
pub fn target_for(id: &DeviceId, transport: Transport) -> ConnectTarget {
    match DeviceRegistry::open() {
        Ok(registry) => resolve_target(&registry, id, transport),
        Err(e) => {
            tracing::warn!("device registry unreadable, falling back to discovery: {e}");
            ConnectTarget::Discover
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn device_record_serde_round_trips() {
        let rec = DeviceRecord::manual("WiredFlexLink-4CD4", ip("10.0.52.162"));
        let json = serde_json::to_string(&rec).unwrap();
        let back: DeviceRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back, rec);
        assert!(json.contains(r#""resolution":"manual""#));
        assert!(json.contains(r#""host":"10.0.52.162""#));
    }

    #[test]
    fn auto_record_omits_host() {
        let rec = DeviceRecord::auto("dev");
        let json = serde_json::to_string(&rec).unwrap();
        assert!(
            !json.contains("host"),
            "host should be skipped when None: {json}"
        );
    }

    #[test]
    fn record_defaults_fill_missing_ports() {
        let rec: DeviceRecord =
            serde_json::from_str(r#"{"name":"d","resolution":"manual","host":"10.0.0.1"}"#)
                .unwrap();
        assert_eq!(rec.framelink_port, FRAMELINK_DEFAULT_PORT);
        assert_eq!(rec.smp_port, MCUMGR_UDP_DEFAULT_PORT);
    }

    #[test]
    fn canonical_name_strips_known_prefixes() {
        assert_eq!(
            canonical_name("udp:WiredFlexLink-4CD4"),
            "WiredFlexLink-4CD4"
        );
        assert_eq!(canonical_name("mdns:udp:WFL-1"), "WFL-1");
        assert_eq!(canonical_name("mdns:WFL-1"), "WFL-1");
        assert_eq!(canonical_name("ble:WFL-1"), "WFL-1");
        assert_eq!(canonical_name("fl:WFL-1"), "WFL-1");
        assert_eq!(canonical_name("ip:WFL-1"), "WFL-1");
        assert_eq!(canonical_name("WFL-1"), "WFL-1");
    }

    fn unix(xdg: Option<&str>, home: Option<&str>) -> PathBuf {
        registry_path_in(false, xdg.map(PathBuf::from), home.map(PathBuf::from), None)
    }

    #[test]
    fn the_registry_is_under_an_absolute_xdg_config_home() {
        assert_eq!(
            unix(Some("/custom/cfg"), Some("/home/u")),
            PathBuf::from("/custom/cfg/framelink/framelink.json")
        );
    }

    #[test]
    fn without_an_absolute_xdg_config_home_the_registry_is_under_dot_config() {
        let expected = PathBuf::from("/home/u/.config/framelink/framelink.json");
        assert_eq!(unix(None, Some("/home/u")), expected);
        assert_eq!(unix(Some("relative/path"), Some("/home/u")), expected);
        assert_eq!(
            unix(None, None),
            PathBuf::from(".config/framelink/framelink.json")
        );
    }

    #[test]
    fn on_windows_the_registry_is_under_appdata_whatever_xdg_says() {
        let path = registry_path_in(
            true,
            Some(PathBuf::from("/custom/cfg")),
            Some(PathBuf::from("/home/u")),
            Some(PathBuf::from(r"C:\Users\u\AppData\Roaming")),
        );
        assert_eq!(
            path,
            PathBuf::from(r"C:\Users\u\AppData\Roaming")
                .join("framelink")
                .join("framelink.json")
        );
        assert_eq!(
            registry_path_in(true, None, None, None),
            PathBuf::from("./framelink/framelink.json")
        );
    }

    #[test]
    fn registry_path_ends_with_framelink_json() {
        let p = registry_path();
        assert!(
            p.ends_with(Path::new("framelink/framelink.json")),
            "got {p:?}"
        );
    }

    #[test]
    fn open_at_missing_file_is_empty_then_save_round_trips() {
        let dir = std::env::temp_dir().join(format!("flreg-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("framelink.json");

        let mut reg = DeviceRegistry::open_at(&path).unwrap();
        assert!(reg.get("dev").is_none());

        reg.upsert(DeviceRecord::manual("dev", ip("10.0.0.5")));
        reg.save().unwrap();
        assert!(path.exists());

        let reg2 = DeviceRegistry::open_at(&path).unwrap();
        let rec = reg2.get("dev").expect("record persisted");
        assert_eq!(rec.resolution, Resolution::Manual);
        assert_eq!(rec.host, Some(ip("10.0.0.5")));

        let mut reg3 = DeviceRegistry::open_at(&path).unwrap();
        assert!(reg3.remove("dev").is_some());
        reg3.save().unwrap();
        assert!(DeviceRegistry::open_at(&path).unwrap().get("dev").is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn open_at_corrupt_json_is_a_registry_file_error() {
        let dir = std::env::temp_dir().join(format!("flreg-corrupt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("framelink.json");
        std::fs::write(&path, b"{ not json").unwrap();
        let err = DeviceRegistry::open_at(&path).unwrap_err();
        assert!(matches!(err, Error::RegistryFile(_)), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_saved_registry_is_its_owners_alone() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("flreg-mode-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("framelink.json");
        let mut reg = DeviceRegistry::open_at(&path).unwrap();
        reg.upsert(DeviceRecord::auto("dev"));
        reg.save().unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "{mode:o}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_without_path_errors() {
        let reg = DeviceRegistry::default();
        assert!(reg.save().is_err());
    }

    fn reg_with(records: Vec<DeviceRecord>) -> DeviceRegistry {
        let mut reg = DeviceRegistry::default();
        for r in records {
            reg.upsert(r);
        }
        reg
    }

    #[test]
    fn manual_resolves_to_direct_address_per_transport() {
        let reg = reg_with(vec![DeviceRecord::manual("WFL-1", ip("10.0.0.9"))]);
        assert_eq!(
            resolve_target(&reg, &DeviceId::from("udp:WFL-1"), Transport::Udp),
            ConnectTarget::Direct(SocketAddr::new(ip("10.0.0.9"), MCUMGR_UDP_DEFAULT_PORT)),
        );
        assert_eq!(
            resolve_target(&reg, &DeviceId::from("fl:WFL-1"), Transport::Tcp),
            ConnectTarget::Direct(SocketAddr::new(ip("10.0.0.9"), FRAMELINK_DEFAULT_PORT)),
        );
    }

    #[test]
    fn manual_custom_ports_are_honoured() {
        let reg = reg_with(vec![DeviceRecord {
            name: "WFL-1".into(),
            resolution: Resolution::Manual,
            host: Some(ip("10.0.0.9")),
            framelink_port: 121,
            smp_port: 9999,
        }]);
        assert_eq!(
            resolve_target(&reg, &DeviceId::from("WFL-1"), Transport::Tcp),
            ConnectTarget::Direct(SocketAddr::new(ip("10.0.0.9"), 121)),
        );
        assert_eq!(
            resolve_target(&reg, &DeviceId::from("WFL-1"), Transport::Udp),
            ConnectTarget::Direct(SocketAddr::new(ip("10.0.0.9"), 9999)),
        );
    }

    #[test]
    fn auto_unregistered_and_hostless_manual_discover() {
        let reg = reg_with(vec![
            DeviceRecord::auto("auto"),
            DeviceRecord {
                name: "broken".into(),
                resolution: Resolution::Manual,
                host: None,
                framelink_port: FRAMELINK_DEFAULT_PORT,
                smp_port: MCUMGR_UDP_DEFAULT_PORT,
            },
        ]);
        for (id, tr) in [
            ("udp:auto", Transport::Udp),
            ("udp:broken", Transport::Udp),
            ("udp:missing", Transport::Udp),
            ("fl:auto", Transport::Tcp),
        ] {
            assert_eq!(
                resolve_target(&reg, &DeviceId::from(id), tr),
                ConnectTarget::Discover
            );
        }
    }

    #[test]
    fn ble_transport_never_uses_manual_address() {
        let reg = reg_with(vec![DeviceRecord::manual("WFL-1", ip("10.0.0.9"))]);
        assert_eq!(
            resolve_target(&reg, &DeviceId::from("ble:WFL-1"), Transport::Ble),
            ConnectTarget::Discover,
        );
    }

    #[test]
    fn prefixed_name_canonicalised_on_upsert_and_lookup() {
        let mut reg = DeviceRegistry::default();
        reg.upsert(DeviceRecord::manual("udp:Foo", ip("10.0.0.1")));
        assert_eq!(reg.get("Foo").map(|r| r.name.as_str()), Some("Foo"));
        assert!(reg.get("mdns:udp:Foo").is_some());
        assert_eq!(
            resolve_target(&reg, &DeviceId::from("udp:Foo"), Transport::Udp),
            ConnectTarget::Direct(SocketAddr::new(ip("10.0.0.1"), MCUMGR_UDP_DEFAULT_PORT)),
        );
        assert!(reg.remove("udp:Foo").is_some());
    }
}
