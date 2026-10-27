//! `appliance.toml`, parsed and checked: one product's system identity and the
//! targets built from it.
//!
//! This is the only place that decides what a legal appliance is. Checking
//! collects every problem rather than stopping at the first, and each field
//! that does not follow from `name` is a warning, so a half-finished rename is
//! visible.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use wslib_appliance_types::manifest::{AppArch, AppImage, AppLabel, AppManifest, ManifestError};

/// Linux's `sun_path` is 108 bytes including the terminating NUL.
const SOCKET_PATH_MAX: usize = 107;

/// What shadow's `useradd` and `groupadd` enforce on Linux.
const NAME_MAX: usize = 32;

/// The size of the build whose SQLite had been dead-code-eliminated.
const THE_BUILD_THAT_GOT_THROUGH: u64 = 1_600_000;

/// Whatever `https_port` says: `config.toml` can move it below 1024 without a
/// new unit.
pub const MANDATORY_CAPABILITIES: [&str; 1] = ["CAP_NET_BIND_SERVICE"];

/// Without `AF_NETLINK`, `getifaddrs` returns nothing.
pub const MANDATORY_ADDRESS_FAMILIES: [&str; 4] = ["AF_UNIX", "AF_INET", "AF_INET6", "AF_NETLINK"];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Appliance {
    pub name: String,
    pub binary: String,
    pub user: String,
    pub group: String,
    pub config_dir: PathBuf,
    pub state_dir: PathBuf,
    pub runtime_dir: PathBuf,
    pub socket: PathBuf,
    pub env_prefix: String,
    pub address_families: Vec<String>,
    pub capabilities: Vec<String>,
    pub package: Package,
    #[serde(default)]
    pub targets: Targets,
}

/// Each rendered into `scaffold/targets/<target>/`; at least one is declared.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Targets {
    pub deb: Option<Deb>,
    pub docker: Option<Docker>,
}

/// `[targets.docker]`: an image a console runs behind its proxy.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Docker {
    /// `[registry[:port]/]path`, with no tag or digest.
    pub repository: String,
    /// The product's source, an `https://` URL.
    pub source: String,
}

/// `[targets.deb]`: the package, for a Debian or Ubuntu host.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Deb {
    /// The package's name, when it is not the system name.
    #[serde(default)]
    pub package: Option<String>,
    /// The package file's `bind_address`.
    #[serde(default = "every_address")]
    pub bind_address: String,
    /// The package file's `https_port`.
    #[serde(default = "unprivileged_https_port")]
    pub https_port: u16,
    /// What this package suggests in place of `[package] suggests`.
    #[serde(default)]
    pub suggests: Option<Vec<String>>,
}

fn every_address() -> String {
    "0.0.0.0".to_string()
}

fn unprivileged_https_port() -> u16 {
    8443
}

/// The package's directory under `scaffold/targets/`, and `make-deb.sh`'s
/// `--target`.
pub const DEB: &str = "deb";

/// The image's label, beside `appliance.toml`.
pub const MANIFEST: &str = "manifest.json";

type Manifest<'a> = Result<&'a str, &'a std::io::Error>;

/// What the image ships, which a volume may not be at, under or above.
const IMAGE_OWNED: [&str; 6] = ["/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc/ssl"];

/// The base's `0700` directories: a volume under one is out of the app's reach.
const UNREACHABLE: [&str; 2] = ["/root", "/home/nonroot"];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Package {
    pub section: String,
    pub maintainer: String,
    pub description: String,
    pub depends: Vec<String>,
    pub suggests: Vec<String>,
    pub min_binary_bytes: u64,

    /// The product's built browser bundle, relative to its repository root;
    /// absent is a headless appliance.
    pub ui_dist: Option<String>,

    /// `<hooks_dir>/postinst.d/*` and `<hooks_dir>/prerm.d/*`, relative to the
    /// repository root.
    #[serde(default)]
    pub hooks_dir: Option<String>,

    /// Files to ship, destination on the box → source relative to the
    /// repository root, each `0644`. A destination under `/etc` is a conffile.
    #[serde(default)]
    pub files: BTreeMap<String, String>,
}

/// Why an `appliance.toml` could not be turned into a scaffold.
#[derive(Debug, thiserror::Error)]
pub enum ModelError {
    #[error("{}: {because}", path.display())]
    Read { path: PathBuf, because: String },

    #[error("{}: {because}", path.display())]
    Parse { path: PathBuf, because: String },

    #[error(
        "{}: {}\n  - {}",
        path.display(),
        if problems.len() == 1 { "one problem to fix before this can be rendered" }
        else { "problems to fix before this can be rendered" },
        problems.join("\n  - ")
    )]
    Invalid {
        path: PathBuf,
        problems: Vec<String>,
    },
}

/// What checking found: a problem refuses the render, a warning does not.
#[derive(Debug, Default)]
pub struct Report {
    pub problems: Vec<String>,
    pub warnings: Vec<String>,
}

impl Report {
    fn problem(&mut self, said: impl Into<String>) {
        self.problems.push(said.into());
    }

    fn warn(&mut self, said: impl Into<String>) {
        self.warnings.push(said.into());
    }
}

/// The three directory names as systemd spells them: relative to the root each
/// of its directives is fixed to.
#[derive(Debug)]
pub struct Dirs {
    pub config: String,
    pub state: String,
    pub runtime: String,
}

/// An `appliance.toml` that has been through [`Appliance::load`].
#[derive(Debug)]
pub struct Checked {
    pub appliance: Appliance,
    pub dirs: Dirs,
    pub label: Option<AppLabel>,
}

impl Checked {
    pub fn deb(&self) -> &Deb {
        self.appliance
            .targets
            .deb
            .as_ref()
            .expect("rendered only for a file that declares [targets.deb]")
    }

    pub fn docker(&self) -> Option<(&Docker, &AppLabel)> {
        self.appliance
            .targets
            .docker
            .as_ref()
            .zip(self.label.as_ref())
    }

    /// The package's name: `[targets.deb] package`, or the system name.
    pub fn package(&self) -> &str {
        self.deb()
            .package
            .as_deref()
            .unwrap_or(&self.appliance.name)
    }
}

/// Keys an earlier version read, each named with what to do about it.
fn retired_keys(table: &toml::Table) -> Vec<String> {
    const NO_IMAGE: &str = "wslib-appliance-xtask builds no card image or its package; delete it";
    let section = |name: &str| table.get(name).and_then(toml::Value::as_table);
    let mut retired: Vec<String> = ["bind_address", "https_port"]
        .into_iter()
        .filter(|key| table.contains_key(*key))
        .map(|key| format!("{key} has moved into [targets.deb]"))
        .collect();
    retired.extend(
        ["privilege", "redirect_port"]
            .into_iter()
            .filter(|key| table.contains_key(*key))
            .map(|key| format!("{key} is no longer read: {NO_IMAGE}")),
    );
    retired.extend(
        ["image", "upgrade"]
            .into_iter()
            .filter(|key| table.contains_key(*key))
            .map(|key| format!("[{key}] is no longer read: {NO_IMAGE}")),
    );
    if section("package").is_some_and(|package| package.contains_key("journal")) {
        retired.push(format!("[package] journal is no longer read: {NO_IMAGE}"));
    }
    if section("targets").is_some_and(|targets| targets.contains_key("image")) {
        retired.push(format!("[targets.image] is no longer read: {NO_IMAGE}"));
    }
    retired
}

impl Appliance {
    /// Read one, refusing it if it could not produce a working box, and hand
    /// back its warnings.
    pub fn load(path: &Path) -> Result<(Checked, Vec<String>), ModelError> {
        let text = std::fs::read_to_string(path).map_err(|e| ModelError::Read {
            path: path.to_path_buf(),
            because: e.to_string(),
        })?;
        let parse_error = |e: toml::de::Error| ModelError::Parse {
            path: path.to_path_buf(),
            because: e.to_string(),
        };
        let retired = retired_keys(&toml::from_str(&text).map_err(parse_error)?);
        if !retired.is_empty() {
            return Err(ModelError::Invalid {
                path: path.to_path_buf(),
                problems: retired,
            });
        }
        let appliance: Appliance = toml::from_str(&text).map_err(parse_error)?;

        let manifest = (appliance.targets.docker.as_ref())
            .map(|_| std::fs::read_to_string(path.with_file_name(MANIFEST)));
        let (dirs, label, report) =
            appliance.inspect(manifest.as_ref().map(|read| read.as_deref()));
        let Some(dirs) = dirs.filter(|_| report.problems.is_empty()) else {
            return Err(ModelError::Invalid {
                path: path.to_path_buf(),
                problems: report.problems,
            });
        };
        let checked = Checked {
            appliance,
            dirs,
            label,
        };
        Ok((checked, report.warnings))
    }

    /// Everything wrong with this file and its `manifest`, everything merely
    /// worth saying, the derived directory names when the paths were
    /// expressible, and the label when it can be carried.
    fn inspect(&self, manifest: Option<Manifest>) -> (Option<Dirs>, Option<AppLabel>, Report) {
        let mut report = Report::default();

        // Debian's character set and the group's length.
        if !is_system_name(&self.name) {
            report.problem(format!(
                "name = {:?} — it becomes a Debian package name and a unit name, so it must \
                 start with a lowercase letter and hold only lowercase letters, digits and \
                 hyphens",
                self.name
            ));
        } else if self.name.len() > NAME_MAX {
            report.problem(format!(
                "name = {:?} is {} characters — a group name is capped at {NAME_MAX} on the \
                 platforms this ships to, and this file is written so the two can be one name",
                self.name,
                self.name.len()
            ));
        } else if self.name.len() < 2 {
            report.problem(format!(
                "name = {:?} — a Debian package name must be at least two characters",
                self.name
            ));
        }

        if !is_file_name(&self.binary) {
            report.problem(format!(
                "binary = {:?} — it is rendered as `/usr/bin/<binary>` in the unit's ExecStart=, \
                 which systemd splits on whitespace, so this is a file name of letters, digits, \
                 `.`, `_` and `-` rather than a path or a command line",
                self.binary
            ));
        }

        for (field, value) in [("user", &self.user), ("group", &self.group)] {
            if !is_unix_user(value) {
                report.problem(format!(
                    "{field} = {value:?} — a system user or group name starts with a lowercase \
                     letter or an underscore and holds only those, digits, hyphens and \
                     underscores"
                ));
            } else if value.len() > NAME_MAX {
                report.problem(format!(
                    "{field} = {value:?} is longer than {NAME_MAX} characters"
                ));
            }
        }

        if !is_env_prefix(&self.env_prefix) {
            report.problem(format!(
                "env_prefix = {:?} — `wslib-appliance-config` reads `<PREFIX>_DB` and the rest, so it \
                 must start with an uppercase letter and hold only uppercase letters, digits \
                 and underscores",
                self.env_prefix
            ));
        }

        let dirs = self.directory_names(&mut report);
        self.check_socket(&mut report);
        self.check_sandbox(&mut report);
        self.check_coherence(&mut report);
        self.package
            .check(&self.name, &self.config_dir, &mut report);

        match &self.targets.deb {
            Some(deb) => deb.check(&mut report),
            None => {
                for (key, set) in [
                    ("package.hooks_dir", self.package.hooks_dir.is_some()),
                    ("[package.files]", !self.package.files.is_empty()),
                    ("package.depends", !self.package.depends.is_empty()),
                    ("package.suggests", !self.package.suggests.is_empty()),
                ] {
                    if set {
                        report.problem(format!(
                            "{key} needs [targets.deb] — only the package ships it; remove it \
                             or declare the target"
                        ));
                    }
                }
            }
        }
        let label =
            self.targets.docker.as_ref().and_then(|docker| {
                docker.check(&self.name, manifest.unwrap_or(Ok("")), &mut report)
            });
        if self.targets.deb.is_none() && self.targets.docker.is_none() {
            report.problem("no target — declare [targets.deb], [targets.docker] or both");
        }

        (dirs, label, report)
    }

    /// systemd's three directory directives take a path relative to a fixed
    /// root, so a directory anywhere else cannot be expressed.
    fn directory_names(&self, report: &mut Report) -> Option<Dirs> {
        let mut name_under = |field: &str, value: &Path, root: &str| match under(value, root) {
            Some(name) => Some(name.to_string()),
            None => {
                report.problem(format!(
                    "{field} = {} — systemd's matching directive takes a path under {root}, and \
                     the unit is where these directories come from",
                    value.display()
                ));
                None
            }
        };

        let config = name_under("config_dir", &self.config_dir, "/etc");
        let state = name_under("state_dir", &self.state_dir, "/var/lib");
        let runtime = name_under("runtime_dir", &self.runtime_dir, "/run");
        Some(Dirs {
            config: config?,
            state: state?,
            runtime: runtime?,
        })
    }

    fn check_socket(&self, report: &mut Report) {
        if !self.socket.starts_with(&self.runtime_dir) {
            report.problem(format!(
                "socket = {} is not inside runtime_dir = {} — `RuntimeDirectory=` is what \
                 creates that directory `0750` owned by the appliance's group, which is what \
                 makes the control socket reachable by an operator and nobody else",
                self.socket.display(),
                self.runtime_dir.display()
            ));
        }

        let length = self.socket.as_os_str().as_encoded_bytes().len();
        if length > SOCKET_PATH_MAX {
            report.problem(format!(
                "socket = {} is {length} bytes — a unix socket path is capped at \
                 {SOCKET_PATH_MAX}, and over it the daemon fails at bind having already opened \
                 its database",
                self.socket.display()
            ));
        }
    }

    fn check_sandbox(&self, report: &mut Report) {
        for family in &self.address_families {
            if !is_token(family, "AF_") {
                report.problem(format!(
                    "address_families holds {family:?} — systemd wants names like AF_PACKET"
                ));
            } else if MANDATORY_ADDRESS_FAMILIES.contains(&family.as_str()) {
                report.warn(format!(
                    "address_families holds {family:?}, which wslib-appliance-xtask always allows \
                     anyway — \
                     the list is for what a product opens *beyond* the mandatory four"
                ));
            }
        }

        for capability in &self.capabilities {
            if !is_token(capability, "CAP_") {
                report.problem(format!(
                    "capabilities holds {capability:?} — systemd wants names like CAP_NET_RAW"
                ));
            } else if MANDATORY_CAPABILITIES.contains(&capability.as_str()) {
                report.warn(format!(
                    "capabilities holds {capability:?}, which wslib-appliance-xtask always grants \
                     anyway — \
                     the list is for what a product needs *beyond* it"
                ));
            }
        }
    }

    /// Every field that does not follow from `name`.
    fn check_coherence(&self, report: &mut Report) {
        let name = &self.name;
        let follows = [
            ("user", self.user.clone(), name.clone()),
            ("group", self.group.clone(), name.clone()),
            (
                "config_dir",
                self.config_dir.display().to_string(),
                format!("/etc/{name}"),
            ),
            (
                "state_dir",
                self.state_dir.display().to_string(),
                format!("/var/lib/{name}"),
            ),
            (
                "runtime_dir",
                self.runtime_dir.display().to_string(),
                format!("/run/{name}"),
            ),
            (
                // The unit passes no `--socket`, so the daemon opens the default.
                "socket",
                self.socket.display().to_string(),
                format!("{}/{name}.sock", self.runtime_dir.display()),
            ),
            (
                "env_prefix",
                self.env_prefix.clone(),
                name.to_ascii_uppercase().replace('-', "_"),
            ),
        ];

        for (field, actual, derived) in follows {
            if actual != derived {
                report.warn(format!(
                    "{field} = {actual:?} does not follow from name = {name:?}, which would give \
                     {derived:?} — deliberate is fine, but a half-finished rename looks exactly \
                     like this"
                ));
            }
        }
    }
}

impl Deb {
    fn check(&self, report: &mut Report) {
        if let Some(package) = self.package.as_deref().filter(|p| !is_package_name(p)) {
            report.problem(format!(
                "targets.deb.package = {package:?} — a Debian package name: at least two \
                 characters of lowercase letters, digits, `+`, `-` and `.`, beginning with a \
                 letter or digit"
            ));
        }
        if self.bind_address.parse::<IpAddr>().is_err() {
            report.problem(format!(
                "targets.deb.bind_address = {:?} is not an IP address",
                self.bind_address
            ));
        }
        if self.https_port == 0 {
            report
                .problem("targets.deb.https_port = 0 — the HTTPS listener cannot be switched off");
        }
        if self
            .suggests
            .as_ref()
            .is_some_and(|entries| entries.iter().any(|e| e.trim().is_empty()))
        {
            report.problem("targets.deb.suggests holds an empty entry");
        }
    }
}

impl Docker {
    /// The label `manifest` gives the image, when the image can carry it.
    fn check(&self, name: &str, manifest: Manifest, report: &mut Report) -> Option<AppLabel> {
        let image = AppImage {
            repository: self.repository.clone(),
            digest: format!("sha256:{}", "0".repeat(64)),
        };
        let bare = AppManifest::new(name, "0", image.clone(), vec![AppArch::Arm64]);
        if bare.validate() == Err(ManifestError::Repository) {
            report.problem(format!(
                "targets.docker.repository = {:?} — {}",
                self.repository,
                ManifestError::Repository
            ));
        }
        if !is_source(&self.source) {
            report.problem(format!(
                "targets.docker.source = {:?} — an https:// URL with no whitespace, quote, \
                 backslash, backtick or `$`",
                self.source
            ));
        }

        let manifest = match manifest {
            Ok(text) => text,
            Err(e) => {
                report.problem(format!(
                    "{MANIFEST} beside appliance.toml cannot be read: {e} — [targets.docker] \
                     labels the image with it"
                ));
                return None;
            }
        };
        let label: AppLabel = match serde_json::from_str(manifest) {
            Ok(label) => label,
            Err(e) => {
                report.problem(format!(
                    "{MANIFEST} is not a manifest without its image: {e} — the console fills \
                     `image` from the image it loaded"
                ));
                return None;
            }
        };
        let before = report.problems.len();
        match AppManifest::from_label(label.clone(), image).validate() {
            Ok(()) | Err(ManifestError::Repository) => {}
            Err(e) => report.problem(format!("{MANIFEST}: {e}")),
        }
        if label.name != name {
            report.problem(format!(
                "{MANIFEST}: name = {:?} is not this appliance's {name:?}",
                label.name
            ));
        }
        if !label.sockets.app {
            report.problem(format!(
                "{MANIFEST}: sockets.app is not set — the image always serves app.sock"
            ));
        }
        for volume in &label.volumes {
            let at = Path::new(&volume.at);
            if let Some(owned) = IMAGE_OWNED
                .iter()
                .find(|owned| at.starts_with(owned) || Path::new(owned).starts_with(at))
            {
                report.problem(format!(
                    "{MANIFEST}: volume {:?} at {:?} overlaps {owned}, which the image owns — \
                     a volume is seeded from the image once and never upgraded; mount it \
                     elsewhere",
                    volume.name, volume.at
                ));
            }
            if let Some(dir) = UNREACHABLE
                .iter()
                .find(|dir| at.starts_with(dir) && at != Path::new(dir))
            {
                report.problem(format!(
                    "{MANIFEST}: volume {:?} at {:?} is under {dir}, which is 0700 to its owner \
                     — mount it elsewhere",
                    volume.name, volume.at
                ));
            }
        }
        if !label.volumes.iter().any(|v| v.name == "data") {
            report.problem(format!(
                "{MANIFEST}: no volume is named data — it is where the app keeps its state"
            ));
        }
        for arch in &label.arches {
            if !matches!(arch, AppArch::Arm64 | AppArch::Amd64) {
                report.problem(format!(
                    "{MANIFEST}: arches holds {} — wslib-appliance-xtask builds arm64 and amd64 \
                     only",
                    serde_json::to_string(arch).unwrap_or_default()
                ));
            }
        }
        if label.version.contains(['+', '~']) {
            report.problem(format!(
                "{MANIFEST}: version = {:?} — it tags the image, and a Docker tag holds no `+` \
                 or `~`",
                label.version
            ));
        }
        if serde_json::to_string(&label).is_ok_and(|json| json.contains('\'')) {
            report.problem(format!(
                "{MANIFEST} holds a `'`, which would end the quoting of the Dockerfile's label"
            ));
        }
        (report.problems.len() == before).then_some(label)
    }
}

/// An `https://` URL with nothing in it that could end or expand the single
/// quotes the Dockerfile renders it in.
fn is_source(s: &str) -> bool {
    s.strip_prefix("https://").is_some_and(|rest| {
        !rest.is_empty()
            && rest
                .bytes()
                .all(|b| b.is_ascii_graphic() && !b"'\"\\`$".contains(&b))
    })
}

impl Package {
    fn check(&self, name: &str, config_dir: &Path, report: &mut Report) {
        if self.section.is_empty() || self.section.contains(char::is_whitespace) {
            report.problem(format!(
                "package.section = {:?} — one word, and `admin` is the one an appliance wants",
                self.section
            ));
        }
        for (field, entries) in [
            ("package.depends", &self.depends),
            ("package.suggests", &self.suggests),
        ] {
            if entries.iter().any(|d| d.trim().is_empty()) {
                report.problem(format!("{field} holds an empty entry"));
            }
        }

        // Policy 5.3 makes both mandatory, and dpkg only warns.
        for (field, value) in [
            ("package.maintainer", &self.maintainer),
            ("package.description", &self.description),
        ] {
            if value.trim().is_empty() {
                report.problem(format!(
                    "{field} is empty — Debian Policy makes it mandatory"
                ));
            } else if value.contains('\n') {
                report.problem(format!(
                    "{field} spans more than one line — it is rendered as a single control \
                     field, and a newline there ends the field"
                ));
            }
        }

        if !is_maintainer(&self.maintainer) {
            report.problem(format!(
                "package.maintainer = {:?} — Policy 5.6.2 wants `Name <address>`, and the \
                 changelog the build writes is unparseable without the brackets",
                self.maintainer
            ));
        }

        if self.description.len() > 80 {
            report.warn(format!(
                "package.description is {} characters — it is the synopsis, and `apt search` \
                 truncates it. The extended description below it has no such limit",
                self.description.len()
            ));
        }

        if self.min_binary_bytes == 0 {
            report.problem(
                "package.min_binary_bytes = 0 — the floor is what refuses a binary the linker \
                 has quietly emptied, and zero refuses nothing",
            );
        } else if self.min_binary_bytes <= THE_BUILD_THAT_GOT_THROUGH {
            report.warn(format!(
                "package.min_binary_bytes = {} is at or below the {THE_BUILD_THAT_GOT_THROUGH} \
                 byte build this floor exists because of, so it would have let that one \
                 through — set it just under a known-good build",
                self.min_binary_bytes
            ));
        }

        let repo_relative =
            self.ui_dist
                .iter()
                .map(|dist| ("package.ui_dist".to_string(), dist))
                .chain(
                    self.hooks_dir
                        .iter()
                        .map(|dir| ("package.hooks_dir".to_string(), dir)),
                )
                .chain(self.files.iter().map(|(destination, source)| {
                    (format!("package.files {destination:?}"), source)
                }));
        for (field, value) in repo_relative {
            if !is_repo_relative(value) {
                report.problem(format!(
                    "{field} = {value:?} — a path relative to the repository root, rendered into \
                     a build script: components of letters, digits, `.`, `_` and `-`, beginning \
                     with a letter or digit, with no `..`. Remove the key entirely for a product \
                     with nothing to name"
                ));
            }
        }

        for destination in self.files.keys() {
            if let Some(why) = refused_destination(destination, name, config_dir) {
                report.problem(format!("package.files {destination:?} — {why}"));
            }
        }
    }
}

/// Why a `[package.files]` destination may not be shipped: only `/etc` and
/// `/usr/share/<name>` take one, less the paths the chassis writes itself.
fn refused_destination(destination: &str, name: &str, config_dir: &Path) -> Option<String> {
    let path = Path::new(destination);
    let share = format!("/usr/share/{name}");

    // Written verbatim into `conffiles`, which `Path` would normalise.
    if destination.contains("//") || destination.ends_with('/') {
        return Some(
            "spelled with `//` or a trailing `/`, which is written into the package as it is \
             and would not match the file dpkg unpacks"
                .to_string(),
        );
    }

    if under(path, "/etc").is_some() {
        if path == config_dir.join("config.toml") {
            return Some(format!(
                "`{}` is the conffile the package renders, every key commented — ship a \
                 `config.toml.example` beside it instead",
                path.display()
            ));
        }
        return path.starts_with("/etc/systemd/system").then(|| {
            "`/etc/systemd/system` is the operator's unit directory; a unit drop-in of the \
             product's ships from `scaffold/systemd/<name>.service.d/` to `/usr/lib`"
                .to_string()
        });
    }
    if let Some(rest) = under(path, &share) {
        let first = rest.split_once('/').map_or(rest, |(first, _)| first);
        if rest == "config.toml" {
            return Some(format!(
                "`{share}/config.toml` is the package's values, rendered from `[targets.deb]`"
            ));
        }
        return matches!(first, "ui" | "postinst.d" | "prerm.d").then(|| {
            format!(
                "`{share}/{first}` is staged from its own knob — `ui_dist` for the bundle, \
                 `hooks_dir` for the hooks"
            )
        });
    }
    Some(format!(
        "a shipped file goes under `/etc/` or `{share}/`, as path components of letters, \
         digits, `.`, `_` and `-` with no `..`; `/usr/share/doc/<package>/` is written by the \
         build from `scaffold/debian/copyright`, and anything else is another package's"
    ))
}

pub(crate) fn is_conffile(destination: &str) -> bool {
    under(Path::new(destination), "/etc").is_some()
}

/// `Name <address>`, as Policy 5.6.2 and dpkg's changelog trailer want it.
fn is_maintainer(s: &str) -> bool {
    matches!(
        s.split_once(" <"),
        Some((name, rest)) if !name.trim().is_empty() && rest.contains('@') && rest.ends_with('>')
    )
}

fn is_hostname_label(s: &str) -> bool {
    s.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && !s.ends_with('-')
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Legal as a package, a unit, a group and a directory.
fn is_system_name(s: &str) -> bool {
    is_hostname_label(s) && s.starts_with(|c: char| c.is_ascii_lowercase())
}

/// A package name as Debian Policy 5.6.1 has it.
fn is_package_name(s: &str) -> bool {
    s.len() >= 2
        && s.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '+' | '-' | '.'))
}

fn is_unix_user(s: &str) -> bool {
    s.starts_with(|c: char| c.is_ascii_lowercase() || c == '_')
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

fn is_shouty(s: &str) -> bool {
    s.chars()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

fn is_env_prefix(s: &str) -> bool {
    s.starts_with(|c: char| c.is_ascii_uppercase()) && is_shouty(s)
}

fn is_token(s: &str, prefix: &str) -> bool {
    s.len() > prefix.len() && s.starts_with(prefix) && is_shouty(s)
}

/// No shell metacharacter, quote or whitespace: these reach scripts run as
/// root, single-quoted.
fn is_name_safe(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// [`is_name_safe`] with a leading letter or digit, so neither `..` nor a flag.
fn is_file_name(s: &str) -> bool {
    is_name_safe(s) && s.starts_with(|c: char| c.is_ascii_alphanumeric())
}

/// A directory a rendered build script joins onto the repository root, as a
/// bare argument, so it may not lead with `-`.
fn is_repo_relative(s: &str) -> bool {
    under(Path::new(s), "").is_some() && s.starts_with(|c: char| c.is_ascii_alphanumeric())
}

/// The part of `path` below `root`, if it names something; `.` and `..` are
/// refused rather than resolved.
fn under<'a>(path: &'a Path, root: &str) -> Option<&'a str> {
    let safe = |component: &str| is_name_safe(component) && !matches!(component, "." | "..");
    let rest = path.strip_prefix(root).ok()?.to_str()?;
    (!rest.is_empty() && rest.split('/').all(safe)).then_some(rest)
}

#[cfg(test)]
pub(crate) const EXAMPLE: &str = include_str!("../appliance.toml.example");

#[cfg(test)]
pub(crate) fn without_ui_dist(text: &str) -> String {
    text.lines()
        .filter(|line| !line.starts_with("ui_dist"))
        .map(|line| format!("{line}\n"))
        .collect()
}

/// `text` with more keys at the end of `[package]`.
#[cfg(test)]
pub(crate) fn with_package_keys(text: &str, keys: &str) -> String {
    const NEXT_SECTION: &str = "\n[targets.";
    assert!(
        text.contains(NEXT_SECTION),
        "the example no longer has a [targets.*] section after [package]"
    );
    text.replacen(NEXT_SECTION, &format!("\n{keys}\n{NEXT_SECTION}"), 1)
}

/// `text` with more keys at the top of `[targets.deb]`.
#[cfg(test)]
pub(crate) fn with_deb_keys(text: &str, keys: &str) -> String {
    const SECTION: &str = "[targets.deb]\n";
    assert!(text.contains(SECTION), "no [targets.deb] section");
    text.replacen(SECTION, &format!("{SECTION}{keys}\n"), 1)
}

#[cfg(test)]
pub(crate) fn with_every_package_knob() -> String {
    with_package_keys(
        EXAMPLE,
        "hooks_dir = \"scaffold/hooks\"\n\n[package.files]\n\
         \"/etc/myappliance/config.toml.example\" = \"scaffold/files/config.toml.example\"\n\
         \"/usr/share/myappliance/templates/report.html\" = \"scaffold/files/report.html\"",
    )
}

#[cfg(test)]
pub(crate) const LABEL: &str = r#"{"schema": 1, "name": "myappliance", "version": "1.2.3",
    "arches": ["arm64", "amd64"], "sockets": {"app": true},
    "volumes": [{"name": "data", "at": "/data"}, {"name": "spool", "at": "/var/spool/x"}]}"#;

/// `text` with the example's commented-out `[targets.docker]` turned on.
#[cfg(test)]
pub(crate) fn with_docker(text: &str) -> String {
    let block: String = EXAMPLE
        .split_once("# [targets.docker]\n")
        .expect("a commented [targets.docker]")
        .1
        .lines()
        .take_while(|line| line.starts_with("# ") && line.contains(" = "))
        .map(|line| format!("{}\n", &line[2..]))
        .collect();
    format!("{text}\n[targets.docker]\n{block}")
}

#[cfg(test)]
pub(crate) fn docker_only() -> String {
    const DEPENDS: &str =
        r#"depends = ["init-system-helpers (>= 1.54)", "adduser", "ca-certificates"]"#;
    assert!(EXAMPLE.contains(DEPENDS), "the example's depends moved");
    let packageless = EXAMPLE.split("\n[targets.deb]").next().expect("the file");
    with_docker(&packageless.replace(DEPENDS, "depends = []"))
}

#[cfg(test)]
pub(crate) fn checked(text: &str) -> Checked {
    let appliance: Appliance = toml::from_str(text).expect("parses");
    let (dirs, label, report) = appliance.inspect(Some(Ok(LABEL)));
    assert!(report.problems.is_empty(), "{:?}", report.problems);
    Checked {
        appliance,
        dirs: dirs.expect("checked paths have directory names"),
        label,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inspect(text: &str) -> Report {
        inspect_with(text, LABEL)
    }

    fn inspect_with(text: &str, manifest: &str) -> Report {
        let appliance: Appliance = toml::from_str(text).expect("parses");
        appliance.inspect(Some(Ok(manifest))).2
    }

    /// The problems with the example's image when its label's `key` is `value`.
    fn label_with(key: &str, value: serde_json::Value) -> Vec<String> {
        let mut json: serde_json::Value = serde_json::from_str(LABEL).unwrap();
        json[key] = value;
        inspect_with(&with_docker(EXAMPLE), &json.to_string()).problems
    }

    #[test]
    fn the_shipped_example_is_a_legal_appliance_and_says_nothing() {
        let appliance: Appliance = toml::from_str(EXAMPLE).expect("the example parses");
        let (dirs, _, report) = appliance.inspect(None);
        assert!(report.problems.is_empty(), "{:#?}", report.problems);
        assert!(report.warnings.is_empty(), "{:#?}", report.warnings);

        let dirs = dirs.expect("three directory names");
        assert_eq!(dirs.config, "myappliance");
        assert_eq!(dirs.state, "myappliance");
        assert_eq!(dirs.runtime, "myappliance");
    }

    #[test]
    fn a_key_the_chassis_does_not_know_is_refused_rather_than_ignored() {
        let text = EXAMPLE.replace("binary = ", "binery = ");
        let e = toml::from_str::<Appliance>(&text).expect_err("a typo must not parse");
        assert!(e.to_string().contains("binery"), "{e}");
    }

    #[test]
    fn a_file_that_would_not_produce_a_working_box_is_refused() {
        let long_socket = format!("/run/myappliance/{}.sock", "a".repeat(95));
        let cases: [(&str, String, &str); 5] = [
            (
                "a socket systemd did not create the directory for",
                EXAMPLE.replace(
                    r#"socket = "/run/myappliance/myappliance.sock""#,
                    r#"socket = "/tmp/myappliance.sock""#,
                ),
                "runtime_dir",
            ),
            (
                "a socket path longer than sun_path",
                EXAMPLE.replace("/run/myappliance/myappliance.sock", &long_socket),
                "capped",
            ),
            (
                "a configuration directory systemd cannot express",
                EXAMPLE.replace(
                    r#"config_dir = "/etc/myappliance""#,
                    r#"config_dir = "/opt/myappliance/etc""#,
                ),
                "/etc",
            ),
            (
                "a name that is not a legal group",
                EXAMPLE.replace(r#"name = "myappliance""#, r#"name = "MyAppliance""#),
                "name",
            ),
            (
                "a prefix wslib-appliance-config cannot build a variable on",
                EXAMPLE.replace(r#"env_prefix = "MYAPPLIANCE""#, r#"env_prefix = "my-app""#),
                "env_prefix",
            ),
        ];

        for (what, text, expected) in cases {
            let report = inspect(&text);
            assert!(
                report.problems.iter().any(|p| p.contains(expected)),
                "{what}: expected a problem naming {expected:?}, got {:#?}",
                report.problems
            );
        }
    }

    #[test]
    fn a_low_port_needs_nothing_listed_to_bind() {
        let report = inspect(&EXAMPLE.replace("https_port = 8443", "https_port = 443"));
        assert!(report.problems.is_empty(), "{:#?}", report.problems);
        assert!(report.warnings.is_empty(), "{:#?}", report.warnings);
    }

    #[test]
    fn an_https_port_of_zero_or_an_address_that_is_not_one_is_refused() {
        let report = inspect(&EXAMPLE.replacen("https_port = 8443", "https_port = 0", 1));
        assert_eq!(
            report.problems,
            ["targets.deb.https_port = 0 — the HTTPS listener cannot be switched off"]
        );
        let report = inspect(&EXAMPLE.replacen("\"0.0.0.0\"", "\"everywhere\"", 1));
        assert_eq!(
            report.problems,
            ["targets.deb.bind_address = \"everywhere\" is not an IP address"]
        );
    }

    #[test]
    fn listing_the_capability_the_chassis_grants_is_harmless_and_said_to_be() {
        let report = inspect(&EXAMPLE.replace(
            "capabilities = []",
            r#"capabilities = ["CAP_NET_BIND_SERVICE"]"#,
        ));
        assert!(report.problems.is_empty(), "{:#?}", report.problems);
        assert!(
            report
                .warnings
                .iter()
                .any(|w| w.contains("CAP_NET_BIND_SERVICE")),
            "{:#?}",
            report.warnings
        );
    }

    #[test]
    fn a_socket_wrong_twice_is_two_problems() {
        let text = EXAMPLE.replace(
            "/run/myappliance/myappliance.sock",
            &format!("/tmp/{}.sock", "a".repeat(110)),
        );
        let report = inspect(&text);

        assert!(report.problems.iter().any(|p| p.contains("runtime_dir")));
        assert!(report.problems.iter().any(|p| p.contains("capped")));
    }

    #[test]
    fn a_half_finished_rename_is_named_field_by_field() {
        let text = EXAMPLE.replace(r#"name = "myappliance""#, r#"name = "widgetwatch""#);
        let report = inspect(&text);

        assert!(report.problems.is_empty(), "{:#?}", report.problems);
        for field in [
            "user",
            "group",
            "config_dir",
            "state_dir",
            "runtime_dir",
            "socket",
            "env_prefix",
        ] {
            assert!(
                report
                    .warnings
                    .iter()
                    .any(|w| w.starts_with(&format!("{field} ="))),
                "{field} was not named: {:#?}",
                report.warnings
            );
        }
    }

    #[test]
    fn a_directory_that_climbs_out_of_its_root_is_not_under_it() {
        assert_eq!(
            under(Path::new("/etc/myappliance"), "/etc"),
            Some("myappliance")
        );
        assert_eq!(under(Path::new("/etc/a/b"), "/etc"), Some("a/b"));
        assert_eq!(under(Path::new("/etc"), "/etc"), None);
        assert_eq!(under(Path::new("/etc/../opt/x"), "/etc"), None);
        assert_eq!(under(Path::new("/opt/x"), "/etc"), None);
    }

    #[test]
    fn a_path_that_would_be_a_command_in_a_root_script_is_refused() {
        for hostile in [
            "/etc/my appliance",
            "/etc/x;rm -rf /",
            "/etc/$(id)",
            "/etc/`id`",
            "/etc/x'y",
            "/etc/x\"y",
            "/etc/x$y",
        ] {
            assert_eq!(
                under(Path::new(hostile), "/etc"),
                None,
                "{hostile} reached a root shell script"
            );
        }

        assert_eq!(under(Path::new("/etc/my-app.d"), "/etc"), Some("my-app.d"));
        assert_eq!(under(Path::new("/etc/my_app2"), "/etc"), Some("my_app2"));
    }

    #[test]
    fn a_bundle_path_that_would_escape_the_repository_or_the_quoting_is_refused() {
        // Otherwise a `replace` that matched nothing would pass every `fine`.
        const SPELLED: &str = r#"ui_dist = "ui/dist""#;
        assert!(
            EXAMPLE.contains(SPELLED),
            "the example no longer spells {SPELLED}"
        );

        let refused = |dist: &str| {
            inspect(&EXAMPLE.replace(SPELLED, &format!("ui_dist = {dist:?}")))
                .problems
                .iter()
                .any(|p| p.starts_with("package.ui_dist ="))
        };

        for hostile in [
            "/srv/ui/dist",
            "../../etc",
            "ui/../../etc",
            "ui dist",
            "ui/$(id)",
            "ui;rm -rf /",
            "ui/'x",
            "",
            // Harmless in the shell; refused as a side effect of the component rule.
            "ui//dist",
            ".",
            "ui/./dist",
            "./ui/dist",
            "-rf",
            "-name",
            "-",
            "_ui/dist",
        ] {
            assert!(refused(hostile), "ui_dist = {hostile:?} was accepted");
        }

        // `Path` drops a trailing separator and keeps an interior one.
        for fine in ["ui/dist", "dist", "web/build", "ui-2/dist", "ui/dist/"] {
            assert!(!refused(fine), "ui_dist = {fine:?} was refused");
        }
    }

    fn files_problem(destination: &str, source: &str) -> Option<String> {
        inspect(&with_package_keys(
            EXAMPLE,
            &format!("[package.files]\n{destination:?} = {source:?}"),
        ))
        .problems
        .into_iter()
        .find(|p| p.starts_with("package.files "))
    }

    /// The wiring only; the predicate's coverage is `a_bundle_path_…` above.
    #[test]
    fn a_hooks_dir_and_a_shipped_files_source_take_the_rule_ui_dist_takes() {
        let hooks_dir = |dir: &str| {
            inspect(&with_package_keys(EXAMPLE, &format!("hooks_dir = {dir:?}")))
                .problems
                .iter()
                .any(|p| p.starts_with("package.hooks_dir ="))
        };
        assert!(hooks_dir("../hooks"), "a climbing hooks_dir was accepted");
        assert!(
            !hooks_dir("scaffold/hooks"),
            "a plain hooks_dir was refused"
        );

        assert!(files_problem("/etc/myappliance/x", "../secrets").is_some());
        assert!(files_problem("/etc/myappliance/x", "scaffold/files/x").is_none());
    }

    #[test]
    fn a_package_file_outside_the_allowed_roots_is_refused() {
        for hostile in [
            "/usr/bin/other",
            "/usr/share/other/x",
            "/var/lib/myappliance/x",
            "/etc",
            "/etc/",
            "etc/myappliance/x",
            "/etc/../usr/bin/x",
            "/etc/myappliance/x y",
            "/usr/share/doc/myappliance/copyright",
            "/etc//myappliance/x",
            "//etc/myappliance/x",
            "/etc/myappliance/x/",
        ] {
            assert!(
                files_problem(hostile, "scaffold/files/x").is_some(),
                "{hostile:?} was accepted as a destination"
            );
        }
        for fine in [
            "/etc/myappliance/config.toml.example",
            "/etc/ssh/sshd_config.d/50-myappliance.conf",
            "/usr/share/myappliance/templates/report.html",
        ] {
            assert!(
                files_problem(fine, "scaffold/files/x").is_none(),
                "{fine:?} was refused as a destination"
            );
        }
    }

    /// The refused conffile is `config_dir`'s, not `name`'s.
    #[test]
    fn a_package_file_aimed_at_a_reserved_destination_is_refused() {
        for (reserved, names) in [
            ("/usr/share/myappliance/ui/index.html", "ui_dist"),
            ("/usr/share/myappliance/postinst.d/10-x", "hooks_dir"),
            ("/usr/share/myappliance/prerm.d/10-x", "hooks_dir"),
            ("/usr/share/myappliance/config.toml", "the package's values"),
            (
                "/etc/myappliance/config.toml",
                "conffile the package renders",
            ),
            (
                "/etc/systemd/system/myappliance.service.d/10-x.conf",
                "operator's unit directory",
            ),
        ] {
            let problem = files_problem(reserved, "scaffold/files/x")
                .unwrap_or_else(|| panic!("{reserved:?} was accepted"));
            assert!(problem.contains(names), "{reserved}: {problem}");
        }

        let elsewhere = with_package_keys(
            &EXAMPLE.replace(
                r#"config_dir = "/etc/myappliance""#,
                r#"config_dir = "/etc/myappliance-conf""#,
            ),
            "[package.files]\n\"/etc/myappliance-conf/config.toml\" = \"scaffold/files/x\"\n\
             \"/etc/myappliance/config.toml\" = \"scaffold/files/y\"",
        );
        let problems = inspect(&elsewhere).problems;
        assert!(
            problems
                .iter()
                .any(|p| p.contains("/etc/myappliance-conf/config.toml")
                    && p.contains("conffile the package renders")),
            "{problems:?}"
        );
        assert!(
            !problems
                .iter()
                .any(|p| p.starts_with("package.files \"/etc/myappliance/config.toml\"")),
            "a file that is not the operator's was refused as it: {problems:?}"
        );
    }

    #[test]
    fn a_maintainer_is_name_then_address_in_brackets() {
        const SPELLED: &str = r#"maintainer = "Maintainer <support@example.invalid>""#;
        assert!(
            EXAMPLE.contains(SPELLED),
            "the example no longer spells {SPELLED}"
        );
        let refused = |maintainer: &str| {
            inspect(&EXAMPLE.replace(SPELLED, &format!("maintainer = {maintainer:?}")))
                .problems
                .iter()
                .any(|p| p.starts_with("package.maintainer ="))
        };

        for hostile in [
            "Wired Square",
            "apps@wiredsquare.com",
            "<apps@wiredsquare.com>",
            "Wired Square<apps@wiredsquare.com>",
            "Wired Square <apps@wiredsquare.com> ",
            "Wired Square <apps at wiredsquare.com>",
        ] {
            assert!(refused(hostile), "{hostile:?} was accepted");
        }
        for fine in [
            "Wired Square <apps@wiredsquare.com>",
            "Maintainer <support@example.invalid>",
        ] {
            assert!(!refused(fine), "{fine:?} was refused");
        }
    }

    fn load_problems(text: &str) -> Vec<String> {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let path = dir.path().join("appliance.toml");
        std::fs::write(&path, text).expect("write");
        match Appliance::load(&path) {
            Err(ModelError::Invalid { problems, .. }) => problems,
            other => panic!("not refused as invalid: {other:?}"),
        }
    }

    #[test]
    fn a_key_an_earlier_tag_read_is_refused_saying_what_became_of_it() {
        let old = EXAMPLE.replacen(
            "[package]\n",
            "privilege = \"host-admin\"\nbind_address = \"0.0.0.0\"\nredirect_port = 80\n\
             [package]\njournal = \"persistent\"\n",
            1,
        ) + "\n[targets.image]\npi_gen_ref = \"arm64\"\n\n[upgrade]\nenabled = true\n";
        let problems = load_problems(&old);
        for said in [
            "bind_address has moved into [targets.deb]",
            "privilege is no longer read",
            "redirect_port is no longer read",
            "[package] journal is no longer read",
            "[targets.image] is no longer read",
            "[upgrade] is no longer read",
        ] {
            assert!(
                problems.iter().any(|p| p.starts_with(said)),
                "{said}: {problems:#?}"
            );
        }
    }

    #[test]
    fn a_file_with_no_target_is_refused() {
        let none = EXAMPLE
            .split("\n[targets.deb]")
            .next()
            .expect("the file before its target")
            .to_string();
        assert!(
            inspect(&none)
                .problems
                .iter()
                .any(|p| p.starts_with("no target")),
        );
    }

    #[test]
    fn the_package_is_fixed_but_for_its_listeners() {
        let bare = EXAMPLE.replace(
            "[targets.deb]\nbind_address = \"0.0.0.0\"\nhttps_port = 8443\n",
            "[targets.deb]\n",
        );
        assert_ne!(bare, EXAMPLE, "the example no longer spells [targets.deb]");
        let checked = checked(&bare);
        let deb = checked.deb();
        assert_eq!(
            (deb.bind_address.as_str(), deb.https_port),
            ("0.0.0.0", 8443)
        );

        for key in ["privilege", "redirect_port", "journal", "hats"] {
            let widened = with_deb_keys(&bare, &format!("{key} = 1"));
            let e = toml::from_str::<Appliance>(&widened).expect_err("refused");
            assert!(e.to_string().contains(key), "{key}: {e}");
        }
    }

    #[test]
    fn the_package_is_a_debian_name_and_defaults_to_the_system_name() {
        let named = |package: &str| with_deb_keys(EXAMPLE, &format!("package = {package:?}"));
        assert_eq!(
            checked(&named("myappliance-generic")).package(),
            "myappliance-generic"
        );
        assert_eq!(checked(EXAMPLE).package(), "myappliance");

        for fine in ["my-appliance.deb", "myappliance+1", "0x"] {
            let report = inspect(&named(fine));
            assert!(report.problems.is_empty(), "{fine}: {:#?}", report.problems);
        }
        for refused in [
            "MyAppliance",
            "my_appliance",
            "-deb",
            "x",
            "my appliance",
            "a'b",
        ] {
            let problems = inspect(&named(refused)).problems;
            assert!(
                problems
                    .iter()
                    .any(|p| p.starts_with("targets.deb.package =")),
                "{refused}: {problems:#?}"
            );
        }
    }

    #[test]
    fn a_binary_that_would_not_be_one_word_of_an_exec_line_is_refused() {
        let refused = |binary: &str| {
            inspect(&EXAMPLE.replace(
                r#"binary = "myappliance-server""#,
                &format!("binary = {binary:?}"),
            ))
            .problems
            .iter()
            .any(|p| p.starts_with("binary ="))
        };

        for hostile in [
            "my server",
            "myappliance-server --debug",
            "bin/myappliance",
            "-server",
            "..",
            "",
            "my;server",
        ] {
            assert!(refused(hostile), "binary = {hostile:?} was accepted");
        }

        for fine in ["myappliance-server", "myappliance_server2", "app.bin"] {
            assert!(!refused(fine), "binary = {fine:?} was refused");
        }
    }

    #[test]
    fn the_packages_suggests_is_its_own_when_set() {
        assert_eq!(checked(EXAMPLE).deb().suggests, None);
        let own = checked(&with_deb_keys(EXAMPLE, "suggests = []"));
        assert_eq!(own.deb().suggests.as_deref(), Some(&[][..]));

        let problems = inspect(&with_deb_keys(EXAMPLE, r#"suggests = ["chrony", " "]"#)).problems;
        assert_eq!(problems, ["targets.deb.suggests holds an empty entry"]);
    }

    #[test]
    fn an_image_alone_is_a_target_and_its_label_is_the_manifest() {
        for text in [with_docker(EXAMPLE), docker_only()] {
            let checked = checked(&text);
            let (docker, label) = checked.docker().expect("an image");
            assert_eq!(docker.repository, "ghcr.io/example/myappliance");
            assert_eq!(*label, serde_json::from_str::<AppLabel>(LABEL).unwrap());
        }
        assert!(checked(EXAMPLE).docker().is_none());
        assert!(checked(&docker_only()).appliance.targets.deb.is_none());
    }

    /// Each refusal alone, so one cannot pass by riding on another.
    #[test]
    fn an_image_its_table_or_its_label_cannot_carry_is_refused() {
        let docker = |key: &str, value: &str| {
            let text = with_docker(EXAMPLE);
            let (head, tail) = text.rsplit_once("[targets.docker]\n").expect("the table");
            let kept: String = tail
                .lines()
                .filter(|line| !line.starts_with(&format!("{key} =")))
                .map(|line| format!("{line}\n"))
                .collect();
            inspect(&format!(
                "{head}[targets.docker]\n{key} = {value:?}\n{kept}"
            ))
            .problems
        };
        for (key, value) in [
            ("repository", "Ghcr.io/example/x"),
            ("repository", "ghcr.io/example/x:1"),
            ("repository", ""),
            ("source", "http://example.com/x"),
            ("source", "https://"),
            ("source", "https://example.com/x y"),
            ("source", "https://example.com/x'y"),
            ("source", "https://example.com/$x"),
        ] {
            let problems = docker(key, value);
            assert_eq!(problems.len(), 1, "{key} = {value:?}: {problems:#?}");
            assert!(
                problems[0].starts_with(&format!("targets.docker.{key} =")),
                "{problems:#?}"
            );
        }

        let data = serde_json::json!({"name": "data", "at": "/data"});
        for (key, value, said) in [
            (
                "image",
                serde_json::json!({"repository": "x", "digest": "y"}),
                "manifest.json is not a manifest without its image",
            ),
            ("listeners", 1.into(), "manifest.json is not a manifest"),
            ("name", "other".into(), "manifest.json: name ="),
            (
                "sockets",
                serde_json::json!({"app": false}),
                "manifest.json: sockets.app",
            ),
            (
                "volumes",
                serde_json::json!([{"name": "state", "at": "/data"}]),
                "manifest.json: no volume is named data",
            ),
            (
                "arches",
                serde_json::json!(["arm64", "arm/v7"]),
                "manifest.json: arches holds \"arm/v7\"",
            ),
            ("version", "1.0+b".into(), "manifest.json: version ="),
            (
                "volumes",
                serde_json::json!([data, {"name": "x", "at": "/proc/x"}]),
                "manifest.json: a volume's path",
            ),
            (
                "arches",
                serde_json::json!([]),
                "manifest.json: the manifest names no",
            ),
        ] {
            let problems = label_with(key, value);
            assert_eq!(problems.len(), 1, "{said}: {problems:#?}");
            assert!(problems[0].starts_with(said), "{said}: {problems:#?}");
        }

        let quoted = label_with("version", "1'2".into());
        assert!(
            quoted.iter().any(|p| p.contains("holds a `'`")),
            "{quoted:#?}"
        );
        assert!(inspect_with(&with_docker(EXAMPLE), "").problems[0].starts_with("manifest.json"));
    }

    #[test]
    fn a_volume_at_under_or_above_what_the_image_ships_or_under_a_0700_dir_is_refused() {
        let binary = format!("/usr/bin/{}", checked(EXAMPLE).appliance.binary);
        let ui = wslib_appliance_config::default_ui_dir("myappliance");
        let volumes = |at: &str| {
            label_with(
                "volumes",
                serde_json::json!([{"name": "data", "at": "/data"}, {"name": "x", "at": at}]),
            )
        };
        for at in [
            "/usr",
            "/usr/bin",
            &binary,
            ui.to_str().expect("utf-8"),
            "/usr/share/myappliance",
            "/usr/local/x",
            "/etc",
            "/etc/ssl",
            "/etc/ssl/certs",
            "/run",
            "/run/appliance",
            "/bin",
            "/sbin/x",
            "/lib",
            "/lib64/x",
            "/root/x",
            "/home/nonroot/x",
        ] {
            let problems = volumes(at);
            assert_eq!(problems.len(), 1, "{at}: {problems:#?}");
            assert!(problems[0].starts_with("manifest.json"), "{problems:#?}");
        }
        for at in [
            "/usr2",
            "/etc/myappliance",
            "/etc/ssl2",
            "/srv/x",
            "/library",
            "/root",
            "/home/nonroot",
            "/home/x",
        ] {
            assert_eq!(volumes(at), Vec::<String>::new(), "{at}");
        }
    }

    #[test]
    fn what_only_the_package_ships_is_refused_without_it() {
        let knobs = with_every_package_knob().replace("suggests = []", r#"suggests = ["chrony"]"#);
        let problems =
            inspect(&with_docker(knobs.split("\n[targets.deb]").next().unwrap())).problems;
        assert_eq!(problems.len(), 4, "{problems:#?}");
        for (problem, key) in problems.iter().zip([
            "package.hooks_dir",
            "[package.files]",
            "package.depends",
            "package.suggests",
        ]) {
            assert!(
                problem.starts_with(&format!("{key} needs [targets.deb]")),
                "{problem}"
            );
        }
    }

    #[test]
    fn the_label_is_read_from_beside_the_file() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let path = dir.path().join("appliance.toml");
        let source = with_docker(EXAMPLE).replace("source = \"", "source = \"http:");
        std::fs::write(&path, source).expect("write");
        match Appliance::load(&path) {
            Err(ModelError::Invalid { problems, .. }) => {
                assert_eq!(problems.len(), 2, "{problems:#?}");
                assert!(problems[0].starts_with("targets.docker.source"));
                assert!(problems[1].starts_with("manifest.json beside appliance.toml cannot"));
            }
            other => panic!("not refused for want of its label: {other:?}"),
        }

        std::fs::write(&path, with_docker(EXAMPLE)).expect("write");
        std::fs::write(dir.path().join(MANIFEST), LABEL).expect("write");
        let (checked, warnings) = Appliance::load(&path).expect("loads");
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(checked.docker().expect("an image").1.name, "myappliance");
    }
}
