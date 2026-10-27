//! Where a service keeps its state, endpoints and log, checked before serving.

use std::path::{Path, PathBuf};

use wslib_appliance_core::backend::ControlEndpoint;
use wslib_appliance_store::{Migrator, Store};
use wslib_appliance_types::Role;
use wslib_service::{Held, Layout};

use crate::LocalError;

/// The longest socket path macOS binds: `sun_path` less its NUL.
#[cfg(unix)]
pub(crate) const MAX_SOCKET_PATH: usize = 103;

/// Where the service's files are; a product overrides any field after the
/// platform's defaults.
#[derive(Clone, Debug)]
pub struct LocalBootstrap {
    /// Refused unless [`wslib_service::private_directory`] passes it, and so
    /// must `db`'s directory when it is another.
    pub state_dir: PathBuf,
    pub db: PathBuf,
    pub endpoints: Vec<LocalEndpoint>,
    /// Read only for the build `GET /api/branding` reports; never served.
    pub ui: Option<PathBuf>,
    /// Written by this process only; point launchd's `StandardErrorPath`
    /// elsewhere to keep panics.
    pub log_file: PathBuf,
    /// The service whose account, `NT SERVICE\<service>`, owns every pipe;
    /// `None` leaves them this process's user's.
    #[cfg(windows)]
    pub service: Option<String>,
}

/// A control endpoint, and the group its directory is owned by, or on Windows
/// the local group its pipe is granted to.
///
/// On unix the installer's directory must be owned by this process's user or
/// root and by `group`, writable by neither its group nor others, with no
/// extended ACL on macOS; a macOS socket takes its group, a Linux one the
/// process's unless the directory is setgid. On Windows an empty `group` grants
/// the pipe to nobody but SYSTEM and its owner.
///
/// It holds 32 connections, closing one idle for 5 s; an open feed holds one
/// for up to 5 minutes. Past the 32, a socket's clients wait to be accepted; a
/// pipe refuses all but its next client as busy.
#[derive(Clone, Debug)]
pub struct LocalEndpoint {
    pub path: PathBuf,
    pub ceiling: Role,
    pub group: String,
}

impl LocalBootstrap {
    /// `/Library/Application Support/<product>` holding `state/` and
    /// `run/<role>/<name>.sock`, each role's directory owned by `<name>`,
    /// `<name>-operator` or `<name>-viewer`, and `/Library/Logs/<product>/<name>.log`.
    /// A socket path may be at most 103 bytes, so keep both short.
    pub fn macos(product: &str, name: &str) -> Self {
        let support = Path::new("/Library/Application Support").join(product);
        let endpoint = |role: Role, group: String| LocalEndpoint {
            path: support
                .join("run")
                .join(role.as_str())
                .join(format!("{name}.sock")),
            ceiling: role,
            group,
        };
        Self {
            endpoints: vec![
                endpoint(Role::Admin, name.to_string()),
                endpoint(Role::Operator, format!("{name}-operator")),
                endpoint(Role::Viewer, format!("{name}-viewer")),
            ],
            ..Self::from_layout(Layout::macos(product, name), name)
        }
    }

    fn from_layout(layout: Layout, name: &str) -> Self {
        Self {
            db: layout.state_dir.join(format!("{name}.db")),
            state_dir: layout.state_dir,
            endpoints: Vec::new(),
            ui: None,
            log_file: layout
                .log_file
                .expect("the macOS and Windows layouts name a log file; only systemd's does not"),
            #[cfg(windows)]
            service: None,
        }
    }

    /// `%ProgramData%\<product>\state\<name>.db` and `logs\<name>.log`, and
    /// the pipes `\\.\pipe\<name>-admin`, `-operator` and `-viewer`, granted to
    /// the local groups `<product> Administrators`, `<product> Operators` and
    /// `<product> Viewers` and owned by the service `name`, whose SID type must
    /// be unrestricted.
    #[cfg(windows)]
    pub fn windows(product: &str, name: &str) -> Self {
        let endpoint = |role: Role, group: &str| LocalEndpoint {
            path: PathBuf::from(format!(r"\\.\pipe\{name}-{role}")),
            ceiling: role,
            group: format!("{product} {group}"),
        };
        Self {
            endpoints: vec![
                endpoint(Role::Admin, "Administrators"),
                endpoint(Role::Operator, "Operators"),
                endpoint(Role::Viewer, "Viewers"),
            ],
            service: Some(name.to_string()),
            ..Self::from_layout(Layout::windows(product, name), name)
        }
    }

    /// The store at [`db`](Self::db), once the state directory has been checked,
    /// so a database is never made in one that fails it.
    pub async fn open_store(&self, app: Option<Migrator>) -> Result<Store, LocalError> {
        let _held = self.check_state()?;
        Ok(Store::open(&self.db, app).await?)
    }

    pub(crate) async fn check(&self) -> Result<(), LocalError> {
        if self.endpoints.is_empty() {
            return Err(LocalError::NoEndpoints);
        }
        for endpoint in &self.endpoints {
            endpoint.check().await?;
        }
        self.check_state().map(drop)
    }

    /// On Windows no directory can be renamed until what this returns drops.
    fn check_state(&self) -> Result<Vec<Held>, LocalError> {
        let db_dir = self.db.parent().filter(|dir| *dir != self.state_dir);
        let held = std::iter::once(self.state_dir.as_path())
            .chain(db_dir)
            .map(wslib_service::private_directory)
            .collect::<Result<_, _>>()?;
        Ok(held)
    }

    pub(crate) fn control_endpoints(&self) -> Vec<ControlEndpoint> {
        #[cfg(unix)]
        let served =
            |endpoint: &LocalEndpoint| ControlEndpoint::new(&endpoint.path, endpoint.ceiling);
        #[cfg(windows)]
        let served = |endpoint: &LocalEndpoint| {
            let pipe = ControlEndpoint::new(&endpoint.path, endpoint.ceiling);
            let pipe = match endpoint.group.as_str() {
                "" => pipe,
                group => pipe.granted_to(group),
            };
            match &self.service {
                Some(service) => pipe.owned_by_service(service),
                None => pipe,
            }
        };
        self.endpoints.iter().map(served).collect()
    }
}

impl LocalEndpoint {
    async fn check(&self) -> Result<(), LocalError> {
        #[cfg(unix)]
        {
            let length = self.path.as_os_str().len();
            if length > MAX_SOCKET_PATH {
                return Err(LocalError::refused(
                    &self.path,
                    format!(
                        "a macOS socket path may be at most {MAX_SOCKET_PATH} bytes, and this is {length}"
                    ),
                ));
            }
            let dir = self.path.parent().unwrap_or(Path::new(""));
            crate::checks::endpoint_directory(dir, &self.group)
                .await
                .map_err(|because| {
                    LocalError::refused(
                        dir,
                        format!(
                            "it is the control endpoint directory for the group {}, and {because}",
                            self.group
                        ),
                    )
                })?;
        }
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::testing::laid_out;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::time::Duration;
    use wslib_appliance_core::testing::group_of;

    fn chmod(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[cfg(target_os = "macos")]
    fn add_acl(dir: &Path) {
        let added = std::process::Command::new("chmod")
            .args(["+a", "everyone allow list"])
            .arg(dir)
            .status()
            .unwrap();
        assert!(added.success());
    }

    async fn refusal(bootstrap: &LocalBootstrap) -> String {
        bootstrap.check().await.expect_err("refuses").to_string()
    }

    #[test]
    fn the_macos_layout_puts_each_role_in_a_directory_of_its_own() {
        let bootstrap = LocalBootstrap::macos("Widget Monitor", "widgets");
        assert_eq!(
            bootstrap.db,
            Path::new("/Library/Application Support/Widget Monitor/state/widgets.db")
        );
        assert_eq!(
            bootstrap.log_file,
            Path::new("/Library/Logs/Widget Monitor/widgets.log")
        );
        let endpoints: Vec<_> = bootstrap
            .endpoints
            .iter()
            .map(|e| (e.path.to_str().unwrap(), e.ceiling, e.group.as_str()))
            .collect();
        let run = "/Library/Application Support/Widget Monitor/run";
        assert_eq!(
            endpoints,
            [
                (
                    &*format!("{run}/admin/widgets.sock"),
                    Role::Admin,
                    "widgets"
                ),
                (
                    &*format!("{run}/operator/widgets.sock"),
                    Role::Operator,
                    "widgets-operator"
                ),
                (
                    &*format!("{run}/viewer/widgets.sock"),
                    Role::Viewer,
                    "widgets-viewer"
                ),
            ]
        );
    }

    #[tokio::test]
    async fn a_laid_out_install_passes() {
        let dir = tempfile::tempdir().unwrap();
        let bootstrap = laid_out(dir.path());
        bootstrap.check().await.expect("passes");
        chmod(&bootstrap.state_dir, 0o750);
        bootstrap.check().await.expect("its group may read it");
    }

    #[tokio::test]
    async fn a_missing_endpoint_directory_refuses_naming_it_and_its_group() {
        let dir = tempfile::tempdir().unwrap();
        let bootstrap = laid_out(dir.path());
        let operator = dir.path().join("operator");
        std::fs::remove_dir(&operator).unwrap();

        let said = refusal(&bootstrap).await;
        assert!(
            said.contains(&*operator.to_string_lossy())
                && said.contains(&bootstrap.endpoints[1].group)
                && said.ends_with("it is missing"),
            "{said}"
        );
        assert!(!operator.exists(), "nothing made it");
    }

    #[tokio::test]
    async fn an_endpoint_directory_its_group_or_others_can_write_refuses() {
        for mode in [0o770, 0o752] {
            let dir = tempfile::tempdir().unwrap();
            let bootstrap = laid_out(dir.path());
            chmod(&dir.path().join("viewer"), mode);
            let said = refusal(&bootstrap).await;
            assert!(said.contains(&format!("its mode is {mode:04o}")), "{said}");
        }
    }

    #[tokio::test]
    async fn an_endpoint_directory_owned_by_another_group_refuses_naming_both() {
        let dir = tempfile::tempdir().unwrap();
        let mut bootstrap = laid_out(dir.path());
        let gid = |path: &Path| std::fs::metadata(path).unwrap().gid();
        let found = gid(&dir.path().join("admin"));
        let elsewhere = ["/", "/dev/tty"]
            .map(Path::new)
            .into_iter()
            .find(|path| gid(path) != found)
            .expect("a path of another group");
        let other = group_of(elsewhere);
        bootstrap.endpoints[2].group = other.clone();

        let said = refusal(&bootstrap).await;
        assert!(
            said.contains(&*dir.path().join("admin").to_string_lossy())
                && said.ends_with(&format!(
                    "it is owned by gid {found}, not {other}'s {}",
                    gid(elsewhere)
                )),
            "{said}"
        );
    }

    #[tokio::test]
    async fn no_endpoints_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let mut bootstrap = laid_out(dir.path());
        bootstrap.endpoints.clear();
        assert!(matches!(
            bootstrap.check().await,
            Err(LocalError::NoEndpoints)
        ));
    }

    #[tokio::test]
    async fn a_failed_group_lookup_is_told_apart_from_no_such_group() {
        let said = crate::checks::group_id("appliance-admin", Duration::from_secs(5), |_| {
            Err(libc::EIO)
        })
        .await
        .expect_err("refuses");
        assert!(
            said.starts_with("looking up the group appliance-admin failed: ")
                && said.contains(&std::io::Error::from_raw_os_error(libc::EIO).to_string()),
            "{said}"
        );
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn an_endpoint_directory_with_an_extended_acl_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let bootstrap = laid_out(dir.path());
        add_acl(&dir.path().join("operator"));
        assert!(
            refusal(&bootstrap)
                .await
                .ends_with("it carries an extended ACL")
        );
    }

    #[tokio::test]
    async fn an_unknown_group_refuses_saying_so() {
        let dir = tempfile::tempdir().unwrap();
        let mut bootstrap = laid_out(dir.path());
        bootstrap.endpoints[0].group = "appliance-no-such-group".to_string();
        let said = refusal(&bootstrap).await;
        assert!(
            said.ends_with("there is no group named appliance-no-such-group"),
            "{said}"
        );
    }

    #[tokio::test]
    async fn a_group_lookup_past_its_deadline_refuses_saying_so() {
        let (release, stalled) = std::sync::mpsc::channel::<()>();
        let said = tokio::time::timeout(
            Duration::from_secs(5),
            crate::checks::group_id("appliance-admin", Duration::from_millis(20), move |_| {
                stalled.recv().ok();
                Ok(Some(0))
            }),
        )
        .await
        .expect("the deadline, not the lookup, decides")
        .expect_err("refuses");
        release.send(()).ok();
        assert!(said.contains("did not answer within 20ms"), "{said}");
    }

    #[tokio::test]
    async fn a_socket_path_longer_than_macos_binds_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let mut bootstrap = laid_out(dir.path());
        let long = "s".repeat(MAX_SOCKET_PATH);
        bootstrap.endpoints[1].path = dir.path().join("operator").join(long);
        let said = refusal(&bootstrap).await;
        assert!(said.contains("103 bytes"), "{said}");
    }

    #[tokio::test]
    async fn a_state_directory_open_to_others_or_writable_by_its_group_refuses() {
        for mode in [0o720, 0o701, 0o704, 0o755] {
            let dir = tempfile::tempdir().unwrap();
            let bootstrap = laid_out(dir.path());
            chmod(&bootstrap.state_dir, mode);

            let said = refusal(&bootstrap).await;
            assert!(
                said.contains(&*bootstrap.state_dir.to_string_lossy())
                    && said.contains(&format!("its mode is {mode:04o}")),
                "{said}"
            );
            let before_the_store = bootstrap.open_store(None).await.expect_err("refuses");
            assert!(matches!(before_the_store, LocalError::Refused { .. }));
            assert!(!bootstrap.db.exists(), "no database was made");
        }
    }

    #[tokio::test]
    async fn a_state_directory_behind_a_link_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let mut bootstrap = laid_out(dir.path());
        let link = dir.path().join("linked");
        std::os::unix::fs::symlink(&bootstrap.state_dir, &link).unwrap();
        bootstrap.state_dir = link;
        assert!(refusal(&bootstrap).await.ends_with("it is a symbolic link"));
    }

    #[tokio::test]
    async fn the_databases_own_directory_is_held_to_the_same_rule() {
        let dir = tempfile::tempdir().unwrap();
        let mut bootstrap = laid_out(dir.path());
        let elsewhere = dir.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        chmod(&elsewhere, 0o755);
        bootstrap.db = elsewhere.join("t.db");
        let said = refusal(&bootstrap).await;
        assert!(said.contains(&*elsewhere.to_string_lossy()), "{said}");
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn a_state_directory_with_an_extended_acl_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let bootstrap = laid_out(dir.path());
        add_acl(&bootstrap.state_dir);
        assert!(
            refusal(&bootstrap)
                .await
                .ends_with("it carries an extended ACL")
        );
    }

    #[tokio::test]
    async fn serving_refuses_before_anything_binds() {
        let dir = tempfile::tempdir().unwrap();
        let bootstrap = laid_out(dir.path());
        let store = bootstrap.open_store(None).await.expect("store");
        std::fs::remove_dir(dir.path().join("viewer")).unwrap();

        let served = tokio::time::timeout(
            Duration::from_secs(10),
            crate::Service::new(
                store,
                wslib_appliance_types::Branding::unbranded(),
                "0.0.0",
                crate::logs(&[]),
            )
            .serve_local(&bootstrap, std::future::pending()),
        )
        .await
        .expect("refuses rather than serving");
        assert!(
            matches!(served, Err(LocalError::Refused { .. })),
            "{served:?}"
        );
        assert!(!bootstrap.endpoints[2].path.exists(), "nothing bound");
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;
    use crate::testing::laid_out;

    fn icacls(path: &Path, args: &[&str]) {
        let status = std::process::Command::new("icacls")
            .arg(path)
            .args(args)
            .status()
            .unwrap();
        assert!(status.success(), "icacls {} {args:?}", path.display());
    }

    fn refusal(bootstrap: &LocalBootstrap) -> String {
        bootstrap.check_state().expect_err("refuses").to_string()
    }

    #[test]
    fn the_windows_layout_names_each_role_its_pipe_and_group() {
        let bootstrap = LocalBootstrap::windows("Widget Monitor", "widgets");
        let data = PathBuf::from(std::env::var_os("ProgramData").unwrap()).join("Widget Monitor");
        assert_eq!(bootstrap.db, data.join(r"state\widgets.db"));
        assert_eq!(bootstrap.log_file, data.join(r"logs\widgets.log"));
        assert_eq!(bootstrap.service.as_deref(), Some("widgets"));
        let endpoints: Vec<_> = bootstrap
            .endpoints
            .iter()
            .map(|e| (e.path.to_str().unwrap(), e.ceiling, e.group.as_str()))
            .collect();
        assert_eq!(
            endpoints,
            [
                (
                    r"\\.\pipe\widgets-admin",
                    Role::Admin,
                    "Widget Monitor Administrators"
                ),
                (
                    r"\\.\pipe\widgets-operator",
                    Role::Operator,
                    "Widget Monitor Operators"
                ),
                (
                    r"\\.\pipe\widgets-viewer",
                    Role::Viewer,
                    "Widget Monitor Viewers"
                ),
            ]
        );
    }

    #[test]
    fn a_state_directory_only_its_owner_and_system_may_use_passes() {
        let dir = tempfile::tempdir().unwrap();
        laid_out(dir.path()).check_state().expect("passes");
    }

    #[tokio::test]
    async fn a_state_directory_granting_users_anything_refuses_naming_its_dacl() {
        let dir = tempfile::tempdir().unwrap();
        let bootstrap = laid_out(dir.path());
        icacls(
            &bootstrap.state_dir,
            &["/grant", "*S-1-5-32-545:(OI)(CI)(RD)"],
        );

        let said = refusal(&bootstrap);
        assert!(
            said.contains(&*bootstrap.state_dir.to_string_lossy())
                && said.contains("its DACL allows someone besides")
                && said.contains(";;;BU)"),
            "{said}"
        );
        let before_the_store = bootstrap.open_store(None).await.expect_err("refuses");
        assert!(matches!(before_the_store, LocalError::Refused { .. }));
        assert!(!bootstrap.db.exists(), "no database was made");
    }

    #[test]
    fn a_state_directory_behind_a_junction_or_not_a_directory_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let mut bootstrap = laid_out(dir.path());
        let junction = dir.path().join("junction");
        let linked = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .args([&junction, &bootstrap.state_dir])
            .status()
            .unwrap();
        assert!(linked.success());
        bootstrap.state_dir = junction;
        assert!(refusal(&bootstrap).ends_with("it is a link or a junction"));

        let file = dir.path().join("file");
        std::fs::write(&file, "").unwrap();
        bootstrap.state_dir = file;
        assert!(refusal(&bootstrap).ends_with("it is not a directory"));
    }

    #[test]
    fn the_databases_own_directory_is_held_to_the_same_rule() {
        let dir = tempfile::tempdir().unwrap();
        let mut bootstrap = laid_out(dir.path());
        let elsewhere = dir.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        icacls(&elsewhere, &["/grant", "*S-1-1-0:(OI)(CI)(R)"]);
        bootstrap.db = elsewhere.join("t.db");
        let said = refusal(&bootstrap);
        assert!(said.contains(&*elsewhere.to_string_lossy()), "{said}");
    }

    #[tokio::test]
    async fn a_parent_users_may_add_to_passes_and_one_they_may_delete_from_or_resecure_refuses() {
        for refused in ["(DC)", "(WDAC)"] {
            let dir = tempfile::tempdir().unwrap();
            let bootstrap = laid_out(dir.path());
            let grant =
                |rights: &str| icacls(dir.path(), &["/grant", &format!("*S-1-5-32-545:{rights}")]);
            grant("(RX)");
            grant("(WD,AD)");
            bootstrap
                .check_state()
                .expect("others may read it and add to it");

            grant(refused);
            let said = refusal(&bootstrap);
            assert!(
                said.starts_with(&format!("refusing {}: ", dir.path().display()))
                    && said.contains("delete from it")
                    && said.contains(";;;BU)"),
                "{refused}: {said}"
            );
            let before_the_store = bootstrap.open_store(None).await.expect_err("refuses");
            assert!(matches!(before_the_store, LocalError::Refused { .. }));
            assert!(!bootstrap.db.exists(), "no database was made");
        }
    }

    #[test]
    fn a_checked_state_directory_and_its_parent_cannot_be_renamed_while_held() {
        let dir = tempfile::tempdir().unwrap();
        let bootstrap = laid_out(dir.path());
        let moved = dir.path().join("moved");
        let held = bootstrap.check_state().expect("passes");
        std::fs::rename(&bootstrap.state_dir, &moved).expect_err("the state directory is held");
        let parent_moved = dir.path().with_extension("moved");
        std::fs::rename(dir.path(), &parent_moved).expect_err("its parent is held");

        drop(held);
        std::fs::rename(&bootstrap.state_dir, &moved).expect("released");
    }
}
