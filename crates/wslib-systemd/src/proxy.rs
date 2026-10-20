use zbus::proxy;
use zbus::zvariant::OwnedObjectPath;

/// A row of `ListUnitsFiltered`: name, description, load state, active state,
/// sub-state, followed unit, unit path, job id, job type and job path.
pub type UnitRow = (
    String,
    String,
    String,
    String,
    String,
    String,
    OwnedObjectPath,
    u32,
    String,
    OwnedObjectPath,
);

/// systemd's manager.
///
/// `StartUnit` and its kin take any unit name; never pass one from a request.
#[proxy(
    interface = "org.freedesktop.systemd1.Manager",
    default_service = "org.freedesktop.systemd1",
    default_path = "/org/freedesktop/systemd1"
)]
pub trait Systemd {
    fn start_unit(&self, name: &str, mode: &str) -> zbus::Result<OwnedObjectPath>;
    fn stop_unit(&self, name: &str, mode: &str) -> zbus::Result<OwnedObjectPath>;
    fn restart_unit(&self, name: &str, mode: &str) -> zbus::Result<OwnedObjectPath>;
    fn try_restart_unit(&self, name: &str, mode: &str) -> zbus::Result<OwnedObjectPath>;
    fn mask_unit_files(
        &self,
        files: &[&str],
        runtime: bool,
        force: bool,
    ) -> zbus::Result<Vec<(String, String, String)>>;
    fn unmask_unit_files(
        &self,
        files: &[&str],
        runtime: bool,
    ) -> zbus::Result<Vec<(String, String, String)>>;
    /// `systemctl daemon-reload`.
    fn reload(&self) -> zbus::Result<()>;
    /// `enabled`, `disabled`, `masked`, …
    fn get_unit_file_state(&self, name: &str) -> zbus::Result<String>;
    /// The unit's object path, for a [`UnitProxy`].
    fn load_unit(&self, name: &str) -> zbus::Result<OwnedObjectPath>;
    fn list_units_filtered(&self, states: &[&str]) -> zbus::Result<Vec<UnitRow>>;

    #[zbus(property)]
    fn finish_timestamp_monotonic(&self) -> zbus::Result<u64>;
}

/// One unit, at the path [`SystemdProxy::load_unit`] gave, set with the
/// builder's `path`.
#[proxy(
    interface = "org.freedesktop.systemd1.Unit",
    default_service = "org.freedesktop.systemd1"
)]
pub trait Unit {
    #[zbus(property)]
    fn load_state(&self) -> zbus::Result<String>;
    /// `active`, `deactivating`, `inactive`, `failed`, …
    #[zbus(property)]
    fn active_state(&self) -> zbus::Result<String>;
    /// The queued job, id 0 when there is none.
    #[zbus(property)]
    fn job(&self) -> zbus::Result<(u32, OwnedObjectPath)>;
}

/// systemd-hostnamed. Activatable: the first call starts it, or fails with
/// [`nobody_owns`](crate::nobody_owns) where it is not installed.
#[proxy(
    interface = "org.freedesktop.hostname1",
    default_service = "org.freedesktop.hostname1",
    default_path = "/org/freedesktop/hostname1"
)]
pub trait Hostname {
    /// Writes `/etc/hostname`.
    fn set_static_hostname(&self, hostname: &str, interactive: bool) -> zbus::Result<()>;
    /// Sets the running kernel's name.
    fn set_hostname(&self, hostname: &str, interactive: bool) -> zbus::Result<()>;

    #[zbus(property)]
    fn hostname(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn static_hostname(&self) -> zbus::Result<String>;
}

/// systemd-timedated. Activatable, like hostnamed.
#[proxy(
    interface = "org.freedesktop.timedate1",
    default_service = "org.freedesktop.timedate1",
    default_path = "/org/freedesktop/timedate1"
)]
pub trait Timedate {
    fn set_timezone(&self, timezone: &str, interactive: bool) -> zbus::Result<()>;
    /// Enables and starts, or disables and stops, the NTP unit.
    #[zbus(name = "SetNTP")]
    fn set_ntp(&self, use_ntp: bool, interactive: bool) -> zbus::Result<()>;
    /// Refused while NTP is on.
    fn set_time(&self, usec_utc: i64, relative: bool, interactive: bool) -> zbus::Result<()>;
    fn list_timezones(&self) -> zbus::Result<Vec<String>>;

    #[zbus(property)]
    fn timezone(&self) -> zbus::Result<String>;
    /// Whether the NTP unit is active.
    #[zbus(property, name = "NTP")]
    fn ntp(&self) -> zbus::Result<bool>;
    /// Whether an NTP unit is known, from `ntp-units.d`.
    #[zbus(property, name = "CanNTP")]
    fn can_ntp(&self) -> zbus::Result<bool>;
    /// The kernel's `adjtimex` answer.
    #[zbus(property, name = "NTPSynchronized")]
    fn ntp_synchronized(&self) -> zbus::Result<bool>;
}

/// systemd-timesyncd's manager.
#[proxy(
    interface = "org.freedesktop.timesync1.Manager",
    default_service = "org.freedesktop.timesync1",
    default_path = "/org/freedesktop/timesync1"
)]
pub trait Timesync {
    /// Empty when it has none.
    #[zbus(property)]
    fn server_name(&self) -> zbus::Result<String>;
}

/// systemd-logind's manager: reboot and power-off. Prefer it to
/// `StartUnit("reboot.target")`, which takes any unit name; these take none.
#[proxy(
    interface = "org.freedesktop.login1.Manager",
    default_service = "org.freedesktop.login1",
    default_path = "/org/freedesktop/login1"
)]
pub trait Login1 {
    fn reboot(&self, interactive: bool) -> zbus::Result<()>;
    fn power_off(&self, interactive: bool) -> zbus::Result<()>;
    /// `yes`, `no`, `na` (not here, as in a container) or `challenge`
    /// (polkit would ask).
    fn can_reboot(&self) -> zbus::Result<String>;
    fn can_power_off(&self) -> zbus::Result<String>;
}
