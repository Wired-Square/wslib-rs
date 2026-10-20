#![cfg(unix)]

use std::sync::{Arc, Mutex};

use wslib_systemd::testing::Fakes;
use wslib_systemd::{
    HostnameProxy, Login1Proxy, NOBODY_OWNS_IT, SystemdProxy, TimedateProxy, TimesyncProxy,
    UnitProxy, error_is, nobody_owns, refused,
};
use zbus::fdo;
use zbus::zvariant::OwnedObjectPath;

const UNIT: &str = "/org/freedesktop/systemd1/unit/widget_2eservice";

type Heard = Arc<Mutex<Vec<String>>>;

fn path(p: &str) -> OwnedObjectPath {
    OwnedObjectPath::try_from(p).unwrap()
}

#[derive(zbus::DBusError, Debug)]
#[zbus(prefix = "org.freedesktop.systemd1")]
enum SystemdError {
    #[zbus(error)]
    ZBus(zbus::Error),
    NoSuchUnit(String),
    UnitMasked(String),
}

struct Systemd(Heard);

impl Systemd {
    fn heard(&self, what: String) -> OwnedObjectPath {
        self.0.lock().unwrap().push(what);
        path("/org/freedesktop/systemd1/job/1")
    }
}

#[zbus::interface(name = "org.freedesktop.systemd1.Manager")]
impl Systemd {
    #[zbus(name = "StartUnit")]
    fn start_unit(&self, name: &str, mode: &str) -> Result<OwnedObjectPath, SystemdError> {
        match name {
            "missing.service" => Err(SystemdError::NoSuchUnit(name.into())),
            "masked.service" => Err(SystemdError::UnitMasked(name.into())),
            _ => Ok(self.heard(format!("start {name} {mode}"))),
        }
    }
    #[zbus(name = "StopUnit")]
    fn stop_unit(&self, name: &str, mode: &str) -> OwnedObjectPath {
        self.heard(format!("stop {name} {mode}"))
    }
    #[zbus(name = "RestartUnit")]
    fn restart_unit(&self, name: &str, mode: &str) -> OwnedObjectPath {
        self.heard(format!("restart {name} {mode}"))
    }
    #[zbus(name = "TryRestartUnit")]
    fn try_restart_unit(&self, name: &str, mode: &str) -> OwnedObjectPath {
        self.heard(format!("try-restart {name} {mode}"))
    }
    #[zbus(name = "MaskUnitFiles")]
    fn mask_unit_files(
        &self,
        files: Vec<String>,
        runtime: bool,
        force: bool,
    ) -> Vec<(String, String, String)> {
        self.heard(format!("mask {files:?} {runtime} {force}"));
        vec![("symlink".into(), "/etc/x".into(), "/dev/null".into())]
    }
    #[zbus(name = "UnmaskUnitFiles")]
    fn unmask_unit_files(
        &self,
        files: Vec<String>,
        runtime: bool,
    ) -> Vec<(String, String, String)> {
        self.heard(format!("unmask {files:?} {runtime}"));
        vec![]
    }
    #[zbus(name = "Reload")]
    fn reload(&self) {
        self.heard("reload".into());
    }
    #[zbus(name = "GetUnitFileState")]
    fn get_unit_file_state(&self, _name: &str) -> String {
        "masked".into()
    }
    #[zbus(name = "LoadUnit")]
    fn load_unit(&self, _name: &str) -> OwnedObjectPath {
        path(UNIT)
    }
    #[zbus(name = "ListUnitsFiltered")]
    fn list_units_filtered(&self, states: Vec<String>) -> Vec<wslib_systemd::UnitRow> {
        self.heard(format!("list {states:?}"));
        vec![(
            "widget.service".into(),
            "Widget".into(),
            "loaded".into(),
            "failed".into(),
            "failed".into(),
            String::new(),
            path(UNIT),
            0,
            String::new(),
            path("/"),
        )]
    }
    #[zbus(property, name = "FinishTimestampMonotonic")]
    fn finish_timestamp_monotonic(&self) -> u64 {
        7_000_000
    }
}

struct Unit;

#[zbus::interface(name = "org.freedesktop.systemd1.Unit")]
impl Unit {
    #[zbus(property, name = "LoadState")]
    fn load_state(&self) -> String {
        "loaded".into()
    }
    #[zbus(property, name = "ActiveState")]
    fn active_state(&self) -> String {
        "active".into()
    }
    #[zbus(property, name = "Job")]
    fn job(&self) -> (u32, OwnedObjectPath) {
        (0, path("/"))
    }
}

#[tokio::test]
async fn the_manager_and_a_unit_answer_on_systemds_wire_names() {
    let heard = Heard::default();
    let (client, _served) = Fakes::new()
        .at("/org/freedesktop/systemd1", Systemd(heard.clone()))
        .at(UNIT, Unit)
        .connect()
        .await
        .unwrap();
    let systemd = SystemdProxy::new(&client).await.unwrap();

    systemd
        .start_unit("widget.service", "replace")
        .await
        .unwrap();
    systemd
        .stop_unit("widget.service", "replace")
        .await
        .unwrap();
    systemd
        .restart_unit("widget.service", "replace")
        .await
        .unwrap();
    systemd
        .try_restart_unit("widget.service", "replace")
        .await
        .unwrap();
    let changes = systemd
        .mask_unit_files(&["bluetooth.service"], false, true)
        .await
        .unwrap();
    assert_eq!(changes.len(), 1);
    systemd
        .unmask_unit_files(&["bluetooth.service"], false)
        .await
        .unwrap();
    systemd.reload().await.unwrap();
    assert_eq!(
        systemd
            .get_unit_file_state("bluetooth.service")
            .await
            .unwrap(),
        "masked"
    );
    let rows = systemd.list_units_filtered(&["failed"]).await.unwrap();
    assert_eq!(rows[0].0, "widget.service");
    assert_eq!(
        systemd.finish_timestamp_monotonic().await.unwrap(),
        7_000_000
    );
    assert_eq!(
        *heard.lock().unwrap(),
        [
            "start widget.service replace",
            "stop widget.service replace",
            "restart widget.service replace",
            "try-restart widget.service replace",
            "mask [\"bluetooth.service\"] false true",
            "unmask [\"bluetooth.service\"] false",
            "reload",
            "list [\"failed\"]",
        ]
    );

    let unit = UnitProxy::builder(&client)
        .path(systemd.load_unit("widget.service").await.unwrap())
        .unwrap()
        .build()
        .await
        .unwrap();
    assert_eq!(unit.load_state().await.unwrap(), "loaded");
    assert_eq!(unit.active_state().await.unwrap(), "active");
    assert_eq!(unit.job().await.unwrap().0, 0);
}

#[tokio::test]
async fn a_missing_or_masked_unit_reads_as_nobody_owning_it() {
    let (client, _served) = Fakes::new()
        .at("/org/freedesktop/systemd1", Systemd(Heard::default()))
        .connect()
        .await
        .unwrap();
    let systemd = SystemdProxy::new(&client).await.unwrap();
    for unit in ["missing.service", "masked.service"] {
        let e = systemd.start_unit(unit, "replace").await.unwrap_err();
        assert!(nobody_owns(&e), "{unit}: {e}");
        assert!(!refused(&e));
    }
}

struct Hostnamed {
    refusal: Option<fdo::Error>,
    set: Heard,
}

#[zbus::interface(name = "org.freedesktop.hostname1")]
impl Hostnamed {
    #[zbus(name = "SetStaticHostname")]
    fn set_static_hostname(&self, name: &str, interactive: bool) -> fdo::Result<()> {
        self.refusal.clone().map_or(Ok(()), Err)?;
        self.set
            .lock()
            .unwrap()
            .push(format!("static {name} {interactive}"));
        Ok(())
    }
    #[zbus(name = "SetHostname")]
    fn set_hostname(&self, name: &str, interactive: bool) -> fdo::Result<()> {
        self.set
            .lock()
            .unwrap()
            .push(format!("transient {name} {interactive}"));
        Ok(())
    }
    #[zbus(property, name = "Hostname")]
    fn hostname(&self) -> String {
        "dhcp-given".into()
    }
    #[zbus(property, name = "StaticHostname")]
    fn static_hostname(&self) -> String {
        "widget-01".into()
    }
}

async fn hostnamed(
    refusal: Option<fdo::Error>,
) -> (HostnameProxy<'static>, Heard, zbus::Connection) {
    let set = Heard::default();
    let fake = Hostnamed {
        refusal,
        set: set.clone(),
    };
    let (client, served) = Fakes::new()
        .at("/org/freedesktop/hostname1", fake)
        .connect()
        .await
        .unwrap();
    (HostnameProxy::new(&client).await.unwrap(), set, served)
}

#[tokio::test]
async fn hostnamed_sets_and_reads_both_names() {
    let (hostname, set, _served) = hostnamed(None).await;
    hostname
        .set_static_hostname("widget-02", false)
        .await
        .unwrap();
    hostname.set_hostname("widget-02", false).await.unwrap();
    assert_eq!(
        *set.lock().unwrap(),
        ["static widget-02 false", "transient widget-02 false"]
    );
    assert_eq!(hostname.hostname().await.unwrap(), "dhcp-given");
    assert_eq!(hostname.static_hostname().await.unwrap(), "widget-01");
}

#[tokio::test]
async fn polkits_refusals_read_as_refused_and_nothing_else_does() {
    for refusal in [
        fdo::Error::AccessDenied("no".into()),
        fdo::Error::InteractiveAuthorizationRequired("ask".into()),
    ] {
        let (hostname, _, _served) = hostnamed(Some(refusal)).await;
        let e = hostname.set_static_hostname("x", false).await.unwrap_err();
        assert!(refused(&e), "{e}");
        assert!(!nobody_owns(&e));
    }
    for other in [
        fdo::Error::ServiceUnknown("gone".into()),
        fdo::Error::NameHasNoOwner("gone".into()),
        fdo::Error::InvalidArgs("bad".into()),
    ] {
        let (hostname, _, _served) = hostnamed(Some(other)).await;
        let e = hostname.set_static_hostname("x", false).await.unwrap_err();
        assert!(!refused(&e), "{e}");
    }
}

#[tokio::test]
async fn error_is_matches_only_the_name_it_is_given() {
    let (hostname, _, _served) = hostnamed(Some(fdo::Error::ServiceUnknown("gone".into()))).await;
    let e = hostname.set_static_hostname("x", false).await.unwrap_err();
    assert!(nobody_owns(&e));
    assert!(error_is(&e, NOBODY_OWNS_IT[0]));
    assert!(!error_is(&e, NOBODY_OWNS_IT[1]));
}

struct Timedated(Heard);

#[zbus::interface(name = "org.freedesktop.timedate1")]
impl Timedated {
    #[zbus(name = "SetTimezone")]
    fn set_timezone(&self, zone: &str, interactive: bool) {
        self.0
            .lock()
            .unwrap()
            .push(format!("zone {zone} {interactive}"));
    }
    #[zbus(name = "SetNTP")]
    fn set_ntp(&self, on: bool, interactive: bool) {
        self.0
            .lock()
            .unwrap()
            .push(format!("ntp {on} {interactive}"));
    }
    #[zbus(name = "SetTime")]
    fn set_time(&self, usec: i64, relative: bool, interactive: bool) {
        self.0
            .lock()
            .unwrap()
            .push(format!("time {usec} {relative} {interactive}"));
    }
    #[zbus(name = "ListTimezones")]
    fn list_timezones(&self) -> Vec<String> {
        vec!["Australia/Sydney".into(), "UTC".into()]
    }
    #[zbus(property, name = "Timezone")]
    fn timezone(&self) -> String {
        "Australia/Sydney".into()
    }
    #[zbus(property, name = "NTP")]
    fn ntp(&self) -> bool {
        true
    }
    #[zbus(property, name = "CanNTP")]
    fn can_ntp(&self) -> bool {
        true
    }
    #[zbus(property, name = "NTPSynchronized")]
    fn ntp_synchronized(&self) -> bool {
        false
    }
}

struct Timesyncd;

#[zbus::interface(name = "org.freedesktop.timesync1.Manager")]
impl Timesyncd {
    #[zbus(property, name = "ServerName")]
    fn server_name(&self) -> String {
        "ntp.example.com".into()
    }
}

#[tokio::test]
async fn timedated_and_timesyncd_answer_on_their_wire_names() {
    let heard = Heard::default();
    let (client, _served) = Fakes::new()
        .at("/org/freedesktop/timedate1", Timedated(heard.clone()))
        .at("/org/freedesktop/timesync1", Timesyncd)
        .connect()
        .await
        .unwrap();
    let timedate = TimedateProxy::new(&client).await.unwrap();
    timedate.set_timezone("UTC", false).await.unwrap();
    timedate.set_ntp(false, false).await.unwrap();
    timedate.set_time(1_000_000, true, false).await.unwrap();
    assert_eq!(
        *heard.lock().unwrap(),
        [
            "zone UTC false",
            "ntp false false",
            "time 1000000 true false"
        ]
    );
    assert_eq!(
        timedate.list_timezones().await.unwrap(),
        ["Australia/Sydney", "UTC"]
    );
    assert_eq!(timedate.timezone().await.unwrap(), "Australia/Sydney");
    assert!(timedate.ntp().await.unwrap());
    assert!(timedate.can_ntp().await.unwrap());
    assert!(!timedate.ntp_synchronized().await.unwrap());

    let timesync = TimesyncProxy::new(&client).await.unwrap();
    assert_eq!(timesync.server_name().await.unwrap(), "ntp.example.com");
}

struct Logind(Heard);

#[zbus::interface(name = "org.freedesktop.login1.Manager")]
impl Logind {
    #[zbus(name = "Reboot")]
    fn reboot(&self, interactive: bool) {
        self.0.lock().unwrap().push(format!("reboot {interactive}"));
    }
    #[zbus(name = "PowerOff")]
    fn power_off(&self, interactive: bool) {
        self.0
            .lock()
            .unwrap()
            .push(format!("power-off {interactive}"));
    }
    #[zbus(name = "CanReboot")]
    fn can_reboot(&self) -> String {
        "yes".into()
    }
    #[zbus(name = "CanPowerOff")]
    fn can_power_off(&self) -> String {
        "na".into()
    }
}

#[tokio::test]
async fn logind_reboots_and_powers_off_on_its_wire_names() {
    let heard = Heard::default();
    let (client, _served) = Fakes::new()
        .at("/org/freedesktop/login1", Logind(heard.clone()))
        .connect()
        .await
        .unwrap();
    let login = Login1Proxy::new(&client).await.unwrap();
    assert_eq!(login.can_reboot().await.unwrap(), "yes");
    assert_eq!(login.can_power_off().await.unwrap(), "na");
    login.reboot(false).await.unwrap();
    login.power_off(false).await.unwrap();
    assert_eq!(*heard.lock().unwrap(), ["reboot false", "power-off false"]);
}

#[tokio::test]
async fn a_path_that_is_not_an_object_path_fails_to_connect() {
    assert!(
        Fakes::new()
            .at("not a path", Timesyncd)
            .connect()
            .await
            .is_err()
    );
}
