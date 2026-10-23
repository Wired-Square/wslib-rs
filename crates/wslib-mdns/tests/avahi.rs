#![cfg(unix)]

use std::net::IpAddr;
use std::time::Duration;

use futures_util::StreamExt;
use wslib_mdns::avahi::{self, AddressGroup, Avahi, ServerState};
use wslib_mdns::testing::FakeAvahi;
use wslib_mdns::{AdvertState, Error, Service};

fn error_name(e: &zbus::Error) -> Option<&str> {
    match e {
        zbus::Error::MethodError(name, ..) => Some(name.as_str()),
        _ => None,
    }
}

async fn eventually(fake: &FakeAvahi, call: &str) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !fake.heard().iter().any(|c| c == call) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{call} never came: {:?}", fake.heard()));
}

fn service() -> Service {
    let mut service = Service::new(
        "_https._tcp".parse().unwrap(),
        "Widget".parse().unwrap(),
        443,
    );
    service
        .subtypes
        .push("_widget._sub._https._tcp".parse().unwrap());
    service.txt.push("product=widget".parse().unwrap());
    service
}

async fn settles(state: &mut tokio::sync::watch::Receiver<AdvertState>, to: AdvertState) {
    tokio::time::timeout(Duration::from_secs(5), state.wait_for(|s| *s == to))
        .await
        .expect("in time")
        .expect("watched");
}

#[tokio::test]
async fn an_advert_goes_on_every_interface_and_protocol_with_its_subtype_and_txt() {
    let fake = FakeAvahi::new();
    let (bus, _served) = fake.connect().await.unwrap();
    let advert = Avahi::new(&bus).advertise(&service()).await.unwrap();
    settles(&mut advert.state(), AdvertState::Established).await;
    assert_eq!(
        fake.heard(),
        [
            "EntryGroupNew 1",
            "AddService 1 -1 -1 0 Widget _https._tcp 443 product=widget",
            "AddServiceSubtype 1 Widget _widget._sub._https._tcp",
            "Commit 1",
        ]
    );
    assert_eq!(fake.established(), ["Widget"]);

    advert.withdraw().await.unwrap();
    assert_eq!(fake.heard().last().unwrap(), "Free 1");
    assert!(fake.established().is_empty());
}

#[tokio::test]
async fn a_dropped_advert_is_withdrawn() {
    let fake = FakeAvahi::new();
    let (bus, _served) = fake.connect().await.unwrap();
    drop(Avahi::new(&bus).advertise(&service()).await.unwrap());
    eventually(&fake, "Free 1").await;
}

#[tokio::test]
async fn both_publishes_can_run_in_a_spawned_task() {
    let fake = FakeAvahi::new();
    let (bus, _served) = fake.connect().await.unwrap();
    let advertising = bus.clone();
    let advert = tokio::spawn(async move { Avahi::new(&advertising).advertise(&service()).await });
    let addresses = [(2, "192.168.1.10".parse::<IpAddr>().unwrap())];
    let group = tokio::spawn(async move {
        AddressGroup::publish(&bus, &"widget".parse().unwrap(), addresses).await
    });
    advert.await.unwrap().unwrap();
    group.await.unwrap().unwrap();
}

#[tokio::test]
async fn a_publish_cut_short_while_filling_or_committing_frees_its_group() {
    let fake = FakeAvahi::new();
    let (bus, _served) = fake.connect().await.unwrap();
    for (method, group) in [("AddServiceSubtype", 1), ("Commit", 2)] {
        let hold = fake.hold(method);
        let avahi = Avahi::new(&bus);
        let service = service();
        let publish = avahi.advertise(&service);
        tokio::select! {
            outcome = publish => panic!("{method} answered while held: {outcome:?}"),
            () = hold.entered() => {}
        }
        eventually(&fake, &format!("Free {group}")).await;
        hold.release();
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        fake.established().is_empty(),
        "a cut-short commit stayed published"
    );
}

#[tokio::test]
async fn a_collision_stays_collided_and_nothing_renames_it() {
    let fake = FakeAvahi::new().colliding("Widget");
    let (bus, _served) = fake.connect().await.unwrap();
    let advert = Avahi::new(&bus).advertise(&service()).await.unwrap();
    settles(&mut advert.state(), AdvertState::Collided).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(*advert.state().borrow(), AdvertState::Collided);
    assert_eq!(
        fake.heard()
            .iter()
            .filter(|c| c.starts_with("AddService "))
            .count(),
        1
    );
}

#[tokio::test]
async fn a_later_collision_reaches_the_adverts_state() {
    let fake = FakeAvahi::new();
    let (bus, served) = fake.connect().await.unwrap();
    let advert = Avahi::new(&bus).advertise(&service()).await.unwrap();
    let mut state = advert.state();
    settles(&mut state, AdvertState::Established).await;
    fake.collide(&served, "Widget").await.unwrap();
    settles(&mut state, AdvertState::Collided).await;
}

#[tokio::test]
async fn a_name_another_client_holds_is_a_collision_error_and_its_group_is_freed() {
    let fake = FakeAvahi::new().taken("Widget");
    let (bus, _served) = fake.connect().await.unwrap();
    let refused = Avahi::new(&bus).advertise(&service()).await;
    assert!(
        matches!(&refused, Err(Error::Collision(e)) if error_name(e) == Some("org.freedesktop.Avahi.CollisionError")),
        "{refused:?}"
    );
    assert_eq!(fake.heard().last().unwrap(), "Free 1");

    fake.forgive();
    let advert = Avahi::new(&bus).advertise(&service()).await.unwrap();
    settles(&mut advert.state(), AdvertState::Established).await;
}

#[tokio::test]
async fn a_counted_refusal_refuses_only_that_many_calls() {
    let fake = FakeAvahi::new();
    let (bus, _served) = fake.connect().await.unwrap();
    fake.refuse_next("EntryGroupNew", 1);
    let refused = Avahi::new(&bus).advertise(&service()).await;
    assert!(
        matches!(&refused, Err(Error::Bus(e)) if error_name(e) == Some("org.freedesktop.Avahi.NotPermittedError")),
        "{refused:?}"
    );
    Avahi::new(&bus).advertise(&service()).await.unwrap();
}

#[tokio::test]
async fn a_subtype_of_another_type_is_refused_before_avahi_is_asked() {
    let fake = FakeAvahi::new();
    let (bus, _served) = fake.connect().await.unwrap();
    let mut service = service();
    service
        .subtypes
        .push("_widget._sub._http._tcp".parse().unwrap());
    let refused = Avahi::new(&bus).advertise(&service).await;
    assert!(matches!(refused, Err(Error::Unsupported(_))), "{refused:?}");
    assert!(fake.heard().is_empty());
}

#[tokio::test]
async fn an_address_group_publishes_each_address_without_a_reverse_record() {
    let fake = FakeAvahi::new();
    let (bus, _served) = fake.connect().await.unwrap();
    let addresses = [
        (2, "192.168.1.10".parse().unwrap()),
        (2, "fe80::1".parse().unwrap()),
    ];
    let group = AddressGroup::publish(&bus, &"widget".parse().unwrap(), addresses)
        .await
        .unwrap();
    settles(&mut group.state(), AdvertState::Established).await;
    assert_eq!(
        fake.heard(),
        [
            "EntryGroupNew 1",
            "AddAddress 1 2 0 16 widget.local 192.168.1.10",
            "AddAddress 1 2 -1 16 widget.local fe80::1",
            "Commit 1",
        ]
    );
    group.withdraw().await.unwrap();
    assert_eq!(fake.heard().last().unwrap(), "Free 1");
}

#[tokio::test]
async fn an_address_group_reports_a_collision() {
    let fake = FakeAvahi::new().colliding("widget");
    let (bus, _served) = fake.connect().await.unwrap();
    let addresses = [(2, "192.168.1.10".parse().unwrap())];
    let group = AddressGroup::publish(&bus, &"widget".parse().unwrap(), addresses)
        .await
        .unwrap();
    settles(&mut group.state(), AdvertState::Collided).await;

    let none = AddressGroup::publish(&bus, &"widget".parse().unwrap(), Vec::new()).await;
    assert!(matches!(none, Err(Error::Unsupported(_))), "{none:?}");
}

#[tokio::test]
async fn the_host_name_is_read_and_set_and_its_server_states_follow() {
    let fake = FakeAvahi::new().called("widget-2");
    let (bus, served) = fake.connect().await.unwrap();
    assert_eq!(avahi::host_name(&bus).await.unwrap(), "widget-2");
    assert!(avahi::renamed_by_avahi(
        "widget",
        &avahi::host_name(&bus).await.unwrap()
    ));

    let mut states = avahi::server_states(&bus).await.unwrap();
    avahi::set_host_name(&bus, &"widget".parse().unwrap())
        .await
        .unwrap();
    assert_eq!(fake.host_name(), "widget");
    assert_eq!(states.next().await, Some(ServerState::Registering));
    assert_eq!(states.next().await, Some(ServerState::Running));

    fake.rename(&served, "widget-3").await.unwrap();
    assert_eq!(states.next().await, Some(ServerState::Collision));
    assert_eq!(states.next().await, Some(ServerState::Registering));
    assert_eq!(states.next().await, Some(ServerState::Running));
    assert_eq!(avahi::host_name(&bus).await.unwrap(), "widget-3");
    assert!(fake.heard().iter().any(|c| c == "GetHostName"));

    avahi::set_host_name(&bus, &"widget-3".parse().unwrap())
        .await
        .expect("avahi's own name already is no change");
    assert_eq!(fake.heard().last().unwrap(), "SetHostName widget-3");
}

#[tokio::test]
async fn a_refused_rename_is_the_buss_error() {
    let fake = FakeAvahi::new().refusing("SetHostName");
    let (bus, _served) = fake.connect().await.unwrap();
    let refused = avahi::set_host_name(&bus, &"widget".parse().unwrap()).await;
    assert!(
        matches!(&refused, Err(Error::Bus(e)) if error_name(e) == Some("org.freedesktop.Avahi.NotPermittedError")),
        "{refused:?}"
    );
    assert_eq!(fake.host_name(), "box");
}

#[tokio::test]
async fn restarts_and_stops_are_watched_and_a_stopped_avahi_is_not_running() {
    let fake = FakeAvahi::new();
    let (bus, served) = fake.connect().await.unwrap();
    assert!(avahi::is_running(&bus).await.unwrap());
    let advert = Avahi::new(&bus).advertise(&service()).await.unwrap();
    settles(&mut advert.state(), AdvertState::Established).await;

    let mut restarts = avahi::restarts(&bus).await.unwrap();
    fake.restart(&served).await.unwrap();
    assert_eq!(restarts.next().await, Some(true));
    assert!(
        fake.established().is_empty(),
        "the new avahi holds the old one's group"
    );

    fake.stop(&served).await.unwrap();
    assert_eq!(restarts.next().await, Some(false));
    assert!(!avahi::is_running(&bus).await.unwrap());
    let unknown = Some("org.freedesktop.DBus.Error.ServiceUnknown");
    let refused = Avahi::new(&bus).advertise(&service()).await;
    assert!(
        matches!(&refused, Err(Error::NotRunning(e)) if error_name(e) == unknown),
        "{refused:?}"
    );
    let refused = avahi::host_name(&bus).await;
    assert!(
        matches!(&refused, Err(Error::NotRunning(e)) if error_name(e) == unknown),
        "{refused:?}"
    );
    assert_eq!(fake.heard().last().unwrap(), "GetHostName");

    fake.restart(&served).await.unwrap();
    assert_eq!(restarts.next().await, Some(true));
    assert_eq!(
        avahi::host_name(&bus).await.unwrap(),
        "box",
        "avahi starts after the app"
    );
}

#[tokio::test]
async fn signals_after_a_restart_come_from_the_new_owner_and_reach_the_client() {
    let fake = FakeAvahi::new();
    let (bus, served) = fake.connect().await.unwrap();
    let first = fake.owner().unwrap();
    let mut states = avahi::server_states(&bus).await.unwrap();
    let mut restarts = avahi::restarts(&bus).await.unwrap();

    fake.restart(&served).await.unwrap();
    assert_eq!(restarts.next().await, Some(true));
    assert_ne!(fake.owner().unwrap(), first);
    fake.server_state(&served, ServerState::Running)
        .await
        .unwrap();
    assert_eq!(states.next().await, Some(ServerState::Running));

    fake.rename(&served, "box-2").await.unwrap();
    for state in [
        ServerState::Collision,
        ServerState::Registering,
        ServerState::Running,
    ] {
        assert_eq!(states.next().await, Some(state));
    }
    let advert = Avahi::new(&bus).advertise(&service()).await.unwrap();
    let mut state = advert.state();
    settles(&mut state, AdvertState::Established).await;
    fake.collide(&served, "Widget").await.unwrap();
    settles(&mut state, AdvertState::Collided).await;

    fake.stop(&served).await.unwrap();
    assert_eq!(restarts.next().await, Some(false));
    assert_eq!(fake.owner(), None);
}
