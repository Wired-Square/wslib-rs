#![cfg(unix)]

use std::error::Error;
use std::time::Duration;

use wslib_ble::testing::{Asked, FakeBluez, FakeDevice, device_path};
use wslib_ble::{Address, ForgetError, Forgotten, PairError, Paired, Pairing, Refusal, forget_on};
use zbus::zvariant::OwnedObjectPath;

const ADAPTER: &str = "hci0";
const OTHER_ADAPTER: &str = "hci1";
const TARGET: Address = Address::new([0xAA, 0xBB, 0xCC, 0x00, 0x09, 0xB0]);
const OTHER: Address = Address::new([0xAA, 0xBB, 0xCC, 0x00, 0x9D, 0x04]);
const BLUEZ: &str = "org.bluez";
const DEVICE: &str = "org.bluez.Device1";
const MANAGER: &str = "/org/bluez";
const AGENT_MANAGER: &str = "org.bluez.AgentManager1";
const ADAPTER_INTERFACE: &str = "org.bluez.Adapter1";
const DOES_NOT_EXIST: &str = "org.bluez.Error.DoesNotExist";
const AGENT: &str = "org.bluez.Agent1";
const REJECTED: &str = "org.bluez.Error.Rejected";
const CAPABILITY: &str = "NoInputNoOutput";
const PASSKEY: u32 = 123_456;
const ENTERED: u16 = 0;
const PIN: &str = "0000";
const SERIAL_PORT: &str = "00001101-0000-1000-8000-00805f9b34fb";
const LIMIT: Duration = Duration::from_secs(5);
const SHORT: Duration = Duration::from_millis(50);
const POLL: Duration = Duration::from_millis(5);

fn host() -> FakeBluez {
    FakeBluez::new()
        .with(FakeDevice::new(ADAPTER, TARGET))
        .with(FakeDevice::new(ADAPTER, OTHER))
}

fn error_name(error: &zbus::Error) -> Option<&str> {
    match error {
        zbus::Error::MethodError(name, _, _) => Some(name.as_str()),
        _ => None,
    }
}

fn target() -> OwnedObjectPath {
    device_path(ADAPTER, &TARGET)
}

fn other() -> OwnedObjectPath {
    device_path(ADAPTER, &OTHER)
}

fn agent_path(fake: &FakeBluez) -> OwnedObjectPath {
    fake.agent().expect("an agent is registered").0
}

async fn until(what: &str, met: impl Fn() -> bool) {
    let waited = tokio::time::timeout(LIMIT, async {
        while !met() {
            tokio::time::sleep(POLL).await;
        }
    });
    waited.await.unwrap_or_else(|_| panic!("{what}"));
}

macro_rules! ask {
    ($served:expr, $fake:expr, $method:literal, $body:expr) => {
        $served
            .call_method(
                None::<&str>,
                &agent_path(&$fake),
                Some(AGENT),
                $method,
                $body,
            )
            .await
            .err()
            .map(|error| error_name(&error).expect("a D-Bus error").to_string())
    };
}

#[tokio::test]
async fn forgetting_removes_the_one_device() {
    let fake = host();
    let (bus, _served) = fake.connect().await.unwrap();
    let forgotten = forget_on(&bus, ADAPTER, &TARGET).await.unwrap();
    assert_eq!(forgotten, Forgotten::Removed);
    assert!(!fake.knows(ADAPTER, &TARGET));
    assert!(fake.knows(ADAPTER, &OTHER));
    assert_eq!(
        fake.heard(),
        ["RemoveDevice /org/bluez/hci0/dev_AA_BB_CC_00_09_B0"]
    );
}

#[tokio::test]
async fn forgetting_a_device_the_host_never_saw_finds_nothing() {
    let fake = FakeBluez::new().with(FakeDevice::new(ADAPTER, OTHER));
    let (bus, _served) = fake.connect().await.unwrap();
    let forgotten = forget_on(&bus, ADAPTER, &TARGET).await.unwrap();
    assert_eq!(forgotten, Forgotten::NotKnown);
    assert!(fake.heard().is_empty());
}

#[tokio::test]
async fn a_device_on_another_adapter_is_not_this_adapters() {
    let fake = FakeBluez::new()
        .adapter(ADAPTER)
        .with(FakeDevice::new(OTHER_ADAPTER, TARGET));
    let (bus, _served) = fake.connect().await.unwrap();
    let forgotten = forget_on(&bus, ADAPTER, &TARGET).await.unwrap();
    assert_eq!(forgotten, Forgotten::NotKnown);
    assert!(fake.knows(OTHER_ADAPTER, &TARGET));
}

#[tokio::test]
async fn a_device_gone_before_the_removal_was_not_known() {
    let fake = host().vanishing(ADAPTER, &TARGET);
    let (bus, _served) = fake.connect().await.unwrap();
    let forgotten = forget_on(&bus, ADAPTER, &TARGET).await.unwrap();
    assert_eq!(forgotten, Forgotten::NotKnown);
    assert_eq!(fake.heard().len(), 1);
}

#[tokio::test]
async fn forgetting_on_an_adapter_the_host_lacks_names_it() {
    let (bus, _served) = host().connect().await.unwrap();
    for adapter in [OTHER_ADAPTER, "not a path", ""] {
        let refused = forget_on(&bus, adapter, &TARGET).await;
        assert!(
            matches!(&refused, Err(ForgetError::NoAdapter { adapter: named }) if named == adapter),
            "{refused:?}"
        );
    }
}

#[tokio::test]
async fn an_unreachable_service_keeps_the_bus_error_as_the_source() {
    let (bus, served) = host().connect().await.unwrap();
    served.close().await.unwrap();
    let error = forget_on(&bus, ADAPTER, &TARGET).await.unwrap_err();
    assert!(matches!(error, ForgetError::Service(_)), "{error:?}");
    assert_eq!(error.to_string(), "the Bluetooth service call failed");
    assert!(error.source().unwrap().is::<zbus::Error>());
}

#[tokio::test]
async fn a_pairing_once_the_agent_is_gone_is_refused_by_the_host() {
    let fake = host();
    let (bus, _served) = fake.connect().await.unwrap();
    let pairing = Pairing::confirm_on(bus.clone(), ADAPTER, &TARGET)
        .await
        .unwrap();
    bus.call_method(
        Some(BLUEZ),
        MANAGER,
        Some(AGENT_MANAGER),
        "UnregisterAgent",
        &(agent_path(&fake),),
    )
    .await
    .unwrap();
    let error = pairing.pair(LIMIT).await.unwrap_err();
    assert!(
        matches!(
            error,
            PairError::Refused {
                reason: Refusal::AuthenticationFailed,
                ..
            }
        ),
        "{error:?}"
    );
    assert!(!fake.paired(ADAPTER, &TARGET));
}

#[tokio::test]
async fn known_limit_another_device_is_paired_outright_without_the_agent_being_asked() {
    let fake = host();
    let (bus, _served) = fake.connect().await.unwrap();
    let _pairing = Pairing::confirm_on(bus.clone(), ADAPTER, &TARGET)
        .await
        .unwrap();
    bus.call_method(Some(BLUEZ), &other(), Some(DEVICE), "Pair", &())
        .await
        .unwrap();
    assert!(fake.paired(ADAPTER, &OTHER));
    assert_eq!(fake.asked(), 0);
}

#[tokio::test]
async fn a_removal_sent_to_another_adapter_removes_nothing() {
    let fake = host().adapter(OTHER_ADAPTER);
    let (bus, _served) = fake.connect().await.unwrap();
    let error = bus
        .call_method(
            Some(BLUEZ),
            format!("{MANAGER}/{OTHER_ADAPTER}"),
            Some(ADAPTER_INTERFACE),
            "RemoveDevice",
            &(target(),),
        )
        .await
        .unwrap_err();
    assert_eq!(error_name(&error), Some(DOES_NOT_EXIST));
    assert!(fake.knows(ADAPTER, &TARGET));
}

#[tokio::test]
async fn confirming_registers_an_agent_that_is_never_the_default() {
    let fake = host();
    let (bus, _served) = fake.connect().await.unwrap();
    let pairing = Pairing::confirm_on(bus, ADAPTER, &TARGET).await.unwrap();
    let (path, capability) = fake.agent().unwrap();
    assert_eq!(capability, CAPABILITY);
    assert_eq!(fake.heard(), [format!("RegisterAgent {path} {CAPABILITY}")]);
    assert_eq!(pairing.pair(LIMIT).await.unwrap(), Paired::New);
    pairing.close().await.unwrap();
    let default = fake
        .heard()
        .iter()
        .any(|call| call.starts_with("RequestDefaultAgent"));
    assert!(!default);
}

#[tokio::test]
async fn pairing_makes_a_bond_without_the_agent_being_asked() {
    let fake = host();
    let (bus, _served) = fake.connect().await.unwrap();
    let pairing = Pairing::confirm_on(bus, ADAPTER, &TARGET).await.unwrap();
    assert_eq!(pairing.pair(LIMIT).await.unwrap(), Paired::New);
    assert!(fake.paired(ADAPTER, &TARGET));
    assert!(!fake.paired(ADAPTER, &OTHER));
    assert_eq!(fake.asked(), 0);
    assert_eq!(pairing.pair(LIMIT).await.unwrap(), Paired::Existing);
    pairing.close().await.unwrap();
}

#[tokio::test]
async fn a_bond_the_host_already_holds_is_existing() {
    let fake = FakeBluez::new().with(FakeDevice::new(ADAPTER, TARGET).bonded());
    let (bus, _served) = fake.connect().await.unwrap();
    let pairing = Pairing::confirm_on(bus, ADAPTER, &TARGET).await.unwrap();
    assert_eq!(pairing.pair(LIMIT).await.unwrap(), Paired::Existing);
}

#[tokio::test]
async fn a_refusal_keeps_its_reason_and_the_text_bluez_gave() {
    for reason in [
        Refusal::AuthenticationFailed,
        Refusal::AuthenticationRejected,
        Refusal::AuthenticationCanceled,
        Refusal::AuthenticationTimeout,
        Refusal::ConnectionAttemptFailed,
    ] {
        let fake = FakeBluez::new().with(FakeDevice::new(ADAPTER, TARGET).refusing(reason));
        let (bus, _served) = fake.connect().await.unwrap();
        let pairing = Pairing::confirm_on(bus, ADAPTER, &TARGET).await.unwrap();
        let error = pairing.pair(LIMIT).await.unwrap_err();
        assert!(
            matches!(
                &error,
                PairError::Refused { reason: given, detail: Some(detail) }
                    if *given == reason && detail == FakeDevice::REFUSAL_DETAIL
            ),
            "{error:?}"
        );
        assert!(error.source().is_none());
        assert!(!fake.paired(ADAPTER, &TARGET));
    }
}

#[tokio::test]
async fn confirming_a_device_the_adapter_has_not_discovered_names_it() {
    let fake = FakeBluez::new().with(FakeDevice::new(ADAPTER, OTHER));
    let (bus, _served) = fake.connect().await.unwrap();
    let error = Pairing::confirm_on(bus, ADAPTER, &TARGET)
        .await
        .unwrap_err();
    assert!(
        matches!(
            &error,
            PairError::UnknownDevice { adapter, address } if adapter == ADAPTER && *address == TARGET
        ),
        "{error:?}"
    );
    assert!(fake.agent().is_none());
    assert!(fake.heard().is_empty());
}

#[tokio::test]
async fn confirming_on_an_adapter_the_host_lacks_names_it() {
    let fake = host();
    let (bus, _served) = fake.connect().await.unwrap();
    let error = Pairing::confirm_on(bus, OTHER_ADAPTER, &TARGET)
        .await
        .unwrap_err();
    assert!(
        matches!(&error, PairError::NoAdapter { adapter } if adapter == OTHER_ADAPTER),
        "{error:?}"
    );
    assert!(fake.agent().is_none());
}

#[tokio::test]
async fn pairing_a_device_forgotten_since_it_was_confirmed_names_it() {
    let fake = host();
    let (bus, _served) = fake.connect().await.unwrap();
    let pairing = Pairing::confirm_on(bus.clone(), ADAPTER, &TARGET)
        .await
        .unwrap();
    forget_on(&bus, ADAPTER, &TARGET).await.unwrap();
    let error = pairing.pair(LIMIT).await.unwrap_err();
    assert!(
        matches!(&error, PairError::UnknownDevice { address, .. } if *address == TARGET),
        "{error:?}"
    );
}

#[tokio::test]
async fn confirming_with_the_service_unreachable_keeps_the_bus_error() {
    let fake = host();
    let (bus, served) = fake.connect().await.unwrap();
    served.close().await.unwrap();
    let error = Pairing::confirm_on(bus, ADAPTER, &TARGET)
        .await
        .unwrap_err();
    assert!(matches!(error, PairError::Service(_)), "{error:?}");
    assert_eq!(error.to_string(), "the Bluetooth service call failed");
    assert!(error.source().unwrap().is::<zbus::Error>());
}

#[tokio::test]
async fn a_second_guard_on_one_connection_is_refused_and_leaves_the_first() {
    let fake = host();
    let (bus, served) = fake.connect().await.unwrap();
    let first = Pairing::confirm_on(bus.clone(), ADAPTER, &TARGET)
        .await
        .unwrap();
    let error = Pairing::confirm_on(bus, ADAPTER, &OTHER).await.unwrap_err();
    assert!(matches!(error, PairError::AgentExists), "{error:?}");
    let asked = fake.implicit_pairing(&served, ADAPTER, &TARGET).await;
    assert_eq!(asked.unwrap(), Asked::Accepted);
    let asked = fake.implicit_pairing(&served, ADAPTER, &OTHER).await;
    assert_eq!(asked.unwrap(), Asked::Rejected);
    first.close().await.unwrap();
}

#[tokio::test]
async fn a_pairing_that_gets_no_answer_times_out_and_is_cancelled() {
    let fake = FakeBluez::new().with(FakeDevice::new(ADAPTER, TARGET).silent());
    let (bus, _served) = fake.connect().await.unwrap();
    let pairing = Pairing::confirm_on(bus, ADAPTER, &TARGET).await.unwrap();
    let error = pairing.pair(SHORT).await.unwrap_err();
    assert!(
        matches!(error, PairError::TimedOut { limit } if limit == SHORT),
        "{error:?}"
    );
    let path = target();
    assert_eq!(
        fake.heard()[1..],
        [format!("Pair {path}"), format!("CancelPairing {path}")]
    );
    assert!(!fake.pairing(ADAPTER, &TARGET));
}

#[tokio::test]
async fn a_dropped_pairing_is_cancelled_before_the_next_and_not_after() {
    let fake = FakeBluez::new().with(FakeDevice::new(ADAPTER, TARGET).silent());
    let (bus, _served) = fake.connect().await.unwrap();
    let pairing = Pairing::confirm_on(bus, ADAPTER, &TARGET).await.unwrap();
    let abandoned = tokio::time::timeout(SHORT, pairing.pair(LIMIT)).await;
    assert!(abandoned.is_err());
    assert!(fake.pairing(ADAPTER, &TARGET));
    let path = target();
    assert_eq!(fake.heard()[1..], [format!("Pair {path}")]);
    assert_eq!(pairing.pair(LIMIT).await.unwrap(), Paired::New);
    tokio::time::sleep(SHORT).await;
    assert_eq!(
        fake.heard()[1..],
        [
            format!("Pair {path}"),
            format!("CancelPairing {path}"),
            format!("Pair {path}"),
        ]
    );
    assert!(fake.paired(ADAPTER, &TARGET));
}

#[tokio::test]
async fn a_pairing_that_answered_leaves_nothing_to_cancel() {
    let fake = host();
    let (bus, _served) = fake.connect().await.unwrap();
    let pairing = Pairing::confirm_on(bus, ADAPTER, &TARGET).await.unwrap();
    assert_eq!(pairing.pair(LIMIT).await.unwrap(), Paired::New);
    assert_eq!(pairing.pair(LIMIT).await.unwrap(), Paired::Existing);
    pairing.close().await.unwrap();
    let cancelled = fake
        .heard()
        .iter()
        .any(|call| call.starts_with("CancelPairing"));
    assert!(!cancelled);
}

#[tokio::test]
async fn closing_cancels_a_dropped_pairing_before_it_unregisters() {
    let fake = FakeBluez::new().with(FakeDevice::new(ADAPTER, TARGET).silent());
    let (bus, _served) = fake.connect().await.unwrap();
    let pairing = Pairing::confirm_on(bus, ADAPTER, &TARGET).await.unwrap();
    let agent = agent_path(&fake);
    let abandoned = tokio::time::timeout(SHORT, pairing.pair(LIMIT)).await;
    assert!(abandoned.is_err());
    pairing.close().await.unwrap();
    let path = target();
    assert_eq!(
        fake.heard()[1..],
        [
            format!("Pair {path}"),
            format!("CancelPairing {path}"),
            format!("UnregisterAgent {agent}"),
        ]
    );
    assert!(!fake.pairing(ADAPTER, &TARGET));
}

#[tokio::test]
async fn an_implicit_pairing_is_authorised_for_the_one_device_only() {
    let fake = host();
    let (bus, served) = fake.connect().await.unwrap();
    let asked = fake.implicit_pairing(&served, ADAPTER, &TARGET).await;
    assert_eq!(asked.unwrap(), Asked::NoAgent);
    let pairing = Pairing::confirm_on(bus, ADAPTER, &TARGET).await.unwrap();
    let asked = fake.implicit_pairing(&served, ADAPTER, &OTHER).await;
    assert_eq!(asked.unwrap(), Asked::Rejected);
    assert!(!fake.paired(ADAPTER, &OTHER));
    let asked = fake.implicit_pairing(&served, ADAPTER, &TARGET).await;
    assert_eq!(asked.unwrap(), Asked::Accepted);
    assert!(fake.paired(ADAPTER, &TARGET));
    assert_eq!(fake.asked(), 2);
    assert_eq!(pairing.pair(LIMIT).await.unwrap(), Paired::Existing);
}

#[tokio::test]
async fn the_agent_answers_while_a_pairing_is_awaited() {
    let fake = FakeBluez::new()
        .with(FakeDevice::new(ADAPTER, TARGET).silent())
        .with(FakeDevice::new(ADAPTER, OTHER));
    let (bus, served) = fake.connect().await.unwrap();
    let pairing = Pairing::confirm_on(bus, ADAPTER, &TARGET).await.unwrap();
    let asking = async {
        until("the pairing is in progress", || {
            fake.pairing(ADAPTER, &TARGET)
        })
        .await;
        let rejected = fake.implicit_pairing(&served, ADAPTER, &OTHER).await;
        let accepted = fake.implicit_pairing(&served, ADAPTER, &TARGET).await;
        (rejected.unwrap(), accepted.unwrap())
    };
    tokio::select! {
        answers = asking => assert_eq!(answers, (Asked::Rejected, Asked::Accepted)),
        early = pairing.pair(LIMIT) => panic!("the pairing ended first: {early:?}"),
    }
}

#[tokio::test]
async fn the_agent_refuses_a_comparison_even_for_its_device() {
    let fake = host();
    let (bus, served) = fake.connect().await.unwrap();
    let _pairing = Pairing::confirm_on(bus, ADAPTER, &TARGET).await.unwrap();
    let refused = ask!(served, fake, "RequestConfirmation", &(target(), PASSKEY));
    assert_eq!(refused.as_deref(), Some(REJECTED));
    let refused = ask!(served, fake, "RequestConfirmation", &(other(), PASSKEY));
    assert_eq!(refused.as_deref(), Some(REJECTED));
    let refused = ask!(served, fake, "RequestAuthorization", &(other(),));
    assert_eq!(refused.as_deref(), Some(REJECTED));
    let authorised = ask!(served, fake, "RequestAuthorization", &(target(),));
    assert_eq!(authorised, None);
}

#[tokio::test]
async fn the_same_address_on_another_adapter_is_not_the_device() {
    let fake = host().with(FakeDevice::new(OTHER_ADAPTER, TARGET));
    let (bus, served) = fake.connect().await.unwrap();
    let _pairing = Pairing::confirm_on(bus, ADAPTER, &TARGET).await.unwrap();
    let asked = fake.implicit_pairing(&served, OTHER_ADAPTER, &TARGET).await;
    assert_eq!(asked.unwrap(), Asked::Rejected);
    assert!(!fake.paired(OTHER_ADAPTER, &TARGET));
    let asked = fake.implicit_pairing(&served, ADAPTER, &TARGET).await;
    assert_eq!(asked.unwrap(), Asked::Accepted);
}

#[tokio::test]
async fn the_agent_rejects_every_method_that_needs_a_person() {
    let fake = host();
    let (bus, served) = fake.connect().await.unwrap();
    let _pairing = Pairing::confirm_on(bus, ADAPTER, &TARGET).await.unwrap();
    let device = target();
    let answers = [
        ask!(served, fake, "RequestPinCode", &(&device,)),
        ask!(served, fake, "RequestPasskey", &(&device,)),
        ask!(served, fake, "DisplayPinCode", &(&device, PIN)),
        ask!(served, fake, "DisplayPasskey", &(&device, PASSKEY, ENTERED)),
        ask!(served, fake, "AuthorizeService", &(&device, SERIAL_PORT)),
    ];
    for answer in answers {
        assert_eq!(answer.as_deref(), Some(REJECTED));
    }
}

#[tokio::test]
async fn the_agent_accepts_release_and_cancel() {
    let fake = host();
    let (bus, served) = fake.connect().await.unwrap();
    let _pairing = Pairing::confirm_on(bus, ADAPTER, &TARGET).await.unwrap();
    assert_eq!(ask!(served, fake, "Cancel", &()), None);
    assert_eq!(ask!(served, fake, "Release", &()), None);
}

#[tokio::test]
async fn closing_unregisters_the_agent_and_stops_serving_it() {
    let fake = host();
    let (bus, served) = fake.connect().await.unwrap();
    let pairing = Pairing::confirm_on(bus.clone(), ADAPTER, &TARGET)
        .await
        .unwrap();
    let agent = agent_path(&fake);
    pairing.close().await.unwrap();
    assert!(fake.agent().is_none());
    assert_eq!(
        fake.heard().last().unwrap(),
        &format!("UnregisterAgent {agent}")
    );
    let unserved = served
        .call_method(
            None::<&str>,
            &agent,
            Some(AGENT),
            "RequestAuthorization",
            &(target(),),
        )
        .await
        .unwrap_err();
    assert!(error_name(&unserved).is_some(), "{unserved:?}");
    assert_ne!(error_name(&unserved), Some(REJECTED));
}

#[tokio::test]
async fn a_dropped_guard_takes_its_private_connection_and_so_its_agent() {
    let fake = host();
    let (bus, served) = fake.connect().await.unwrap();
    let hung_up = fake.hung_up(&served);
    let pairing = Pairing::confirm_on(bus, ADAPTER, &TARGET).await.unwrap();
    assert!(fake.agent().is_some());
    drop(pairing);
    tokio::time::timeout(LIMIT, hung_up).await.unwrap();
    assert!(fake.agent().is_none());
    assert_eq!(fake.heard().len(), 1);
}

#[tokio::test]
async fn a_dropped_guard_on_a_connection_the_caller_keeps_leaves_its_agent() {
    let fake = host();
    let (bus, served) = fake.connect().await.unwrap();
    let hung_up = fake.hung_up(&served);
    let pairing = Pairing::confirm_on(bus.clone(), ADAPTER, &TARGET)
        .await
        .unwrap();
    drop(pairing);
    assert!(tokio::time::timeout(SHORT, hung_up).await.is_err());
    assert!(fake.agent().is_some());
    let asked = fake.implicit_pairing(&served, ADAPTER, &TARGET).await;
    assert_eq!(asked.unwrap(), Asked::Accepted);
    drop(bus);
}

#[tokio::test]
async fn closing_with_the_service_gone_reports_it() {
    let fake = host();
    let (bus, served) = fake.connect().await.unwrap();
    let pairing = Pairing::confirm_on(bus, ADAPTER, &TARGET).await.unwrap();
    served.close().await.unwrap();
    let error = pairing.close().await.unwrap_err();
    assert!(matches!(error, PairError::Service(_)), "{error:?}");
}
