#![cfg(unix)]

use std::error::Error;

use wslib_ble::testing::{FakeBluez, FakeDevice};
use wslib_ble::{Address, ForgetError, Forgotten, forget_on};

const ADAPTER: &str = "hci0";
const OTHER_ADAPTER: &str = "hci1";
const TARGET: Address = Address::new([0xAA, 0xBB, 0xCC, 0x00, 0x09, 0xB0]);
const OTHER: Address = Address::new([0xAA, 0xBB, 0xCC, 0x00, 0x9D, 0x04]);

fn host() -> FakeBluez {
    FakeBluez::new()
        .with(FakeDevice::new(ADAPTER, TARGET))
        .with(FakeDevice::new(ADAPTER, OTHER))
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
