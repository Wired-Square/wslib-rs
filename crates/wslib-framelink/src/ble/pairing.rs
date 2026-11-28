//! Pairing the host with a peripheral before its encrypted characteristics
//! are read, written or subscribed to.

use std::time::Duration;

use btleplug::api::{BDAddr, Peripheral as _};
use btleplug::platform::Peripheral;
use wslib_ble::{Address, PairError, Pairing};

use crate::{CapabilitySet, Error};

/// A pairing that asks the user nothing was measured at 1.3 seconds.
const PAIR_TIMEOUT: Duration = Duration::from_secs(10);

const ADAPTER_END: char = '/';

/// The adapter a btleplug peripheral id names: on Linux the id is the BlueZ
/// object path below `/org/bluez/`, `hci0/dev_AA_BB_CC_DD_EE_FF`.
fn adapter_name(peripheral_id: &str) -> &str {
    peripheral_id
        .split_once(ADAPTER_END)
        .map_or(peripheral_id, |(adapter, _)| adapter)
}

fn host_address(address: BDAddr) -> Address {
    Address::new(address.into_inner())
}

/// What connecting came to, unless only withdrawing the agent failed.
fn outcome<T>(connected: Result<T, Error>, closed: Result<(), PairError>) -> Result<T, Error> {
    let connected = connected?;
    closed?;
    Ok(connected)
}

pub(crate) fn required(capabilities: CapabilitySet) -> bool {
    capabilities.contains(CapabilitySet::PAIRING_REQUIRED)
}

async fn discover(peripheral: &Peripheral) -> Result<(), btleplug::Error> {
    peripheral.connect().await?;
    peripheral.discover_services().await
}

async fn discover_paired(peripheral: &Peripheral) -> Result<(), Error> {
    let id = peripheral.id().to_string();
    let address = host_address(peripheral.address());
    let pairing = Pairing::confirm(adapter_name(&id), &address).await?;
    let connected = async {
        discover(peripheral).await?;
        pairing.pair(PAIR_TIMEOUT).await?;
        Ok(())
    };
    let connected = connected.await;
    outcome(connected, pairing.close().await)
}

pub(crate) async fn connect(peripheral: &Peripheral, pairs: bool) -> Result<(), Error> {
    if pairs {
        discover_paired(peripheral).await
    } else {
        Ok(discover(peripheral).await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OCTETS: [u8; 6] = [0xAA, 0xBB, 0xCC, 0x00, 0x09, 0xB0];
    const WRITTEN: &str = "AA:BB:CC:00:09:B0";

    fn timed_out() -> PairError {
        PairError::TimedOut {
            limit: PAIR_TIMEOUT,
        }
    }

    #[test]
    fn a_device_that_advertises_pairing_is_paired_with() {
        assert!(required(CapabilitySet::PAIRING_REQUIRED));
        assert!(required(
            CapabilitySet::WIFI_PROV | CapabilitySet::SMP | CapabilitySet::PAIRING_REQUIRED
        ));
    }

    #[test]
    fn a_device_that_does_not_advertise_pairing_is_never_asked() {
        let every_other = CapabilitySet::from_bits(!CapabilitySet::PAIRING_REQUIRED.bits());
        assert!(!required(CapabilitySet::empty()));
        assert!(!required(CapabilitySet::WIFI_PROV | CapabilitySet::SMP));
        assert!(!required(every_other));
    }

    #[test]
    fn a_bluez_peripheral_id_names_its_adapter() {
        assert_eq!(adapter_name("hci0/dev_AA_BB_CC_00_09_B0"), "hci0");
        assert_eq!(adapter_name("hci12/dev_AA_BB_CC_00_09_B0"), "hci12");
    }

    #[test]
    fn an_id_that_names_no_adapter_is_passed_whole() {
        let uuid = "6d1f5a4e-0c7b-4a0e-9f2d-3b8c1e5a7d90";
        assert_eq!(adapter_name(uuid), uuid);
    }

    #[test]
    fn the_address_keeps_the_order_it_is_written_in() {
        let address = host_address(BDAddr::from(OCTETS));
        assert_eq!(address.to_string(), WRITTEN);
        assert_eq!(BDAddr::from(OCTETS).to_string(), WRITTEN);
    }

    #[test]
    fn a_pairing_failure_is_a_layer_over_its_cause() {
        let error = Error::from(timed_out());
        assert_eq!(error.to_string(), "pairing with the device failed");
        let cause = std::error::Error::source(&error).expect("a cause");
        assert!(cause.is::<PairError>());
    }

    #[test]
    fn the_connection_failure_comes_before_the_closing_one() {
        let failed = outcome::<()>(Err(Error::BleLinkDropped), Err(timed_out()));
        assert!(matches!(failed, Err(Error::BleLinkDropped)));
    }

    #[test]
    fn a_failure_to_withdraw_the_agent_is_reported() {
        let failed = outcome(Ok(()), Err(timed_out()));
        assert!(matches!(failed, Err(Error::Pairing(_))));
        assert!(outcome(Ok(()), Ok(())).is_ok());
    }
}
