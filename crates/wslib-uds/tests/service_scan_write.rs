use std::time::Instant;

use wslib_uds::testing::Ecu;
use wslib_uds::{Client, Nrc, Safety, SendError, ServiceScan, ServiceVerdict, Timing, sid};

fn probed(mut scan: ServiceScan) -> Vec<(u8, Safety)> {
    let mut probed = Vec::new();
    while let Some(probe) = scan.next_probe() {
        probed.push((probe.service(), probe.safety()));
        scan.report(None);
    }
    probed
}

#[test]
fn a_service_scan_never_offers_a_probe_above_the_highest_class_allowed() {
    for highest in [Safety::ReadOnly, Safety::StateChanging, Safety::Destructive] {
        let probes = probed(ServiceScan::up_to(highest));
        assert!(probes.iter().all(|(_, safety)| *safety <= highest));
        assert!(probes.iter().all(|(s, _)| *s != sid::REQUEST_TRANSFER_EXIT));
    }
    let state_changing: Vec<u8> = probed(ServiceScan::up_to(Safety::StateChanging))
        .into_iter()
        .map(|(s, _)| s)
        .collect();
    assert_eq!(
        state_changing,
        [0x10, 0x11, 0x19, 0x22, 0x23, 0x27, 0x28, 0x3E, 0x85]
    );
    assert_eq!(probed(ServiceScan::up_to(Safety::Destructive)).len(), 26);
    assert_eq!(
        probed(ServiceScan::up_to(Safety::ReadOnly)),
        probed(ServiceScan::new())
    );
}

#[test]
fn a_service_scan_up_to_destructive_tells_present_absent_and_not_in_session_apart() {
    let mut ecu = Ecu::new();
    let mut scan = ServiceScan::up_to(Safety::Destructive);
    while let Some(probe) = scan.next_probe() {
        let reply = ecu.answer(&probe.request().encode()).pop();
        scan.report(reply.as_deref());
    }
    let verdict = |service: u8| {
        scan.findings()
            .iter()
            .find(|f| f.service == service)
            .unwrap()
            .verdict
    };
    assert_eq!(
        verdict(0x2E),
        ServiceVerdict::Present {
            code: Nrc::INCORRECT_MESSAGE_LENGTH
        }
    );
    assert_eq!(verdict(0x23), ServiceVerdict::Absent);
    assert_eq!(verdict(0x27), ServiceVerdict::NotInSession);
    assert_eq!(scan.progress().found, 11);
}

#[test]
fn a_scan_through_a_client_sends_only_up_to_the_lower_of_the_two_ceilings() {
    let mut ecu = Ecu::new();
    let mut client = Client::up_to(Timing::default(), Safety::StateChanging);
    let mut scan = ServiceScan::up_to(Safety::Destructive);
    let now = Instant::now();
    let mut sent = Vec::new();
    while let Some(probe) = scan.next_probe() {
        let reply = match client.send(probe.request(), now) {
            Ok(bytes) => {
                sent.push(bytes[0]);
                let reply = ecu.answer(&bytes).pop();
                client.abandon(now);
                reply
            }
            Err(SendError::AboveCeiling { .. }) => None,
            Err(SendError::Busy) => unreachable!(),
        };
        scan.report(reply.as_deref());
    }
    let state_changing: Vec<u8> = probed(ServiceScan::up_to(Safety::StateChanging))
        .into_iter()
        .map(|(s, _)| s)
        .collect();
    assert_eq!(sent, state_changing);
}

#[test]
fn a_positive_answer_to_a_bare_id_above_read_only_is_recorded_executed_and_stops_the_scan() {
    let mut scan = ServiceScan::up_to(Safety::StateChanging);
    assert_eq!(scan.next_probe().unwrap().service(), 0x10);
    assert_eq!(scan.report(Some(&[0x50])), Some(ServiceVerdict::Executed));
    assert_eq!(scan.next_probe(), None);
    assert_eq!(scan.report(None), None);
    let progress = scan.progress();
    assert_eq!((progress.done, progress.total), (1, 9));
    assert!(progress.stopped_early);
    assert_eq!(scan.findings()[0].verdict, ServiceVerdict::Executed);
}
