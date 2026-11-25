use std::time::Instant;

use wslib_uds::testing::{Did, Ecu};
use wslib_uds::{
    AddressScan, Client, DidScan, DidVerdict, Event, Nrc, ReadOnly, ReadOnlyServiceScan, Safety,
    ServiceScan, ServiceVerdict, Timing, ecu_answered,
};

fn final_answer(ecu: &mut Ecu, request: &[u8]) -> Option<Vec<u8>> {
    ecu.answer(request).pop()
}

#[test]
fn every_read_only_probe_states_read_only() {
    let address = AddressScan::eleven_bit().next_probe().unwrap();
    assert_eq!(address.safety(), Safety::ReadOnly);
    let mut services = ServiceScan::new();
    while let Some(probe) = services.next_probe() {
        assert_eq!(probe.safety(), Safety::ReadOnly);
        services.report(None);
    }
    assert_eq!(
        DidScan::new(0..=0).next_probe().unwrap().safety(),
        Safety::ReadOnly
    );
}

#[test]
fn the_conventional_address_ranges() {
    let mut eleven = AddressScan::eleven_bit();
    assert_eq!(eleven.progress().total, 0x100);
    assert_eq!(eleven.next_probe().unwrap().address, 0x700);
    let mut fixed = AddressScan::normal_fixed(0xF1);
    assert_eq!(fixed.progress().total, 256);
    let mut addresses = Vec::new();
    while let Some(probe) = fixed.next_probe() {
        addresses.push(probe.address);
        fixed.report(None);
    }
    assert_eq!(addresses[0], 0x18DA_00F1);
    assert_eq!(addresses[255], 0x18DA_FFF1);
    while eleven.next_probe().is_some() {
        eleven.report(None);
    }
    assert_eq!(eleven.report(None), None);
}

#[test]
fn an_address_scan_finds_the_addresses_that_answer_positive_or_negative() {
    let mut ecus = [(0x7E0, Ecu::new()), (0x7E4, Ecu::new())];
    let mut scan = AddressScan::new(0x7DF..=0x7E5);
    while let Some(probe) = scan.next_probe() {
        let bytes = probe.request().request().encode();
        assert_eq!(bytes, [0x3E, 0x00]);
        let reply = ecus
            .iter_mut()
            .find(|(a, _)| *a == probe.address)
            .and_then(|(_, ecu)| final_answer(ecu, &bytes));
        scan.report(reply.as_deref());
    }
    assert_eq!(scan.found(), [0x7E0, 0x7E4]);
    assert_eq!(scan.progress().found, 2);
    assert_eq!(scan.progress().done, 7);
}

#[test]
fn without_write_a_service_scan_probes_only_bare_ids_that_are_read_only() {
    let mut ecu = Ecu::new();
    let mut client = Client::new(Timing::default());
    let mut scan = ServiceScan::new();
    let now = Instant::now();
    let mut probed = Vec::new();
    while let Some(probe) = scan.next_probe() {
        let request = ReadOnly::new(probe.request()).unwrap();
        let sent = client.send_read_only(request, now).unwrap();
        assert_eq!(sent, [probe.service()]);
        probed.push(probe.service());
        let reply = final_answer(&mut ecu, &sent).unwrap();
        client.receive(&reply, now);
        scan.report(Some(&reply));
    }
    assert_eq!(probed, [0x19, 0x22, 0x3E]);
    assert!(scan.findings().iter().all(|f| f.verdict
        == ServiceVerdict::Present {
            code: Nrc::INCORRECT_MESSAGE_LENGTH
        }));
    assert_eq!(scan.progress().found, 3);
    assert!(!scan.progress().stopped_early);
}

#[test]
fn a_read_only_service_scan_hands_out_read_only_probes_and_matches_the_plain_scan() {
    let mut ecu = Ecu::new();
    let mut client = Client::new(Timing::default());
    let mut scan = ReadOnlyServiceScan::new().with_busy_retries(1);
    let now = Instant::now();
    let mut probed = Vec::new();
    while let Some(probe) = scan.next_probe() {
        let sent = client.send_read_only(probe.request(), now).unwrap();
        assert_eq!(sent, [probe.service()]);
        probed.push(probe.service());
        let reply = final_answer(&mut ecu, &sent).unwrap();
        client.receive(&reply, now);
        scan.report(Some(&reply));
    }
    assert_eq!(probed, [0x19, 0x22, 0x3E]);
    let mut plain = ServiceScan::new();
    while plain.next_probe().is_some() {
        plain.report(Some(&[0x7F, plain.next_probe().unwrap().service(), 0x13]));
    }
    assert_eq!(scan.findings(), plain.findings());
    assert_eq!(scan.progress(), plain.progress());
}

#[test]
fn a_positive_answer_to_a_read_only_bare_id_is_recorded_executed_and_the_scan_carries_on() {
    let mut scan = ServiceScan::new();
    scan.report(None);
    scan.report(None);
    assert_eq!(scan.next_probe().unwrap().service(), 0x3E);
    assert_eq!(
        scan.report(Some(&[0x7E, 0x00])),
        Some(ServiceVerdict::Executed)
    );
    assert_eq!(scan.findings()[2].verdict, ServiceVerdict::Executed);
    let mut scan = ServiceScan::new();
    assert_eq!(scan.report(Some(&[0x59])), Some(ServiceVerdict::Executed));
    assert_eq!(scan.next_probe().unwrap().service(), 0x22);
    assert!(!scan.progress().stopped_early);
}

#[test]
fn an_address_counts_as_an_ecu_only_for_an_answer_to_its_tester_present() {
    assert!(ecu_answered(Some(&[0x7E, 0x00])));
    assert!(ecu_answered(Some(&[0x7F, 0x3E, 0x12])));
    assert!(!ecu_answered(Some(&[0x62, 0xF1, 0x90, 0x01])));
    assert!(!ecu_answered(Some(&[0x7F, 0x22, 0x31])));
    assert!(!ecu_answered(Some(&[0x7E, 0x01])));
    assert!(!ecu_answered(Some(&[])));
    assert!(!ecu_answered(None));
}

#[test]
fn service_verdicts_follow_the_refusal_code() {
    use wslib_uds::service_verdict;
    assert_eq!(
        service_verdict(0x22, Some(&[0x7F, 0x22, 0x11])),
        ServiceVerdict::Absent
    );
    assert_eq!(
        service_verdict(0x22, Some(&[0x7F, 0x22, 0x33])),
        ServiceVerdict::Present {
            code: Nrc::SECURITY_ACCESS_DENIED
        }
    );
    assert_eq!(
        service_verdict(0x22, Some(&[0x7F, 0x22, 0x7F])),
        ServiceVerdict::NotInSession
    );
    assert_eq!(
        service_verdict(0x22, Some(&[0x7F, 0x22, 0x21])),
        ServiceVerdict::Busy
    );
    assert_eq!(
        service_verdict(0x3E, Some(&[0x7E, 0x00])),
        ServiceVerdict::Executed
    );
    assert_eq!(
        service_verdict(0x22, Some(&[0x7F, 0x2E, 0x11])),
        ServiceVerdict::Inconclusive
    );
    assert_eq!(service_verdict(0x22, None), ServiceVerdict::Inconclusive);
}

#[test]
fn a_did_scan_reports_present_absent_and_locked_through_a_read_only_client() {
    let mut ecu = Ecu::new()
        .with_did(0xF190, Did::readable(*b"GENERIC-VIN-0001"))
        .with_did(0xF192, Did::readable([0x01]).needs_security());
    let mut client = Client::new(Timing::default());
    let mut scan = DidScan::new(0xF18F..=0xF192);
    let now = Instant::now();
    while let Some(probe) = scan.next_probe() {
        let sent = client.send_read_only(probe.request(), now).unwrap();
        let reply = final_answer(&mut ecu, &sent).unwrap();
        assert!(matches!(
            client.receive(&reply, now),
            Event::Positive(_) | Event::Negative { .. }
        ));
        scan.report(Some(&reply));
    }
    let verdicts: Vec<_> = scan.findings().iter().map(|f| (f.did, f.verdict)).collect();
    assert_eq!(
        verdicts,
        [
            (0xF18F, DidVerdict::Absent),
            (0xF190, DidVerdict::Present { length: 16 }),
            (0xF191, DidVerdict::Absent),
            (0xF192, DidVerdict::Locked),
        ]
    );
    assert_eq!(scan.progress().found, 1);
}

#[test]
fn a_busy_did_is_re_offered_before_it_is_recorded_busy() {
    let mut scan = DidScan::new(0x0001..=0x0002).with_busy_retries(2);
    let busy: &[u8] = &[0x7F, 0x22, 0x21];
    assert_eq!(scan.report(Some(busy)), Some(DidVerdict::Busy));
    assert_eq!(scan.next_probe().unwrap().did, 0x0001);
    scan.report(Some(busy));
    assert_eq!(scan.progress().done, 0);
    scan.report(Some(busy));
    assert_eq!(scan.progress().done, 1);
    assert_eq!(scan.next_probe().unwrap().did, 0x0002);
}

#[test]
fn did_verdicts_follow_the_reply() {
    use wslib_uds::did_verdict;
    assert_eq!(
        did_verdict(0xF190, Some(&[0x7F, 0x22, 0x7F])),
        DidVerdict::NotInSession
    );
    assert_eq!(
        did_verdict(0xF190, Some(&[0x7F, 0x22, 0x22])),
        DidVerdict::Inconclusive {
            code: Some(Nrc::CONDITIONS_NOT_CORRECT)
        }
    );
    assert_eq!(
        did_verdict(0xF190, Some(&[0x62, 0xF1, 0x8C, 0x00])),
        DidVerdict::Inconclusive { code: None }
    );
    assert_eq!(
        did_verdict(0xF190, None),
        DidVerdict::Inconclusive { code: None }
    );
}
