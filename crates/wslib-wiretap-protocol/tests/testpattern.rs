//! Test Pattern's responder driven through the public API the way a run drives it.

use wslib_can::dlc_to_len;
use wslib_wiretap_protocol::testpattern::{self, Command, Flags, Message, Responder, capability};

/// Drive a responder the way a run does, and prove a sweep comes back whole at
/// every length code.
///
/// This is the exchange that validates a real link. A codec that confuses a
/// payload length for a data length code passes at 8 bytes and fails here,
/// which is exactly the fault a fixed-payload protocol could not see.
#[test]
fn a_sweep_round_trips_at_every_length_code() {
    for fd in [false, true] {
        let mut r = Responder::new(if fd { capability::FD } else { 0 }, 0);
        let flags = Flags::new(0, 3);
        r.on_frame(
            testpattern::ID_CONTROL,
            false,
            false,
            &testpattern::encode(Message::Control(Command::Start { mode: 0, run: 3 }), flags),
            0,
        );

        for code in testpattern::sweep_codes(fd) {
            let sent = testpattern::sweep_payload(code, fd);
            let out = r.on_frame(
                testpattern::SWEEP_REQUEST_BASE + u32::from(code),
                false,
                fd,
                &sent,
                0,
            );
            assert_eq!(out.len(), 1, "fd {fd} code {code}");
            assert_eq!(
                testpattern::sweep_code(out[0].arb_id),
                Some((code, true)),
                "fd {fd} code {code}: echoed under the wrong id"
            );
            assert!(
                testpattern::sweep_echo_matches(code, fd, &out[0].data),
                "fd {fd} code {code}: {} bytes back, {} expected",
                out[0].data.len(),
                dlc_to_len(code, fd)
            );
        }
    }
}

/// A whole run, as an initiator drives it: find a peer, start it, exchange
/// traffic, ask what it saw, stop it.
#[test]
fn a_run_is_driven_end_to_end_by_its_control_messages() {
    let run = 6;
    let flags = Flags::new(1, run);
    let mut r = Responder::new(capability::FD, 2);
    let control = |m: Message| (testpattern::ID_CONTROL, testpattern::encode(m, flags));

    // Nobody has said hello yet, so nothing is answered.
    let ping = Message::PingRequest { seq: 0 };
    assert!(
        r.on_frame(
            ping.arb_id(),
            false,
            false,
            &testpattern::encode(ping, flags),
            0
        )
        .is_empty()
    );

    // Discovery.
    let (id, wire) = control(Message::Control(Command::Hello));
    let hello = r.on_frame(id, false, false, &wire, 0);
    assert_eq!(
        testpattern::decode(&hello[0].data).unwrap().0,
        Message::Control(Command::HelloReply {
            capabilities: capability::FD,
            bus: 2
        })
    );

    // Start, then a stream with one frame missing from it.
    let (id, wire) = control(Message::Control(Command::Start { mode: 1, run }));
    r.on_frame(id, false, false, &wire, 0);
    for seq in [0u16, 1, 2, 4, 5] {
        let m = Message::PingRequest { seq };
        let out = r.on_frame(m.arb_id(), false, false, &testpattern::encode(m, flags), 0);
        assert_eq!(
            testpattern::decode(&out[0].data).unwrap().0,
            Message::PingReply { seq }
        );
    }

    // What did it see?
    let (id, wire) = control(Message::Control(Command::RequestStatus));
    let status = r.on_frame(id, false, false, &wire, 1_000_000);
    let value = |field: u8| {
        status
            .iter()
            .find_map(|f| match testpattern::decode(&f.data).unwrap().0 {
                Message::Status { field: g, value } if g == field => Some(value),
                _ => None,
            })
            .unwrap_or_else(|| panic!("no field {field:#x} in the status reply"))
    };
    assert_eq!(value(testpattern::status_field::RX_COUNT), 5);
    assert_eq!(value(testpattern::status_field::DROPS), 1, "seq 3");
    assert_eq!(value(testpattern::status_field::FPS), 5, "5 frames in 1 s");

    // Stop, and it goes quiet again.
    let (id, wire) = control(Message::Control(Command::Stop));
    r.on_frame(id, false, false, &wire, 0);
    let m = Message::PingRequest { seq: 6 };
    assert!(
        r.on_frame(m.arb_id(), false, false, &testpattern::encode(m, flags), 0)
            .is_empty()
    );
}

/// Two initiators sharing a bus. Without the run tag their sequence numbers
/// interleave into one tracker and both report drops that never happened.
#[test]
fn two_runs_on_one_bus_do_not_contaminate_each_other() {
    let (mine, theirs) = (Flags::new(0, 1), Flags::new(0, 2));
    let mut r = Responder::new(0, 0);
    r.on_frame(
        testpattern::ID_CONTROL,
        false,
        false,
        &testpattern::encode(Message::Control(Command::Start { mode: 0, run: 1 }), mine),
        0,
    );

    let mut answered = 0;
    for seq in 0..10u16 {
        // The other run's frames are interleaved with ours, seq for seq.
        for flags in [mine, theirs] {
            let m = Message::PingRequest { seq };
            answered += r
                .on_frame(m.arb_id(), false, false, &testpattern::encode(m, flags), 0)
                .len();
        }
    }

    assert_eq!(answered, 10, "only our run is answered");
    assert_eq!(r.sequence.rx_count, 10, "and only our run is counted");
    assert_eq!(r.sequence.drops, 0, "the other run's traffic is not a gap");
    assert_eq!(r.sequence.duplicates, 0);
}
