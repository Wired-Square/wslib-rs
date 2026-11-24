use wslib_uds::testing::{Did, Ecu};

fn refusal(ecu: &mut Ecu, request: &[u8]) -> u8 {
    match &ecu.answer(request)[..] {
        [answer] if answer.len() == 3 && answer[0] == 0x7F => answer[2],
        other => panic!("{request:02X?}: {other:02X?}"),
    }
}

#[test]
fn negative_responses_come_in_the_standards_order() {
    let mut ecu = Ecu::new()
        .with_session(0x03)
        .with_security(0x01, [0x12], |_, _| false)
        .with_did(0x0100, Did::writable([0x00, 0x00]).needs_security());
    assert_eq!(refusal(&mut ecu, &[0x23, 0x11]), 0x11, "service first");
    assert_eq!(refusal(&mut ecu, &[0x27]), 0x7F, "then session");
    assert_eq!(refusal(&mut ecu, &[0x10]), 0x13, "then minimum length");
    assert_eq!(
        refusal(&mut ecu, &[0x10, 0x05, 0x00]),
        0x12,
        "then sub-function"
    );
    assert_eq!(
        refusal(&mut ecu, &[0x10, 0x03, 0x00]),
        0x13,
        "then full length"
    );
    ecu.answer(&[0x10, 0x03]);
    assert_eq!(refusal(&mut ecu, &[0x27, 0x05]), 0x12);
    assert_eq!(refusal(&mut ecu, &[0x2E, 0x01, 0x00]), 0x13);
    assert_eq!(
        refusal(&mut ecu, &[0x2E, 0x01, 0x00, 0xAA]),
        0x33,
        "security before full length"
    );
    assert_eq!(refusal(&mut ecu, &[0x2E, 0x02, 0x00, 0xAA, 0xBB]), 0x31);
    assert_eq!(refusal(&mut ecu, &[0x31, 0x04, 0x02, 0x03]), 0x12);
    assert_eq!(refusal(&mut ecu, &[0x31, 0x01, 0x02, 0x03]), 0x31);
}
