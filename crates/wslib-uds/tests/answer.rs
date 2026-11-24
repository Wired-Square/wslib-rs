use wslib_uds::{Answer, Nrc, answers};

const POSITIVE: Option<Answer> = Some(Answer::Positive);

#[test]
fn a_negative_response_answers_the_service_it_names_with_its_code() {
    assert_eq!(
        answers(&[0x22, 0xF1, 0x90], &[0x7F, 0x22, 0x31]),
        Some(Answer::Negative {
            code: Nrc::REQUEST_OUT_OF_RANGE
        })
    );
    assert_eq!(answers(&[0x22, 0xF1, 0x90], &[0x7F, 0x2E, 0x31]), None);
}

#[test]
fn a_positive_read_data_answer_must_echo_one_of_the_requested_dids() {
    assert_eq!(
        answers(&[0x22, 0xF1, 0x90], &[0x62, 0xF1, 0x90, 0x01]),
        POSITIVE
    );
    assert_eq!(
        answers(&[0x22, 0xF1, 0x90, 0xF1, 0x8C], &[0x62, 0xF1, 0x8C, 0x01]),
        POSITIVE
    );
    assert_eq!(
        answers(&[0x22, 0xF1, 0x90], &[0x62, 0xF1, 0x8C, 0x01]),
        None
    );
    assert_eq!(answers(&[0x22, 0xF1, 0x90], &[0x62, 0xF1]), None);
}

#[test]
fn a_positive_write_or_io_control_answer_must_echo_the_did() {
    assert_eq!(
        answers(&[0x2E, 0x01, 0x00, 0xAA], &[0x6E, 0x01, 0x00]),
        POSITIVE
    );
    assert_eq!(
        answers(&[0x2E, 0x01, 0x00, 0xAA], &[0x6E, 0x01, 0x01]),
        None
    );
    assert_eq!(
        answers(&[0x2F, 0x01, 0x23, 0x03], &[0x6F, 0x01, 0x23, 0x03]),
        POSITIVE
    );
    assert_eq!(
        answers(&[0x2F, 0x01, 0x23, 0x03], &[0x6F, 0x01, 0x24, 0x03]),
        None
    );
}

#[test]
fn a_positive_routine_answer_must_echo_the_sub_function_and_routine() {
    let start = [0x31, 0x81, 0x02, 0x03];
    assert_eq!(answers(&start, &[0x71, 0x01, 0x02, 0x03]), POSITIVE);
    assert_eq!(answers(&start, &[0x71, 0x03, 0x02, 0x03]), None);
    assert_eq!(answers(&start, &[0x71, 0x01, 0x02, 0x04]), None);
}

#[test]
fn a_positive_answer_to_a_sub_function_service_must_echo_the_sub_function_without_the_suppress_bit()
{
    assert_eq!(
        answers(&[0x10, 0x83], &[0x50, 0x03, 0x00, 0x32, 0x01, 0xF4]),
        POSITIVE
    );
    assert_eq!(answers(&[0x10, 0x03], &[0x50, 0x02]), None);
    assert_eq!(answers(&[0x29, 0x01, 0xAA], &[0x69, 0x01]), POSITIVE);
    assert_eq!(answers(&[0x29, 0x01, 0xAA], &[0x69, 0x02]), None);
}

#[test]
fn a_bare_service_id_is_answered_by_its_positive_id_alone() {
    assert_eq!(answers(&[0x22], &[0x62]), POSITIVE);
    assert_eq!(answers(&[0x10], &[0x50, 0x07]), POSITIVE);
}

#[test]
fn a_positive_answer_is_judged_on_leading_bytes_even_if_strict_decoding_fails() {
    assert_eq!(answers(&[0x10, 0x03], &[0x50, 0x03, 0x00]), POSITIVE);
    assert_eq!(answers(&[0x3E, 0x00], &[0x7E, 0x00, 0x00]), POSITIVE);
}

#[test]
fn a_response_starting_0x7f_is_never_a_positive_answer() {
    assert_eq!(answers(&[0x3F], &[0x7F, 0x10, 0x11]), None);
    assert_eq!(answers(&[0x3F, 0x01], &[0x7F]), None);
}

#[test]
fn a_service_id_from_0xc0_has_no_positive_answer() {
    for service in 0xC0..=0xFFu8 {
        let wrapped = service.wrapping_add(0x40);
        assert_eq!(
            answers(&[service], &[wrapped, 0x00]),
            None,
            "0x{service:02X}"
        );
    }
}

#[test]
fn anything_else_answers_nothing() {
    assert_eq!(answers(&[], &[0x7F, 0x22, 0x31]), None);
    assert_eq!(answers(&[0x22, 0xF1, 0x90], &[]), None);
    assert_eq!(answers(&[0x22, 0xF1, 0x90], &[0x50, 0x01]), None);
}
