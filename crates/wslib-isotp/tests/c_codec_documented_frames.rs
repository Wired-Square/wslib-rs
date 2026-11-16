use wslib_isotp::{FlowControl, FlowStatus, Outcome, Reassembler, Segmenter, StMin, Step};

const C_BLOCK_SIZE: u8 = 0;
const C_ST_MIN: StMin = StMin(0x01);

const SHORT: [u8; 3] = [0x00, 0x01, 0x00];
const SHORT_SF: [u8; 4] = [0x03, 0x00, 0x01, 0x00];

const LONG: [u8; 20] = [
    0x03, 0x0A, 0x11, 0x18, 0x1F, 0x26, 0x2D, 0x34, 0x3B, 0x42, 0x49, 0x50, 0x57, 0x5E, 0x65, 0x6C,
    0x73, 0x7A, 0x81, 0x88,
];
const LONG_FF: [u8; 8] = [0x10, 0x14, 0x03, 0x0A, 0x11, 0x18, 0x1F, 0x26];
const LONG_CF1: [u8; 8] = [0x21, 0x2D, 0x34, 0x3B, 0x42, 0x49, 0x50, 0x57];
const LONG_CF2: [u8; 8] = [0x22, 0x5E, 0x65, 0x6C, 0x73, 0x7A, 0x81, 0x88];
const RECEIVER_FC: [u8; 3] = [0x30, 0x00, 0x01];
const OVERFLOW_FC: [u8; 3] = [0x32, 0x00, 0x00];

fn receiver() -> Reassembler {
    Reassembler::new(C_BLOCK_SIZE, C_ST_MIN)
}

#[test]
fn a_3_byte_message_is_one_single_frame() {
    let segmenter = Segmenter::new(&SHORT).unwrap();
    assert_eq!(segmenter.first(), SHORT_SF);
    assert_eq!(segmenter.count(), 0);
}

#[test]
fn a_20_byte_message_is_a_first_frame_and_two_consecutive_frames() {
    let segmenter = Segmenter::new(&LONG).unwrap();
    assert_eq!(segmenter.first(), LONG_FF);
    let rest: Vec<Vec<u8>> = segmenter.collect();
    assert_eq!(rest, [LONG_CF1, LONG_CF2]);
}

#[test]
fn the_receivers_flow_control_and_an_overflow_encode_as_documented() {
    let cts = FlowControl {
        status: FlowStatus::ContinueToSend,
        block_size: C_BLOCK_SIZE,
        st_min: C_ST_MIN,
    };
    assert_eq!(cts.encode(), RECEIVER_FC);
    let overflow = FlowControl {
        status: FlowStatus::Overflow,
        block_size: 0,
        st_min: StMin(0),
    };
    assert_eq!(overflow.encode(), OVERFLOW_FC);
}

#[test]
fn the_single_frame_reassembles() {
    assert_eq!(
        receiver().on_frame(&SHORT_SF),
        Outcome {
            aborted: None,
            step: Step::Message(SHORT.to_vec())
        }
    );
}

#[test]
fn the_long_frames_reassemble_after_asking_for_the_documented_flow_control() {
    let mut reassembler = receiver();
    let Step::SendFlowControl(asked) = reassembler.on_frame(&LONG_FF).step else {
        panic!("a first frame asks for flow control");
    };
    assert_eq!(asked.encode(), RECEIVER_FC);
    assert_eq!(reassembler.on_frame(&LONG_CF1).step, Step::Accepted);
    assert_eq!(
        reassembler.on_frame(&LONG_CF2).step,
        Step::Message(LONG.to_vec())
    );
}
