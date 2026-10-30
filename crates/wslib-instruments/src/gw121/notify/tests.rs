use std::time::Duration;

use super::{ParseError, line, parse};
use crate::{gw121::Chunk, sample::Stamp};

fn at(start: Stamp, millis: u64) -> Stamp {
    let offset = Duration::from_millis(millis);
    Stamp {
        at: start.at.checked_add(offset).unwrap(),
        wall_clock: start.wall_clock.checked_add(offset).unwrap(),
    }
}

fn error(text: &str) -> ParseError {
    parse(text, Stamp::now()).unwrap_err()
}

#[test]
fn chunks_written_as_lines_parse_back_equal() {
    let start = Stamp::now();
    let chunks: Vec<Chunk> = vec![
        (at(start, 0), vec![0xF2, 0x17, 0x80]),
        (at(start, 17), vec![]),
        (at(start, 1_234_567), vec![0x00, 0xAB, 0xFF]),
    ];
    let text: String = chunks
        .iter()
        .map(|chunk| line(start, chunk) + "\n")
        .collect();
    assert_eq!(text.lines().next(), Some("0 f21780"));
    assert_eq!(parse(&text, start), Ok(chunks));
}

#[test]
fn a_line_keeps_its_offset_only_to_the_millisecond() {
    let start = Stamp::now();
    let late = Stamp {
        at: start.at.checked_add(Duration::from_micros(1_999)).unwrap(),
        ..start
    };
    assert_eq!(line(start, &(late, vec![0x01])), "1 01");
}

#[test]
fn a_malformed_line_is_named_with_why() {
    let odd = error("0 f2\n17 f21\n");
    assert_eq!(odd.line, 2);
    assert_eq!(odd.to_string(), "line 2: an odd number of hex digits");
    assert_eq!(error("0 f2\nf2").line, 2);
    assert!(error("x f2").why.contains("`x`"));
    assert!(error("0 f2\n\n5 zz").why.contains("no space"));
    assert_eq!(error("0 f2\n0 f2\n5 +f").line, 3);
}
