//! The `.notify` capture format: a line per chunk, its offset in milliseconds
//! from the capture's start, a space, and its bytes in hex. A line keeps only
//! that offset, so parsing stamps each chunk at it from a start the caller gives.

use std::{error::Error, fmt, fmt::Write as _, time::Duration};

use super::Chunk;
use crate::sample::Stamp;

/// The line for `chunk`, without its newline.
pub fn line(start: Stamp, (stamp, bytes): &Chunk) -> String {
    let mut line = stamp
        .at
        .saturating_duration_since(start.at)
        .as_millis()
        .to_string();
    line.push(' ');
    for byte in bytes {
        let _ = write!(line, "{byte:02x}");
    }
    line
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ParseError {
    /// Counted from 1.
    pub line: usize,
    pub why: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.why)
    }
}

impl Error for ParseError {}

/// Every chunk in `text`, stamped at its offset from `start`.
pub fn parse(text: &str, start: Stamp) -> Result<Vec<Chunk>, ParseError> {
    text.lines()
        .enumerate()
        .map(|(index, line)| {
            chunk(line, start).map_err(|why| ParseError {
                line: index.saturating_add(1),
                why,
            })
        })
        .collect()
}

fn chunk(line: &str, start: Stamp) -> Result<Chunk, String> {
    let (offset, hex) = line
        .split_once(' ')
        .ok_or("no space between the offset and the bytes")?;
    let offset = offset
        .parse()
        .map(Duration::from_millis)
        .map_err(|_| format!("`{offset}` is not an offset in milliseconds"))?;
    let stamp = start
        .at
        .checked_add(offset)
        .zip(start.wall_clock.checked_add(offset))
        .map(|(at, wall_clock)| Stamp { at, wall_clock })
        .ok_or("the offset is out of range here")?;
    let (pairs, odd) = hex.as_bytes().as_chunks();
    if !odd.is_empty() {
        return Err("an odd number of hex digits".into());
    }
    let bytes = pairs
        .iter()
        .map(|&[high, low]| Some(nibble(high)? << 4 | nibble(low)?))
        .collect::<Option<_>>()
        .ok_or_else(|| format!("`{hex}` is not hex"))?;
    Ok((stamp, bytes))
}

fn nibble(digit: u8) -> Option<u8> {
    char::from(digit)
        .to_digit(16)
        .and_then(|value| u8::try_from(value).ok())
}

#[cfg(test)]
mod tests;
