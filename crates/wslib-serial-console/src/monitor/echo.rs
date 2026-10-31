use std::collections::VecDeque;

use tokio::time::{Duration, Instant};

use super::Update;
use crate::Span;

pub(super) const ECHO_WAIT: Duration = Duration::from_millis(300);

#[derive(Debug)]
struct Pending {
    by: String,
    colour: u8,
    bytes: VecDeque<u8>,
    since: Instant,
    echoing: bool,
}

/// Attributes device output to whoever typed it, matching each writer's
/// unechoed input in order, across read chunks.
#[derive(Debug, Default)]
pub(super) struct EchoMatcher {
    writers: Vec<Pending>,
}

impl EchoMatcher {
    pub(super) fn sent(&mut self, by: &str, colour: u8, bytes: &[u8], now: Instant) {
        match self.writers.iter_mut().find(|w| w.by == by) {
            Some(writer) => writer.bytes.extend(bytes),
            None => self.writers.push(Pending {
                by: by.to_string(),
                colour,
                bytes: bytes.iter().copied().collect(),
                since: now,
                echoing: false,
            }),
        }
    }

    /// A writer whose echo has begun and then diverges is given up on, without an [`Update::Unechoed`].
    pub(super) fn echoed(&mut self, chunk: &[u8]) -> Vec<Span> {
        let mut spans: Vec<Span> = Vec::new();
        for (at, byte) in (0u32..).zip(chunk) {
            if self.writers.is_empty() {
                break;
            }
            let Some(i) = self
                .writers
                .iter()
                .position(|w| w.bytes.front() == Some(byte))
            else {
                self.writers.retain(|w| !w.echoing);
                continue;
            };
            let writer = &mut self.writers[i];
            writer.bytes.pop_front();
            writer.echoing = true;
            match spans.last_mut() {
                Some(span) if span.by == writer.by && span.start + span.len == at => span.len += 1,
                _ => spans.push(Span {
                    start: at,
                    len: 1,
                    by: writer.by.clone(),
                    colour: writer.colour,
                }),
            }
            if writer.bytes.is_empty() {
                self.writers.remove(i);
            }
        }
        spans
    }

    /// When the oldest pending input is due to expire.
    pub(super) fn next_expiry(&self) -> Option<Instant> {
        self.writers.iter().map(|w| w.since + ECHO_WAIT).min()
    }

    /// Input not echoed within [`ECHO_WAIT`], as [`Update::Unechoed`].
    pub(super) fn expire(&mut self, now: Instant) -> Vec<Update> {
        let mut stale = Vec::new();
        self.writers.retain_mut(|w| {
            if now.duration_since(w.since) < ECHO_WAIT {
                return true;
            }
            stale.push(Update::Unechoed {
                by: std::mem::take(&mut w.by),
                colour: w.colour,
                count: w.bytes.len() as u32,
                controls: w.bytes.iter().filter_map(|&b| caret(b)).collect(),
            });
            false
        });
        stale
    }
}

fn caret(byte: u8) -> Option<String> {
    match byte {
        0..=0x1f => Some(format!("^{}", char::from(byte + 0x40))),
        0x7f => Some("^?".into()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn span(start: u32, len: u32, by: &str) -> Span {
        let colour = if by == "alex" { 0 } else { 1 };
        Span {
            start,
            len,
            by: by.into(),
            colour,
        }
    }

    #[test]
    fn an_echo_split_across_chunks_is_still_the_writers() {
        let now = Instant::now();
        let mut matcher = EchoMatcher::default();
        matcher.sent("alex", 0, b"help\r", now);

        assert_eq!(matcher.echoed(b"he"), [span(0, 2, "alex")]);
        assert_eq!(matcher.echoed(b"lp\r\n"), [span(0, 3, "alex")]);
        assert!(matcher.expire(now + ECHO_WAIT).is_empty());
    }

    #[test]
    fn device_output_before_the_echo_is_nobodys() {
        let now = Instant::now();
        let mut matcher = EchoMatcher::default();
        matcher.sent("alex", 0, b"ls", now);

        assert_eq!(matcher.echoed(b"[boot]\r\nls"), [span(8, 2, "alex")]);
    }

    #[test]
    fn interleaved_writers_each_get_their_own_echo() {
        let now = Instant::now();
        let mut matcher = EchoMatcher::default();
        matcher.sent("alex", 0, b"ab", now);
        matcher.sent("olive", 1, b"xy", now);

        assert_eq!(
            matcher.echoed(b"axby"),
            [
                span(0, 1, "alex"),
                span(1, 1, "olive"),
                span(2, 1, "alex"),
                span(3, 1, "olive")
            ]
        );
    }

    #[test]
    fn an_echo_that_diverges_is_given_up_quietly() {
        let now = Instant::now();
        let mut matcher = EchoMatcher::default();
        matcher.sent("alex", 0, b"abc", now);

        assert_eq!(matcher.echoed(b"aZc"), [span(0, 1, "alex")]);
        assert!(matcher.expire(now + ECHO_WAIT).is_empty());
    }

    #[test]
    fn input_never_echoed_is_counted_and_its_control_keys_shown_but_not_its_bytes() {
        let now = Instant::now();
        let mut matcher = EchoMatcher::default();
        matcher.sent("alex", 0, b"s3cret\r", now);
        matcher.sent("olive", 1, &[0x03], now + ECHO_WAIT / 2);

        assert_eq!(matcher.next_expiry(), Some(now + ECHO_WAIT));
        assert!(matcher.expire(now + ECHO_WAIT / 2).is_empty());
        assert_eq!(
            matcher.expire(now + ECHO_WAIT),
            [Update::Unechoed {
                by: "alex".into(),
                colour: 0,
                count: 7,
                controls: "^M".into()
            }]
        );
        assert_eq!(
            matcher.expire(now + ECHO_WAIT * 2),
            [Update::Unechoed {
                by: "olive".into(),
                colour: 1,
                count: 1,
                controls: "^C".into()
            }]
        );
        assert_eq!(matcher.next_expiry(), None);
    }
}
