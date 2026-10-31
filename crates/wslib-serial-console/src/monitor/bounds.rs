use std::{collections::VecDeque, sync::Arc};

use tokio::time::{Duration, Instant};

use crate::EndReason;

/// What a subscription replays and when it ends. None set is the open-ended
/// stream a console wants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bounds {
    /// Replay at most the last this many bytes of the port's output.
    pub tail: Option<u32>,
    /// Replay output from at most this long ago; with `tail`, both apply.
    pub since_ms: Option<u64>,
    /// Keep streaming after the replay; without it and with no other bound,
    /// the subscription ends [`EndReason::Closed`] once the replay is sent.
    pub follow: bool,
    /// End [`EndReason::Pattern`] once the output holds this, across reads.
    pub wait_for: Option<String>,
    /// End [`EndReason::Timeout`] this long after subscribing.
    pub timeout_ms: Option<u64>,
    /// End [`EndReason::Duration`] this long after subscribing; outranks
    /// `timeout_ms`.
    pub duration_ms: Option<u64>,
    /// End [`EndReason::Lines`] after this many newlines.
    pub lines: Option<u32>,
}

impl Default for Bounds {
    fn default() -> Self {
        Self {
            tail: None,
            since_ms: None,
            follow: true,
            wait_for: None,
            timeout_ms: None,
            duration_ms: None,
            lines: None,
        }
    }
}

impl Bounds {
    pub fn is_open_ended(&self) -> bool {
        self.tail.is_none()
            && self.since_ms.is_none()
            && self.wait_for.is_none()
            && self.timeout_ms.is_none()
            && self.duration_ms.is_none()
            && self.lines.is_none()
    }

    pub(super) fn replay_only(&self) -> bool {
        !self.follow
            && self.wait_for.is_none()
            && self.timeout_ms.is_none()
            && self.duration_ms.is_none()
            && self.lines.is_none()
    }

    pub(super) fn deadline(&self, from: Instant) -> Option<(Instant, EndReason)> {
        let (ms, reason) = match (self.duration_ms, self.timeout_ms) {
            (Some(ms), _) => (ms, EndReason::Duration),
            (None, Some(ms)) => (ms, EndReason::Timeout),
            (None, None) => return None,
        };
        Some((from + Duration::from_millis(ms), reason))
    }
}

/// A port's recent output, oldest read dropped first past `cap` bytes.
#[derive(Debug)]
pub(super) struct Ring {
    reads: VecDeque<(Instant, Arc<[u8]>)>,
    len: usize,
    cap: usize,
}

impl Ring {
    pub(super) fn new(cap: usize) -> Self {
        Self {
            reads: VecDeque::new(),
            len: 0,
            cap,
        }
    }

    pub(super) fn push(&mut self, at: Instant, bytes: Arc<[u8]>) {
        self.len += bytes.len();
        self.reads.push_back((at, bytes));
        while self.len > self.cap {
            let Some((_, dropped)) = self.reads.pop_front() else {
                break;
            };
            self.len -= dropped.len();
        }
    }

    /// The bytes read at or after `since` and within the last `tail`.
    pub(super) fn snapshot(&self, tail: Option<u32>, since: Option<Instant>) -> Vec<u8> {
        let mut out: Vec<u8> = self
            .reads
            .iter()
            .filter(|(at, _)| since.is_none_or(|since| *at >= since))
            .flat_map(|(_, bytes)| bytes.iter().copied())
            .collect();
        if let Some(tail) = tail {
            out.drain(..out.len().saturating_sub(tail as usize));
        }
        out
    }
}

/// `wait_for` and `lines`, matched across reads.
#[derive(Debug)]
pub(super) struct BoundChecker {
    wait_for: Option<Vec<u8>>,
    window: VecDeque<u8>,
    lines: Option<u32>,
    lines_seen: u32,
}

impl BoundChecker {
    pub(super) fn new(bounds: &Bounds) -> Self {
        Self {
            wait_for: bounds.wait_for.as_ref().map(|w| w.as_bytes().to_vec()),
            window: VecDeque::new(),
            lines: bounds.lines,
            lines_seen: 0,
        }
    }

    pub(super) fn check(&mut self, chunk: &[u8]) -> Option<EndReason> {
        if let Some(pattern) = self.wait_for.as_deref().filter(|p| !p.is_empty()) {
            for &b in chunk {
                if self.window.len() == pattern.len() {
                    self.window.pop_front();
                }
                self.window.push_back(b);
                if self.window.iter().eq(pattern) {
                    return Some(EndReason::Pattern);
                }
            }
        }
        if let Some(limit) = self.lines {
            for _ in chunk.iter().filter(|&&b| b == b'\n') {
                self.lines_seen += 1;
                if self.lines_seen >= limit {
                    return Some(EndReason::Lines);
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(b: &'static [u8]) -> Arc<[u8]> {
        b.into()
    }

    #[test]
    fn the_ring_drops_the_oldest_read_first_past_its_cap() {
        let mut ring = Ring::new(8);
        let now = Instant::now();
        for read in [b"AAAA", b"BBBB", b"CCCC"] {
            ring.push(now, bytes(read));
        }
        assert_eq!(ring.snapshot(None, None), b"BBBBCCCC");
    }

    #[test]
    fn tail_is_the_last_bytes_of_the_replay() {
        let mut ring = Ring::new(64);
        let now = Instant::now();
        ring.push(now, bytes(b"0123456789"));
        ring.push(now, bytes(b"abcdef"));
        assert_eq!(ring.snapshot(Some(4), None), b"cdef");
        assert_eq!(ring.snapshot(Some(99), None), b"0123456789abcdef");
        assert_eq!(ring.snapshot(Some(0), None), b"");
    }

    #[test]
    fn since_keeps_reads_at_or_after_it_and_tail_trims_those() {
        let mut ring = Ring::new(64);
        let t0 = Instant::now();
        let t1 = t0 + Duration::from_millis(100);
        ring.push(t0, bytes(b"old"));
        ring.push(t1, bytes(b"newer"));
        assert_eq!(ring.snapshot(None, Some(t1)), b"newer");
        assert_eq!(ring.snapshot(Some(2), Some(t1)), b"er");
        assert_eq!(
            ring.snapshot(None, Some(t1 + Duration::from_millis(1))),
            b""
        );
    }

    #[test]
    fn a_pattern_split_across_reads_still_matches() {
        let mut checker = BoundChecker::new(&Bounds {
            wait_for: Some("READY".into()),
            ..Bounds::default()
        });
        assert_eq!(checker.check(b"boot.."), None);
        assert_eq!(checker.check(b"REA"), None);
        assert_eq!(checker.check(b"DY now"), Some(EndReason::Pattern));
    }

    #[test]
    fn lines_count_newlines_across_reads() {
        let mut checker = BoundChecker::new(&Bounds {
            lines: Some(3),
            ..Bounds::default()
        });
        assert_eq!(checker.check(b"first\nsecond\n"), None);
        assert_eq!(checker.check(b"third\n"), Some(EndReason::Lines));
    }

    #[test]
    fn only_history_bounds_without_follow_are_a_replay() {
        let replay = Bounds {
            tail: Some(10),
            follow: false,
            ..Bounds::default()
        };
        assert!(replay.replay_only());
        assert!(!replay.is_open_ended());
        assert!(
            !Bounds {
                follow: true,
                ..replay.clone()
            }
            .replay_only()
        );
        assert!(
            !Bounds {
                lines: Some(1),
                ..replay
            }
            .replay_only()
        );
        assert!(Bounds::default().is_open_ended());
    }

    #[test]
    fn duration_outranks_timeout() {
        let now = Instant::now();
        let both = Bounds {
            timeout_ms: Some(5),
            duration_ms: Some(10),
            ..Bounds::default()
        };
        assert_eq!(
            both.deadline(now),
            Some((now + Duration::from_millis(10), EndReason::Duration))
        );
        let timeout = Bounds {
            timeout_ms: Some(5),
            ..Bounds::default()
        };
        assert_eq!(
            timeout.deadline(now),
            Some((now + Duration::from_millis(5), EndReason::Timeout))
        );
    }
}
