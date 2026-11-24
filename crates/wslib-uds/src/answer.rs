use serde::{Deserialize, Serialize};

use crate::{Nrc, sid};

/// How a response answers a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(rename = "UdsAnswer"))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Answer {
    Positive,
    Negative { code: Nrc },
}

/// Whether `response` answers `request`, judged on leading bytes alone: a
/// negative response names the request's service; a positive one carries the
/// service id plus 0x40 and echoes what the request identified, so far as the
/// request has it. A positive answer may still fail strict decoding.
pub fn answers(request: &[u8], response: &[u8]) -> Option<Answer> {
    let &service = request.first()?;
    match response {
        [sid::NEGATIVE_RESPONSE, s, code, ..] if *s == service => {
            return Some(Answer::Negative { code: Nrc(*code) });
        }
        [sid::NEGATIVE_RESPONSE, ..] => return None,
        [first, ..] if Some(*first) == service.checked_add(sid::POSITIVE_OFFSET) => {}
        _ => return None,
    }
    let echoed = |range: std::ops::Range<usize>| match request.get(range.clone()) {
        Some(asked) => response.get(range) == Some(asked),
        None => true,
    };
    let sub_function_echoed = match request.get(1) {
        Some(sub) if sid::has_sub_function(service) => response.get(1) == Some(&(sub & 0x7F)),
        _ => true,
    };
    let identified = match service {
        sid::READ_DATA_BY_IDENTIFIER => {
            let (dids, _) = request[1..].as_chunks::<2>();
            dids.is_empty()
                || response
                    .get(1..3)
                    .is_some_and(|did| dids.iter().any(|asked| asked.as_slice() == did))
        }
        sid::WRITE_DATA_BY_IDENTIFIER | sid::INPUT_OUTPUT_CONTROL_BY_IDENTIFIER => echoed(1..3),
        sid::ROUTINE_CONTROL => echoed(2..4),
        sid::TRANSFER_DATA => echoed(1..2),
        _ => true,
    };
    (sub_function_echoed && identified).then_some(Answer::Positive)
}

pub(crate) fn suppresses_positive_response(request: &[u8]) -> bool {
    match request {
        [service, sub, ..] => sid::has_sub_function(*service) && sub & 0x80 != 0,
        _ => false,
    }
}
