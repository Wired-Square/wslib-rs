//! Counters: device-side modulo counters a rule can read.
//!
//! COUNTER_ADD (0x78): `counter_id(u16 LE) modulo(u16 LE) init_value(u16 LE)`
//! COUNTER_REMOVE (0x79): `counter_id(u16 LE)`
//! COUNTER_LIST (0x7A): empty payload
//! COUNTER_RESP (0x7B): `counter_id(u16 LE) modulo(u16 LE) init_value(u16 LE) value(u16 LE)`

use crate::Error;
use serde::Serialize;

const COUNTER_ADD_LEN: usize = 6;
const COUNTER_RESP_LEN: usize = 8;

#[derive(Debug, Clone, PartialEq, Serialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct CounterInfo {
    pub counter_id: u16,
    pub modulo: u16,
    pub init_value: u16,
    pub value: u16,
}

pub fn build_counter_add(counter_id: u16, modulo: u16, init_value: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(COUNTER_ADD_LEN);
    buf.extend_from_slice(&counter_id.to_le_bytes());
    buf.extend_from_slice(&modulo.to_le_bytes());
    buf.extend_from_slice(&init_value.to_le_bytes());
    buf
}

pub fn build_counter_remove(counter_id: u16) -> Vec<u8> {
    counter_id.to_le_bytes().to_vec()
}

pub fn build_counter_list() -> Vec<u8> {
    Vec::new()
}

pub fn parse_counter_resp(payload: &[u8]) -> Result<CounterInfo, Error> {
    if payload.len() < COUNTER_RESP_LEN {
        return Err(Error::InvalidPayload("counter resp too short"));
    }
    let le = |i: usize| u16::from_le_bytes([payload[i], payload[i + 1]]);
    Ok(CounterInfo {
        counter_id: le(0),
        modulo: le(2),
        init_value: le(4),
        value: le(6),
    })
}

pub fn next_available_id(existing: &[CounterInfo]) -> u16 {
    crate::next_free_id(existing.iter().map(|c| c.counter_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_counter_add_is_six_bytes_le() {
        assert_eq!(
            build_counter_add(1, 16, 15),
            vec![0x01, 0x00, 0x10, 0x00, 0x0F, 0x00]
        );
    }

    #[test]
    fn build_counter_remove_and_list() {
        assert_eq!(build_counter_remove(0x0102), vec![0x02, 0x01]);
        assert!(build_counter_list().is_empty());
    }

    #[test]
    fn parse_counter_resp_round_trips_add_fields_plus_value() {
        let payload = [0x01, 0x00, 0x10, 0x00, 0x0F, 0x00, 0x03, 0x00];
        let info = parse_counter_resp(&payload).unwrap();
        assert_eq!(
            info,
            CounterInfo {
                counter_id: 1,
                modulo: 16,
                init_value: 15,
                value: 3
            }
        );
        assert_eq!(
            build_counter_add(info.counter_id, info.modulo, info.init_value),
            payload[..COUNTER_ADD_LEN]
        );
    }

    #[test]
    fn parse_counter_resp_rejects_short_payload() {
        assert!(matches!(
            parse_counter_resp(&[0x01, 0x00, 0x10, 0x00, 0x0F, 0x00]),
            Err(Error::InvalidPayload(_))
        ));
    }

    #[test]
    fn next_available_id_skips_used() {
        let used = [
            CounterInfo {
                counter_id: 0,
                modulo: 16,
                init_value: 0,
                value: 0,
            },
            CounterInfo {
                counter_id: 1,
                modulo: 16,
                init_value: 0,
                value: 0,
            },
        ];
        assert_eq!(next_available_id(&used), 2);
        assert_eq!(next_available_id(&[]), 0);
    }
}
