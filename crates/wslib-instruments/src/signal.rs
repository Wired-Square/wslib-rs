pub use wslib_framelink_protocol::dsig::SignalKey;
use wslib_framelink_protocol::{
    dsig::{format_signal_key, parse_signal_key, semantic_signal_name},
    types::{ROLE_DIAGNOSTIC, ROLE_MEASUREMENT, ROLE_STATUS, SIGNAL_TARGET_DEVICE, quantity_unit},
};

pub const INSTRUMENT_INDEX: u8 = 0;

const fn key(role: u8, quantity: u8, aspect: u8, channel: u8) -> SignalKey {
    SignalKey {
        target_type: SIGNAL_TARGET_DEVICE,
        target_index: INSTRUMENT_INDEX,
        role,
        quantity,
        aspect,
        channel,
    }
}

pub const fn measurement(quantity: u8, aspect: u8, channel: u8) -> SignalKey {
    key(ROLE_MEASUREMENT, quantity, aspect, channel)
}

pub const fn status(quantity: u8, aspect: u8, channel: u8) -> SignalKey {
    key(ROLE_STATUS, quantity, aspect, channel)
}

pub const fn diagnostic(quantity: u8, aspect: u8, channel: u8) -> SignalKey {
    key(ROLE_DIAGNOSTIC, quantity, aspect, channel)
}

pub fn unit(key: &SignalKey) -> &'static str {
    quantity_unit(key.quantity)
}

pub fn slug(key: &SignalKey) -> String {
    format_signal_key(key)
}

pub fn parse(slug: &str) -> Result<SignalKey, String> {
    parse_signal_key(slug).map_err(|e| e.to_string())
}

pub fn derived_name(key: &SignalKey) -> String {
    semantic_signal_name(key.role, key.quantity, key.aspect, key.channel, None)
}
