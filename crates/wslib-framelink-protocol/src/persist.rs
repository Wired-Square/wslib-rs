//! Persistence: three empty payloads, each needing the write unlock.
//! PERSIST_LOAD replaces the live rule tables with the stored ones.

pub fn build_persist_save() -> Vec<u8> {
    Vec::new()
}

pub fn build_persist_load() -> Vec<u8> {
    Vec::new()
}

pub fn build_persist_clear() -> Vec<u8> {
    Vec::new()
}
