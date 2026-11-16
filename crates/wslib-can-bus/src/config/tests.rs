use super::{BusConfig, CanMode};

const NOMINAL: u32 = 500_000;
const DATA: u32 = 2_000_000;

#[test]
fn the_default_is_classic_with_no_rate() {
    assert_eq!(BusConfig::default(), BusConfig::classic(None));
    assert_eq!(BusConfig::default().mode, CanMode::Classic);
}

#[test]
fn classic_has_no_data_rate() {
    let config = BusConfig::classic(Some(NOMINAL));
    assert_eq!(config.bitrate, Some(NOMINAL));
    assert!(!config.mode.is_fd());
    assert_eq!(config.mode.data_bitrate(), None);
}

#[test]
fn fd_carries_its_data_rate() {
    let config = BusConfig::fd(Some(NOMINAL), Some(DATA));
    assert_eq!(config.bitrate, Some(NOMINAL));
    assert!(config.mode.is_fd());
    assert_eq!(config.mode.data_bitrate(), Some(DATA));
}

#[test]
fn fd_without_a_data_rate_is_still_fd() {
    let config = BusConfig::fd(None, None);
    assert!(config.mode.is_fd());
    assert_eq!(config.mode.data_bitrate(), None);
}
