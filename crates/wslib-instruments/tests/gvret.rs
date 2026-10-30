use std::{
    io::Write,
    net::{SocketAddr, TcpListener},
    thread,
    time::{Duration, Instant},
};

use wslib_can_gvret::{encode_frame, encode_num_buses};
use wslib_instruments::{
    signal::SignalKey,
    uri::{ProbeUri, open},
    wiredreflow::frame::{TC1, TC2},
};

const THERMOCOUPLE_ID: u32 = 0x028F_0821;
const FAULT_ID: u32 = 0x028F_0825;
const ROOM: [u8; 8] = [0xE8, 0x00, 0xE3, 0x00, 0xFC, 0x00, 0xFA, 0x00];
const CLEAR: [u8; 2] = [0x00, 0x00];
const PERIOD: Duration = Duration::from_millis(50);
const DEADLINE: Duration = Duration::from_secs(5);

fn board_on_a_gvret_device() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    thread::spawn(move || {
        let (mut device, _) = listener.accept().unwrap();
        device.write_all(&encode_num_buses(1)).unwrap();
        loop {
            let mut period = encode_frame(0, THERMOCOUPLE_ID, true, 0, &ROOM, false);
            period.extend(encode_frame(0, FAULT_ID, true, 0, &CLEAR, false));
            if device.write_all(&period).is_err() {
                return;
            }
            thread::sleep(PERIOD);
        }
    });
    address
}

fn thermocouples(address: SocketAddr) -> Vec<SignalKey> {
    let uri: ProbeUri = format!("wiredreflow:gvret={address}/TC1/TC2")
        .parse()
        .unwrap();
    let mut probe = open(&uri).unwrap();
    let until = Instant::now() + DEADLINE;
    loop {
        let keys: Vec<SignalKey> = probe
            .next(until)
            .unwrap()
            .iter()
            .map(|sample| sample.key)
            .collect();
        if !keys.is_empty() {
            return keys;
        }
    }
}

fn current_thread() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

#[test]
fn a_board_on_a_gvret_device_is_discovered_and_read() {
    assert_eq!(thermocouples(board_on_a_gvret_device()), [TC1, TC2]);
}

#[test]
fn a_probe_opens_reads_and_drops_inside_a_current_thread_runtime() {
    let address = board_on_a_gvret_device();
    assert_eq!(
        current_thread().block_on(async { thermocouples(address) }),
        [TC1, TC2]
    );
}

#[test]
fn a_probe_opens_reads_and_drops_in_spawn_blocking() {
    let address = board_on_a_gvret_device();
    let keys = current_thread()
        .block_on(async { tokio::task::spawn_blocking(move || thermocouples(address)).await });
    assert_eq!(keys.unwrap(), [TC1, TC2]);
}
