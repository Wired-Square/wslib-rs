//! A monitor over a real line: a pty, read and written through wslib-serial.
//! serialport can't open a macOS pty read-write, so this runs on Linux.
#![cfg(target_os = "linux")]

use std::{
    ffi::CStr,
    fs::File,
    future::Future,
    io::{ErrorKind, Read, Write},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    ptr,
    time::Duration,
};

use tokio::time::{sleep, timeout};
use wslib_serial_console::{Bounds, MonitorOptions, MonitorState, Monitors, PortKey, Update};

const WAIT: Duration = Duration::from_secs(5);

/// The master end, non-blocking, and the slave's path.
fn pty() -> (File, String) {
    let (mut master, mut slave) = (-1, -1);
    // SAFETY: both out-pointers are valid, and the name, termios and window size are optional.
    let opened = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    assert_eq!(opened, 0, "openpty");
    // SAFETY: openpty returned two descriptors that nothing else owns.
    let (master, slave) = unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) };
    let mut name = [0 as libc::c_char; 128];
    // SAFETY: `slave` is open, and the buffer's length is the one passed.
    assert_eq!(
        unsafe { libc::ttyname_r(slave.as_raw_fd(), name.as_mut_ptr(), name.len()) },
        0
    );
    // SAFETY: ttyname_r wrote a NUL-terminated name.
    let path = unsafe { CStr::from_ptr(name.as_ptr()) }
        .to_str()
        .unwrap()
        .to_owned();
    // SAFETY: `master` is open, and F_SETFL takes an int of flags.
    assert_ne!(
        unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) },
        -1
    );
    (master.into(), path)
}

async fn within<F: Future>(test: F) -> F::Output {
    timeout(WAIT, test).await.expect("timed out")
}

async fn receive(master: &mut File, len: usize) -> Vec<u8> {
    let mut got = Vec::new();
    within(async {
        while got.len() < len {
            let mut buf = [0; 64];
            match master.read(&mut buf) {
                Ok(n) => got.extend(&buf[..n]),
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    sleep(Duration::from_millis(5)).await
                }
                Err(e) => panic!("{e}"),
            }
        }
    })
    .await;
    got
}

#[tokio::test]
async fn a_console_reads_the_line_and_its_input_reaches_the_device_marked_theirs() {
    let (mut master, slave) = pty();
    let monitors = Monitors::new(MonitorOptions::default());
    let key = PortKey::Tty(slave);
    let mut console = monitors.subscribe(key.clone(), None, Bounds::default());
    console.join("local", vec!["alex".into()]);
    within(async {
        while !matches!(
            console.next().await,
            Some(Update::State {
                state: MonitorState::Reading,
                ..
            })
        ) {}
    })
    .await;

    monitors
        .write(&key, b"ls\r".to_vec(), Some("alex"))
        .expect("write");
    assert_eq!(receive(&mut master, 3).await, b"ls\r");
    master.write_all(b"ls\r\n").unwrap();
    let output = within(async {
        loop {
            if let Some(Update::Output { bytes, spans }) = console.next().await {
                return (bytes, spans);
            }
        }
    })
    .await;
    assert!(output.0.starts_with(b"ls"), "{output:?}");
    assert_eq!(output.1.first().map(|span| span.by.as_str()), Some("alex"));

    within(monitors.pause(&key)).await;
    assert!(monitors.write(&key, b"x".to_vec(), None).is_err());
}
