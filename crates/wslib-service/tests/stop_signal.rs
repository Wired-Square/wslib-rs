//! A SIGTERM raised at this process: a binary of its own, because a signal's
//! disposition is process-wide and the handler stays for the binary's life.
#![cfg(unix)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use wslib_service::{Daemon, Manager};

#[test]
fn a_sigterm_sent_while_starting_stops_the_service_once_it_polls_its_stop() {
    // SAFETY: the only test in this binary, so no other thread reads the environment.
    unsafe { std::env::remove_var("NOTIFY_SOCKET") };
    let stopped = Arc::new(AtomicBool::new(false));
    let ran = Daemon::new("widgets").run({
        let stopped = stopped.clone();
        |stop| async move {
            assert_eq!(stop.manager(), Manager::Signals);
            let sent = std::process::Command::new("kill")
                .args(["-TERM", &std::process::id().to_string()])
                .status()
                .expect("run kill");
            assert!(sent.success());
            tokio::time::sleep(Duration::from_millis(100)).await;
            tokio::time::timeout(Duration::from_secs(5), stop)
                .await
                .expect("the signal stopped it");
            stopped.store(true, Ordering::SeqCst);
            Ok::<_, String>(())
        }
    });
    ran.expect("asked to stop, so a success");
    assert!(stopped.load(Ordering::SeqCst));
}
