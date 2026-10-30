//! A runtime of its own for the long-lived BLE tasks (the scanner, notify
//! dispatchers, deferred disconnects), so a busy host runtime cannot delay
//! their polls and lose notifications.

use std::sync::OnceLock;
use tokio::runtime::Handle;

static BLE_RUNTIME: OnceLock<Handle> = OnceLock::new();

/// A second worker keeps a blocking call on one BLE task from starving the
/// dispatcher's poll.
const BLE_RUNTIME_WORKERS: usize = 2;

/// Started on first use; it runs for the life of the process.
pub(crate) fn ble_runtime() -> Handle {
    BLE_RUNTIME
        .get_or_init(|| {
            let (tx, rx) = std::sync::mpsc::sync_channel::<Handle>(1);
            std::thread::Builder::new()
                .name("framelink-ble-host".into())
                .spawn(move || {
                    let runtime = tokio::runtime::Builder::new_multi_thread()
                        .enable_all()
                        .worker_threads(BLE_RUNTIME_WORKERS)
                        .thread_name("framelink-ble")
                        .build()
                        .expect("framelink-ble runtime build");
                    tx.send(runtime.handle().clone())
                        .expect("framelink-ble runtime handle send");
                    runtime.block_on(std::future::pending::<()>());
                })
                .expect("framelink-ble thread spawn");
            rx.recv().expect("framelink-ble runtime handle recv")
        })
        .clone()
}
