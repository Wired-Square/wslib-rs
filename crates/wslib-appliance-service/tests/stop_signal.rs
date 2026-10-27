//! A SIGTERM raised at this process: a binary of its own, because a signal's
//! disposition is process-wide and the handler stays for the binary's life.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;

use wslib_appliance_core::testing::group_of;
use wslib_appliance_service::{LocalBootstrap, LocalEndpoint, LocalError, Service, logs};
use wslib_appliance_types::{Branding, Role};

#[test]
fn a_sigterm_sent_while_starting_stops_the_service_once_it_is_listening() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path();
    let private = |path: &std::path::Path, mode: u32| {
        std::fs::create_dir(path).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    };
    let state_dir = dir.join("state");
    private(&state_dir, 0o700);
    let admin = dir.join("admin");
    private(&admin, 0o750);
    let bootstrap = LocalBootstrap {
        db: state_dir.join("test.db"),
        state_dir,
        endpoints: vec![LocalEndpoint {
            path: admin.join("test.sock"),
            ceiling: Role::Admin,
            group: group_of(&admin),
        }],
        ui: None,
        log_file: dir.join("test.log"),
    };

    let listening_when_stopped = wslib_appliance_service::daemon("stop-signal")
        .run(|stop| async move {
            let sent = std::process::Command::new("kill")
                .args(["-TERM", &std::process::id().to_string()])
                .status()
                .expect("run kill");
            assert!(sent.success());

            let store = bootstrap.open_store(None).await?;
            let socket = bootstrap.endpoints[0].path.clone();
            let mut listening_when_stopped = false;
            Service::new(store, Branding::unbranded(), "0.0.0", logs(&[]))
                .serve_local(&bootstrap, async {
                    stop.await;
                    listening_when_stopped = socket.exists();
                })
                .await?;
            Ok::<_, LocalError>(listening_when_stopped)
        })
        .expect("the signal stopped it");
    assert!(
        listening_when_stopped,
        "stopped before the socket was bound"
    );
}
