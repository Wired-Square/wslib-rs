//! Serving with no rustls provider installed, in a process of its own: the
//! default provider is process-wide, and the unit tests install one.

use std::path::Path;
use std::time::Duration;

use wslib_appliance_service::{
    LocalBootstrap, LocalEndpoint, LocalError, ServeError, Service, logs,
};
use wslib_appliance_types::{Branding, Role};

fn private(dir: &Path) {
    std::fs::create_dir(dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    #[cfg(windows)]
    wslib_file_atomic::owner_only(dir).unwrap();
}

#[cfg(unix)]
fn admin_endpoint(dir: &Path) -> LocalEndpoint {
    use std::os::unix::fs::PermissionsExt;
    let admin = dir.join("admin");
    std::fs::create_dir(&admin).unwrap();
    std::fs::set_permissions(&admin, std::fs::Permissions::from_mode(0o750)).unwrap();
    LocalEndpoint {
        path: admin.join("test.sock"),
        ceiling: Role::Admin,
        group: wslib_appliance_core::testing::group_of(&admin),
    }
}

#[cfg(windows)]
fn admin_endpoint(dir: &Path) -> LocalEndpoint {
    let unique = dir.file_name().unwrap().to_string_lossy();
    LocalEndpoint {
        path: format!(r"\\.\pipe\{unique}-admin").into(),
        ceiling: Role::Admin,
        group: String::new(),
    }
}

#[tokio::test]
async fn serving_with_no_crypto_provider_is_refused_and_fires_the_handle() {
    let temp = tempfile::tempdir().unwrap();
    let state_dir = temp.path().join("state");
    private(&state_dir);
    let bootstrap = LocalBootstrap {
        db: state_dir.join("test.db"),
        state_dir,
        endpoints: vec![admin_endpoint(temp.path())],
        ui: None,
        log_file: temp.path().join("test.log"),
        #[cfg(windows)]
        service: None,
    };
    let store = bootstrap.open_store(None).await.expect("store");
    let service = Service::new(store, Branding::unbranded(), "0.0.0", logs(&[]));
    let stopped = service.shutdown();

    let serving = service.serve_local(&bootstrap, std::future::pending());
    let refused = tokio::time::timeout(Duration::from_secs(5), serving)
        .await
        .expect("refused at once, not serving")
        .expect_err("refused");

    assert!(
        matches!(refused, LocalError::Serve(ServeError::NoCryptoProvider)),
        "{refused}"
    );
    assert!(stopped.is_cancelled());
}
