use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::{error, fmt};

use crate::Secret;

/// Somewhere a secret outlives the process, keyed by service and account.
pub trait SecretStore: Send + Sync {
    /// The secret saved under `service` and `account`, or `None` when there is none.
    fn load(&self, service: &str, account: &str) -> Result<Option<Secret>, StoreError>;

    /// Saves `secret`, replacing whatever was saved under the same key.
    fn save(&self, service: &str, account: &str, secret: &Secret) -> Result<(), StoreError>;

    /// Removes the secret saved under the key, which is not an error when there is none.
    fn delete(&self, service: &str, account: &str) -> Result<(), StoreError>;
}

/// Why a store failed. Never carries the value.
#[derive(Debug)]
#[non_exhaustive]
pub enum StoreError {
    /// The store behind the trait failed.
    Backend(Box<dyn error::Error + Send + Sync>),
    /// The user refused or cancelled the store's prompt, or access was not allowed.
    Denied,
    /// The saved item is not valid UTF-8.
    NotUnicode,
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Backend(source) => write!(f, "secret store failed: {source}"),
            Self::Denied => f.write_str("access to the secret store was denied"),
            Self::NotUnicode => f.write_str("the saved secret is not valid UTF-8"),
        }
    }
}

impl error::Error for StoreError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Backend(source) => Some(source.as_ref()),
            Self::Denied | Self::NotUnicode => None,
        }
    }
}

/// A store in memory, for tests that must not touch the OS.
#[derive(Debug, Default)]
pub struct MemoryStore(Mutex<HashMap<(String, String), Secret>>);

impl MemoryStore {
    fn items(&self) -> MutexGuard<'_, HashMap<(String, String), Secret>> {
        // A map is whole between calls, so a panic elsewhere leaves nothing to repair.
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

fn key(service: &str, account: &str) -> (String, String) {
    (service.to_owned(), account.to_owned())
}

impl SecretStore for MemoryStore {
    fn load(&self, service: &str, account: &str) -> Result<Option<Secret>, StoreError> {
        Ok(self.items().get(&key(service, account)).cloned())
    }

    fn save(&self, service: &str, account: &str, secret: &Secret) -> Result<(), StoreError> {
        self.items().insert(key(service, account), secret.clone());
        Ok(())
    }

    fn delete(&self, service: &str, account: &str) -> Result<(), StoreError> {
        self.items().remove(&key(service, account));
        Ok(())
    }
}

#[cfg(all(feature = "keychain", any(target_os = "macos", target_os = "ios")))]
pub use keychain::Keychain;

#[cfg(all(feature = "keychain", any(target_os = "macos", target_os = "ios")))]
mod keychain {
    use security_framework::base::Error;
    use security_framework::passwords;
    use zeroize::Zeroizing;

    use super::{SecretStore, StoreError};
    use crate::Secret;

    // `errSecItemNotFound`, `errSecUserCanceled`, `errSecAuthFailed` and
    // `errSecInteractionNotAllowed`, from `Security/SecBase.h`.
    const ITEM_NOT_FOUND: i32 = -25300;
    const USER_CANCELED: i32 = -128;
    const AUTH_FAILED: i32 = -25293;
    const INTERACTION_NOT_ALLOWED: i32 = -25308;

    /// The user's default keychain, one generic-password item per service and account;
    /// its calls block and can wait on a user prompt, so hold no lock across them.
    #[derive(Clone, Copy, Debug, Default)]
    pub struct Keychain;

    pub(super) fn backend(error: Error) -> StoreError {
        match error.code() {
            USER_CANCELED | AUTH_FAILED | INTERACTION_NOT_ALLOWED => StoreError::Denied,
            _ => StoreError::Backend(Box::new(error)),
        }
    }

    impl SecretStore for Keychain {
        fn load(&self, service: &str, account: &str) -> Result<Option<Secret>, StoreError> {
            match passwords::get_generic_password(service, account) {
                Ok(bytes) => Secret::from_utf8(Zeroizing::new(bytes))
                    .map(Some)
                    .ok_or(StoreError::NotUnicode),
                Err(error) if error.code() == ITEM_NOT_FOUND => Ok(None),
                Err(error) => Err(backend(error)),
            }
        }

        fn save(&self, service: &str, account: &str, secret: &Secret) -> Result<(), StoreError> {
            passwords::set_generic_password(service, account, secret.expose().as_bytes())
                .map_err(backend)
        }

        fn delete(&self, service: &str, account: &str) -> Result<(), StoreError> {
            match passwords::delete_generic_password(service, account) {
                Err(error) if error.code() != ITEM_NOT_FOUND => Err(backend(error)),
                _ => Ok(()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    fn loaded(store: &dyn SecretStore, service: &str) -> Option<String> {
        let secret = store.load(service, "acct").unwrap();
        secret.map(|secret| secret.expose().to_owned())
    }

    #[test]
    fn a_saved_secret_loads_back() {
        let store = MemoryStore::default();
        store.save("svc", "acct", &Secret::new("hunter2")).unwrap();
        assert_eq!(loaded(&store, "svc").as_deref(), Some("hunter2"));
    }

    #[test]
    fn a_missing_secret_loads_as_none() {
        let store = MemoryStore::default();
        store.save("svc", "acct", &Secret::new("hunter2")).unwrap();
        assert!(store.load("svc", "other").unwrap().is_none());
        assert!(store.load("other", "acct").unwrap().is_none());
    }

    #[test]
    fn saving_again_replaces_the_secret() {
        let store = MemoryStore::default();
        store.save("svc", "acct", &Secret::new("first")).unwrap();
        store.save("svc", "acct", &Secret::new("second")).unwrap();
        assert_eq!(loaded(&store, "svc").as_deref(), Some("second"));
    }

    #[test]
    fn deleting_is_idempotent() {
        let store = MemoryStore::default();
        store.save("svc", "acct", &Secret::new("hunter2")).unwrap();
        store.delete("svc", "acct").unwrap();
        assert!(store.load("svc", "acct").unwrap().is_none());
        store.delete("svc", "acct").unwrap();
    }

    #[test]
    fn a_store_works_behind_a_shared_trait_object() {
        let store: Arc<dyn SecretStore> = Arc::new(MemoryStore::default());
        let writer = Arc::clone(&store);
        std::thread::spawn(move || writer.save("svc", "acct", &Secret::new("hunter2")))
            .join()
            .unwrap()
            .unwrap();
        assert_eq!(loaded(&*store, "svc").as_deref(), Some("hunter2"));
    }

    #[test]
    fn a_store_error_never_carries_the_value() {
        for err in [
            StoreError::Denied,
            StoreError::NotUnicode,
            StoreError::Backend("access denied".into()),
        ] {
            let rendered = format!("{err} {err:?}");
            assert!(!rendered.contains("hunter2"), "leaked: {rendered}");
        }
    }

    #[cfg(all(feature = "keychain", any(target_os = "macos", target_os = "ios")))]
    mod keychain {
        use super::*;

        struct Scratch(String);

        impl Scratch {
            fn new(name: &str) -> Self {
                let nanos = std::time::UNIX_EPOCH.elapsed().unwrap().as_nanos();
                Self(format!(
                    "wslib-secret-test-{name}-{}-{nanos}",
                    std::process::id()
                ))
            }
        }

        impl Drop for Scratch {
            fn drop(&mut self) {
                let _ = Keychain.delete(&self.0, "acct");
            }
        }

        #[test]
        fn a_refused_or_cancelled_prompt_is_denied() {
            use security_framework::base::Error;

            use crate::store::keychain::backend;

            for code in [-128, -25293, -25308] {
                let err = backend(Error::from_code(code));
                assert!(matches!(err, StoreError::Denied), "{code}: {err:?}");
            }
            let err = backend(Error::from_code(-25299));
            assert!(matches!(err, StoreError::Backend(_)), "{err:?}");
        }

        #[test]
        #[ignore = "touches the login keychain, which can prompt"]
        fn the_keychain_saves_replaces_loads_and_deletes() {
            let service = Scratch::new("round-trip");
            let service = &service.0;
            assert_eq!(loaded(&Keychain, service), None);
            for value in ["first", "second"] {
                Keychain.save(service, "acct", &Secret::new(value)).unwrap();
            }
            assert_eq!(loaded(&Keychain, service).as_deref(), Some("second"));
            Keychain.delete(service, "acct").unwrap();
            assert_eq!(loaded(&Keychain, service), None);
            Keychain.delete(service, "acct").unwrap();
        }
    }
}
