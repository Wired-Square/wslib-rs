use std::collections::HashMap;

use super::StoreError;

#[cfg(target_os = "linux")]
pub use native::SecretService;

// keyring 3 adds `target` and `application`; matching these two alone finds its items too.
fn attributes<'a>(service: &'a str, account: &'a str) -> HashMap<&'a str, &'a str> {
    HashMap::from([("service", service), ("username", account)])
}

fn only<T>(mut items: Vec<T>) -> Result<Option<T>, StoreError> {
    match items.len() {
        0 | 1 => Ok(items.pop()),
        count => Err(StoreError::Backend(
            format!("{count} items match one key").into(),
        )),
    }
}

#[cfg(target_os = "linux")]
mod native {
    use secret_service::blocking::{Item, SecretService as Service};
    use secret_service::{EncryptionType, Error};
    use zeroize::Zeroizing;

    use super::{attributes, only};
    use crate::{Secret, SecretStore, StoreError};

    /// The desktop's Secret Service over D-Bus, one item per service and account, created in the
    /// default collection; its calls block and can wait on an unlock prompt, so hold no lock
    /// across them.
    #[derive(Clone, Copy, Debug, Default)]
    pub struct SecretService;

    const CONTENT_TYPE: &str = "text/plain";

    pub(super) fn backend(error: Error) -> StoreError {
        match error {
            Error::Locked | Error::Prompt => StoreError::Denied,
            error => StoreError::Backend(Box::new(error)),
        }
    }

    fn connect() -> Result<Service<'static>, StoreError> {
        Service::connect(EncryptionType::Dh).map_err(backend)
    }

    fn find<'a>(
        store: &'a Service<'a>,
        service: &str,
        account: &str,
    ) -> Result<Vec<Item<'a>>, StoreError> {
        let found = store
            .search_items(attributes(service, account))
            .map_err(backend)?;
        Ok(found.unlocked.into_iter().chain(found.locked).collect())
    }

    fn unlocked(item: Item<'_>) -> Result<Item<'_>, Error> {
        if item.is_locked()? {
            item.unlock()?;
        }
        Ok(item)
    }

    impl SecretStore for SecretService {
        fn load(&self, service: &str, account: &str) -> Result<Option<Secret>, StoreError> {
            let store = connect()?;
            let Some(item) = only(find(&store, service, account)?)? else {
                return Ok(None);
            };
            let bytes = unlocked(item)
                .and_then(|item| item.get_secret())
                .map_err(backend)?;
            Secret::from_utf8(Zeroizing::new(bytes))
                .map(Some)
                .ok_or(StoreError::NotUnicode)
        }

        fn save(&self, service: &str, account: &str, secret: &Secret) -> Result<(), StoreError> {
            let store = connect()?;
            let value = secret.expose().as_bytes();
            match only(find(&store, service, account)?)? {
                Some(item) => unlocked(item).and_then(|item| item.set_secret(value, CONTENT_TYPE)),
                None => store.get_default_collection().and_then(|collection| {
                    if collection.is_locked()? {
                        collection.unlock()?;
                    }
                    let label = format!("{account}@{service}");
                    collection
                        .create_item(
                            &label,
                            attributes(service, account),
                            value,
                            true,
                            CONTENT_TYPE,
                        )
                        .map(drop)
                }),
            }
            .map_err(backend)
        }

        fn delete(&self, service: &str, account: &str) -> Result<(), StoreError> {
            let store = connect()?;
            for item in find(&store, service, account)? {
                unlocked(item)
                    .and_then(|item| item.delete())
                    .map_err(backend)?;
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_item_is_found_by_service_and_username() {
        let found = attributes("svc", "acct");
        assert_eq!(
            found,
            HashMap::from([("service", "svc"), ("username", "acct")])
        );
    }

    #[test]
    fn one_match_is_the_item_and_several_are_an_error() {
        assert_eq!(only(Vec::<u8>::new()).unwrap(), None);
        assert_eq!(only(vec![7]).unwrap(), Some(7));
        let err = only(vec![1, 2]).unwrap_err();
        assert!(matches!(err, StoreError::Backend(_)), "{err:?}");
    }

    #[cfg(target_os = "linux")]
    mod secret_service {
        use std::collections::HashMap;

        use secret_service::{EncryptionType, Error, blocking::SecretService as Service};

        use super::super::native::backend;
        use crate::store::tests::loaded;
        use crate::store::tests::os_store::Scratch;
        use crate::{Secret, SecretService, SecretStore, StoreError};

        #[test]
        fn a_locked_store_or_a_dismissed_prompt_is_denied() {
            for error in [Error::Locked, Error::Prompt] {
                let err = backend(error);
                assert!(matches!(err, StoreError::Denied), "{err:?}");
            }
            for error in [Error::Unavailable, Error::NoResult] {
                let err = backend(error);
                assert!(matches!(err, StoreError::Backend(_)), "{err:?}");
            }
        }

        fn search(service: &str) -> HashMap<String, String> {
            let store = Service::connect(EncryptionType::Dh).unwrap();
            let found = store
                .search_items(HashMap::from([("service", service)]))
                .unwrap();
            let mut items: Vec<_> = found.unlocked.into_iter().chain(found.locked).collect();
            assert_eq!(items.len(), 1, "one item for {service}");
            items.pop().unwrap().get_attributes().unwrap()
        }

        // keyring 3's `sync-secret-service` layout: the default collection, a
        // `account@service:default (keyring v<version>)` label, `service`, `username`,
        // `target = default` and `application = rust-keyring` attributes, and the UTF-8 value
        // as `text/plain`.
        fn write_as_keyring_3(service: &str, value: &str) {
            let store = Service::connect(EncryptionType::Plain).unwrap();
            let collection = store.get_default_collection().unwrap();
            let attributes = HashMap::from([
                ("service", service),
                ("username", "acct"),
                ("target", "default"),
                ("application", "rust-keyring"),
            ]);
            let label = format!("acct@{service}:default (keyring v3.6.3)");
            collection
                .create_item(&label, attributes, value.as_bytes(), true, "text/plain")
                .unwrap();
        }

        #[test]
        #[ignore = "touches the desktop's Secret Service, which can prompt"]
        fn several_matches_refuse_a_load_and_all_go_on_delete() {
            let scratch = Scratch::new("several");
            let service = scratch.service();
            write_as_keyring_3(service, "theirs");
            let store = Service::connect(EncryptionType::Plain).unwrap();
            let collection = store.get_default_collection().unwrap();
            let attributes = HashMap::from([("service", service), ("username", "acct")]);
            collection
                .create_item("second", attributes, b"second", false, "text/plain")
                .unwrap();
            let err = SecretService.load(service, "acct").unwrap_err();
            assert!(matches!(err, StoreError::Backend(_)), "{err:?}");
            SecretService.delete(service, "acct").unwrap();
            assert_eq!(loaded(&SecretService, service), None);
        }

        #[test]
        #[ignore = "touches the desktop's Secret Service, which can prompt"]
        fn a_new_item_has_the_service_and_username_attributes() {
            let scratch = Scratch::new("layout");
            let service = scratch.service();
            SecretService
                .save(service, "acct", &Secret::new("value"))
                .unwrap();
            assert_eq!(search(service)["username"], "acct");
        }

        #[test]
        #[ignore = "touches the desktop's Secret Service, which can prompt"]
        fn an_item_keyring_3_wrote_loads_and_is_overwritten_in_place() {
            let scratch = Scratch::new("keyring-3");
            let service = scratch.service();
            write_as_keyring_3(service, "from keyring ✓");
            assert_eq!(
                loaded(&SecretService, service).as_deref(),
                Some("from keyring ✓")
            );
            SecretService
                .save(service, "acct", &Secret::new("ours ✓"))
                .unwrap();
            assert_eq!(loaded(&SecretService, service).as_deref(), Some("ours ✓"));
            assert_eq!(search(service)["target"], "default");
            SecretService.delete(service, "acct").unwrap();
            assert_eq!(loaded(&SecretService, service), None);
        }
    }
}
