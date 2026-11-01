use std::io;

use zeroize::{Zeroize, Zeroizing};

use super::StoreError;
use crate::Secret;

#[cfg(windows)]
pub use native::CredentialManager;

// `ERROR_ACCESS_DENIED` and `ERROR_NOT_FOUND`, from `winerror.h`.
const ACCESS_DENIED: i32 = 5;
const NOT_FOUND: i32 = 1168;

fn target_name(service: &str, account: &str) -> String {
    format!("{account}.{service}")
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain([0]).collect()
}

// The blob is UTF-16LE with no terminator, as Windows' own tools write it.
fn encode(secret: &Secret) -> Zeroizing<Vec<u8>> {
    let text = secret.expose();
    let mut blob = Zeroizing::new(Vec::with_capacity(text.len() * 2));
    blob.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
    blob
}

fn decode(blob: &[u8]) -> Option<Secret> {
    let (pairs, []) = blob.as_chunks::<2>() else {
        return None;
    };
    // Three UTF-8 bytes per unit at most, so the buffer never moves and leaves no copy behind.
    let mut text = String::with_capacity(pairs.len() * 3);
    for unit in char::decode_utf16(pairs.iter().copied().map(u16::from_le_bytes)) {
        match unit {
            Ok(char) => text.push(char),
            Err(_) => {
                text.zeroize();
                return None;
            }
        }
    }
    Some(Secret(text))
}

fn is_missing(error: &io::Error) -> bool {
    error.raw_os_error() == Some(NOT_FOUND)
}

fn backend(error: io::Error) -> StoreError {
    match error.raw_os_error() {
        Some(ACCESS_DENIED) => StoreError::Denied,
        _ => StoreError::Backend(Box::new(error)),
    }
}

#[cfg(windows)]
mod native {
    use std::{io, ptr, slice};

    use windows_sys::Win32::Security::Credentials::{
        CRED_PERSIST_ENTERPRISE, CRED_TYPE_GENERIC, CREDENTIALW, CredDeleteW, CredFree, CredReadW,
        CredWriteW,
    };
    use zeroize::Zeroize;

    use super::{backend, decode, encode, is_missing, target_name, wide};
    use crate::{Secret, SecretStore, StoreError};

    /// The user's Windows Credential Manager, one generic credential per service and account.
    #[derive(Clone, Copy, Debug, Default)]
    pub struct CredentialManager;

    fn succeeded(result: i32) -> io::Result<()> {
        if result == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Runs `f` over the blob of the generic credential named `target`, then zeroes and frees it.
    pub(super) fn with_blob<T>(target: &str, f: impl FnOnce(&[u8]) -> T) -> io::Result<T> {
        let target = wide(target);
        let mut credential = ptr::null_mut::<CREDENTIALW>();
        // SAFETY: `target` is NUL-terminated and outlives the call.
        succeeded(unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut credential) })?;
        // SAFETY: a successful read leaves one credential that is ours until `CredFree`, whose
        // blob is `CredentialBlobSize` bytes, or null when empty.
        unsafe {
            let read = &*credential;
            let blob = if read.CredentialBlob.is_null() {
                &mut [][..]
            } else {
                slice::from_raw_parts_mut(read.CredentialBlob, read.CredentialBlobSize as usize)
            };
            let result = f(blob);
            blob.zeroize();
            CredFree(credential.cast());
            Ok(result)
        }
    }

    impl SecretStore for CredentialManager {
        fn load(&self, service: &str, account: &str) -> Result<Option<Secret>, StoreError> {
            match with_blob(&target_name(service, account), decode) {
                Ok(secret) => secret.map(Some).ok_or(StoreError::NotUnicode),
                Err(error) if is_missing(&error) => Ok(None),
                Err(error) => Err(backend(error)),
            }
        }

        fn save(&self, service: &str, account: &str, secret: &Secret) -> Result<(), StoreError> {
            let mut target = wide(&target_name(service, account));
            let mut user = wide(account);
            let mut blob = encode(secret);
            let credential = CREDENTIALW {
                Type: CRED_TYPE_GENERIC,
                TargetName: target.as_mut_ptr(),
                UserName: user.as_mut_ptr(),
                CredentialBlobSize: blob.len() as u32,
                CredentialBlob: blob.as_mut_ptr(),
                Persist: CRED_PERSIST_ENTERPRISE,
                ..CREDENTIALW::default()
            };
            // SAFETY: every pointer in `credential` is to a buffer that outlives the call.
            succeeded(unsafe { CredWriteW(&credential, 0) }).map_err(backend)
        }

        fn delete(&self, service: &str, account: &str) -> Result<(), StoreError> {
            let target = wide(&target_name(service, account));
            // SAFETY: `target` is NUL-terminated and outlives the call.
            match succeeded(unsafe { CredDeleteW(target.as_ptr(), CRED_TYPE_GENERIC, 0) }) {
                Err(error) if !is_missing(&error) => Err(backend(error)),
                _ => Ok(()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16le(text: &str) -> Vec<u8> {
        text.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn the_target_name_is_the_account_dot_the_service() {
        assert_eq!(target_name("svc", "acct"), "acct.svc");
        assert_eq!(wide("ab"), [u16::from(b'a'), u16::from(b'b'), 0]);
    }

    #[test]
    fn a_secret_is_kept_as_utf16le_without_a_terminator() {
        let text = "pässwörd \u{1F511}";
        assert_eq!(*encode(&Secret::new(text)), utf16le(text));
        assert_eq!(decode(&utf16le(text)).unwrap().expose(), text);
        assert_eq!(decode(&[]).unwrap().expose(), "");
    }

    #[test]
    fn a_blob_that_is_not_utf16_does_not_decode() {
        assert!(decode(b"abc").is_none());
        assert!(decode(&0xD800u16.to_le_bytes()).is_none());
    }

    #[test]
    fn access_denied_is_denied_and_not_found_is_missing() {
        let denied = backend(io::Error::from_raw_os_error(ACCESS_DENIED));
        assert!(matches!(denied, StoreError::Denied), "{denied:?}");
        assert!(is_missing(&io::Error::from_raw_os_error(NOT_FOUND)));
        // `ERROR_NO_SUCH_LOGON_SESSION`: a logon with no credential set has no store at all.
        let absent = backend(io::Error::from_raw_os_error(1312));
        assert!(matches!(absent, StoreError::Backend(_)), "{absent:?}");
    }

    #[cfg(windows)]
    mod credential_manager {
        use windows_sys::Win32::Security::Credentials::{
            CRED_PERSIST_ENTERPRISE, CRED_TYPE_GENERIC, CREDENTIALW, CredWriteW,
        };

        use super::super::native::with_blob;
        use super::*;
        use crate::SecretStore;
        use crate::store::tests::loaded;
        use crate::store::tests::os_store::Scratch;

        // keyring 3's `windows-native` layout: a generic credential named `account.service`,
        // the account as its user name, a `keyring v<version>` comment, enterprise persistence
        // and a UTF-16LE blob.
        fn write_as_keyring_3(service: &str, value: &str) {
            let mut target = wide(&target_name(service, "acct"));
            let mut user = wide("acct");
            let mut comment = wide("keyring v3.6.3");
            let mut alias = wide("");
            let mut blob = utf16le(value);
            let credential = CREDENTIALW {
                Type: CRED_TYPE_GENERIC,
                TargetName: target.as_mut_ptr(),
                Comment: comment.as_mut_ptr(),
                TargetAlias: alias.as_mut_ptr(),
                UserName: user.as_mut_ptr(),
                CredentialBlobSize: blob.len() as u32,
                CredentialBlob: blob.as_mut_ptr(),
                Persist: CRED_PERSIST_ENTERPRISE,
                ..CREDENTIALW::default()
            };
            assert_ne!(unsafe { CredWriteW(&credential, 0) }, 0);
        }

        #[test]
        #[ignore = "touches the user's Credential Manager"]
        fn an_item_keyring_3_wrote_loads_and_is_overwritten_in_its_layout() {
            let scratch = Scratch::new("keyring-3");
            let service = scratch.service();
            write_as_keyring_3(service, "from keyring ✓");
            assert_eq!(
                loaded(&CredentialManager, service).as_deref(),
                Some("from keyring ✓")
            );
            CredentialManager
                .save(service, "acct", &Secret::new("ours ✓"))
                .unwrap();
            let blob = with_blob(&target_name(service, "acct"), <[u8]>::to_vec).unwrap();
            assert_eq!(blob, utf16le("ours ✓"));
            CredentialManager.delete(service, "acct").unwrap();
            assert_eq!(loaded(&CredentialManager, service), None);
        }
    }
}
