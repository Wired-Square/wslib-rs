//! The crate's blocking calls, run on tokio's blocking pool.

use crate::{PasswordError, Policy};

async fn off_thread<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, PasswordError> {
    ::tokio::task::spawn_blocking(work).await.map_err(|e| {
        if e.is_panic() {
            PasswordError::Panicked
        } else {
            PasswordError::Cancelled
        }
    })
}

/// [`Policy::hash`] off the runtime's threads.
pub async fn hash(policy: Policy, password: &str) -> Result<String, PasswordError> {
    policy.check(password)?;
    let password = password.to_owned();
    off_thread(move || policy.hash(&password)).await?
}

/// [`rehash`](crate::rehash) off the runtime's threads, for a password that has just verified.
pub async fn rehash(password: &str) -> Result<String, PasswordError> {
    crate::check_max(password)?;
    let password = password.to_owned();
    off_thread(move || crate::rehash(&password)).await?
}

/// [`verify`](crate::verify) off the runtime's threads; an error, not an
/// answer, if the work panicked or the runtime shut down first. Sign in only
/// on `Ok(true)`.
pub async fn verify(stored: &str, password: &str) -> Result<bool, PasswordError> {
    let (stored, password) = (stored.to_owned(), password.to_owned());
    off_thread(move || crate::verify(&stored, &password)).await
}

/// [`verify_absent`](crate::verify_absent) off the runtime's threads:
/// `Ok(false)`, or an error as [`verify`] has.
pub async fn verify_absent(password: &str) -> Result<bool, PasswordError> {
    let password = password.to_owned();
    off_thread(move || crate::verify_absent(&password)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_wrappers_answer_as_the_blocking_calls_do() {
        let stored = hash(Policy::default(), "correct horse battery staple")
            .await
            .unwrap();
        assert!(matches!(
            verify(&stored, "correct horse battery staple").await,
            Ok(true)
        ));
        assert!(matches!(verify(&stored, "wrong").await, Ok(false)));
        assert!(matches!(
            verify_absent("correct horse battery staple").await,
            Ok(false)
        ));
        assert!(matches!(
            hash(Policy::default(), "short").await,
            Err(PasswordError::TooShort { min_chars: 12 })
        ));
        assert!(matches!(
            verify(&rehash("short").await.unwrap(), "short").await,
            Ok(true)
        ));
    }

    #[tokio::test]
    async fn a_panic_off_the_runtimes_threads_is_an_error_not_a_panic_here() {
        let answer = off_thread(|| -> () { panic!("argon2 went wrong") }).await;
        assert!(matches!(answer, Err(PasswordError::Panicked)), "{answer:?}");
    }

    #[test]
    fn work_the_runtime_dropped_before_it_ran_is_cancelled() {
        let runtime = ::tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let handle = runtime.handle().clone();
        drop(runtime);
        let answer = handle.block_on(off_thread(|| ()));
        assert!(
            matches!(answer, Err(PasswordError::Cancelled)),
            "{answer:?}"
        );
    }

    #[test]
    fn a_verify_the_runtime_dropped_is_an_error_and_never_a_sign_in() {
        let stored = Policy::default()
            .hash("correct horse battery staple")
            .unwrap();
        let runtime = ::tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let handle = runtime.handle().clone();
        drop(runtime);
        let verified = handle.block_on(verify(&stored, "correct horse battery staple"));
        assert!(
            matches!(verified, Err(PasswordError::Cancelled)),
            "{verified:?}"
        );
        let absent = handle.block_on(verify_absent("correct horse battery staple"));
        assert!(
            matches!(absent, Err(PasswordError::Cancelled)),
            "{absent:?}"
        );
    }
}
