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

/// [`verify`](crate::verify) off the runtime's threads; false, as for a
/// wrong password, if the work panicked or the runtime shut down first.
pub async fn verify(stored: &str, password: &str) -> bool {
    let (stored, password) = (stored.to_owned(), password.to_owned());
    off_thread(move || crate::verify(&stored, &password))
        .await
        .unwrap_or(false)
}

/// [`verify_absent`](crate::verify_absent) off the runtime's threads.
pub async fn verify_absent(password: &str) -> bool {
    let password = password.to_owned();
    off_thread(move || crate::verify_absent(&password))
        .await
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_wrappers_answer_as_the_blocking_calls_do() {
        let stored = hash(Policy::default(), "correct horse battery staple")
            .await
            .unwrap();
        assert!(verify(&stored, "correct horse battery staple").await);
        assert!(!verify(&stored, "wrong").await);
        assert!(!verify_absent("correct horse battery staple").await);
        assert!(matches!(
            hash(Policy::default(), "short").await,
            Err(PasswordError::TooShort { min_chars: 12 })
        ));
        assert!(verify(&rehash("short").await.unwrap(), "short").await);
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
}
