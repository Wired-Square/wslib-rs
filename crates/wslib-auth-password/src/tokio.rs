//! The crate's blocking calls, run on tokio's blocking pool.

use std::panic::resume_unwind;

use crate::{PasswordError, Policy};

async fn off_thread<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
    if_cancelled: T,
) -> T {
    match ::tokio::task::spawn_blocking(work).await {
        Ok(done) => done,
        Err(e) => match e.try_into_panic() {
            Ok(panic) => resume_unwind(panic),
            Err(_) => if_cancelled,
        },
    }
}

/// [`Policy::hash`] off the runtime's threads.
pub async fn hash(policy: Policy, password: &str) -> Result<String, PasswordError> {
    policy.check(password)?;
    let password = password.to_owned();
    off_thread(
        move || policy.hash(&password),
        Err(PasswordError::Hash("the runtime shut down".into())),
    )
    .await
}

/// [`verify`](crate::verify) off the runtime's threads.
pub async fn verify(stored: &str, password: &str) -> bool {
    let (stored, password) = (stored.to_owned(), password.to_owned());
    off_thread(move || crate::verify(&stored, &password), false).await
}

/// [`verify_absent`](crate::verify_absent) off the runtime's threads.
pub async fn verify_absent(password: &str) -> bool {
    let password = password.to_owned();
    off_thread(move || crate::verify_absent(&password), false).await
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
        assert_eq!(
            hash(Policy::default(), "short").await,
            Err(PasswordError::TooShort { min_chars: 12 })
        );
    }
}
