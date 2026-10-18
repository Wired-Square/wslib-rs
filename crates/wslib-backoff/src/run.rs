use std::future::Future;
use std::time::Duration;

use crate::Backoff;

/// How one attempt of [`reconnect`] ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attempt<T, E> {
    /// Finished for good: [`reconnect`] returns the value.
    Done(T),
    /// Failed before it got anywhere: the next wait grows.
    Failed(E),
    /// Worked for a while, then ended: the next wait restarts from the initial
    /// delay.
    Dropped(E),
}

/// Runs `attempt` until it is [`Attempt::Done`], handing `on_retry` each error
/// with the wait that follows it.
///
/// Dropping the future stops the loop, so select it against a shutdown signal.
pub async fn reconnect<T, E, F, Fut>(
    backoff: &mut Backoff,
    mut attempt: F,
    mut on_retry: impl FnMut(E, Duration),
) -> T
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Attempt<T, E>>,
{
    loop {
        let error = match attempt().await {
            Attempt::Done(value) => {
                backoff.reset();
                return value;
            }
            Attempt::Failed(error) => error,
            Attempt::Dropped(error) => {
                backoff.reset();
                error
            }
        };
        let delay = backoff.next();
        on_retry(error, delay);
        tokio::time::sleep(delay).await;
    }
}

/// Runs `attempt` until it succeeds, handing `on_retry` each error with the
/// wait that follows it, and resets `backoff` on success.
pub async fn retry<T, E, F, Fut>(
    backoff: &mut Backoff,
    mut attempt: F,
    on_retry: impl FnMut(E, Duration),
) -> T
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
{
    let attempt = || {
        let result = attempt();
        async move {
            match result.await {
                Ok(value) => Attempt::Done(value),
                Err(error) => Attempt::Failed(error),
            }
        }
    };
    reconnect(backoff, attempt, on_retry).await
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use tokio::time::Instant;

    use super::*;

    fn secs(s: u64) -> Duration {
        Duration::from_secs(s)
    }

    #[tokio::test(start_paused = true)]
    async fn reconnect_grows_on_failure_and_restarts_after_a_drop() {
        let start = Instant::now();
        let script = RefCell::new(
            vec![
                Attempt::Failed("refused"),
                Attempt::Failed("refused"),
                Attempt::Failed("refused"),
                Attempt::Dropped("reset by peer"),
                Attempt::Failed("refused"),
                Attempt::Done("stopped"),
            ]
            .into_iter(),
        );
        let started = RefCell::new(Vec::new());
        let mut retries = Vec::new();
        let mut backoff = Backoff::default();

        let value = reconnect(
            &mut backoff,
            || {
                started.borrow_mut().push(start.elapsed());
                let outcome = script.borrow_mut().next().unwrap();
                async move { outcome }
            },
            |error, delay| retries.push((error, delay)),
        )
        .await;

        assert_eq!(value, "stopped");
        assert_eq!(
            started.into_inner(),
            [0, 1, 3, 7, 8, 10].map(secs),
            "waits of 1, 2, 4, then 1 after the drop and 2 after it"
        );
        assert_eq!(
            retries,
            [
                ("refused", secs(1)),
                ("refused", secs(2)),
                ("refused", secs(4)),
                ("reset by peer", secs(1)),
                ("refused", secs(2)),
            ]
        );
        assert_eq!(backoff.next(), secs(1), "finishing resets the backoff");
    }

    #[tokio::test(start_paused = true)]
    async fn retry_waits_out_each_failure_then_returns_the_success() {
        let start = Instant::now();
        let mut failures_left = 3;
        let mut backoff = Backoff::new(Duration::from_millis(250), secs(1));
        let mut waits = Vec::new();

        let value = retry(
            &mut backoff,
            || {
                let result = if failures_left == 0 {
                    Ok(42)
                } else {
                    failures_left -= 1;
                    Err("busy")
                };
                async move { result }
            },
            |_, delay| waits.push(delay),
        )
        .await;

        assert_eq!(value, 42);
        assert_eq!(waits, [250, 500, 1000].map(Duration::from_millis));
        assert_eq!(start.elapsed(), Duration::from_millis(1750));
        assert_eq!(backoff.next(), Duration::from_millis(250));
    }

    #[tokio::test(start_paused = true)]
    async fn dropping_the_loop_stops_it_mid_wait() {
        let attempts = RefCell::new(0);
        let mut backoff = Backoff::default();
        let looping = retry(
            &mut backoff,
            || {
                *attempts.borrow_mut() += 1;
                async { Err::<(), _>("down") }
            },
            |_, _| {},
        );
        assert!(tokio::time::timeout(secs(10), looping).await.is_err());
        assert_eq!(attempts.into_inner(), 4, "at 0, 1, 3 and 7 s");
    }
}
