//! The crate's blocking calls, run on tokio's blocking pool.

use std::panic::resume_unwind;

use crate::Error;

/// `work` on a clone of `client` (an [`Op`](crate::Op) or a [`Vault`](crate::Vault)),
/// off the runtime's threads.
///
/// ```no_run
/// # async fn run(vault: wslib_1password::Vault) -> Result<(), wslib_1password::Error> {
/// use wslib_1password::{ItemRef, tokio::blocking};
///
/// let item = blocking(&vault, |v| v.item(&ItemRef::title("Deploy key"))).await?;
/// # Ok(())
/// # }
/// ```
pub async fn blocking<C, T>(
    client: &C,
    work: impl FnOnce(&C) -> Result<T, Error> + Send + 'static,
) -> Result<T, Error>
where
    C: Clone + Send + 'static,
    T: Send + 'static,
{
    let client = client.clone();
    match ::tokio::task::spawn_blocking(move || work(&client)).await {
        Ok(done) => done,
        Err(e) => match e.try_into_panic() {
            Ok(panic) => resume_unwind(panic),
            Err(_) => Err(Error::Cancelled),
        },
    }
}

#[cfg(all(test, feature = "testing"))]
mod tests {
    use super::*;
    use crate::{Op, Output, testing::FakeRunner};

    #[tokio::test]
    async fn a_call_answers_as_the_blocking_one_does() {
        let fake = FakeRunner::new();
        fake.respond(Output::ok(r#"[{"id":"v1","name":"Ops"}]"#));
        let op = Op::new(fake.clone(), "ops");
        let vaults = blocking(&op, |op| op.vaults()).await.unwrap();
        assert_eq!(vaults[0].name, "Ops");
        assert_eq!(fake.calls().len(), 1);
    }
}
