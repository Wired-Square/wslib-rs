use std::time::Duration;

use chrono::TimeDelta;

use super::*;
use crate::{Proof, SessionError, SessionToken, Sessions};

// Expands in a backend's module, which names `Db`, `Backend`, `SESSIONS_DDL` and `BOUND_DDL`.
macro_rules! store_tests {
    () => {
        type Store<U> = SqlSessionStore<Db, U>;

        async fn store<U>(db: &Backend, table: &'static str) -> Store<U> {
            let pool = db.pool().await;
            sqlx::raw_sql(&SESSIONS_DDL.replace("app_sessions", table))
                .execute(&pool)
                .await
                .unwrap();
            Store::new(pool, TableName::new(table))
        }

        async fn sessions(db: &Backend) -> Sessions<Store<String>> {
            Sessions::new(store(db, "app_sessions").await)
        }

        async fn bound_sessions(db: &Backend) -> Sessions<Store<String>> {
            let store = store(db, "app_sessions").await;
            sqlx::query(BOUND_DDL).execute(store.pool()).await.unwrap();
            Sessions::new(store.with_bound_secrets(TableName::new("app_session_secrets")))
        }

        async fn count(sessions: &Sessions<Store<String>>, table: &str) -> i64 {
            sqlx::query_scalar(&format!("SELECT count(*) FROM {table}"))
                .fetch_one(sessions.store().pool())
                .await
                .unwrap()
        }

        async fn rows(sessions: &Sessions<Store<String>>) -> i64 {
            count(sessions, "app_sessions").await
        }

        async fn secret_rows(sessions: &Sessions<Store<String>>) -> i64 {
            count(sessions, "app_session_secrets").await
        }

        async fn bind(sessions: &Sessions<Store<String>>, token: &SessionToken) -> SessionToken {
            sessions
                .bind(token)
                .await
                .unwrap()
                .expect("a session to bind to")
        }

        async fn admitted(
            sessions: &Sessions<Store<String>>,
            token: &SessionToken,
            secret: Option<&SessionToken>,
        ) -> bool {
            sessions
                .lookup_bound(token, secret)
                .await
                .unwrap()
                .is_some()
        }

        async fn issue(sessions: &Sessions<Store<String>>, user_id: &str) -> SessionToken {
            sessions
                .issue(user_id.to_owned(), Proof::begin())
                .await
                .unwrap()
                .0
        }

        store_tests! { @each
            fn the_calls_can_be_awaited_in_a_spawned_task(db) {
                let sessions = sessions(&db).await;
                tokio::spawn(async move {
                    let token = issue(&sessions, "u1").await;
                    sessions.lookup(&token).await.unwrap()
                })
                .await
                .unwrap()
                .unwrap();
            }

            fn an_issued_session_is_found_by_its_token_and_only_its_hash_is_kept(db) {
                let sessions = sessions(&db).await;
                let proof = Proof::begin();
                a_moment_passes();
                let (token, issued) = sessions.issue("u1".to_owned(), proof).await.unwrap();
                assert_eq!(issued.expires_at - issued.created_at, TimeDelta::hours(12));
                assert_eq!(issued.proved_at, proof.at());
                assert!(issued.created_at > issued.proved_at);
                assert_eq!(sessions.lookup(&token).await.unwrap(), Some(issued));

                let stored: String = sqlx::query_scalar("SELECT token_hash FROM app_sessions")
                    .fetch_one(sessions.store().pool())
                    .await
                    .unwrap();
                assert_eq!(stored, token.hash().as_str());
                assert_ne!(stored, token.expose());

                let stranger = SessionToken::generate().unwrap();
                assert_eq!(sessions.lookup(&stranger).await.unwrap(), None);
            }

            fn a_proof_begun_before_the_cutoff_is_refused_though_issued_after_it(db) {
                let sessions = sessions(&db).await;
                let proof = Proof::begin();
                a_moment_passes();
                let sessions_valid_from = crate::now();
                a_moment_passes();
                let (_, session) = sessions.issue("u1".to_owned(), proof).await.unwrap();
                assert!(session.created_at > sessions_valid_from);
                assert!(!session.proved_since(sessions_valid_from));
                assert!(session.proved_since(proof.at()));
            }

            fn an_expired_session_is_not_found_and_goes_at_the_next_issue(db) {
                let sessions = sessions(&db).await.with_lifetime(TimeDelta::zero());
                let expired = issue(&sessions, "u1").await;
                assert_eq!(sessions.lookup(&expired).await.unwrap(), None);
                assert_eq!(rows(&sessions).await, 1);

                let sessions = sessions.with_lifetime(TimeDelta::hours(1));
                let live = issue(&sessions, "u1").await;
                assert_eq!(rows(&sessions).await, 1, "the expired row went");
                assert!(sessions.lookup(&live).await.unwrap().is_some());

                sessions
                    .store()
                    .remove_expired(crate::now() + TimeDelta::hours(2))
                    .await
                    .unwrap();
                assert_eq!(rows(&sessions).await, 0);
            }

            fn ending_one_session_leaves_the_others_and_ending_all_leaves_other_users(db) {
                let sessions = sessions(&db).await;
                let a1 = issue(&sessions, "a").await;
                let a2 = issue(&sessions, "a").await;
                let b = issue(&sessions, "b").await;

                assert!(sessions.end(&a1).await.unwrap());
                assert!(!sessions.end(&a1).await.unwrap(), "already ended");
                assert_eq!(sessions.lookup(&a1).await.unwrap(), None);
                assert!(sessions.lookup(&a2).await.unwrap().is_some());

                assert!(sessions.end_all(&"a".to_owned()).await.unwrap());
                assert!(!sessions.end_all(&"a".to_owned()).await.unwrap());
                assert_eq!(sessions.lookup(&a2).await.unwrap(), None);
                assert!(sessions.lookup(&b).await.unwrap().is_some());
            }

            fn removing_a_users_sessions_in_a_transaction_rolls_back_with_it(db) {
                let sessions = sessions(&db).await;
                let a = issue(&sessions, "a").await;
                let b = issue(&sessions, "b").await;
                let store = sessions.store();
                let user_a = "a".to_owned();

                let mut tx = store.pool().begin().await.unwrap();
                assert!(store.remove_user_in(&mut tx, &user_a).await.unwrap());
                tx.rollback().await.unwrap();
                assert!(sessions.lookup(&a).await.unwrap().is_some());

                let mut tx = store.pool().begin().await.unwrap();
                assert!(store.remove_user_in(&mut tx, &user_a).await.unwrap());
                assert!(!store.remove_user_in(&mut tx, &user_a).await.unwrap());
                tx.commit().await.unwrap();
                assert_eq!(sessions.lookup(&a).await.unwrap(), None);
                assert!(sessions.lookup(&b).await.unwrap().is_some());
            }

            fn reauthenticating_stamps_the_proofs_instant_and_nothing_else(db) {
                let sessions = sessions(&db).await;
                let (token, issued) = sessions
                    .issue("u1".to_owned(), Proof::begin())
                    .await
                    .unwrap();
                let earlier = issued.created_at - TimeDelta::minutes(10);
                sessions
                    .store()
                    .set_reauthenticated_at(&token.hash(), earlier)
                    .await
                    .unwrap();
                let stale = sessions.lookup(&token).await.unwrap().unwrap();
                assert!(
                    !stale.reauthenticated_within(crate::REAUTHENTICATION_WINDOW, crate::now())
                );

                let proof = Proof::begin();
                a_moment_passes();
                assert!(sessions.reauthenticated(&token, proof).await.unwrap());
                let fresh = sessions.lookup(&token).await.unwrap().unwrap();
                assert_eq!(fresh.reauthenticated_at, proof.at());
                assert_eq!(
                    Session {
                        reauthenticated_at: issued.reauthenticated_at,
                        ..fresh
                    },
                    issued
                );

                let stranger = SessionToken::generate().unwrap();
                assert!(!sessions.reauthenticated(&stranger, proof).await.unwrap());
            }

            fn a_user_id_reads_back_through_from_str_and_a_bad_one_names_its_column(db) {
                let sessions = Sessions::new(store::<u64>(&db, "s").await);
                let (token, _) = sessions.issue(42, Proof::begin()).await.unwrap();
                assert_eq!(sessions.lookup(&token).await.unwrap().unwrap().user_id, 42);

                sqlx::query("UPDATE s SET user_id = 'x'")
                    .execute(sessions.store().pool())
                    .await
                    .unwrap();
                let Err(SessionError::Store(sqlx::Error::ColumnDecode { index, .. })) =
                    sessions.lookup(&token).await
                else {
                    panic!("a decode error");
                };
                assert_eq!(index, "s.user_id");
            }

            fn a_bound_session_is_found_only_with_one_of_its_secrets_and_only_its_hash_is_kept(db) {
                let sessions = bound_sessions(&db).await;
                let token = issue(&sessions, "u1").await;
                assert!(admitted(&sessions, &token, None).await, "nothing bound yet");

                let secret = bind(&sessions, &token).await;
                let stranger = SessionToken::generate().unwrap();
                assert!(!admitted(&sessions, &token, None).await);
                assert!(!admitted(&sessions, &token, Some(&stranger)).await);
                assert!(
                    !admitted(&sessions, &token, Some(&token)).await,
                    "the token is no secret"
                );
                assert!(admitted(&sessions, &token, Some(&secret)).await);
                assert!(!admitted(&sessions, &stranger, Some(&secret)).await);

                let stored: String =
                    sqlx::query_scalar("SELECT secret_hash FROM app_session_secrets")
                        .fetch_one(sessions.store().pool())
                        .await
                        .unwrap();
                assert_eq!(stored, secret.hash().as_str());
            }

            fn a_session_keeps_its_newest_sixteen_secrets_and_leaves_anothers_alone(db) {
                let sessions = bound_sessions(&db).await;
                let token = issue(&sessions, "u1").await;
                let other = issue(&sessions, "u1").await;
                let others = bind(&sessions, &other).await;

                let mut secrets = Vec::new();
                for _ in 0..=crate::BOUND_SECRETS_KEPT {
                    a_moment_passes();
                    secrets.push(bind(&sessions, &token).await);
                }
                assert!(
                    !admitted(&sessions, &token, Some(&secrets[0])).await,
                    "the oldest went"
                );
                for secret in &secrets[1..] {
                    assert!(admitted(&sessions, &token, Some(secret)).await);
                }
                assert!(admitted(&sessions, &other, Some(&others)).await);
                assert_eq!(secret_rows(&sessions).await, 17);
            }

            fn nothing_binds_to_an_unknown_or_expired_session(db) {
                let sessions = bound_sessions(&db).await.with_lifetime(TimeDelta::zero());
                let expired = issue(&sessions, "u1").await;
                let stranger = SessionToken::generate().unwrap();
                for token in [expired, stranger] {
                    assert_eq!(sessions.bind(&token).await.unwrap(), None);
                }
                assert_eq!(secret_rows(&sessions).await, 0);
            }

            fn the_secrets_end_with_their_session_however_it_ends(db) {
                let sessions = bound_sessions(&db).await;
                let ended = issue(&sessions, "a").await;
                bind(&sessions, &ended).await;
                let a = issue(&sessions, "a").await;
                bind(&sessions, &a).await;
                let b = issue(&sessions, "b").await;
                bind(&sessions, &b).await;

                sessions.end(&ended).await.unwrap();
                assert_eq!(secret_rows(&sessions).await, 2);
                sessions.end_all(&"a".to_owned()).await.unwrap();
                assert_eq!(secret_rows(&sessions).await, 1);
                sessions
                    .store()
                    .remove_expired(crate::now() + TimeDelta::hours(13))
                    .await
                    .unwrap();
                assert_eq!(secret_rows(&sessions).await, 0);
            }

            fn a_store_without_a_secrets_table_fails_to_bind_or_look_up_bound(db) {
                let sessions = sessions(&db).await;
                let token = issue(&sessions, "u1").await;
                let unconfigured =
                    |e| matches!(e, SessionError::Store(sqlx::Error::Configuration(_)));
                assert!(unconfigured(sessions.bind(&token).await.unwrap_err()));
                assert!(unconfigured(
                    sessions.lookup_bound(&token, None).await.unwrap_err()
                ));
            }
        }
    };
    (@each $(fn $name:ident($db:ident) $body:block)*) => {
        $(
            #[tokio::test]
            async fn $name() {
                let Some($db) = Backend::connect().await else {
                    return;
                };
                $body
                $db.close().await;
            }
        )*
    };
}

fn a_moment_passes() {
    std::thread::sleep(Duration::from_millis(2));
}

#[cfg(feature = "sqlite")]
mod sqlite {
    use sqlx::sqlite::SqlitePoolOptions;

    use super::*;

    type Db = sqlx::Sqlite;

    const SESSIONS_DDL: &str = "CREATE TABLE app_sessions (
        token_hash          TEXT PRIMARY KEY NOT NULL,
        user_id             TEXT NOT NULL,
        created_at          TEXT NOT NULL,
        expires_at          TEXT NOT NULL,
        proved_at           TEXT NOT NULL,
        reauthenticated_at  TEXT NOT NULL
    ) STRICT;

    CREATE INDEX app_sessions_by_user ON app_sessions (user_id)";

    const BOUND_DDL: &str = "CREATE TABLE app_session_secrets (
        session_hash  TEXT NOT NULL REFERENCES app_sessions (token_hash) ON DELETE CASCADE,
        secret_hash   TEXT NOT NULL,
        issued_at     TEXT NOT NULL,
        PRIMARY KEY (session_hash, secret_hash)
    ) STRICT";

    struct Backend;

    impl Backend {
        async fn connect() -> Option<Self> {
            Some(Self)
        }

        async fn pool(&self) -> Pool<Db> {
            SqlitePoolOptions::new()
                .max_connections(1)
                .idle_timeout(None)
                .max_lifetime(None)
                .connect("sqlite::memory:")
                .await
                .unwrap()
        }

        async fn close(self) {}
    }

    store_tests!();
}

#[cfg(feature = "postgres")]
mod postgres {
    use std::time::Instant;

    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

    use super::*;

    type Db = sqlx::Postgres;

    const URL: &str = "WSLIB_TEST_POSTGRES_URL";

    const SESSIONS_DDL: &str = r#"CREATE TABLE app_sessions (
        token_hash          TEXT PRIMARY KEY,
        user_id             TEXT NOT NULL,
        created_at          TEXT COLLATE "C" NOT NULL,
        expires_at          TEXT COLLATE "C" NOT NULL,
        proved_at           TEXT COLLATE "C" NOT NULL,
        reauthenticated_at  TEXT COLLATE "C" NOT NULL
    );

    CREATE INDEX app_sessions_by_user ON app_sessions (user_id)"#;

    const BOUND_DDL: &str = r#"CREATE TABLE app_session_secrets (
        session_hash  TEXT NOT NULL REFERENCES app_sessions (token_hash) ON DELETE CASCADE,
        secret_hash   TEXT NOT NULL,
        issued_at     TEXT COLLATE "C" NOT NULL,
        PRIMARY KEY (session_hash, secret_hash)
    )"#;

    struct Backend {
        admin: Pool<Db>,
        options: PgConnectOptions,
        schema: String,
    }

    impl Backend {
        async fn connect() -> Option<Self> {
            let Some(url) = std::env::var(URL).ok().filter(|url| !url.is_empty()) else {
                println!("skipped: {URL} names no Postgres server");
                return None;
            };
            let options: PgConnectOptions = url.parse().unwrap();
            let admin = PgPoolOptions::new()
                .max_connections(1)
                .connect_with(options.clone())
                .await
                .unwrap();
            let schema = format!("wslib_auth_test_{:016x}", getrandom::u64().unwrap());
            sqlx::query(&format!("CREATE SCHEMA {schema}"))
                .execute(&admin)
                .await
                .unwrap();
            let options = options
                .application_name(&schema)
                .options([("search_path", schema.as_str())]);
            Some(Self {
                admin,
                options,
                schema,
            })
        }

        async fn pool(&self) -> Pool<Db> {
            PgPoolOptions::new()
                .max_connections(4)
                .connect_with(self.options.clone())
                .await
                .unwrap()
        }

        async fn close(self) {
            sqlx::query(&format!("DROP SCHEMA {} CASCADE", self.schema))
                .execute(&self.admin)
                .await
                .unwrap();
            self.admin.close().await;
        }

        async fn wait_until_blocked_on_a_lock(&self) {
            let deadline = Instant::now() + Duration::from_secs(10);
            while Instant::now() < deadline {
                let blocked: bool = sqlx::query_scalar(
                    "SELECT EXISTS (SELECT 1 FROM pg_stat_activity \
                     WHERE application_name = $1 AND wait_event_type = 'Lock')",
                )
                .bind(&self.schema)
                .fetch_one(&self.admin)
                .await
                .unwrap();
                if blocked {
                    return;
                }
                tokio::task::yield_now().await;
            }
            panic!("nothing blocked on a lock within 10 s");
        }
    }

    store_tests!();

    store_tests! { @each
        fn a_bind_racing_its_sessions_removal_finds_no_session(db) {
            let sessions = bound_sessions(&db).await;
            let token = issue(&sessions, "u1").await;

            let mut removal = sessions.store().pool().begin().await.unwrap();
            sqlx::query("DELETE FROM app_sessions")
                .execute(&mut *removal)
                .await
                .unwrap();
            let bind = tokio::spawn({
                let sessions = sessions.clone();
                async move { sessions.bind(&token).await }
            });
            db.wait_until_blocked_on_a_lock().await;
            removal.commit().await.unwrap();

            assert_eq!(bind.await.unwrap().unwrap(), None);
            assert_eq!(secret_rows(&sessions).await, 0);
        }
    }
}
