//! Local accounts.
//!
//! **The store takes a hash, never a password**: every write that touches a
//! credential takes an argon2id PHC string the caller computed, off the async
//! runtime.

use chrono::{DateTime, Utc};
use sqlx::{Row, Sqlite, Transaction};
use uuid::Uuid;
use wslib_appliance_types::{AppRole, ListedUser, Role, User};
use wslib_secret::Secret;

use crate::{SecondFactors, Store, StoreError, now, parse_stamp, row_stamp, stamp};

const TABLE: &str = "users";

/// The columns a [`User`] is built from; a macro so every statement is
/// `concat!`ed at compile time.
macro_rules! user_columns {
    () => {
        "id, username, role, enabled, created_at, last_login_at"
    };
}

/// True of every row but the last enabled host admin, so a write guarded by it
/// cannot leave a box that has one with none.
macro_rules! not_the_last_host_admin {
    () => {
        "(role != 'hostadmin' OR enabled = 0 OR \
         (SELECT count(*) FROM users WHERE role = 'hostadmin' AND enabled = 1) > 1)"
    };
}

/// Those, plus the two a client never sees.
macro_rules! account_columns {
    () => {
        concat!(user_columns!(), ", password_hash, sessions_valid_from")
    };
}

const BY_ID: &str = concat!("SELECT ", account_columns!(), " FROM users WHERE id = ?");
const BY_USERNAME: &str = concat!(
    "SELECT ",
    account_columns!(),
    " FROM users WHERE username = ?"
);
const ALL: &str = concat!("SELECT ", user_columns!(), " FROM users ORDER BY username");
const LISTED: &str = concat!(
    "SELECT ",
    user_columns!(),
    ", EXISTS (SELECT 1 FROM totp WHERE user_id = users.id AND confirmed = 1) AS totp, \
     (SELECT count(*) FROM passkeys WHERE user_id = users.id) AS passkeys, \
     EXISTS (SELECT 1 FROM totp_required WHERE user_id = users.id) AS totp_required \
     FROM users ORDER BY username"
);
const COUNT: &str = "SELECT count(*) FROM users";

const INSERT: &str = concat!(
    "INSERT INTO users (",
    user_columns!(),
    ", password_hash, updated_at, sessions_valid_from) \
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
);

/// [`INSERT`] that overwrites a row already holding the id, for a restore.
const UPSERT: &str = concat!(
    "INSERT INTO users (",
    user_columns!(),
    ", password_hash, updated_at, sessions_valid_from) \
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) \
     ON CONFLICT (id) DO UPDATE SET username = excluded.username, \
     role = excluded.role, enabled = excluded.enabled, \
     created_at = excluded.created_at, last_login_at = excluded.last_login_at, \
     password_hash = excluded.password_hash, updated_at = excluded.updated_at, \
     sessions_valid_from = excluded.sessions_valid_from"
);

/// [`INSERT`] guarded on the table being empty, for the first account.
const INSERT_FIRST: &str = concat!(
    "INSERT INTO users (",
    user_columns!(),
    ", password_hash, updated_at, sessions_valid_from) \
     SELECT ?, ?, ?, ?, ?, ?, ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM users)"
);

/// A `users` row, including the two columns the wire projection omits; not
/// `Serialize`, so a client is answered with [`Account::user`].
#[derive(Debug, Clone)]
pub struct Account {
    /// Everything a client may see.
    pub user: User,

    /// The argon2id PHC string.
    pub password_hash: Secret,

    /// Sessions proved before this instant are refused. Stamped by a password
    /// change, a disable and a restore.
    pub sessions_valid_from: chrono::DateTime<Utc>,
}

impl Store {
    pub async fn create_user(
        &self,
        username: &str,
        password_hash: &str,
        role: Role,
    ) -> Result<User, StoreError> {
        let now = now();
        let user = User {
            id: Uuid::new_v4().to_string(),
            username: username.to_string(),
            role,
            enabled: true,
            created_at: now,
            last_login_at: None,
        };

        bind_user(sqlx::query(INSERT), &user, password_hash, now)
            .execute(self.pool())
            .await
            .map_err(|e| match &e {
                sqlx::Error::Database(db) if db.is_unique_violation() => {
                    StoreError::UsernameTaken(username.to_string())
                }
                _ => StoreError::Db(e),
            })?;

        Ok(user)
    }

    /// Create the first account, at `role`, if and only if there is none, in
    /// one statement so two callers racing cannot both win; `None` means the
    /// box already had one and nothing was written.
    pub async fn create_first_user(
        &self,
        username: &str,
        password_hash: &str,
        role: Role,
    ) -> Result<Option<User>, StoreError> {
        let now = now();
        let user = User {
            id: Uuid::new_v4().to_string(),
            username: username.to_string(),
            role,
            enabled: true,
            created_at: now,
            last_login_at: None,
        };

        let written = bind_user(sqlx::query(INSERT_FIRST), &user, password_hash, now)
            .execute(self.pool())
            .await?
            .rows_affected();

        Ok((written == 1).then_some(user))
    }

    pub async fn user_by_id(&self, id: &str) -> Result<Option<Account>, StoreError> {
        self.account(BY_ID, id).await
    }

    /// Case-insensitive, as the username's uniqueness is.
    pub async fn user_by_username(&self, username: &str) -> Result<Option<Account>, StoreError> {
        self.account(BY_USERNAME, username).await
    }

    async fn account(&self, sql: &str, value: &str) -> Result<Option<Account>, StoreError> {
        sqlx::query(sql)
            .bind(value)
            .fetch_optional(self.pool())
            .await?
            .map(|row| account_from_row(&row))
            .transpose()
    }

    /// Every account, by username, unpaged.
    pub async fn users(&self) -> Result<Vec<User>, StoreError> {
        sqlx::query(ALL)
            .fetch_all(self.pool())
            .await?
            .iter()
            .map(user_from_row)
            .collect()
    }

    /// [`Store::users`], each with its second factors, for the accounts screen.
    pub async fn listed_users(&self) -> Result<Vec<ListedUser>, StoreError> {
        sqlx::query(LISTED)
            .fetch_all(self.pool())
            .await?
            .iter()
            .map(|row| {
                Ok(ListedUser {
                    user: user_from_row(row)?,
                    totp: row.try_get("totp")?,
                    passkeys: u32::try_from(row.try_get::<i64, _>("passkeys")?).unwrap_or(u32::MAX),
                    totp_required: row.try_get("totp_required")?,
                })
            })
            .collect()
    }

    /// Every account, **password hash included**, by username: the read a
    /// backup makes.
    pub async fn accounts(&self) -> Result<Vec<Account>, StoreError> {
        sqlx::query(concat!(
            "SELECT ",
            account_columns!(),
            " FROM users ORDER BY username"
        ))
        .fetch_all(self.pool())
        .await?
        .iter()
        .map(account_from_row)
        .collect()
    }

    /// Replace every account with `accounts`, inside a restore's `tx`.
    ///
    /// **This signs everybody out**, the caller included. `sessions_valid_from`
    /// is stamped now, never taken from the input, so a restore cannot revive
    /// a revoked session.
    ///
    /// An account whose id the box already has is updated in place, so a
    /// product column referencing `users` keeps its reference, and loses it
    /// only for the accounts not carried.
    ///
    /// Each account's app roles and second factors become those in `app_roles`
    /// and `factors`; a row naming an account not in `accounts` is dropped.
    pub async fn replace_accounts(
        &self,
        tx: &mut Transaction<'_, Sqlite>,
        accounts: &[Account],
        app_roles: &[AppRole],
        factors: &[SecondFactors],
    ) -> Result<(), StoreError> {
        let kept: std::collections::HashSet<&str> =
            accounts.iter().map(|a| a.user.id.as_str()).collect();
        let existing: Vec<String> = sqlx::query_scalar("SELECT id FROM users")
            .fetch_all(&mut **tx)
            .await?;
        for id in &existing {
            self.sessions.remove_user_in(tx, id).await?;
        }
        for id in existing.iter().filter(|id| !kept.contains(id.as_str())) {
            sqlx::query("DELETE FROM users WHERE id = ?")
                .bind(id)
                .execute(&mut **tx)
                .await?;
        }
        // Parked first, or a username moving between two surviving ids collides
        // mid-way; no accepted username begins with a control character.
        sqlx::query("UPDATE users SET username = char(1) || id")
            .execute(&mut **tx)
            .await?;

        for account in accounts {
            bind_user(
                sqlx::query(UPSERT),
                &account.user,
                account.password_hash.expose(),
                now(),
            )
            .execute(&mut **tx)
            .await?;
        }

        sqlx::query("DELETE FROM app_roles")
            .execute(&mut **tx)
            .await?;
        for row in app_roles
            .iter()
            .filter(|r| kept.contains(r.user_id.as_str()))
        {
            sqlx::query("INSERT INTO app_roles (user_id, app, role) VALUES (?, ?, ?)")
                .bind(&row.user_id)
                .bind(&row.app)
                .bind(row.role.as_str())
                .execute(&mut **tx)
                .await?;
        }

        for id in &kept {
            crate::factors::clear(tx, id).await?;
            sqlx::query("DELETE FROM totp_required WHERE user_id = ?")
                .bind(id)
                .execute(&mut **tx)
                .await?;
        }
        for account in factors.iter().filter(|f| kept.contains(f.user_id.as_str())) {
            crate::factors::insert(tx, account).await?;
        }
        Ok(())
    }

    pub async fn user_count(&self) -> Result<u64, StoreError> {
        let count: i64 = sqlx::query_scalar(COUNT).fetch_one(self.pool()).await?;
        Ok(count.max(0) as u64)
    }

    /// Whether there is a host admin inside `tx`, and whether an enabled one.
    pub async fn host_admins_in(
        tx: &mut Transaction<'_, Sqlite>,
    ) -> Result<(bool, bool), StoreError> {
        let (all, enabled): (i64, i64) = sqlx::query_as(
            "SELECT count(*), coalesce(sum(enabled), 0) FROM users WHERE role = 'hostadmin'",
        )
        .fetch_one(&mut **tx)
        .await?;
        Ok((all > 0, enabled > 0))
    }

    /// [`Store::user_count`] inside `tx`, which holds the write lock: the answer
    /// is the one the transaction's own writes will see.
    pub async fn user_count_in(tx: &mut Transaction<'_, Sqlite>) -> Result<u64, StoreError> {
        let count: i64 = sqlx::query_scalar(COUNT).fetch_one(&mut **tx).await?;
        Ok(count.max(0) as u64)
    }

    /// An administrator's reset: replace the password, **end every session
    /// issued before now, and clear the account's TOTP, recovery codes and
    /// passkeys**; a requirement to enrol TOTP stays. Answers whether there was
    /// a second factor to clear.
    ///
    /// Unconditional, and blind to who asks: do not aim it at the account
    /// making the request, and a caller that does reissues its own session.
    pub async fn set_password(&self, id: &str, password_hash: &str) -> Result<bool, StoreError> {
        let query = sqlx::query(concat!(
            "UPDATE users SET password_hash = ?, updated_at = ? WHERE ",
            the_target!()
        ))
        .bind(password_hash)
        .bind(stamp(now()));
        let mut tx = self.guarded_in(self.begin().await?, query, id).await?;
        self.revoke(&mut tx, id).await?;
        let cleared = crate::factors::clear(&mut tx, id).await?;
        tx.commit().await?;
        Ok(cleared)
    }

    /// A self-service change: replace the password **only if it is still
    /// `verified_hash` and the account is enabled**, and end every session
    /// issued before now, so it cannot land over an administrator's reset.
    ///
    /// The cutoff it stamped, or `None` when the account is gone, disabled, or
    /// its password is no longer the one verified.
    pub async fn set_password_if_unchanged(
        &self,
        id: &str,
        verified_hash: &str,
        password_hash: &str,
    ) -> Result<Option<DateTime<Utc>>, StoreError> {
        let mut tx = self.begin().await?;
        // `password_hash` is not `NOCASE`, so the comparison is byte-exact.
        let affected = sqlx::query(
            "UPDATE users SET password_hash = ?, updated_at = ? \
             WHERE id = ? AND password_hash = ? AND enabled = 1",
        )
        .bind(password_hash)
        .bind(stamp(now()))
        .bind(id)
        .bind(verified_hash)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if affected == 0 {
            return Ok(None);
        }
        let cutoff = self.revoke(&mut tx, id).await?;
        tx.commit().await?;
        Ok(Some(cutoff))
    }

    /// Replace the password hash with `rehashed`, the same password hashed
    /// again, **only if it is still `verified_hash`**; answers whether it was.
    /// Not a revocation: the cutoff and the sessions are left alone.
    pub async fn rehash_password(
        &self,
        id: &str,
        verified_hash: &str,
        rehashed: &str,
    ) -> Result<bool, StoreError> {
        let affected =
            sqlx::query("UPDATE users SET password_hash = ? WHERE id = ? AND password_hash = ?")
                .bind(rehashed)
                .bind(id)
                .bind(verified_hash)
                .execute(self.pool())
                .await?
                .rows_affected();
        Ok(affected == 1)
    }

    /// Disabling ends the account's sessions and moves its cutoff, so
    /// re-enabling revives none.
    ///
    /// Refuses to disable the last enabled host admin, as [`StoreError::LastHostAdmin`].
    pub async fn set_enabled(&self, id: &str, enabled: bool) -> Result<(), StoreError> {
        let query = sqlx::query(concat!(
            "UPDATE users SET enabled = ?, updated_at = ? WHERE (? OR ",
            not_the_last_host_admin!(),
            ") AND ",
            the_target!()
        ))
        .bind(enabled)
        .bind(stamp(now()))
        .bind(enabled);
        let mut tx = self.guarded_in(self.begin().await?, query, id).await?;
        if !enabled {
            self.revoke(&mut tx, id).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Change a role, leaving the sessions alone: a caller re-reads the role
    /// per request, so a demotion takes effect on the next one.
    ///
    /// Refuses to demote the last enabled host admin, as
    /// [`StoreError::LastHostAdmin`]; the last admin is the caller's policy.
    pub async fn set_role(&self, id: &str, role: Role) -> Result<(), StoreError> {
        self.guarded(
            sqlx::query(concat!(
                "UPDATE users SET role = ?, updated_at = ? WHERE (? = 'hostadmin' OR ",
                not_the_last_host_admin!(),
                ") AND ",
                the_target!()
            ))
            .bind(role.as_str())
            .bind(stamp(now()))
            .bind(role.as_str()),
            id,
        )
        .await
    }

    /// Foreign keys are on, so a product row referencing `users (id)` refuses
    /// the delete unless its key says `ON DELETE SET NULL` or `CASCADE`.
    ///
    /// Refuses the last enabled host admin, as [`StoreError::LastHostAdmin`].
    pub async fn delete_user(&self, id: &str) -> Result<(), StoreError> {
        self.guarded(
            sqlx::query(concat!(
                "DELETE FROM users WHERE ",
                not_the_last_host_admin!(),
                " AND ",
                the_target!()
            )),
            id,
        )
        .await
    }

    /// Every account's role in every app it has one in, by app then account.
    pub async fn app_roles(&self) -> Result<Vec<AppRole>, StoreError> {
        sqlx::query("SELECT user_id, app, role FROM app_roles ORDER BY app, user_id")
            .fetch_all(self.pool())
            .await?
            .iter()
            .map(|row| {
                Ok(AppRole {
                    user_id: row.try_get("user_id")?,
                    app: row.try_get("app")?,
                    role: parse_role(row, "app_roles", "role")?,
                })
            })
            .collect()
    }

    /// Give account `id` a role in `app`, or with `None` take it away; `false`
    /// when there was none to take.
    pub async fn set_app_role(
        &self,
        id: &str,
        app: &str,
        role: Option<Role>,
    ) -> Result<bool, StoreError> {
        let Some(role) = role else {
            let clear = sqlx::query(concat!(
                "DELETE FROM app_roles WHERE app = ? AND user_id IN (SELECT id FROM users WHERE ",
                the_target!(),
                ")"
            ));
            if self.write_on(clear.bind(app), id).await? > 0 {
                return Ok(true);
            }
            return match self.refusal(id).await? {
                Some(refusal) => Err(refusal),
                None => Ok(false),
            };
        };
        if role == Role::HostAdmin {
            return Err(StoreError::NotAnAppRole);
        }
        self.guarded(
            sqlx::query(concat!(
                "INSERT INTO app_roles (user_id, app, role) SELECT id, ?, ? FROM users WHERE ",
                the_target!(),
                " ON CONFLICT (user_id, app) DO UPDATE SET role = excluded.role"
            ))
            .bind(app)
            .bind(role.as_str()),
            id,
        )
        .await?;
        Ok(true)
    }

    /// The role account `id` has in `app`: Admin for a host admin, whatever
    /// its rows say, and none for an account that is disabled or not there.
    pub async fn role_in_app(&self, id: &str, app: &str) -> Result<Option<Role>, StoreError> {
        let Some(row) = sqlx::query(
            "SELECT users.role, users.enabled, app_roles.role AS app_role FROM users \
             LEFT JOIN app_roles ON app_roles.user_id = users.id AND app_roles.app = ? \
             WHERE users.id = ?",
        )
        .bind(app)
        .bind(id)
        .fetch_optional(self.pool())
        .await?
        else {
            return Ok(None);
        };
        if !row.try_get::<bool, _>("enabled")? {
            return Ok(None);
        }
        if parse_role(&row, TABLE, "role")? == Role::HostAdmin {
            return Ok(Some(Role::Admin));
        }
        row.try_get::<Option<&str>, _>("app_role")?
            .map(|role| {
                role.parse()
                    .map_err(|e| StoreError::unreadable("app_roles", "role", e))
            })
            .transpose()
    }

    /// Record that this account has just signed in; for a sign-in only, never
    /// per request.
    pub async fn stamp_login(&self, id: &str) -> Result<(), StoreError> {
        self.touch(
            sqlx::query("UPDATE users SET last_login_at = ? WHERE id = ?").bind(stamp(now())),
            id,
        )
        .await
    }

    /// Bind the id last and run the statement; no row is [`StoreError::NoSuchUser`].
    async fn touch<'q>(
        &self,
        query: sqlx::query::Query<'q, sqlx::Sqlite, sqlx::sqlite::SqliteArguments<'q>>,
        id: &'q str,
    ) -> Result<(), StoreError> {
        let affected = query.bind(id).execute(self.pool()).await?.rows_affected();
        if affected == 0 {
            return Err(StoreError::NoSuchUser(id.to_string()));
        }
        Ok(())
    }

    /// Run a write ending in [`the_target!`]; no row is the account not being
    /// there, a spared host admin, or [`not_the_last_host_admin!`] holding.
    async fn guarded<'q>(
        &self,
        query: sqlx::query::Query<'q, sqlx::Sqlite, sqlx::sqlite::SqliteArguments<'q>>,
        id: &'q str,
    ) -> Result<(), StoreError> {
        if self.write_on(query, id).await? == 0 {
            return Err(self.refusal(id).await?.unwrap_or(StoreError::LastHostAdmin));
        }
        Ok(())
    }

    /// [`guarded`](Self::guarded) inside `tx`, handed back for the rest of the write.
    async fn guarded_in<'t, 'q>(
        &self,
        mut tx: Transaction<'t, Sqlite>,
        query: sqlx::query::Query<'q, sqlx::Sqlite, sqlx::sqlite::SqliteArguments<'q>>,
        id: &'q str,
    ) -> Result<Transaction<'t, Sqlite>, StoreError> {
        let written = query
            .bind(!self.spares_host_admins)
            .bind(id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if written == 0 {
            // Dropped first: the in-memory store's one connection is the transaction's.
            drop(tx);
            return Err(self.refusal(id).await?.unwrap_or(StoreError::LastHostAdmin));
        }
        Ok(tx)
    }

    /// Bind [`the_target!`]'s parameters, run the statement, and count its rows.
    async fn write_on<'q>(
        &self,
        query: sqlx::query::Query<'q, sqlx::Sqlite, sqlx::sqlite::SqliteArguments<'q>>,
        id: &'q str,
    ) -> Result<u64, StoreError> {
        Ok(query
            .bind(!self.spares_host_admins)
            .bind(id)
            .execute(self.pool())
            .await?
            .rows_affected())
    }

    /// Move `id`'s session cutoff to now and end its sessions, inside `tx` so
    /// the instant is taken under its write lock; answers the cutoff.
    async fn revoke(
        &self,
        tx: &mut Transaction<'_, Sqlite>,
        id: &str,
    ) -> Result<DateTime<Utc>, StoreError> {
        let now = now();
        sqlx::query("UPDATE users SET sessions_valid_from = ? WHERE id = ?")
            .bind(stamp(now))
            .bind(id)
            .execute(&mut **tx)
            .await?;
        self.sessions.remove_user_in(tx, &id.to_string()).await?;
        Ok(now)
    }

    /// Why [`the_target!`] matches nothing for `id`, or `None` when it matches.
    pub(crate) async fn refusal(&self, id: &str) -> Result<Option<StoreError>, StoreError> {
        Ok(match self.user_by_id(id).await? {
            None => Some(StoreError::NoSuchUser(id.to_string())),
            Some(account) if self.spares_host_admins && account.user.role == Role::HostAdmin => {
                Some(StoreError::HostAdminsOnly)
            }
            Some(_) => None,
        })
    }
}

pub(crate) fn parse_role(
    row: &sqlx::sqlite::SqliteRow,
    table: &'static str,
    column: &'static str,
) -> Result<Role, StoreError> {
    row.try_get::<&str, _>(column)?
        .parse()
        .map_err(|e| StoreError::unreadable(table, column, e))
}

/// The nine binds [`INSERT`], [`UPSERT`] and [`INSERT_FIRST`] want, in order.
fn bind_user<'q>(
    query: sqlx::query::Query<'q, Sqlite, sqlx::sqlite::SqliteArguments<'q>>,
    user: &'q User,
    password_hash: &'q str,
    sessions_valid_from: DateTime<Utc>,
) -> sqlx::query::Query<'q, Sqlite, sqlx::sqlite::SqliteArguments<'q>> {
    query
        .bind(&user.id)
        .bind(&user.username)
        .bind(user.role.as_str())
        .bind(user.enabled)
        .bind(stamp(user.created_at))
        .bind(user.last_login_at.map(stamp))
        .bind(password_hash)
        .bind(stamp(now()))
        .bind(stamp(sessions_valid_from))
}

fn user_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<User, StoreError> {
    Ok(User {
        id: row.try_get("id")?,
        username: row.try_get("username")?,
        role: parse_role(row, TABLE, "role")?,
        enabled: row.try_get("enabled")?,
        created_at: row_stamp(row, TABLE, "created_at")?,
        last_login_at: row
            .try_get::<Option<&str>, _>("last_login_at")?
            .map(|at| parse_stamp(TABLE, "last_login_at", at))
            .transpose()?,
    })
}

fn account_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<Account, StoreError> {
    Ok(Account {
        user: user_from_row(row)?,
        password_hash: Secret::new(row.try_get::<String, _>("password_hash")?),
        sessions_valid_from: row_stamp(row, TABLE, "sessions_valid_from")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::store;
    use crate::{SESSION_SECRETS_TABLE, SESSIONS_TABLE};

    const HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNo";

    async fn admin(store: &Store, username: &str) -> User {
        store
            .create_user(username, HASH, Role::Admin)
            .await
            .expect("create")
    }

    /// `app_notes.author` is `ON DELETE SET NULL`, which a delete-then-insert would blank.
    async fn note_by(store: &Store, title: &str, author: &str) {
        sqlx::query("INSERT INTO app_notes (title, author) VALUES (?, ?)")
            .bind(title)
            .bind(author)
            .execute(store.pool())
            .await
            .expect("an app row");
    }

    /// `None` is a `NULL` author on a row that is still there.
    async fn author_of(store: &Store, title: &str) -> Option<String> {
        sqlx::query_scalar::<_, Option<String>>("SELECT author FROM app_notes WHERE title = ?")
            .bind(title)
            .fetch_one(store.pool())
            .await
            .expect("the row is still there")
    }

    #[tokio::test]
    async fn an_accounts_debug_leaves_out_the_hash() {
        let store = store().await;
        admin(&store, "admin").await;
        let accounts = store.accounts().await.unwrap();

        let rendered = format!("{accounts:?}");
        assert!(!rendered.contains("argon2id"), "{rendered}");
        assert!(rendered.contains("admin"), "{rendered}");
    }

    async fn replace_with(store: &Store, accounts: &[Account]) {
        let mut tx = store.begin().await.expect("begin");
        store
            .replace_accounts(&mut tx, accounts, &[], &[])
            .await
            .expect("replace");
        tx.commit().await.expect("commit");
    }

    /// The session rows, each still with the one secret bound to it.
    async fn sessions(store: &Store) -> i64 {
        let rows = crate::reset::tests::rows(store, SESSIONS_TABLE).await;
        let secrets = crate::reset::tests::rows(store, SESSION_SECRETS_TABLE).await;
        assert_eq!(secrets, rows, "the secrets went with their sessions");
        rows
    }

    async fn cutoff(store: &Store, id: &str) -> DateTime<Utc> {
        let account = store.user_by_id(id).await.unwrap().expect("the account");
        account.sessions_valid_from
    }

    fn renamed(account: &Account, username: &str) -> Account {
        let mut account = account.clone();
        account.user.username = username.to_string();
        account
    }

    #[tokio::test]
    async fn a_restore_keeps_a_products_rows_for_every_account_it_carries() {
        let store = store().await;
        let kept = admin(&store, "admin").await;
        let gone = admin(&store, "operator").await;
        note_by(&store, "handover", &kept.id).await;
        note_by(&store, "orphaned", &gone.id).await;
        let carried = store.account(BY_ID, &kept.id).await.unwrap().unwrap();

        replace_with(&store, &[renamed(&carried, "administrator")]).await;

        assert_eq!(
            author_of(&store, "handover").await.as_deref(),
            Some(kept.id.as_str())
        );
        assert_eq!(
            author_of(&store, "orphaned").await,
            None,
            "an account the bundle did not carry is gone, and its rows say so"
        );
        assert_eq!(
            store
                .user_by_id(&kept.id)
                .await
                .unwrap()
                .unwrap()
                .user
                .username,
            "administrator",
            "the row is the bundle's now"
        );
        assert!(store.user_by_id(&gone.id).await.unwrap().is_none());
        assert_eq!(store.user_count().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn a_restore_ends_the_sessions_of_the_accounts_it_carries_too() {
        let store = store().await;
        let kept = admin(&store, "admin").await;
        crate::tests::session(&store, &kept.id).await;
        let carried = store.account(BY_ID, &kept.id).await.unwrap().unwrap();

        replace_with(&store, &[carried]).await;

        assert_eq!(sessions(&store).await, 0);
    }

    #[tokio::test]
    async fn every_revocation_ends_the_accounts_sessions_and_only_its_own() {
        let store = store().await;
        let user = admin(&store, "admin").await;
        let other = admin(&store, "other").await;
        crate::tests::session(&store, &other.id).await;

        crate::tests::session(&store, &user.id).await;
        store
            .set_password(&user.id, "$argon2id$v=19$reset")
            .await
            .unwrap();
        assert_eq!(sessions(&store).await, 1, "an administrator's reset");

        crate::tests::session(&store, &user.id).await;
        let changed = store.set_password_if_unchanged(&user.id, "$argon2id$v=19$reset", HASH);
        assert!(changed.await.unwrap().is_some());
        assert_eq!(sessions(&store).await, 1, "a self-service change");

        crate::tests::session(&store, &user.id).await;
        let before = cutoff(&store, &user.id).await;
        store.set_enabled(&user.id, false).await.unwrap();
        assert_eq!(sessions(&store).await, 1, "a disable");
        assert!(
            cutoff(&store, &user.id).await > before,
            "and moves the cutoff"
        );

        crate::tests::session(&store, &user.id).await;
        store.set_enabled(&user.id, true).await.unwrap();
        assert_eq!(sessions(&store).await, 2, "enabling ends nothing");
    }

    #[tokio::test]
    async fn two_surviving_accounts_may_swap_usernames_in_one_restore() {
        let store = store().await;
        let a = admin(&store, "alice").await;
        let b = admin(&store, "bob").await;
        let a = store.account(BY_ID, &a.id).await.unwrap().unwrap();
        let b = store.account(BY_ID, &b.id).await.unwrap().unwrap();

        replace_with(&store, &[renamed(&a, "Bob"), renamed(&b, "alice")]).await;

        let names = |id: &str| {
            let store = store.clone();
            let id = id.to_string();
            async move { store.user_by_id(&id).await.unwrap().unwrap().user.username }
        };
        assert_eq!(names(&a.user.id).await, "Bob");
        assert_eq!(names(&b.user.id).await, "alice");
    }

    #[tokio::test]
    async fn a_restore_replaces_the_app_roles_of_the_accounts_it_carries() {
        let store = store().await;
        let kept = admin(&store, "admin").await;
        let gone = admin(&store, "operator").await;
        for (id, app) in [(&kept.id, "gauges"), (&gone.id, "widgets")] {
            store
                .set_app_role(id, app, Some(Role::Viewer))
                .await
                .unwrap();
        }
        let carried = store.account(BY_ID, &kept.id).await.unwrap().unwrap();
        let role = |user: &User, app: &str| AppRole {
            user_id: user.id.clone(),
            app: app.to_string(),
            role: Role::Operator,
        };

        let mut tx = store.begin().await.unwrap();
        store
            .replace_accounts(
                &mut tx,
                &[carried],
                &[role(&kept, "widgets"), role(&gone, "gauges")],
                &[],
            )
            .await
            .unwrap();
        tx.commit().await.unwrap();

        assert_eq!(store.app_roles().await.unwrap(), [role(&kept, "widgets")]);
    }

    #[tokio::test]
    async fn the_first_account_is_made_once_at_the_role_it_is_given() {
        for role in [Role::Admin, Role::HostAdmin] {
            let store = store().await;

            let first = store
                .create_first_user("first", HASH, role)
                .await
                .expect("query")
                .expect("an empty box takes the first account");
            assert_eq!(first.role, role);
            assert_eq!(store.user_count().await.unwrap(), 1);

            for name in ["second", "first"] {
                assert!(
                    store
                        .create_first_user(name, HASH, role)
                        .await
                        .unwrap()
                        .is_none(),
                    "{name} was accepted as a first account on a box that has one"
                );
            }
            assert_eq!(store.user_count().await.unwrap(), 1);
        }
    }

    async fn host_admin(store: &Store, username: &str) -> User {
        store
            .create_user(username, HASH, Role::HostAdmin)
            .await
            .expect("create")
    }

    #[tokio::test]
    async fn a_box_with_no_host_admin_may_lose_every_admin() {
        let store = store().await;
        let only = admin(&store, "admin").await;
        store
            .set_role(&only.id, Role::Viewer)
            .await
            .expect("demote");
        store.set_enabled(&only.id, false).await.expect("disable");
        store.delete_user(&only.id).await.expect("delete");
    }

    #[tokio::test]
    async fn the_last_enabled_host_admin_cannot_be_demoted_disabled_or_deleted() {
        let store = store().await;
        let first = host_admin(&store, "first").await;
        let second = host_admin(&store, "second").await;
        store
            .set_role(&first.id, Role::Admin)
            .await
            .expect("another host admin remains");

        for refused in [
            store.set_role(&second.id, Role::Admin).await,
            store.set_enabled(&second.id, false).await,
            store.delete_user(&second.id).await,
        ] {
            assert!(
                matches!(refused, Err(StoreError::LastHostAdmin)),
                "{refused:?}"
            );
        }
        let kept = store.user_by_id(&second.id).await.unwrap().unwrap().user;
        assert_eq!((kept.role, kept.enabled), (Role::HostAdmin, true));

        store
            .set_role(&second.id, Role::HostAdmin)
            .await
            .expect("re-stating the role demotes nobody");
        store
            .set_enabled(&second.id, true)
            .await
            .expect("enabling disables nobody");
    }

    #[tokio::test]
    async fn a_disabled_host_admin_does_not_count_as_the_one_the_box_keeps() {
        let store = store().await;
        let enabled = host_admin(&store, "enabled").await;
        let disabled = host_admin(&store, "disabled").await;
        store
            .set_enabled(&disabled.id, false)
            .await
            .expect("disable");

        assert!(matches!(
            store.delete_user(&enabled.id).await,
            Err(StoreError::LastHostAdmin)
        ));
        store
            .delete_user(&disabled.id)
            .await
            .expect("a disabled host admin holds nothing");
    }

    #[tokio::test]
    async fn a_store_sparing_host_admins_writes_nothing_on_one() {
        let store = store().await;
        let owner = host_admin(&store, "owner").await;
        host_admin(&store, "spare").await;
        store
            .set_app_role(&owner.id, "widgets", Some(Role::Viewer))
            .await
            .unwrap();
        let before = store.user_by_id(&owner.id).await.unwrap().unwrap();
        let sparing = store.sparing_host_admins();

        for refused in [
            sparing
                .set_password(&owner.id, "$argon2id$other")
                .await
                .map(drop),
            sparing.set_role(&owner.id, Role::Viewer).await,
            sparing.set_enabled(&owner.id, false).await,
            sparing
                .set_app_role(&owner.id, "widgets", Some(Role::Admin))
                .await
                .map(drop),
            sparing
                .set_app_role(&owner.id, "widgets", None)
                .await
                .map(drop),
            sparing.delete_user(&owner.id).await,
        ] {
            assert!(
                matches!(refused, Err(StoreError::HostAdminsOnly)),
                "{refused:?}"
            );
        }
        let after = store.user_by_id(&owner.id).await.unwrap().unwrap();
        assert_eq!(after.user, before.user);
        assert_eq!(after.password_hash.expose(), before.password_hash.expose());
        assert_eq!(store.app_roles().await.unwrap()[0].role, Role::Viewer);

        let member = admin(&store, "member").await;
        sparing.set_role(&member.id, Role::Viewer).await.unwrap();
        assert!(
            !sparing
                .set_app_role(&member.id, "widgets", None)
                .await
                .expect("clearing a role nobody had is no refusal"),
            "and says nothing was cleared"
        );
        sparing.delete_user(&member.id).await.unwrap();
    }

    #[tokio::test]
    async fn an_app_role_is_set_listed_cleared_and_goes_with_its_account() {
        let store = store().await;
        let user = admin(&store, "member").await;
        store
            .set_app_role(&user.id, "widgets", Some(Role::Operator))
            .await
            .unwrap();
        store
            .set_app_role(&user.id, "gauges", Some(Role::Viewer))
            .await
            .unwrap();
        store
            .set_app_role(&user.id, "widgets", Some(Role::Admin))
            .await
            .unwrap();
        let listed = store.app_roles().await.unwrap();
        assert_eq!(
            listed
                .iter()
                .map(|r| (r.app.as_str(), r.role))
                .collect::<Vec<_>>(),
            [("gauges", Role::Viewer), ("widgets", Role::Admin)]
        );

        store.set_app_role(&user.id, "gauges", None).await.unwrap();
        assert_eq!(store.app_roles().await.unwrap().len(), 1);

        store.delete_user(&user.id).await.unwrap();
        assert!(store.app_roles().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_app_role_is_never_host_admin_and_never_for_nobody() {
        let store = store().await;
        let user = admin(&store, "member").await;
        assert!(matches!(
            store
                .set_app_role(&user.id, "widgets", Some(Role::HostAdmin))
                .await,
            Err(StoreError::NotAnAppRole)
        ));
        assert!(matches!(
            store
                .set_app_role("nobody", "widgets", Some(Role::Viewer))
                .await,
            Err(StoreError::NoSuchUser(_))
        ));
        assert!(matches!(
            store.set_app_role("nobody", "widgets", None).await,
            Err(StoreError::NoSuchUser(_))
        ));
    }

    #[tokio::test]
    async fn the_role_in_an_app_is_admin_for_a_host_admin_and_none_for_the_disabled() {
        let store = store().await;
        let owner = host_admin(&store, "owner").await;
        let member = store
            .create_user("member", HASH, Role::Viewer)
            .await
            .unwrap();
        store
            .set_app_role(&member.id, "widgets", Some(Role::Operator))
            .await
            .unwrap();

        let role = |id: &str, app: &str| {
            let (store, id, app) = (store.clone(), id.to_string(), app.to_string());
            async move { store.role_in_app(&id, &app).await.unwrap() }
        };
        assert_eq!(role(&owner.id, "widgets").await, Some(Role::Admin));
        assert_eq!(role(&owner.id, "anything").await, Some(Role::Admin));
        assert_eq!(role(&member.id, "widgets").await, Some(Role::Operator));
        assert_eq!(role(&member.id, "gauges").await, None);
        assert_eq!(role("nobody", "widgets").await, None);

        store.set_enabled(&member.id, false).await.unwrap();
        assert_eq!(role(&member.id, "widgets").await, None);
    }

    #[tokio::test]
    async fn a_new_account_has_never_signed_in() {
        let store = store().await;
        let user = admin(&store, "admin").await;

        assert_eq!(
            user.last_login_at, None,
            "None means never, which is the answer worth having"
        );
        assert!(user.enabled);
        assert_eq!(user.role, Role::Admin);

        let stored = store
            .user_by_id(&user.id)
            .await
            .expect("read")
            .expect("row");
        assert_eq!(stored.user, user);
        assert_eq!(stored.password_hash.expose(), HASH);
    }

    #[tokio::test]
    async fn a_username_is_matched_and_constrained_case_insensitively() {
        let store = store().await;
        let user = admin(&store, "Admin").await;

        let found = store
            .user_by_username("admin")
            .await
            .expect("read")
            .expect("row");
        assert_eq!(found.user.id, user.id);
        assert_eq!(
            found.user.username, "Admin",
            "and the capitalisation they chose survives"
        );

        assert!(matches!(
            store.create_user("ADMIN", HASH, Role::Viewer).await,
            Err(StoreError::UsernameTaken(_))
        ));
    }

    #[tokio::test]
    async fn rotating_a_password_ends_the_sessions_taken_with_it() {
        let store = store().await;
        let user = admin(&store, "admin").await;
        let asked = now();

        store
            .set_password(&user.id, "$argon2id$v=19$new")
            .await
            .expect("rotate");

        let after = store
            .user_by_id(&user.id)
            .await
            .expect("read")
            .expect("row");
        assert_eq!(after.password_hash.expose(), "$argon2id$v=19$new");
        assert!(
            after.sessions_valid_from >= asked,
            "{:?} is the instant of the rotation, not before {asked:?}",
            after.sessions_valid_from
        );
    }

    #[tokio::test]
    async fn a_guarded_rotation_lands_only_while_the_password_is_the_one_verified() {
        let store = store().await;
        let user = admin(&store, "admin").await;

        let verified = HASH.to_string();
        store
            .set_password(&user.id, "$argon2id$v=19$the-admins-reset")
            .await
            .expect("reset");

        assert!(
            store
                .set_password_if_unchanged(&user.id, &verified, "$argon2id$v=19$chosen-by-somebody")
                .await
                .expect("query")
                .is_none(),
            "a change verified against a hash that has since moved must not land"
        );
        assert_eq!(
            store
                .user_by_id(&user.id)
                .await
                .expect("read")
                .expect("row")
                .password_hash
                .expose(),
            "$argon2id$v=19$the-admins-reset",
            "the administrator's reset stands"
        );
    }

    #[tokio::test]
    async fn a_guarded_rotation_ends_sessions_exactly_as_an_unguarded_one_does() {
        let store = store().await;
        let user = admin(&store, "admin").await;
        let before = store
            .user_by_id(&user.id)
            .await
            .expect("read")
            .expect("row")
            .sessions_valid_from;

        let cutoff = store
            .set_password_if_unchanged(&user.id, HASH, "$argon2id$v=19$new")
            .await
            .expect("query")
            .expect("written");

        let after = store
            .user_by_id(&user.id)
            .await
            .expect("read")
            .expect("row");
        assert_eq!(after.password_hash.expose(), "$argon2id$v=19$new");
        assert!(after.sessions_valid_from >= before);
        assert_eq!(after.sessions_valid_from, cutoff, "the cutoff it answers");

        assert!(
            store
                .set_password_if_unchanged("nobody", HASH, "$argon2id$v=19$new")
                .await
                .expect("query")
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_disable_stops_a_self_service_change_and_never_an_administrators_reset() {
        let store = store().await;
        let user = admin(&store, "admin").await;

        store.set_enabled(&user.id, false).await.expect("disable");

        assert!(
            store
                .set_password_if_unchanged(&user.id, HASH, "$argon2id$v=19$chosen-by-somebody")
                .await
                .expect("query")
                .is_none(),
            "a disabled account must not take a self-service change, \
             even from somebody holding the current password"
        );
        assert_eq!(
            store
                .user_by_id(&user.id)
                .await
                .expect("read")
                .expect("row")
                .password_hash
                .expose(),
            HASH,
            "and the password is still the one it was"
        );

        store
            .set_password(&user.id, "$argon2id$v=19$the-admins-reset")
            .await
            .expect("an administrator may reset a disabled account");
        assert_eq!(
            store
                .user_by_id(&user.id)
                .await
                .expect("read")
                .expect("row")
                .password_hash
                .expose(),
            "$argon2id$v=19$the-admins-reset"
        );
    }

    #[tokio::test]
    async fn a_re_hash_moves_no_cutoff_and_loses_to_a_change() {
        let store = store().await;
        let user = admin(&store, "admin").await;
        async fn account(store: &Store, id: &str) -> Account {
            store.user_by_id(id).await.expect("read").expect("row")
        }
        let before = account(&store, &user.id).await.sessions_valid_from;

        let rehashed = store.rehash_password(&user.id, HASH, "$argon2id$v=19$rehashed");
        assert!(rehashed.await.expect("query"));
        let after = account(&store, &user.id).await;
        assert_eq!(after.password_hash.expose(), "$argon2id$v=19$rehashed");
        assert_eq!(after.sessions_valid_from, before);

        store
            .set_password(&user.id, "$argon2id$v=19$the-admins-reset")
            .await
            .expect("reset");
        let lost =
            store.rehash_password(&user.id, "$argon2id$v=19$rehashed", "$argon2id$v=19$late");
        assert!(!lost.await.expect("query"));
        let reset = account(&store, &user.id).await;
        assert_eq!(
            reset.password_hash.expose(),
            "$argon2id$v=19$the-admins-reset"
        );
    }

    #[tokio::test]
    async fn changing_a_role_does_not_sign_anybody_out() {
        let store = store().await;
        let user = admin(&store, "admin").await;
        let before = store
            .user_by_id(&user.id)
            .await
            .expect("read")
            .expect("row")
            .sessions_valid_from;

        store
            .set_role(&user.id, Role::Viewer)
            .await
            .expect("demote");

        let after = store
            .user_by_id(&user.id)
            .await
            .expect("read")
            .expect("row");
        assert_eq!(after.user.role, Role::Viewer);
        assert_eq!(after.sessions_valid_from, before);
    }

    #[tokio::test]
    async fn a_write_against_an_account_that_is_not_there_says_so() {
        let store = store().await;
        for result in [
            store.set_password("nobody", HASH).await.map(drop),
            store.set_enabled("nobody", false).await,
            store.set_role("nobody", Role::Viewer).await,
            store.stamp_login("nobody").await,
            store.delete_user("nobody").await,
        ] {
            assert!(
                matches!(result, Err(StoreError::NoSuchUser(_))),
                "{result:?}"
            );
        }
    }

    #[tokio::test]
    async fn only_signing_in_stamps_the_last_login() {
        let store = store().await;
        let user = admin(&store, "admin").await;

        store.set_role(&user.id, Role::Viewer).await.expect("role");
        assert_eq!(
            store
                .user_by_id(&user.id)
                .await
                .expect("read")
                .expect("row")
                .user
                .last_login_at,
            None,
            "an edit is not a sign-in"
        );

        store.stamp_login(&user.id).await.expect("sign in");
        assert!(
            store
                .user_by_id(&user.id)
                .await
                .expect("read")
                .expect("row")
                .user
                .last_login_at
                .is_some()
        );
    }

    #[tokio::test]
    async fn a_freshly_imaged_box_has_no_accounts() {
        let store = store().await;
        assert_eq!(store.user_count().await.expect("count"), 0);
        assert!(store.users().await.expect("list").is_empty());

        admin(&store, "other").await;
        admin(&store, "admin").await;
        assert_eq!(store.user_count().await.expect("count"), 2);
        assert_eq!(
            store
                .users()
                .await
                .expect("list")
                .iter()
                .map(|u| u.username.as_str())
                .collect::<Vec<_>>(),
            ["admin", "other"]
        );
    }

    #[tokio::test]
    async fn the_listing_carries_each_accounts_factors_and_a_waiting_enrolment_is_not_totp() {
        use crate::factors::tests::{furnish, passkey};

        let store = store().await;
        let plain = admin(&store, "a-plain").await;
        let furnished = admin(&store, "b-furnished").await;
        let waiting = admin(&store, "c-waiting").await;
        furnish(&store, &furnished.id, 1).await;
        store.require_totp(&waiting.id).await.unwrap();
        store
            .enrol_totp(&waiting.id, &Secret::new("JBSWY3DPEHPK3PXP"))
            .await
            .unwrap();
        for credential in [2, 3] {
            store
                .add_passkey(&waiting.id, passkey(credential))
                .await
                .unwrap();
        }

        let listed = store.listed_users().await.unwrap();
        let factors =
            |l: &ListedUser| (l.user.username.clone(), l.totp, l.passkeys, l.totp_required);
        assert_eq!(
            listed.iter().map(factors).collect::<Vec<_>>(),
            [
                (plain.username, false, 0, false),
                (furnished.username, true, 1, false),
                (waiting.username, false, 2, true),
            ]
        );
        assert_eq!(
            listed.into_iter().map(|l| l.user).collect::<Vec<_>>(),
            store.users().await.unwrap()
        );
    }

    #[tokio::test]
    async fn an_unreadable_role_names_the_column_rather_than_deserialising_to_a_viewer() {
        let store = store().await;
        let user = admin(&store, "admin").await;
        sqlx::query("UPDATE users SET role = 'superuser' WHERE id = ?")
            .bind(&user.id)
            .execute(store.pool())
            .await
            .expect("write a role this build does not know");

        let e = store.user_by_id(&user.id).await.expect_err("must refuse");
        assert!(e.to_string().contains("role"), "{e}");
        assert!(e.to_string().contains("superuser"), "{e}");
    }
}
