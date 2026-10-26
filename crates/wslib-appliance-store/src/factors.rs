//! An account's second factors: a TOTP key, its recovery codes, and passkeys.
//!
//! The store verifies nothing: it is handed a step already accepted, a
//! recovery code's hash, or the counter an assertion carried. A TOTP step and a
//! counting authenticator's counter are written compare-and-swap, so one step
//! or one count is accepted once; an authenticator that keeps no count repeats
//! zero, and the defence against replaying its assertion is the challenge, not
//! the store.

use chrono::{DateTime, Utc};
use sqlx::sqlite::SqliteRow;
use sqlx::{Row, Sqlite, SqliteConnection, Transaction};
use uuid::Uuid;
use wslib_appliance_types::passkey::{PasskeyHost, PasskeyView};
use wslib_secret::Secret;

use crate::{Store, StoreError, now, parse_stamp, row_stamp, stamp};

/// The factors a password reset clears; `totp_required` it keeps.
const TABLES: [&str; 3] = ["passkeys", "recovery_codes", "totp"];

macro_rules! passkey_columns {
    () => {
        "id, user_id, credential_id, public_key, sign_count, name, rp_id, created_at, last_used_at"
    };
}

const PASSKEY_INSERT: &str = concat!(
    "INSERT INTO passkeys (",
    passkey_columns!(),
    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
);

/// An account's TOTP key.
#[derive(Debug, Clone)]
pub struct Totp {
    pub secret: Secret,
    /// False while the enrolment waits for its first code; until then it is
    /// not asked for at sign-in.
    pub confirmed: bool,
    /// The newest time step a code was accepted for.
    pub last_step: Option<u64>,
}

/// A passkey as its registration ceremony leaves it.
#[derive(Clone)]
pub struct NewPasskey {
    pub credential_id: Vec<u8>,
    /// The credential's COSE_Key.
    pub public_key: Vec<u8>,
    pub sign_count: u32,
    pub name: String,
    /// The host it was registered on, the only one it signs for.
    pub rp_id: String,
}

#[derive(Clone, PartialEq)]
pub struct Passkey {
    /// This store's name for it, for a route's path; never the credential id.
    pub id: String,
    pub user_id: String,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub sign_count: u32,
    pub name: String,
    pub rp_id: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

impl Passkey {
    /// As an account's listing shows it, without the credential id.
    pub fn view(&self) -> PasskeyView {
        PasskeyView {
            id: self.id.clone(),
            name: self.name.clone(),
            host: self.rp_id.clone(),
            created_at: self.created_at,
            last_used_at: self.last_used_at,
        }
    }
}

/// One account's factors whole: what a backup carries and a restore puts back.
#[derive(Clone, Default)]
pub struct SecondFactors {
    pub user_id: String,
    pub totp: Option<Totp>,
    /// Lowercase hex SHA-256 of each unused recovery code.
    pub recovery_codes: Vec<String>,
    pub passkeys: Vec<Passkey>,
    /// An administrator has required the account to enrol TOTP.
    pub totp_required: bool,
}

/// What [`Store::use_passkey`] made of a sign-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasskeyUse {
    Used,
    /// The counter did not move past the stored one: possibly a cloned
    /// authenticator.
    CounterDidNotMove,
    NoSuchPasskey,
}

const REDACTED: &str = "<redacted>";

impl std::fmt::Debug for NewPasskey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewPasskey")
            .field("credential_id", &REDACTED)
            .field("public_key", &REDACTED)
            .field("sign_count", &self.sign_count)
            .field("name", &self.name)
            .field("rp_id", &self.rp_id)
            .finish()
    }
}

impl std::fmt::Debug for Passkey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Passkey")
            .field("id", &self.id)
            .field("user_id", &self.user_id)
            .field("credential_id", &REDACTED)
            .field("public_key", &REDACTED)
            .field("sign_count", &self.sign_count)
            .field("name", &self.name)
            .field("rp_id", &self.rp_id)
            .field("created_at", &self.created_at)
            .field("last_used_at", &self.last_used_at)
            .finish()
    }
}

impl std::fmt::Debug for SecondFactors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecondFactors")
            .field("user_id", &self.user_id)
            .field("totp", &self.totp.as_ref().map(|t| t.confirmed))
            .field("recovery_codes", &self.recovery_codes.len())
            .field("passkeys", &self.passkeys.len())
            .field("totp_required", &self.totp_required)
            .finish()
    }
}

impl Store {
    pub async fn totp(&self, user_id: &str) -> Result<Option<Totp>, StoreError> {
        sqlx::query("SELECT secret, confirmed, last_step FROM totp WHERE user_id = ?")
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await?
            .map(|row| totp_from_row(&row))
            .transpose()
    }

    /// Start a TOTP enrolment with `secret`, replacing one still waiting for
    /// its first code, and drop the account's recovery codes. `false` when the
    /// account's TOTP is already confirmed: that is cleared first.
    pub async fn enrol_totp(&self, user_id: &str, secret: &Secret) -> Result<bool, StoreError> {
        let mut tx = self.begin().await?;
        let written = sqlx::query(
            "INSERT INTO totp (user_id, secret, confirmed, last_step) \
             SELECT id, ?, 0, NULL FROM users WHERE id = ? \
             ON CONFLICT (user_id) DO UPDATE SET secret = excluded.secret, last_step = NULL \
             WHERE totp.confirmed = 0",
        )
        .bind(secret.expose())
        .bind(user_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if written == 0 {
            drop(tx);
            self.existing(user_id).await?;
            return Ok(false);
        }
        // Codes made for an abandoned enrolment must not come back with this key.
        sqlx::query("DELETE FROM recovery_codes WHERE user_id = ?")
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Confirm the waiting enrolment of `secret`, the key the first code was
    /// checked against, with the step it was accepted for, and give the account
    /// these recovery codes' hashes in the same transaction; `false`, and
    /// nothing written, when no enrolment of that key is waiting.
    pub async fn confirm_totp(
        &self,
        user_id: &str,
        secret: &Secret,
        step: u64,
        recovery_sha256: &[String],
    ) -> Result<bool, StoreError> {
        let mut tx = self.begin().await?;
        let done = sqlx::query(
            "UPDATE totp SET confirmed = 1, last_step = ? \
             WHERE user_id = ? AND confirmed = 0 AND secret = ?",
        )
        .bind(step_value(step))
        .bind(user_id)
        .bind(secret.expose())
        .execute(&mut *tx)
        .await?;
        if done.rows_affected() == 0 {
            return Ok(false);
        }
        replace_recovery_codes(&mut tx, user_id, recovery_sha256).await?;
        sqlx::query("DELETE FROM totp_required WHERE user_id = ?")
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Clear the account's TOTP and recovery codes, and require it to enrol a
    /// key at its next password sign-in, until one is confirmed. A host
    /// admin's account is refused on a store sparing them.
    pub async fn require_totp(&self, user_id: &str) -> Result<(), StoreError> {
        let mut tx = self.begin().await?;
        let target = sqlx::query(concat!("SELECT 1 FROM users WHERE ", the_target!()))
            .bind(!self.spares_host_admins)
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?;
        if target.is_none() {
            drop(tx);
            return Err(self
                .refusal(user_id)
                .await?
                .unwrap_or(StoreError::LastHostAdmin));
        }
        for statement in [
            "DELETE FROM totp WHERE user_id = ?",
            "DELETE FROM recovery_codes WHERE user_id = ?",
            "INSERT INTO totp_required (user_id) VALUES (?) ON CONFLICT DO NOTHING",
        ] {
            sqlx::query(statement)
                .bind(user_id)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Whether the account must enrol TOTP before its next password sign-in.
    pub async fn totp_required(&self, user_id: &str) -> Result<bool, StoreError> {
        let row = sqlx::query("SELECT 1 FROM totp_required WHERE user_id = ?")
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.is_some())
    }

    /// [`Store::remove_passkey`] for an administrator acting on another's
    /// account: a host admin's is refused on a store sparing them.
    pub async fn remove_passkey_of(
        &self,
        user_id: &str,
        id: &str,
    ) -> Result<Option<Passkey>, StoreError> {
        let removed = sqlx::query(concat!(
            "DELETE FROM passkeys WHERE id = ? AND user_id IN (SELECT id FROM users WHERE ",
            the_target!(),
            ") RETURNING ",
            passkey_columns!()
        ))
        .bind(id)
        .bind(!self.spares_host_admins)
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;
        match removed {
            Some(row) => passkey_from_row(&row).map(Some),
            None => self.writable(user_id).await.map(|()| None),
        }
    }

    /// `Ok` when this store writes account `user_id`: it exists, and is no
    /// host admin's on a store sparing them.
    pub async fn writable(&self, user_id: &str) -> Result<(), StoreError> {
        self.refusal(user_id).await?.map_or(Ok(()), Err)
    }

    /// Record that a code for `step` signed in; `false`, and nothing written,
    /// when that step or a later one already did or the TOTP is not confirmed.
    pub async fn use_totp_step(&self, user_id: &str, step: u64) -> Result<bool, StoreError> {
        let done = sqlx::query(
            "UPDATE totp SET last_step = ?1 \
             WHERE user_id = ?2 AND confirmed = 1 AND (last_step IS NULL OR last_step < ?1)",
        )
        .bind(step_value(step))
        .bind(user_id)
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() > 0)
    }

    /// Turn TOTP off, taking its recovery codes with it; `false` when it was
    /// not on or waiting.
    pub async fn clear_totp(&self, user_id: &str) -> Result<bool, StoreError> {
        let mut tx = self.begin().await?;
        let had = sqlx::query("DELETE FROM totp WHERE user_id = ?")
            .bind(user_id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        sqlx::query("DELETE FROM recovery_codes WHERE user_id = ?")
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(had > 0)
    }

    /// Replace the account's recovery codes with these hashes.
    pub async fn set_recovery_codes(
        &self,
        user_id: &str,
        sha256: &[String],
    ) -> Result<(), StoreError> {
        // Checked under the write lock `begin` takes, so a delete cannot land
        // between the check and the inserts.
        let mut tx = self.begin().await?;
        let there: Option<i64> = sqlx::query_scalar("SELECT 1 FROM users WHERE id = ?")
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?;
        if there.is_none() {
            return Err(StoreError::NoSuchUser(user_id.to_string()));
        }
        replace_recovery_codes(&mut tx, user_id, sha256).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Spend the recovery code with this hash; `false` when the account has no
    /// unused one with it or its TOTP is not confirmed.
    pub async fn use_recovery_code(&self, user_id: &str, sha256: &str) -> Result<bool, StoreError> {
        let done = sqlx::query(
            "DELETE FROM recovery_codes WHERE user_id = ?1 AND sha256 = ?2 \
             AND EXISTS (SELECT 1 FROM totp WHERE user_id = ?1 AND confirmed = 1)",
        )
        .bind(user_id)
        .bind(sha256)
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() > 0)
    }

    pub async fn recovery_codes_left(&self, user_id: &str) -> Result<u64, StoreError> {
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM recovery_codes WHERE user_id = ?")
                .bind(user_id)
                .fetch_one(&self.pool)
                .await?;
        Ok(count.max(0) as u64)
    }

    /// Refuses a credential already registered, to any account, as
    /// [`StoreError::PasskeyTaken`].
    pub async fn add_passkey(&self, user_id: &str, new: NewPasskey) -> Result<Passkey, StoreError> {
        let passkey = Passkey {
            id: Uuid::new_v4().to_string(),
            user_id: user_id.to_string(),
            credential_id: new.credential_id,
            public_key: new.public_key,
            sign_count: new.sign_count,
            name: new.name,
            rp_id: new.rp_id,
            created_at: now(),
            last_used_at: None,
        };
        let written = bind_passkey(
            sqlx::query(concat!(
                "INSERT INTO passkeys (",
                passkey_columns!(),
                ") SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9 \
                 WHERE EXISTS (SELECT 1 FROM users WHERE id = ?2)"
            )),
            &passkey,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db) if db.is_unique_violation() => StoreError::PasskeyTaken,
            _ => StoreError::Db(e),
        })?
        .rows_affected();
        if written == 0 {
            return Err(StoreError::NoSuchUser(user_id.to_string()));
        }
        Ok(passkey)
    }

    /// The account's passkeys, oldest first.
    pub async fn passkeys(&self, user_id: &str) -> Result<Vec<Passkey>, StoreError> {
        sqlx::query(concat!(
            "SELECT ",
            passkey_columns!(),
            " FROM passkeys WHERE user_id = ? ORDER BY created_at, id"
        ))
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?
        .iter()
        .map(passkey_from_row)
        .collect()
    }

    pub async fn passkey_by_credential_id(
        &self,
        credential_id: &[u8],
    ) -> Result<Option<Passkey>, StoreError> {
        sqlx::query(concat!(
            "SELECT ",
            passkey_columns!(),
            " FROM passkeys WHERE credential_id = ?"
        ))
        .bind(credential_id)
        .fetch_optional(&self.pool)
        .await?
        .map(|row| passkey_from_row(&row))
        .transpose()
    }

    /// How many passkeys were made on each host, the box's or one account's.
    pub async fn passkey_hosts(
        &self,
        user_id: Option<&str>,
    ) -> Result<Vec<PasskeyHost>, StoreError> {
        let rows = sqlx::query(
            "SELECT rp_id, count(*) AS passkeys FROM passkeys \
             WHERE ?1 IS NULL OR user_id = ?1 GROUP BY rp_id ORDER BY rp_id",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|row| {
                Ok(PasskeyHost {
                    host: row.try_get("rp_id")?,
                    passkeys: u32::try_from(row.try_get::<i64, _>("passkeys")?).unwrap_or(u32::MAX),
                })
            })
            .collect()
    }

    /// `false` when the account has no passkey `id`.
    pub async fn rename_passkey(
        &self,
        user_id: &str,
        id: &str,
        name: &str,
    ) -> Result<bool, StoreError> {
        let done = sqlx::query("UPDATE passkeys SET name = ? WHERE id = ? AND user_id = ?")
            .bind(name)
            .bind(id)
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(done.rows_affected() > 0)
    }

    /// The passkey removed, or `None` when the account has no passkey `id`.
    pub async fn remove_passkey(
        &self,
        user_id: &str,
        id: &str,
    ) -> Result<Option<Passkey>, StoreError> {
        sqlx::query(concat!(
            "DELETE FROM passkeys WHERE id = ? AND user_id = ? RETURNING ",
            passkey_columns!()
        ))
        .bind(id)
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?
        .map(|row| passkey_from_row(&row))
        .transpose()
    }

    /// Record a sign-in with passkey `id` whose assertion carried `sign_count`,
    /// unless the count has not moved past the stored one, in which case
    /// nothing is written; both zero is an authenticator that keeps no count
    /// (WebAuthn §6.1.1).
    pub async fn use_passkey(&self, id: &str, sign_count: u32) -> Result<PasskeyUse, StoreError> {
        let done = sqlx::query(
            "UPDATE passkeys SET sign_count = ?1, last_used_at = ?2 \
             WHERE id = ?3 AND (?1 > sign_count OR (?1 = 0 AND sign_count = 0))",
        )
        .bind(i64::from(sign_count))
        .bind(stamp(now()))
        .bind(id)
        .execute(&self.pool)
        .await?;
        if done.rows_affected() > 0 {
            return Ok(PasskeyUse::Used);
        }
        let there: Option<i64> = sqlx::query_scalar("SELECT 1 FROM passkeys WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(match there {
            Some(_) => PasskeyUse::CounterDidNotMove,
            None => PasskeyUse::NoSuchPasskey,
        })
    }

    /// Every account's factors, by account id, for a backup; an account with
    /// none is left out.
    pub async fn second_factors(&self) -> Result<Vec<SecondFactors>, StoreError> {
        let mut by_user = std::collections::BTreeMap::<String, SecondFactors>::new();
        fn entry(
            by_user: &mut std::collections::BTreeMap<String, SecondFactors>,
            user_id: String,
        ) -> &mut SecondFactors {
            by_user
                .entry(user_id.clone())
                .or_insert_with(|| SecondFactors {
                    user_id,
                    ..SecondFactors::default()
                })
        }
        for row in sqlx::query("SELECT user_id, secret, confirmed, last_step FROM totp")
            .fetch_all(&self.pool)
            .await?
        {
            entry(&mut by_user, row.try_get("user_id")?).totp = Some(totp_from_row(&row)?);
        }
        for row in sqlx::query("SELECT user_id, sha256 FROM recovery_codes ORDER BY sha256")
            .fetch_all(&self.pool)
            .await?
        {
            entry(&mut by_user, row.try_get("user_id")?)
                .recovery_codes
                .push(row.try_get("sha256")?);
        }
        for row in sqlx::query(concat!(
            "SELECT ",
            passkey_columns!(),
            " FROM passkeys ORDER BY created_at, id"
        ))
        .fetch_all(&self.pool)
        .await?
        {
            let passkey = passkey_from_row(&row)?;
            entry(&mut by_user, passkey.user_id.clone())
                .passkeys
                .push(passkey);
        }
        for row in sqlx::query("SELECT user_id FROM totp_required")
            .fetch_all(&self.pool)
            .await?
        {
            entry(&mut by_user, row.try_get("user_id")?).totp_required = true;
        }
        Ok(by_user.into_values().collect())
    }

    async fn existing(&self, user_id: &str) -> Result<(), StoreError> {
        match self.user_by_id(user_id).await? {
            Some(_) => Ok(()),
            None => Err(StoreError::NoSuchUser(user_id.to_string())),
        }
    }
}

/// Whether the account had any factor to clear.
pub(crate) async fn clear(conn: &mut SqliteConnection, user_id: &str) -> Result<bool, StoreError> {
    let mut cleared = false;
    for table in TABLES {
        cleared |= sqlx::query(&format!("DELETE FROM {table} WHERE user_id = ?"))
            .bind(user_id)
            .execute(&mut *conn)
            .await?
            .rows_affected()
            > 0;
    }
    Ok(cleared)
}

/// Write `factors` for an account that has none.
pub(crate) async fn insert(
    tx: &mut Transaction<'_, Sqlite>,
    factors: &SecondFactors,
) -> Result<(), StoreError> {
    let user_id = factors.user_id.as_str();
    if let Some(totp) = &factors.totp {
        sqlx::query("INSERT INTO totp (user_id, secret, confirmed, last_step) VALUES (?, ?, ?, ?)")
            .bind(user_id)
            .bind(totp.secret.expose())
            .bind(totp.confirmed)
            .bind(totp.last_step.map(step_value))
            .execute(&mut **tx)
            .await?;
    }
    insert_recovery_codes(tx, user_id, &factors.recovery_codes).await?;
    for passkey in &factors.passkeys {
        bind_passkey(sqlx::query(PASSKEY_INSERT), passkey)
            .execute(&mut **tx)
            .await?;
    }
    if factors.totp_required {
        sqlx::query("INSERT INTO totp_required (user_id) VALUES (?)")
            .bind(user_id)
            .execute(&mut **tx)
            .await?;
    }
    Ok(())
}

async fn replace_recovery_codes(
    tx: &mut Transaction<'_, Sqlite>,
    user_id: &str,
    sha256: &[String],
) -> Result<(), StoreError> {
    debug_assert!(
        sha256
            .iter()
            .all(|h| h.len() == 64 && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))),
        "a recovery code's hash is 64 lowercase hex digits"
    );
    sqlx::query("DELETE FROM recovery_codes WHERE user_id = ?")
        .bind(user_id)
        .execute(&mut **tx)
        .await?;
    insert_recovery_codes(tx, user_id, sha256).await
}

async fn insert_recovery_codes(
    tx: &mut Transaction<'_, Sqlite>,
    user_id: &str,
    sha256: &[String],
) -> Result<(), StoreError> {
    for hash in sha256 {
        sqlx::query(
            "INSERT INTO recovery_codes (user_id, sha256) VALUES (?, ?) ON CONFLICT DO NOTHING",
        )
        .bind(user_id)
        .bind(hash)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

fn step_value(step: u64) -> i64 {
    i64::try_from(step).unwrap_or(i64::MAX)
}

fn bind_passkey<'q>(
    query: sqlx::query::Query<'q, Sqlite, sqlx::sqlite::SqliteArguments<'q>>,
    passkey: &'q Passkey,
) -> sqlx::query::Query<'q, Sqlite, sqlx::sqlite::SqliteArguments<'q>> {
    query
        .bind(&passkey.id)
        .bind(&passkey.user_id)
        .bind(&passkey.credential_id)
        .bind(&passkey.public_key)
        .bind(i64::from(passkey.sign_count))
        .bind(&passkey.name)
        .bind(&passkey.rp_id)
        .bind(stamp(passkey.created_at))
        .bind(passkey.last_used_at.map(stamp))
}

fn totp_from_row(row: &SqliteRow) -> Result<Totp, StoreError> {
    Ok(Totp {
        secret: Secret::new(row.try_get::<String, _>("secret")?),
        confirmed: row.try_get("confirmed")?,
        last_step: row
            .try_get::<Option<i64>, _>("last_step")?
            .map(|step| {
                u64::try_from(step).map_err(|e| StoreError::unreadable("totp", "last_step", e))
            })
            .transpose()?,
    })
}

fn passkey_from_row(row: &SqliteRow) -> Result<Passkey, StoreError> {
    Ok(Passkey {
        id: row.try_get("id")?,
        user_id: row.try_get("user_id")?,
        credential_id: row.try_get("credential_id")?,
        public_key: row.try_get("public_key")?,
        sign_count: u32::try_from(row.try_get::<i64, _>("sign_count")?)
            .map_err(|e| StoreError::unreadable("passkeys", "sign_count", e))?,
        name: row.try_get("name")?,
        rp_id: row.try_get("rp_id")?,
        created_at: row_stamp(row, "passkeys", "created_at")?,
        last_used_at: row
            .try_get::<Option<&str>, _>("last_used_at")?
            .map(|at| parse_stamp("passkeys", "last_used_at", at))
            .transpose()?,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::tests::store;
    use wslib_appliance_types::Role;

    pub(crate) fn passkey(credential: u8) -> NewPasskey {
        NewPasskey {
            credential_id: vec![credential; 16],
            public_key: vec![0xa5, credential],
            sign_count: 0,
            name: format!("key {credential}"),
            rp_id: "widget-01.local".to_string(),
        }
    }

    async fn confirmed_totp(store: &Store, user_id: &str, step: u64) {
        let key = Secret::new("JBSWY3DPEHPK3PXP");
        assert!(store.enrol_totp(user_id, &key).await.unwrap());
        assert!(store.confirm_totp(user_id, &key, step, &[]).await.unwrap());
    }

    /// Account `user_id` with a confirmed TOTP, two recovery codes and a passkey.
    pub(crate) async fn furnish(store: &Store, user_id: &str, credential: u8) {
        confirmed_totp(store, user_id, 100).await;
        store
            .set_recovery_codes(user_id, &["aa".repeat(32), "bb".repeat(32)])
            .await
            .unwrap();
        store
            .add_passkey(user_id, passkey(credential))
            .await
            .unwrap();
    }

    pub(crate) async fn has_none(store: &Store, user_id: &str) -> bool {
        store.totp(user_id).await.unwrap().is_none()
            && store.recovery_codes_left(user_id).await.unwrap() == 0
            && store.passkeys(user_id).await.unwrap().is_empty()
    }

    async fn account(store: &Store, username: &str) -> String {
        store
            .create_user(username, "not-a-real-hash", Role::Admin)
            .await
            .unwrap()
            .id
    }

    #[tokio::test]
    async fn an_enrolment_takes_effect_only_once_a_code_confirms_it() {
        let store = store().await;
        let id = account(&store, "admin").await;

        assert!(store.enrol_totp(&id, &Secret::new("first")).await.unwrap());
        assert!(
            store.enrol_totp(&id, &Secret::new("second")).await.unwrap(),
            "a waiting enrolment is replaced"
        );
        let waiting = store.totp(&id).await.unwrap().unwrap();
        assert_eq!(waiting.secret.expose(), "second");
        assert!(!waiting.confirmed);
        assert!(
            !store.use_totp_step(&id, 5).await.unwrap(),
            "no sign-in on an unconfirmed key"
        );

        let second = Secret::new("second");
        assert!(store.confirm_totp(&id, &second, 7, &[]).await.unwrap());
        assert!(
            !store.confirm_totp(&id, &second, 8, &[]).await.unwrap(),
            "only once"
        );
        assert!(
            !store.enrol_totp(&id, &Secret::new("third")).await.unwrap(),
            "a confirmed key is cleared before another is enrolled"
        );
        let confirmed = store.totp(&id).await.unwrap().unwrap();
        assert_eq!(confirmed.secret.expose(), "second");
        assert!(confirmed.confirmed);
        assert_eq!(confirmed.last_step, Some(7));

        assert!(matches!(
            store.enrol_totp("nobody", &Secret::new("x")).await,
            Err(StoreError::NoSuchUser(_))
        ));
    }

    #[tokio::test]
    async fn a_confirmation_for_a_key_since_replaced_is_refused() {
        let store = store().await;
        let id = account(&store, "admin").await;
        let checked = Secret::new("checked");
        store.enrol_totp(&id, &checked).await.unwrap();
        store
            .enrol_totp(&id, &Secret::new("swapped in"))
            .await
            .unwrap();

        assert!(
            !store
                .confirm_totp(&id, &checked, 7, &["aa".repeat(32)])
                .await
                .unwrap()
        );
        let waiting = store.totp(&id).await.unwrap().unwrap();
        assert_eq!(waiting.secret.expose(), "swapped in");
        assert!(!waiting.confirmed);
        assert_eq!(
            store.recovery_codes_left(&id).await.unwrap(),
            0,
            "a refused confirmation writes no codes"
        );
    }

    #[tokio::test]
    async fn a_confirmation_gives_the_account_its_codes_in_place_of_any_before() {
        let store = store().await;
        let id = account(&store, "admin").await;
        let key = Secret::new("JBSWY3DPEHPK3PXP");
        store.enrol_totp(&id, &key).await.unwrap();
        store
            .set_recovery_codes(&id, &["aa".repeat(32)])
            .await
            .unwrap();

        let given = ["bb".repeat(32), "cc".repeat(32)];
        assert!(store.confirm_totp(&id, &key, 1, &given).await.unwrap());
        assert_eq!(store.recovery_codes_left(&id).await.unwrap(), 2);
        assert!(
            !store
                .use_recovery_code(&id, &"aa".repeat(32))
                .await
                .unwrap()
        );
        assert!(store.use_recovery_code(&id, &given[0]).await.unwrap());
    }

    #[tokio::test]
    async fn a_step_is_accepted_once_and_never_after_a_later_one() {
        let store = store().await;
        let id = account(&store, "admin").await;
        confirmed_totp(&store, &id, 10).await;

        assert!(
            !store.use_totp_step(&id, 10).await.unwrap(),
            "the confirming code's step"
        );
        assert!(store.use_totp_step(&id, 12).await.unwrap());
        assert!(!store.use_totp_step(&id, 12).await.unwrap(), "a replay");
        assert!(
            !store.use_totp_step(&id, 11).await.unwrap(),
            "an earlier step"
        );
        assert!(store.use_totp_step(&id, 13).await.unwrap());
        assert_eq!(store.totp(&id).await.unwrap().unwrap().last_step, Some(13));
    }

    #[tokio::test]
    async fn turning_totp_off_takes_its_recovery_codes() {
        let store = store().await;
        let id = account(&store, "admin").await;
        furnish(&store, &id, 1).await;

        assert!(store.clear_totp(&id).await.unwrap());
        assert!(store.totp(&id).await.unwrap().is_none());
        assert_eq!(store.recovery_codes_left(&id).await.unwrap(), 0);
        assert_eq!(store.passkeys(&id).await.unwrap().len(), 1, "passkeys stay");
        assert!(!store.clear_totp(&id).await.unwrap());
    }

    #[tokio::test]
    async fn an_abandoned_enrolments_codes_do_not_return_with_the_next_key() {
        let store = store().await;
        let id = account(&store, "admin").await;
        let abandoned = "aa".repeat(32);
        store.enrol_totp(&id, &Secret::new("first")).await.unwrap();
        store
            .set_recovery_codes(&id, std::slice::from_ref(&abandoned))
            .await
            .unwrap();
        let next = Secret::new("second");
        store.enrol_totp(&id, &next).await.unwrap();
        store.confirm_totp(&id, &next, 1, &[]).await.unwrap();

        assert!(!store.use_recovery_code(&id, &abandoned).await.unwrap());
        assert_eq!(store.recovery_codes_left(&id).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn a_recovery_code_is_single_use_and_a_new_set_replaces_the_old() {
        let store = store().await;
        let id = account(&store, "admin").await;
        let other = account(&store, "operator").await;
        let (a, b, c) = ("aa".repeat(32), "bb".repeat(32), "cc".repeat(32));
        let key = Secret::new("JBSWY3DPEHPK3PXP");
        store.enrol_totp(&id, &key).await.unwrap();
        store
            .set_recovery_codes(&id, &[a.clone(), b.clone()])
            .await
            .unwrap();
        assert!(
            !store.use_recovery_code(&id, &a).await.unwrap(),
            "not while the enrolment is pending"
        );
        store
            .confirm_totp(&id, &key, 1, &[a.clone(), b.clone()])
            .await
            .unwrap();

        assert!(
            !store.use_recovery_code(&other, &a).await.unwrap(),
            "not theirs"
        );
        assert!(store.use_recovery_code(&id, &a).await.unwrap());
        assert!(!store.use_recovery_code(&id, &a).await.unwrap(), "spent");
        assert_eq!(store.recovery_codes_left(&id).await.unwrap(), 1);

        store
            .set_recovery_codes(&id, std::slice::from_ref(&c))
            .await
            .unwrap();
        assert!(!store.use_recovery_code(&id, &b).await.unwrap(), "replaced");
        assert!(store.use_recovery_code(&id, &c).await.unwrap());

        assert!(matches!(
            store.set_recovery_codes("nobody", &[c]).await,
            Err(StoreError::NoSuchUser(_))
        ));
    }

    #[tokio::test]
    async fn passkeys_are_listed_found_renamed_and_removed_by_their_owner_alone() {
        let store = store().await;
        let id = account(&store, "admin").await;
        let other = account(&store, "operator").await;
        let first = store.add_passkey(&id, passkey(1)).await.unwrap();
        let second = store.add_passkey(&id, passkey(2)).await.unwrap();

        assert_eq!(
            store.passkeys(&id).await.unwrap(),
            [first.clone(), second.clone()]
        );
        assert_eq!(
            store.passkey_by_credential_id(&[2; 16]).await.unwrap(),
            Some(second.clone())
        );
        assert_eq!(
            store.passkey_by_credential_id(&[3; 16]).await.unwrap(),
            None
        );
        assert!(matches!(
            store.add_passkey(&other, passkey(1)).await,
            Err(StoreError::PasskeyTaken)
        ));
        assert!(matches!(
            store.add_passkey("nobody", passkey(9)).await,
            Err(StoreError::NoSuchUser(_))
        ));

        assert!(
            !store
                .rename_passkey(&other, &first.id, "mine now")
                .await
                .unwrap()
        );
        assert!(
            store
                .rename_passkey(&id, &first.id, "laptop")
                .await
                .unwrap()
        );
        assert_eq!(store.passkeys(&id).await.unwrap()[0].name, "laptop");

        assert_eq!(store.remove_passkey(&other, &first.id).await.unwrap(), None);
        let removed = store.remove_passkey(&id, &first.id).await.unwrap().unwrap();
        assert_eq!(removed.name, "laptop");
        assert_eq!(store.passkeys(&id).await.unwrap(), [second]);
    }

    #[tokio::test]
    async fn passkeys_are_counted_by_the_host_they_were_made_on() {
        let store = store().await;
        let id = account(&store, "admin").await;
        let other = account(&store, "operator").await;
        let on = |credential, rp_id: &str| NewPasskey {
            rp_id: rp_id.to_string(),
            ..passkey(credential)
        };
        store
            .add_passkey(&id, on(1, "widget-01.local"))
            .await
            .unwrap();
        let listed = store.add_passkey(&id, on(2, "widget.lan")).await.unwrap();
        store
            .add_passkey(&other, on(3, "widget-01.local"))
            .await
            .unwrap();

        let hosts = |pairs: &[(&str, u32)]| {
            pairs
                .iter()
                .map(|&(host, passkeys)| PasskeyHost {
                    host: host.to_string(),
                    passkeys,
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(
            store.passkey_hosts(None).await.unwrap(),
            hosts(&[("widget-01.local", 2), ("widget.lan", 1)])
        );
        assert_eq!(
            store.passkey_hosts(Some(&other)).await.unwrap(),
            hosts(&[("widget-01.local", 1)])
        );
        assert_eq!(store.passkey_hosts(Some("nobody")).await.unwrap(), []);

        let view = listed.view();
        assert_eq!((view.id, view.host), (listed.id, "widget.lan".to_string()));
    }

    #[tokio::test]
    async fn a_passkeys_counter_only_moves_forward_unless_it_keeps_none() {
        let store = store().await;
        let id = account(&store, "admin").await;
        let none = store.add_passkey(&id, passkey(1)).await.unwrap();
        let counting = store
            .add_passkey(
                &id,
                NewPasskey {
                    sign_count: 5,
                    ..passkey(2)
                },
            )
            .await
            .unwrap();

        let used = |id: &str, count| {
            let store = store.clone();
            let id = id.to_string();
            async move { store.use_passkey(&id, count).await.unwrap() }
        };
        assert_eq!(used(&none.id, 0).await, PasskeyUse::Used);
        assert_eq!(used(&none.id, 0).await, PasskeyUse::Used, "zero and zero");

        let stale = PasskeyUse::CounterDidNotMove;
        assert_eq!(used(&counting.id, 5).await, stale, "not past it");
        assert_eq!(used(&counting.id, 0).await, stale, "a count dropped");
        assert_eq!(used(&counting.id, 6).await, PasskeyUse::Used);
        assert_eq!(used(&counting.id, 6).await, stale, "a replay");

        let after = store
            .passkey_by_credential_id(&[2; 16])
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after.sign_count, 6);
        assert!(after.last_used_at.is_some());
        assert_eq!(used("gone", 7).await, PasskeyUse::NoSuchPasskey);
    }

    #[tokio::test]
    async fn debug_names_no_credential_key_or_recovery_code() {
        let store = store().await;
        let id = account(&store, "admin").await;
        furnish(&store, &id, 0xfe).await;
        let factors = store.second_factors().await.unwrap();
        let rendered = format!(
            "{factors:?} {:?} {:?}",
            store.passkeys(&id).await.unwrap(),
            passkey(0xfe)
        );

        assert!(!rendered.contains("254, 254"), "credential: {rendered}");
        assert!(!rendered.contains("165, 254"), "public key: {rendered}");
        assert!(!rendered.contains("aaaa"), "a code's hash: {rendered}");
        assert!(!rendered.contains("JBSW"), "the key: {rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
    }

    #[tokio::test]
    async fn deleting_an_account_takes_its_factors() {
        let store = store().await;
        let id = account(&store, "admin").await;
        let other = account(&store, "operator").await;
        furnish(&store, &id, 1).await;
        furnish(&store, &other, 2).await;

        store.delete_user(&id).await.unwrap();

        assert!(has_none(&store, &id).await);
        let left = store.second_factors().await.unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].user_id, other);
    }

    #[tokio::test]
    async fn a_password_reset_clears_the_accounts_factors_and_a_change_does_not() {
        let store = store().await;
        let id = account(&store, "admin").await;
        let other = account(&store, "operator").await;
        furnish(&store, &id, 1).await;
        furnish(&store, &other, 2).await;

        assert!(
            store
                .set_password_if_unchanged(&id, "not-a-real-hash", "changed")
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            !has_none(&store, &id).await,
            "a self-service change keeps them"
        );

        assert!(store.set_password(&id, "reset").await.unwrap(), "cleared");
        assert!(has_none(&store, &id).await);
        assert!(
            !store.set_password(&id, "again").await.unwrap(),
            "nothing left to clear"
        );
        assert!(!has_none(&store, &other).await, "nobody else's");
    }

    #[tokio::test]
    async fn a_refused_reset_clears_nothing() {
        let store = store().await;
        let host = store
            .create_user("root", "not-a-real-hash", Role::HostAdmin)
            .await
            .unwrap();
        furnish(&store, &host.id, 1).await;

        assert!(matches!(
            store
                .sparing_host_admins()
                .set_password(&host.id, "reset")
                .await,
            Err(StoreError::HostAdminsOnly)
        ));
        assert!(!has_none(&store, &host.id).await);
    }

    #[tokio::test]
    async fn a_restore_puts_back_the_bundles_factors_and_drops_the_boxs_own() {
        let store = store().await;
        let id = account(&store, "admin").await;
        let other = account(&store, "operator").await;
        furnish(&store, &id, 1).await;
        let accounts = store.accounts().await.unwrap();
        let carried = store.second_factors().await.unwrap();

        store.clear_totp(&id).await.unwrap();
        let theirs = store.passkeys(&id).await.unwrap().remove(0);
        store.remove_passkey(&id, &theirs.id).await.unwrap();
        furnish(&store, &other, 2).await;

        let mut tx = store.begin().await.unwrap();
        store
            .replace_accounts(&mut tx, &accounts, &[], &carried)
            .await
            .unwrap();
        tx.commit().await.unwrap();

        let totp = store.totp(&id).await.unwrap().unwrap();
        assert!(totp.confirmed);
        assert_eq!(totp.last_step, Some(100));
        assert_eq!(store.recovery_codes_left(&id).await.unwrap(), 2);
        assert_eq!(store.passkeys(&id).await.unwrap(), [theirs]);
        assert!(
            has_none(&store, &other).await,
            "the bundle carried no factors for them"
        );
    }

    #[tokio::test]
    async fn requiring_totp_clears_the_key_and_codes_until_a_key_is_confirmed() {
        let store = store().await;
        let id = account(&store, "member").await;
        furnish(&store, &id, 1).await;
        store.require_totp(&id).await.unwrap();
        assert!(store.totp(&id).await.unwrap().is_none());
        assert_eq!(store.recovery_codes_left(&id).await.unwrap(), 0);
        assert_eq!(store.passkeys(&id).await.unwrap().len(), 1, "passkeys stay");
        assert!(store.totp_required(&id).await.unwrap());
        let factors = store.second_factors().await.unwrap();
        assert!(factors.iter().any(|f| f.user_id == id && f.totp_required));

        confirmed_totp(&store, &id, 5).await;
        assert!(
            !store.totp_required(&id).await.unwrap(),
            "a confirmed key ends it"
        );

        store.require_totp(&id).await.unwrap();
        store.set_password(&id, "reset").await.unwrap();
        assert!(store.totp_required(&id).await.unwrap(), "a reset keeps it");
    }

    #[tokio::test]
    async fn a_store_sparing_host_admins_requires_and_removes_nothing_of_theirs() {
        let store = store().await;
        let host = store
            .create_user("root", "not-a-real-hash", Role::HostAdmin)
            .await
            .unwrap();
        furnish(&store, &host.id, 1).await;
        let sparing = store.sparing_host_admins();
        let passkey = store.passkeys(&host.id).await.unwrap().remove(0);
        assert!(matches!(
            sparing.require_totp(&host.id).await,
            Err(StoreError::HostAdminsOnly)
        ));
        assert!(matches!(
            sparing.remove_passkey_of(&host.id, &passkey.id).await,
            Err(StoreError::HostAdminsOnly)
        ));
        assert!(!has_none(&store, &host.id).await);
        assert!(matches!(
            store.require_totp("nobody").await,
            Err(StoreError::NoSuchUser(_))
        ));
        assert!(matches!(
            sparing.writable(&host.id).await,
            Err(StoreError::HostAdminsOnly)
        ));
        assert!(matches!(
            store.remove_passkey_of("nobody", &passkey.id).await,
            Err(StoreError::NoSuchUser(_))
        ));
        assert!(
            store
                .remove_passkey_of(&host.id, "no-such-id")
                .await
                .unwrap()
                .is_none(),
            "a passkey the account does not have"
        );
        assert!(
            store
                .remove_passkey_of(&host.id, &passkey.id)
                .await
                .unwrap()
                .is_some()
        );
    }
}
