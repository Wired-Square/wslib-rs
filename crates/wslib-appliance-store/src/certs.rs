//! What this appliance trusts for the connections it makes: hosts by
//! fingerprint, and authorities by certificate. Each table is listed whole,
//! added to, removed from, and replaced on a restore.

use sqlx::{Row, Sqlite, Transaction};
use wslib_appliance_types::{TrustedCa, TrustedCert};

use crate::{Store, StoreError, row_stamp, stamp};

const TABLE: &str = "trusted_certs";
const CAS: &str = "trusted_cas";

macro_rules! columns {
    () => {
        "host, sha256, subject, issuer, not_before, not_after, added_at, added_by"
    };
}

const ALL: &str = concat!("SELECT ", columns!(), " FROM trusted_certs ORDER BY host");

const UPSERT: &str = concat!(
    "INSERT INTO trusted_certs (",
    columns!(),
    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?) \
     ON CONFLICT (host) DO UPDATE SET \
     sha256 = excluded.sha256, subject = excluded.subject, \
     issuer = excluded.issuer, not_before = excluded.not_before, \
     not_after = excluded.not_after, added_at = excluded.added_at, \
     added_by = excluded.added_by"
);

impl Store {
    pub async fn trusted_certs(&self) -> Result<Vec<TrustedCert>, StoreError> {
        sqlx::query(ALL)
            .fetch_all(self.pool())
            .await?
            .iter()
            .map(cert_from_row)
            .collect()
    }

    /// Trust this certificate for this host, replacing any earlier pin: a
    /// rotated certificate is a re-pin.
    pub async fn pin_cert(&self, cert: &TrustedCert) -> Result<(), StoreError> {
        bind_cert(sqlx::query(UPSERT), cert)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    /// Stop trusting a host. `false` when it was not pinned.
    pub async fn unpin_cert(&self, host: &str) -> Result<bool, StoreError> {
        let done = sqlx::query("DELETE FROM trusted_certs WHERE host = ?")
            .bind(host)
            .execute(self.pool())
            .await?;
        Ok(done.rows_affected() > 0)
    }

    /// Replace every pin with `certs`, inside a restore's `tx`; two rows for
    /// one host take the last.
    pub async fn replace_trusted_certs(
        tx: &mut Transaction<'_, Sqlite>,
        certs: &[TrustedCert],
    ) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM trusted_certs")
            .execute(&mut **tx)
            .await?;

        for cert in certs {
            bind_cert(sqlx::query(UPSERT), cert)
                .execute(&mut **tx)
                .await?;
        }
        Ok(())
    }

    /// Every authority this box trusts beside the OS's, oldest first.
    pub async fn trusted_cas(&self) -> Result<Vec<TrustedCa>, StoreError> {
        sqlx::query(CAS_ALL)
            .fetch_all(self.pool())
            .await?
            .iter()
            .map(ca_from_row)
            .collect()
    }

    /// Trust this authority. Installing one already there replaces its
    /// record — who added it, and when — and nothing else.
    pub async fn trust_ca(&self, ca: &TrustedCa) -> Result<(), StoreError> {
        bind_ca(sqlx::query(CAS_UPSERT), ca)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    /// Stop trusting an authority. `false` when it was not trusted.
    pub async fn distrust_ca(&self, sha256: &str) -> Result<bool, StoreError> {
        let done = sqlx::query("DELETE FROM trusted_cas WHERE sha256 = ?")
            .bind(sha256)
            .execute(self.pool())
            .await?;
        Ok(done.rows_affected() > 0)
    }

    /// Replace every authority with `cas`, inside a restore's `tx`.
    pub async fn replace_trusted_cas(
        tx: &mut Transaction<'_, Sqlite>,
        cas: &[TrustedCa],
    ) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM trusted_cas")
            .execute(&mut **tx)
            .await?;
        for ca in cas {
            bind_ca(sqlx::query(CAS_UPSERT), ca)
                .execute(&mut **tx)
                .await?;
        }
        Ok(())
    }
}

macro_rules! ca_columns {
    () => {
        "sha256, subject, not_before, not_after, added_at, added_by, pem"
    };
}

const CAS_ALL: &str = concat!(
    "SELECT ",
    ca_columns!(),
    " FROM trusted_cas ORDER BY added_at, sha256"
);

const CAS_UPSERT: &str = concat!(
    "INSERT INTO trusted_cas (",
    ca_columns!(),
    ") VALUES (?, ?, ?, ?, ?, ?, ?) \
     ON CONFLICT (sha256) DO UPDATE SET added_at = excluded.added_at, \
     added_by = excluded.added_by"
);

fn bind_ca<'q>(
    query: sqlx::query::Query<'q, Sqlite, sqlx::sqlite::SqliteArguments<'q>>,
    ca: &'q TrustedCa,
) -> sqlx::query::Query<'q, Sqlite, sqlx::sqlite::SqliteArguments<'q>> {
    query
        .bind(&ca.sha256)
        .bind(&ca.subject)
        .bind(stamp(ca.not_before))
        .bind(stamp(ca.not_after))
        .bind(stamp(ca.added_at))
        .bind(&ca.added_by)
        .bind(&ca.pem)
}

fn ca_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<TrustedCa, StoreError> {
    Ok(TrustedCa {
        sha256: row.try_get("sha256")?,
        subject: row.try_get("subject")?,
        not_before: row_stamp(row, CAS, "not_before")?,
        not_after: row_stamp(row, CAS, "not_after")?,
        added_at: row_stamp(row, CAS, "added_at")?,
        added_by: row.try_get("added_by")?,
        pem: row.try_get("pem")?,
    })
}

fn bind_cert<'q>(
    query: sqlx::query::Query<'q, Sqlite, sqlx::sqlite::SqliteArguments<'q>>,
    cert: &'q TrustedCert,
) -> sqlx::query::Query<'q, Sqlite, sqlx::sqlite::SqliteArguments<'q>> {
    query
        .bind(&cert.host)
        .bind(&cert.sha256)
        .bind(&cert.subject)
        .bind(&cert.issuer)
        .bind(stamp(cert.not_before))
        .bind(stamp(cert.not_after))
        .bind(stamp(cert.added_at))
        .bind(&cert.added_by)
}

fn cert_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<TrustedCert, StoreError> {
    Ok(TrustedCert {
        host: row.try_get("host")?,
        sha256: row.try_get("sha256")?,
        subject: row.try_get("subject")?,
        issuer: row.try_get("issuer")?,
        not_before: row_stamp(row, TABLE, "not_before")?,
        not_after: row_stamp(row, TABLE, "not_after")?,
        added_at: row_stamp(row, TABLE, "added_at")?,
        added_by: row.try_get("added_by")?,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::tests::store;
    use chrono::{DateTime, Utc};

    pub(crate) fn cert(host: &str, sha256: &str) -> TrustedCert {
        let at = |secs| DateTime::<Utc>::from_timestamp(secs, 0).unwrap();
        TrustedCert {
            host: host.to_string(),
            sha256: sha256.to_string(),
            subject: "CN=widget-01".to_string(),
            issuer: "CN=widget-01".to_string(),
            not_before: at(1_757_000_000),
            not_after: at(1_788_536_000),
            added_at: at(1_757_000_100),
            added_by: "admin".to_string(),
        }
    }

    #[tokio::test]
    async fn a_pin_survives_the_round_trip() {
        let store = store().await;
        let pinned = cert("widget-01.local", "aa11");
        store.pin_cert(&pinned).await.expect("pin");

        assert_eq!(store.trusted_certs().await.expect("read"), [pinned]);
    }

    #[tokio::test]
    async fn rotating_a_certificate_replaces_the_pin_rather_than_adding_one() {
        let store = store().await;
        store
            .pin_cert(&cert("widget-01.local", "aa11"))
            .await
            .expect("pin");
        store
            .pin_cert(&cert("widget-01.local", "bb22"))
            .await
            .expect("re-pin");

        let all = store.trusted_certs().await.expect("list");
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].sha256, "bb22");
    }

    #[tokio::test]
    async fn a_restore_carrying_two_rows_for_one_host_takes_the_last() {
        let store = store().await;
        let mut tx = store.begin().await.expect("begin");
        Store::replace_trusted_certs(
            &mut tx,
            &[
                cert("widget-01.local", "aa11"),
                cert("widget-01.local", "bb22"),
            ],
        )
        .await
        .expect("restore");
        tx.commit().await.expect("commit");

        let all = store.trusted_certs().await.expect("list");
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].sha256, "bb22");
    }

    #[tokio::test]
    async fn a_restore_replaces_the_pins_rather_than_adding_to_them() {
        let store = store().await;
        store
            .pin_cert(&cert("widget-09.local", "old"))
            .await
            .expect("pin");

        let mut tx = store.begin().await.expect("begin");
        Store::replace_trusted_certs(&mut tx, &[cert("widget-01.local", "aa11")])
            .await
            .expect("restore");
        tx.commit().await.expect("commit");

        let all = store.trusted_certs().await.expect("list");
        assert_eq!(
            all.len(),
            1,
            "a pin from this box's own life does not survive"
        );
        assert_eq!(all[0].host, "widget-01.local");
    }

    #[tokio::test]
    async fn unpinning_says_whether_the_host_was_pinned() {
        let store = store().await;
        assert!(!store.unpin_cert("widget-09.local").await.expect("unpin"));

        store
            .pin_cert(&cert("widget-01.local", "aa11"))
            .await
            .expect("pin");
        assert!(store.unpin_cert("widget-01.local").await.expect("unpin"));
        assert!(store.trusted_certs().await.expect("list").is_empty());
    }

    pub(crate) fn ca(sha256: &str, added_by: &str) -> TrustedCa {
        let at = |secs| DateTime::<Utc>::from_timestamp(secs, 0).unwrap();
        TrustedCa {
            sha256: sha256.to_string(),
            subject: "CN=Widget Root".to_string(),
            not_before: at(1_757_000_000),
            not_after: at(2_072_536_000),
            added_at: at(1_757_000_100),
            added_by: added_by.to_string(),
            pem: format!("-----BEGIN CERTIFICATE-----\n{sha256}\n-----END CERTIFICATE-----\n"),
        }
    }

    #[tokio::test]
    async fn an_authority_survives_the_round_trip_and_is_installed_once() {
        let store = store().await;
        store.trust_ca(&ca("aa11", "admin")).await.expect("trust");
        store
            .trust_ca(&ca("aa11", "operator"))
            .await
            .expect("again");

        let all = store.trusted_cas().await.expect("list");
        assert_eq!(all.len(), 1, "the same bytes are one row");
        assert_eq!(all[0].added_by, "operator", "and the record is the newer");
        assert_eq!(all[0].pem, ca("aa11", "").pem);
    }

    #[tokio::test]
    async fn distrusting_says_whether_the_authority_was_trusted() {
        let store = store().await;
        assert!(!store.distrust_ca("aa11").await.expect("distrust"));
        store.trust_ca(&ca("aa11", "admin")).await.expect("trust");
        assert!(store.distrust_ca("aa11").await.expect("distrust"));
        assert!(store.trusted_cas().await.expect("list").is_empty());
    }

    #[tokio::test]
    async fn a_restore_replaces_the_authorities_rather_than_adding_to_them() {
        let store = store().await;
        store.trust_ca(&ca("old0", "admin")).await.expect("trust");

        let mut tx = store.begin().await.expect("begin");
        Store::replace_trusted_cas(&mut tx, &[ca("aa11", "admin"), ca("aa11", "operator")])
            .await
            .expect("restore");
        tx.commit().await.expect("commit");

        let all = store.trusted_cas().await.expect("list");
        assert_eq!(
            all.len(),
            1,
            "the box's own went, and a duplicate took the last"
        );
        assert_eq!(
            (all[0].sha256.as_str(), all[0].added_by.as_str()),
            ("aa11", "operator")
        );
    }
}
