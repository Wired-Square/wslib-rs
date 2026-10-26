//! The durable record of what a human asked this daemon to do: newest first,
//! cursor-paged, and swept, or it grows without bound.

use chrono::{DateTime, Utc};
use sqlx::Row;
use wslib_appliance_types::{AuditRecord, MAX_AUDIT_PAGE, Page};

use crate::{Store, StoreError, parse_stamp, row_stamp, stamp};

const TABLE: &str = "audit";

macro_rules! columns {
    () => {
        "id, at, level, actor, actor_id, target, message, fields"
    };
}

impl Store {
    /// Append one audited event.
    pub async fn record_audit(&self, record: &AuditRecord) -> Result<(), StoreError> {
        let fields = serde_json::to_string(&record.fields)
            .map_err(|e| StoreError::unreadable(TABLE, "fields", e))?;

        sqlx::query(
            "INSERT INTO audit (at, level, actor, actor_id, target, message, fields) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(stamp(record.at))
        .bind(&record.level)
        .bind(&record.actor)
        .bind(&record.actor_id)
        .bind(&record.target)
        .bind(&record.message)
        .bind(fields)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// One page, newest first; `next` is set only when a further row exists.
    pub async fn audit(
        &self,
        limit: u32,
        cursor: Option<&str>,
    ) -> Result<Page<AuditRecord>, StoreError> {
        let limit = limit.clamp(1, MAX_AUDIT_PAGE) as usize;

        // Two statements, and the index's columns in its order, so the cursor
        // is a seek rather than a scan.
        const FIRST: &str = concat!(
            "SELECT ",
            columns!(),
            " FROM audit ORDER BY at DESC, id DESC LIMIT ?"
        );
        const AFTER: &str = concat!(
            "SELECT ",
            columns!(),
            " FROM audit WHERE (at < ?) OR (at = ? AND id < ?) \
             ORDER BY at DESC, id DESC LIMIT ?"
        );

        // One more than asked for, so `next` is observed rather than inferred.
        let fetch = limit as i64 + 1;
        let mut rows = match cursor {
            Some(cursor) => {
                let (at, id) = parse_cursor(cursor)?;
                sqlx::query(AFTER)
                    .bind(at.clone())
                    .bind(at)
                    .bind(id)
                    .bind(fetch)
            }
            None => sqlx::query(FIRST).bind(fetch),
        }
        .fetch_all(&self.pool)
        .await?;

        let mut next = None;
        if rows.len() > limit {
            rows.truncate(limit);
            let last = rows.last().expect("limit is at least 1");
            next = Some(format!(
                "{}|{}",
                last.get::<&str, _>("at"),
                last.get::<i64, _>("id")
            ));
        }

        Ok(Page {
            items: rows.iter().map(record_from_row).collect::<Result<_, _>>()?,
            next,
        })
    }

    /// Delete everything older than `before`, and say how much.
    pub async fn sweep_audit(&self, before: DateTime<Utc>) -> Result<u64, StoreError> {
        Ok(sqlx::query("DELETE FROM audit WHERE at < ?")
            .bind(stamp(before))
            .execute(&self.pool)
            .await?
            .rows_affected())
    }
}

/// Split a cursor this store issued; a malformed one is an error, never a
/// silent first page.
fn parse_cursor(cursor: &str) -> Result<(String, i64), StoreError> {
    let bad = || StoreError::BadCursor(cursor.to_string());
    let (at, id) = cursor.split_once('|').ok_or_else(bad)?;
    // Re-rendered, so another spelling of the instant compares as the column does.
    let at = stamp(parse_stamp(TABLE, "cursor", at).map_err(|_| bad())?);
    Ok((at, id.parse().map_err(|_| bad())?))
}

fn record_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<AuditRecord, StoreError> {
    Ok(AuditRecord {
        at: row_stamp(row, TABLE, "at")?,
        level: row.try_get("level")?,
        actor: row.try_get("actor")?,
        actor_id: row.try_get("actor_id")?,
        target: row.try_get("target")?,
        message: row.try_get("message")?,
        // An empty value is a field the emitter had nothing to say in.
        fields: serde_json::from_str::<Vec<(String, String)>>(row.try_get::<&str, _>("fields")?)
            .map_err(|e| StoreError::unreadable(TABLE, "fields", e))?
            .into_iter()
            .filter(|(_, value)| !value.is_empty())
            .collect(),
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::tests::store;

    pub(crate) fn record(at: DateTime<Utc>, message: &str) -> AuditRecord {
        AuditRecord {
            at,
            level: "INFO".to_string(),
            actor: "admin".to_string(),
            actor_id: Some("3b1d1c6e".to_string()),
            target: "myappliance_server::api::host".to_string(),
            message: message.to_string(),
            fields: vec![("host".to_string(), "widget-01".to_string())],
        }
    }

    /// `count` events, one microsecond apart so their order is unambiguous.
    async fn fill(store: &Store, count: u32) {
        let base = DateTime::from_timestamp(1_757_000_000, 0).unwrap();
        for i in 0..count {
            store
                .record_audit(&record(
                    base + chrono::Duration::microseconds(i.into()),
                    &format!("event {i}"),
                ))
                .await
                .expect("record");
        }
    }

    #[tokio::test]
    async fn an_event_survives_the_round_trip_with_its_fields() {
        let store = store().await;
        let written = record(DateTime::from_timestamp(1_757_000_000, 0).unwrap(), "hello");
        store.record_audit(&written).await.expect("record");

        let page = store.audit(10, None).await.expect("read");
        assert_eq!(page.items, [written]);
        assert_eq!(page.next, None, "one page, and nothing after it");
    }

    #[tokio::test]
    async fn an_empty_field_is_kept_in_the_row_and_left_out_of_the_answer() {
        let store = store().await;
        let mut written = record(
            DateTime::from_timestamp(1_757_000_000, 0).unwrap(),
            "trusted",
        );
        written.fields.push(("warnings".to_string(), String::new()));
        store.record_audit(&written).await.expect("record");

        let page = store.audit(10, None).await.expect("read");
        assert_eq!(
            page.items[0].fields,
            [("host".to_string(), "widget-01".to_string())]
        );
    }

    #[tokio::test]
    async fn paging_walks_every_row_exactly_once_newest_first() {
        let store = store().await;
        fill(&store, 7).await;

        let mut seen = Vec::new();
        let mut cursor = None;
        loop {
            let page = store.audit(3, cursor.as_deref()).await.expect("page");
            assert!(page.items.len() <= 3);
            seen.extend(page.items.iter().map(|r| r.message.clone()));
            match page.next {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }

        assert_eq!(
            seen,
            [
                "event 6", "event 5", "event 4", "event 3", "event 2", "event 1", "event 0"
            ],
            "every row once, and in order"
        );
    }

    #[tokio::test]
    async fn there_is_no_next_page_when_the_last_one_was_exactly_full() {
        let store = store().await;
        fill(&store, 3).await;

        let page = store.audit(3, None).await.expect("page");
        assert_eq!(page.items.len(), 3);
        assert_eq!(page.next, None);
    }

    #[tokio::test]
    async fn rows_written_in_the_same_instant_still_page_without_skipping() {
        let store = store().await;
        let at = DateTime::from_timestamp(1_757_000_000, 0).unwrap();
        for i in 0..4 {
            store
                .record_audit(&record(at, &format!("event {i}")))
                .await
                .expect("record");
        }

        let first = store.audit(2, None).await.expect("page");
        let second = store
            .audit(2, first.next.as_deref())
            .await
            .expect("second page");

        let messages: Vec<&str> = first
            .items
            .iter()
            .chain(&second.items)
            .map(|r| r.message.as_str())
            .collect();
        assert_eq!(messages, ["event 3", "event 2", "event 1", "event 0"]);
    }

    #[tokio::test]
    async fn a_cursor_that_is_not_one_of_ours_is_refused() {
        let store = store().await;
        fill(&store, 3).await;
        for cursor in ["", "nonsense", "2025-09-04T15:33:20.000000Z", "yesterday|1"] {
            assert!(
                store.audit(3, Some(cursor)).await.is_err(),
                "{cursor:?} must not quietly restart the listing"
            );
        }
    }

    #[tokio::test]
    async fn the_page_size_is_capped_by_the_store_not_by_the_caller() {
        let store = store().await;
        fill(&store, 3).await;
        assert_eq!(
            store.audit(u32::MAX, None).await.expect("page").items.len(),
            3
        );
        assert_eq!(
            store.audit(0, None).await.expect("page").items.len(),
            1,
            "a limit of zero is a caller mistake, not a request for nothing"
        );
    }

    #[tokio::test]
    async fn the_sweep_takes_what_is_older_and_leaves_what_is_not() {
        let store = store().await;
        fill(&store, 5).await;
        let base = DateTime::from_timestamp(1_757_000_000, 0).unwrap();

        let removed = store
            .sweep_audit(base + chrono::Duration::microseconds(3))
            .await
            .expect("sweep");
        assert_eq!(removed, 3);
        assert_eq!(store.audit(10, None).await.expect("page").items.len(), 2);

        assert_eq!(
            store.sweep_audit(base).await.expect("sweep"),
            0,
            "a sweep with nothing to do says so rather than failing"
        );
    }
}
