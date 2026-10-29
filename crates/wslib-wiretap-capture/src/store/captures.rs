use crate::Store;
use crate::store::error::Result;

const DATA_TABLES: [&str; 3] = ["frames", "bytes", "capture_events"];

impl Store {
    /// Copy a capture's frames, bytes and events to `dest_id` in one transaction; the
    /// count is of frames and bytes.
    pub async fn copy_capture_data(&self, source_id: &str, dest_id: &str) -> Result<usize> {
        let mut tx = self.db.begin().await?;
        let mut copied = 0;
        for sql in [
            "INSERT INTO frames (capture_id, protocol, timestamp_us, frame_id, bus, dlc, payload, is_extended, is_fd, is_rtr, is_brs, is_esi, source_address, incomplete, direction, crc_valid)
             SELECT ?2, protocol, timestamp_us, frame_id, bus, dlc, payload, is_extended, is_fd, is_rtr, is_brs, is_esi, source_address, incomplete, direction, crc_valid
             FROM frames WHERE capture_id = ?1 ORDER BY rowid",
            "INSERT INTO bytes (capture_id, byte_val, timestamp_us, bus)
             SELECT ?2, byte_val, timestamp_us, bus
             FROM bytes WHERE capture_id = ?1 ORDER BY rowid",
        ] {
            copied += sqlx::query(sql)
                .bind(source_id)
                .bind(dest_id)
                .execute(&mut *tx)
                .await?
                .rows_affected();
        }
        sqlx::query(
            "INSERT INTO capture_events (capture_id, timestamp_us, duration_us, note, created_at_us, updated_at_us)
             SELECT ?2, timestamp_us, duration_us, note, created_at_us, updated_at_us
             FROM capture_events WHERE capture_id = ?1 ORDER BY id",
        )
        .bind(source_id)
        .bind(dest_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(copied as usize)
    }

    /// Delete a capture's frames, bytes and events in one transaction, leaving its metadata.
    pub async fn delete_capture_data(&self, capture_id: &str) -> Result<()> {
        let mut tx = self.db.begin().await?;
        for table in DATA_TABLES {
            sqlx::query(&format!("DELETE FROM {table} WHERE capture_id = ?1"))
                .bind(capture_id)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Delete every capture not marked persistent, then rows with no metadata at all,
    /// and give the space back to the file system.
    pub async fn sweep_non_persistent(&self) -> Result<()> {
        let mut tx = self.db.begin().await?;
        for table in DATA_TABLES {
            sqlx::query(&format!(
                "DELETE FROM {table} WHERE capture_id IN (SELECT capture_id FROM capture_metadata WHERE persistent = 0)"
            ))
            .execute(&mut *tx)
            .await?;
        }
        sqlx::query("DELETE FROM capture_metadata WHERE persistent = 0")
            .execute(&mut *tx)
            .await?;
        for table in DATA_TABLES {
            sqlx::query(&format!(
                "DELETE FROM {table} WHERE capture_id NOT IN (SELECT capture_id FROM capture_metadata)"
            ))
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        // In WAL, VACUUM's smaller file reaches the disk at the checkpoint.
        let mut conn = self.pool().acquire().await?;
        sqlx::query("VACUUM").execute(&mut *conn).await?;
        sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
            .execute(&mut *conn)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::event;
    use crate::frames::{StoredFrame, can_frame};
    use crate::store::testing::{count, execute, multi_protocol_capture, store, whole};

    async fn event_count(store: &Store, capture_id: &str) -> usize {
        store.list_capture_events(capture_id).await.unwrap().len()
    }

    #[tokio::test]
    async fn a_frame_keeps_rtr_brs_and_esi_through_insert_select_and_copy() {
        let store = store().await;
        let frames = [
            StoredFrame {
                rtr: true,
                len: 6,
                ..can_frame(0x100, &[])
            },
            StoredFrame {
                fd: true,
                brs: true,
                esi: true,
                ..can_frame(0x101, &[1, 2])
            },
            can_frame(0x102, &[3]),
        ];
        store.insert_frames("c1", &frames).await.unwrap();
        store.copy_capture_data("c1", "c2").await.unwrap();

        for capture in ["c1", "c2"] {
            let (read, _, _) = store
                .get_frames_paginated_filtered(capture, 0, 10, &whole("can"))
                .await
                .unwrap();
            assert_eq!(
                read.iter()
                    .map(|f| (f.rtr, f.fd, f.brs, f.esi, f.len))
                    .collect::<Vec<_>>(),
                [
                    (true, false, false, false, 6),
                    (false, true, true, true, 2),
                    (false, false, false, false, 1)
                ],
                "{capture}"
            );
        }
    }

    #[tokio::test]
    async fn a_frame_keeps_its_crc_verdict_through_copy() {
        let store = store().await;
        let frames = [false, true].map(|valid| StoredFrame {
            crc_valid: Some(valid),
            ..can_frame(0x0103, &[1])
        });
        store.insert_frames("c1", &frames).await.unwrap();
        store.copy_capture_data("c1", "c2").await.unwrap();

        assert_eq!(store.get_all_frames("c2").await.unwrap(), frames);
    }

    #[tokio::test]
    async fn deleting_capture_data_removes_its_events() {
        let store = multi_protocol_capture().await;
        store
            .insert_capture_event("c1", &event(10, 0, "gone"))
            .await
            .unwrap();
        store
            .insert_capture_event("c2", &event(10, 0, "kept"))
            .await
            .unwrap();

        store.delete_capture_data("c1").await.unwrap();

        assert_eq!(event_count(&store, "c1").await, 0);
        assert_eq!(event_count(&store, "c2").await, 1);
        assert_eq!(count(&store, "SELECT COUNT(*) FROM frames").await, 0);
    }

    #[tokio::test]
    async fn copying_a_capture_copies_its_events() {
        let store = multi_protocol_capture().await;
        store
            .insert_capture_event("c1", &event(10, 3, "first"))
            .await
            .unwrap();
        store
            .insert_capture_event("c1", &event(40, 0, "second"))
            .await
            .unwrap();

        let copied_rows = store.copy_capture_data("c1", "c1_copy").await.unwrap();
        assert_eq!(copied_rows, 4, "events are not counted as data rows");

        let copied = store.list_capture_events("c1_copy").await.unwrap();
        assert_eq!(
            copied.iter().map(|e| e.note.as_str()).collect::<Vec<_>>(),
            ["first", "second"]
        );
        assert_eq!(copied[0].duration_us, 3);
        assert_eq!(event_count(&store, "c1").await, 2);
    }

    #[tokio::test]
    async fn a_sweep_removes_non_persistent_and_orphaned_rows() {
        let store = multi_protocol_capture().await;
        execute(
            &store,
            "INSERT INTO capture_metadata (capture_id, capture_kind, name, created_at, persistent)
             VALUES ('pinned', 'frames', 'pinned', 0, 1), ('ephemeral', 'frames', 'ephemeral', 0, 0);
             INSERT INTO bytes (capture_id, byte_val, timestamp_us) VALUES ('pinned', 1, 1), ('ephemeral', 2, 2);",
        )
        .await;
        store
            .insert_capture_event("pinned", &event(1, 0, "survives"))
            .await
            .unwrap();
        store
            .insert_capture_event("ephemeral", &event(1, 0, "swept"))
            .await
            .unwrap();
        store
            .insert_capture_event("no_metadata", &event(1, 0, "orphan"))
            .await
            .unwrap();

        store.sweep_non_persistent().await.unwrap();

        assert_eq!(event_count(&store, "pinned").await, 1);
        assert_eq!(event_count(&store, "ephemeral").await, 0);
        assert_eq!(event_count(&store, "no_metadata").await, 0);
        assert_eq!(
            count(
                &store,
                "SELECT COUNT(*) FROM frames WHERE capture_id = 'c1'"
            )
            .await,
            0,
            "c1 has no metadata row"
        );
        assert_eq!(count(&store, "SELECT COUNT(*) FROM bytes").await, 1);
        assert_eq!(
            count(&store, "SELECT COUNT(*) FROM capture_metadata").await,
            1
        );
    }
}
