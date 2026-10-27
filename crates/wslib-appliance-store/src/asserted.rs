//! The roles this box keeps for callers a front door asserts by an id of its
//! own rather than as one of the store's accounts.
//!
//! **The front door names the caller; the box decides the role.** A row is
//! made the first time an id is seen, with the role the product gives on first
//! sight, and from then on the stored role is the answer: a kept role is
//! changed through these methods, not by editing the first-sight rule. A caller
//! the rule refuses is kept with no role, so an administrator can give it one,
//! and takes the rule's role once the rule gives one. The table belongs to this
//! box, and a backup does not carry it.
//!
//! An `id` is the front door's own, without the `ingress:` prefix a principal
//! carries.

use chrono::{DateTime, Utc};
use sqlx::Row;
use wslib_appliance_types::Role;

use crate::{Store, StoreError, now, row_stamp, stamp};

const TABLE: &str = "asserted_roles";

fn kept_role(row: &sqlx::sqlite::SqliteRow) -> Result<Option<Role>, StoreError> {
    row.try_get::<Option<&str>, _>("role")?
        .map(|role| {
            role.parse()
                .map_err(|e| StoreError::unreadable(TABLE, "role", e))
        })
        .transpose()
}

/// A caller a front door asserts, and the role this box keeps for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssertedCaller {
    pub source: String,
    pub id: String,
    pub username: String,
    pub display_name: Option<String>,
    /// `None` for a caller the first-sight rule refused and nobody has given a
    /// role since.
    pub role: Option<Role>,
    pub first_seen: DateTime<Utc>,
}

impl Store {
    /// The role kept for `source`'s caller `id`, its names brought up to date.
    ///
    /// With no row, or a row with no role, `first_sight` is stored and
    /// answered, `None` included; a kept role wins. A HostAdmin is kept as
    /// Admin. Writes only when there is something new to keep.
    pub async fn asserted_role(
        &self,
        source: &str,
        id: &str,
        username: &str,
        display_name: Option<&str>,
        first_sight: Option<Role>,
    ) -> Result<Option<Role>, StoreError> {
        let kept = sqlx::query(
            "SELECT username, display_name, role FROM asserted_roles WHERE source = ? AND id = ?",
        )
        .bind(source)
        .bind(id)
        .fetch_optional(self.pool())
        .await?;
        if let Some(row) = kept {
            let role = kept_role(&row)?;
            let current = row.try_get::<&str, _>("username")? == username
                && row.try_get::<Option<&str>, _>("display_name")? == display_name;
            if current && (role.is_some() || first_sight.is_none()) {
                return Ok(role);
            }
        }
        let row = sqlx::query(
            "INSERT INTO asserted_roles (source, id, username, display_name, role, first_seen) \
             VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (source, id) DO UPDATE SET \
             username = excluded.username, display_name = excluded.display_name, \
             role = COALESCE(asserted_roles.role, excluded.role) RETURNING role",
        )
        .bind(source)
        .bind(id)
        .bind(username)
        .bind(display_name)
        .bind(first_sight.map(|role| role.min(Role::Admin).as_str()))
        .bind(stamp(now()))
        .fetch_one(self.pool())
        .await?;
        kept_role(&row)
    }

    /// Every caller `source` has asserted here, by username.
    pub async fn asserted_callers(&self, source: &str) -> Result<Vec<AssertedCaller>, StoreError> {
        sqlx::query(
            "SELECT source, id, username, display_name, role, first_seen FROM asserted_roles \
             WHERE source = ? ORDER BY username, id",
        )
        .bind(source)
        .fetch_all(self.pool())
        .await?
        .iter()
        .map(|row| {
            Ok(AssertedCaller {
                source: row.try_get("source")?,
                id: row.try_get("id")?,
                username: row.try_get("username")?,
                display_name: row.try_get("display_name")?,
                role: kept_role(row)?,
                first_seen: row_stamp(row, TABLE, "first_seen")?,
            })
        })
        .collect()
    }

    /// Give `source`'s caller `id` `role`, a HostAdmin kept as Admin; `false`
    /// when it has never been seen.
    pub async fn set_asserted_role(
        &self,
        source: &str,
        id: &str,
        role: Role,
    ) -> Result<bool, StoreError> {
        let changed = sqlx::query("UPDATE asserted_roles SET role = ? WHERE source = ? AND id = ?")
            .bind(role.min(Role::Admin).as_str())
            .bind(source)
            .bind(id)
            .execute(self.pool())
            .await?
            .rows_affected();
        Ok(changed > 0)
    }

    /// Drop the role kept for `source`'s caller `id`, so it is next seen as
    /// new; `false` when it has never been seen.
    pub async fn forget_asserted_caller(&self, source: &str, id: &str) -> Result<bool, StoreError> {
        let forgotten = sqlx::query("DELETE FROM asserted_roles WHERE source = ? AND id = ?")
            .bind(source)
            .bind(id)
            .execute(self.pool())
            .await?
            .rows_affected();
        Ok(forgotten > 0)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::tests::store;

    pub(crate) async fn seen(store: &Store, id: &str, first_sight: Option<Role>) -> Option<Role> {
        store
            .asserted_role("ingress", id, id, Some("Mémber"), first_sight)
            .await
            .expect("asserted role")
    }

    #[tokio::test]
    async fn the_first_sight_role_is_kept_and_the_stored_one_wins_after() {
        let store = store().await;
        assert_eq!(
            seen(&store, "a1", Some(Role::Admin)).await,
            Some(Role::Admin)
        );
        assert_eq!(
            seen(&store, "a1", Some(Role::Viewer)).await,
            Some(Role::Admin)
        );
        assert_eq!(seen(&store, "a1", None).await, Some(Role::Admin));
    }

    #[tokio::test]
    async fn a_refused_caller_is_kept_and_listed_with_no_role() {
        let store = store().await;
        assert_eq!(seen(&store, "a1", None).await, None);
        let callers = store.asserted_callers("ingress").await.unwrap();
        assert_eq!(
            callers
                .iter()
                .map(|c| (c.id.as_str(), c.role))
                .collect::<Vec<_>>(),
            [("a1", None)]
        );
    }

    #[tokio::test]
    async fn a_refused_caller_takes_the_rules_role_once_it_gives_one_but_not_over_a_granted_one() {
        let store = store().await;
        seen(&store, "a1", None).await;
        assert_eq!(
            seen(&store, "a1", Some(Role::HostAdmin)).await,
            Some(Role::Admin)
        );
        assert_eq!(
            seen(&store, "a1", Some(Role::Viewer)).await,
            Some(Role::Admin)
        );

        seen(&store, "b1", None).await;
        assert!(
            store
                .set_asserted_role("ingress", "b1", Role::Viewer)
                .await
                .unwrap()
        );
        assert_eq!(
            seen(&store, "b1", Some(Role::Admin)).await,
            Some(Role::Viewer)
        );
    }

    #[tokio::test]
    async fn a_refused_caller_can_be_given_a_role_or_forgotten() {
        let store = store().await;
        seen(&store, "a1", None).await;
        assert!(
            store
                .set_asserted_role("ingress", "a1", Role::Operator)
                .await
                .unwrap()
        );
        assert_eq!(seen(&store, "a1", None).await, Some(Role::Operator));

        seen(&store, "b1", None).await;
        assert!(store.forget_asserted_caller("ingress", "b1").await.unwrap());
        let callers = store.asserted_callers("ingress").await.unwrap();
        assert_eq!(
            callers.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(),
            ["a1"]
        );
    }

    #[tokio::test]
    async fn the_names_follow_the_front_door_and_the_role_does_not() {
        let store = store().await;
        seen(&store, "a1", Some(Role::Operator)).await;
        let renamed = store
            .asserted_role("ingress", "a1", "member", None, Some(Role::Admin))
            .await
            .unwrap();
        assert_eq!(renamed, Some(Role::Operator));
        let callers = store.asserted_callers("ingress").await.unwrap();
        assert_eq!(callers.len(), 1);
        assert_eq!(
            (
                callers[0].username.as_str(),
                callers[0].display_name.as_deref()
            ),
            ("member", None)
        );
    }

    #[tokio::test]
    async fn a_kept_role_can_be_changed_and_a_host_admin_is_kept_as_admin() {
        let store = store().await;
        seen(&store, "a1", Some(Role::HostAdmin)).await;
        assert_eq!(seen(&store, "a1", None).await, Some(Role::Admin));
        assert!(
            store
                .set_asserted_role("ingress", "a1", Role::Viewer)
                .await
                .unwrap()
        );
        assert_eq!(
            seen(&store, "a1", Some(Role::Admin)).await,
            Some(Role::Viewer)
        );
        assert!(
            !store
                .set_asserted_role("ingress", "never", Role::Viewer)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn a_forgotten_caller_takes_its_first_sight_role_again() {
        let store = store().await;
        seen(&store, "a1", Some(Role::Admin)).await;
        assert!(store.forget_asserted_caller("ingress", "a1").await.unwrap());
        assert!(!store.forget_asserted_caller("ingress", "a1").await.unwrap());
        assert!(store.asserted_callers("ingress").await.unwrap().is_empty());
        assert_eq!(
            seen(&store, "a1", Some(Role::Viewer)).await,
            Some(Role::Viewer)
        );
    }

    #[tokio::test]
    async fn one_sources_ids_are_not_anothers() {
        let store = store().await;
        seen(&store, "a1", Some(Role::Admin)).await;
        let other = store
            .asserted_role("elsewhere", "a1", "a1", None, None)
            .await
            .unwrap();
        assert_eq!(other, None);
        assert_eq!(seen(&store, "a1", None).await, Some(Role::Admin));
        let elsewhere = store.asserted_callers("elsewhere").await.unwrap();
        assert_eq!(elsewhere.iter().map(|c| c.role).collect::<Vec<_>>(), [None]);
    }
}
