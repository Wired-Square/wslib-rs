//! The one spelling of an instant in the database: RFC 3339 in UTC, always six
//! subsecond digits, so every stamp has one width.
//!
//! The width is part of the schema: with a variable number of digits `…:00Z`
//! sorts after `…:00.5Z`, because `.` is below `Z`, and a column ordered or
//! compared as text stops being chronological.

use chrono::{DateTime, SecondsFormat, SubsecRound, Utc};
use sqlx::Row;
use sqlx::sqlite::SqliteRow;

use crate::Error;

pub fn format(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(SecondsFormat::Micros, true)
}

/// The current instant at the precision [`format()`] keeps, so a value handed to
/// a caller equals the same value read back.
pub fn now() -> DateTime<Utc> {
    Utc::now().trunc_subsecs(6)
}

/// Read a stamp; a malformed one is [`Error::Unreadable`] naming `table` and `what`.
pub fn parse(table: &'static str, what: &'static str, raw: &str) -> Result<DateTime<Utc>, Error> {
    DateTime::parse_from_rfc3339(raw)
        .map(|t| t.with_timezone(&Utc))
        .map_err(|e| Error::Unreadable {
            table,
            what,
            because: e.to_string(),
        })
}

/// [`parse()`] straight off a row, borrowing the column rather than allocating it.
pub fn from_row(
    row: &SqliteRow,
    table: &'static str,
    column: &'static str,
) -> Result<DateTime<Utc>, Error> {
    parse(table, column, row.try_get::<&str, _>(column)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_instant_is_stored_in_a_form_that_sorts_chronologically() {
        let whole = format(DateTime::from_timestamp(1_757_000_000, 0).unwrap());
        let fraction = format(DateTime::from_timestamp(1_757_000_000, 500_000_000).unwrap());

        assert_eq!(whole, "2025-09-04T15:33:20.000000Z");
        assert!(whole < fraction, "{whole} must sort before {fraction}");
        assert_eq!(whole.len(), fraction.len());
    }

    #[test]
    fn an_instant_survives_the_round_trip() {
        let at = DateTime::from_timestamp(1_757_000_000, 123_456_000).unwrap();
        assert_eq!(parse("t", "at", &format(at)).unwrap(), at);
        assert!(matches!(
            parse("t", "at", "yesterday"),
            Err(Error::Unreadable {
                table: "t",
                what: "at",
                ..
            })
        ));
    }

    #[test]
    fn now_round_trips_exactly() {
        let at = now();
        assert_eq!(parse("t", "at", &format(at)).unwrap(), at);
    }
}
