use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Deserializer, Serializer, de, ser};

pub(crate) fn serialize<S: Serializer>(span: &Duration, serializer: S) -> Result<S::Ok, S::Error> {
    let micros = u64::try_from(span.as_micros())
        .map_err(|_| ser::Error::custom("a span over u64::MAX microseconds"))?;
    serializer.serialize_u64(micros)
}

pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Duration, D::Error> {
    u64::deserialize(deserializer).map(Duration::from_micros)
}

pub(crate) mod since_epoch {
    use super::*;

    pub(crate) fn serialize<S: Serializer>(
        at: &SystemTime,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let since = at
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ser::Error::custom("a time before the Unix epoch"))?;
        super::serialize(&since, serializer)
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<SystemTime, D::Error> {
        let since = super::deserialize(deserializer)?;
        UNIX_EPOCH
            .checked_add(since)
            .ok_or_else(|| de::Error::custom("a time this platform cannot hold"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(json: &str) -> Result<SystemTime, serde_json::Error> {
        since_epoch::deserialize(&mut serde_json::Deserializer::from_str(json))
    }

    fn write(at: SystemTime) -> Result<String, serde_json::Error> {
        let mut out = Vec::new();
        since_epoch::serialize(&at, &mut serde_json::Serializer::new(&mut out))?;
        Ok(String::from_utf8(out).unwrap())
    }

    #[test]
    fn the_largest_time_read_is_a_time_or_an_error_never_a_panic() {
        let largest = Duration::from_micros(u64::MAX);
        match (read(&u64::MAX.to_string()), UNIX_EPOCH.checked_add(largest)) {
            (Ok(at), Some(held)) => assert_eq!(at, held),
            (Err(error), None) => assert!(error.to_string().contains("cannot hold")),
            (got, held) => panic!("{got:?} against {held:?}"),
        }
    }

    #[test]
    fn a_time_before_the_epoch_or_past_u64_microseconds_is_an_error_to_write() {
        let before = UNIX_EPOCH - Duration::from_secs(1);
        assert!(write(before).is_err());
        let past = Duration::from_secs(u64::MAX / 1_000_000 + 1);
        if let Some(far) = UNIX_EPOCH.checked_add(past) {
            assert!(write(far).is_err());
        }
        assert_eq!(write(UNIX_EPOCH + Duration::from_micros(7)).unwrap(), "7");
    }
}
