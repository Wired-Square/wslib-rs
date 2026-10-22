use std::str::FromStr;

use zbus::zvariant::{OwnedValue, Value};

use crate::Group;

pub(crate) fn prop<T: TryFrom<OwnedValue>>(group: &Group, key: &str) -> Option<T> {
    T::try_from(group.get(key)?.clone()).ok()
}

pub(crate) fn text(group: &Group, key: &str) -> Option<String> {
    prop(group, key)
}

pub(crate) fn number(group: &Group, key: &str) -> Option<u32> {
    prop(group, key)
}

/// An `aa{sv}` property's entries.
pub(crate) fn entries(group: &Group, key: &str) -> Vec<Group> {
    prop(group, key).unwrap_or_default()
}

pub(crate) fn owned(value: Value<'_>) -> OwnedValue {
    OwnedValue::try_from(value).expect("a value without file descriptors converts")
}

/// One interface's or setting group's properties from `(name, value)` pairs;
/// panics on a file descriptor.
pub fn group<'a>(pairs: impl IntoIterator<Item = (&'a str, Value<'a>)>) -> Group {
    pairs
        .into_iter()
        .map(|(key, value)| (key.to_string(), owned(value)))
        .collect()
}

/// The `address`/`prefix` pairs of an `AddressData` or `address-data` list.
pub(crate) fn addresses<A: FromStr>(group: &Group, key: &str) -> Vec<crate::Address<A>> {
    entries(group, key)
        .iter()
        .filter_map(|entry| {
            Some(crate::Address {
                address: text(entry, "address")?.parse().ok()?,
                prefix: u8::try_from(number(entry, "prefix")?).ok()?,
            })
        })
        .collect()
}
