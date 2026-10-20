/// How the bus says nobody owns a name: not installed (no service file), or
/// installed with its unit disabled or masked, which dbus-daemon relays in
/// systemd's words and dbus-broker as the last one.
pub const NOBODY_OWNS_IT: [&str; 4] = [
    "org.freedesktop.DBus.Error.ServiceUnknown",
    "org.freedesktop.systemd1.NoSuchUnit",
    "org.freedesktop.systemd1.UnitMasked",
    "org.freedesktop.DBus.Error.NameHasNoOwner",
];

/// How bus policy or polkit refuses a caller; `InteractiveAuthorizationRequired`
/// when polkit would have asked, had the call been interactive.
pub const REFUSALS: [&str; 2] = [
    "org.freedesktop.DBus.Error.AccessDenied",
    "org.freedesktop.DBus.Error.InteractiveAuthorizationRequired",
];

/// Whether a call came back as the D-Bus error `name`.
pub fn error_is(e: &zbus::Error, name: &str) -> bool {
    matches!(e, zbus::Error::MethodError(theirs, ..) if theirs.as_str() == name)
}

/// Whether a call failed because nobody owns the destination's name: a host
/// without that service, rather than a failed call.
pub fn nobody_owns(e: &zbus::Error) -> bool {
    NOBODY_OWNS_IT.iter().any(|name| error_is(e, name))
}

/// Whether the caller was refused permission, typically a process that is not
/// root.
pub fn refused(e: &zbus::Error) -> bool {
    REFUSALS.iter().any(|name| error_is(e, name))
}
