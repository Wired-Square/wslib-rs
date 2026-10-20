# Changelog

## 0.1.0

- zbus 5 proxies, tokio only: `SystemdProxy` and `UnitProxy`
  (`org.freedesktop.systemd1`) with `UnitRow`, `HostnameProxy`,
  `TimedateProxy`, `TimesyncProxy` and `Login1Proxy`, declaring only the
  members a consumer uses.
- `error_is`, `nobody_owns` and `refused` read a `zbus::Error`; the names
  they match are `NOBODY_OWNS_IT` and `REFUSALS`. No logging.
- `clean_hostname` trims and validates a hostname as RFC 1123 labels within
  `MAX_HOSTNAME_LEN` (63) bytes, refusing with a `HostnameError` that names
  the rule.
- `testing::Fakes` behind the `testing` feature, on Unix: serves interface
  objects at paths over a peer-to-peer socket pair.
