# wslib-mdns

DNS-SD on the local network: service types, subtypes, instance names and TXT
entries checked before anything is published, adverts that withdraw when
dropped and report where they stand, an in-process responder and browser over
mdns-sd, and avahi over D-Bus. A fake avahi for tests comes with the `testing`
feature.

```rust
use wslib_mdns::{AdvertState, Options, Responder, Service};

let responder = Responder::system(Options::default()).await?;
let mut service = Service::new("_https._tcp".parse()?, "Widget".parse()?, 443);
service.subtypes.push("_widget._sub._https._tcp".parse()?);
service.txt.push("product=widget".parse()?);
let advert = responder.advertise(&service).await?;
let mut state = advert.state();
state.wait_for(|s| !matches!(s, AdvertState::Registering)).await?;
// Dropping `advert` withdraws it.
```

## What's here

- **Names**, each with `FromStr` and `Display`, refused with an `Invalid`
  saying which rule broke. `ServiceType` is `_name._tcp` or `_name._udp`, the
  name as RFC 6335 has it (1 to 15 letters, digits and single hyphens, a
  letter among them), read with or without `.local.` and printed without.
  `Subtype` is `_name._sub.` and a service type. `InstanceName` is any UTF-8
  of 1 to 63 bytes without control characters. `Txt` is one `key=value`
  entry, the key printable ASCII other than `=`, 255 bytes in all.
  `HostName` is one `.local` label.
- **`Service`** to advertise, **`Resolved`** for what a browse finds
  (instance, host, port, addresses, TXT, with `txt(key)`), and
  **`BrowseEvent`**, `Resolved` or `Removed`.
- **`Advert`**: withdrawn when dropped, or by `withdraw().await`, which waits
  for the responder. `state()` is a watch of `AdvertState`: `Registering`,
  `Established`, `Collided` (down, and left down), `Renamed` (up under the
  name the responder chose), or `Failed`.
- **`InProcess`** (feature `in-process`): one mdns-sd daemon shared by its
  clones, on the `Interfaces` asked for (all, loopback, or those a test of the
  name accepts). `advertise` carries this host's addresses as they come and
  go, and maps mdns-sd's rename to `Renamed`; mdns-sd takes one subtype per
  advert. `browse` yields `BrowseEvent`s until dropped, one browse per type
  at a time, and `verify` asks an instance to answer or be removed.
  **`Host`**: beside avahi or mDNSResponder an advert must not claim the
  machine's own `<host>.local`, so the default host is
  `<host>-<program>.local`; `Host::System` is for a machine with no other
  responder.
- **`avahi::Avahi`** (feature `avahi`) on a `zbus::Connection`:
  `advertise` puts the service, its subtypes and TXT in an entry group on
  every interface and both protocols, under avahi's host name. avahi does not
  rename a D-Bus client's record, so a collision stays `Collided`. Another
  client here holding the name is `Error::Collision`.
- **`avahi::AddressGroup`**: A and AAAA records for one name on each
  `(interface index, address)`, with no reverse record, reporting collision.
- **`avahi::is_running`**, **`host_name`**, **`set_host_name`** (root or
  `netdev`), **`restarts`** (`NameOwnerChanged`, `true` when an avahi takes
  the name) and **`server_states`**. **`renamed_by_avahi(label, called)`**:
  whether avahi's collision rename turns `label` into `called`.
- **`Responder`** (both features): avahi when anything owns
  `org.freedesktop.Avahi` on the system bus, otherwise in process.
- **`testing::FakeAvahi`** (feature `testing`, Unix only): served in-process
  over a socket pair. It records each call, holds the host name, collides a
  name on commit (`colliding`), refuses one as held locally (`taken`) or a
  method as not permitted (`refusing`), and from the test collides an
  established group, renames its host, sends a server state, restarts or
  stops.

## What isn't

Which name to advertise under and what to do about a collision: stored
settings, wording, which interfaces to leave out, reclaiming a renamed host
name and how often, watching addresses for an alias, and keeping app
listeners' adverts in step. Browsing through avahi, wide-area DNS-SD, and
more than one subtype in process.
