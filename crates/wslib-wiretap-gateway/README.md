# wslib-wiretap-gateway

A capture gateway's HTTP API as serde types, the JSON both ends agree on. It
touches no database, and opens no connection unless `client` is on: a server
maps its rows into these, and a client sends and reads them.

- `query`: the nine analytical results with their `QueryStats`.
- `archive`: the inventory, time bounds, the `/frames` cursor batch,
  `/payloads` and the import result.
- `events`: `Event`, and the `NewEvent` and `EventPatch` a client sends.
- `activity`: `pg_stat_activity` rows and the cancel or terminate answer.
- `server`: `Health`, the database list and `ErrorBody`.
- `params`: `FrameFilter`, the query and `/payloads` bodies that flatten it,
  the `GET` query strings, and `Protocol`, wslib-wiretap-protocol's archive
  protocol.
- `spec`: `QuerySpec`, the ten queries as one value tagged by `type`, bounds in
  µs; `request` turns one into the gateway's path and body.
- `admin`: the daemons and their devices, catalogue assignment and the stored
  catalogues.
- `client`: an HTTP client for all of it, under the `client` feature.

A field's name, type and order are the contract. No type refuses an unknown
field, so a newer gateway can add one. A request whose `protocol` is `None`
leaves the key out, which the gateway reads as CAN.

## The admin API

All admin role. A SHA is the catalogue's git blob SHA-1, as 40 lowercase hex
characters, and timestamps are epoch µs.

| endpoint | body | answers |
|----------|------|---------|
| `GET /v1/admin/daemons` | | 200 `DaemonList` |
| `PUT /v1/admin/assignments` | `AssignCatalogue` | 200 `AssignedCatalogue`, 400 `CatalogueRejected`, 409 `AssignmentConflict` |
| `DELETE /v1/admin/assignments?daemon_id&interface&expected` | `UnassignParams` | 204, 409 `AssignmentConflict` |
| `GET /v1/admin/catalogs/{sha}` | | 200 `StoredCatalogue` |

`expected` guards a `PUT` or `DELETE` against a concurrent change. A SHA must
match the one assigned now; `""` means "only if this interface is
unassigned"; absent means no guard. On a mismatch the answer is 409, and its
`current` is the SHA assigned now (`null` for none).

A 400's `findings` and a 200's `warnings` are `CatalogueFinding`s, the same
JSON as a catalogue's validation finding (`{ "field", "message" }`).

## The client

`GatewayClient` holds a base URL and a key, sent as a bearer token unless
empty. Its clones, and those from `with_endpoint`, share one connection pool
and one registry of running queries, which `cancel` reaches by query id
whichever gateway runs it. `db(name, protocol)` reads one database as one
protocol: inventory, payloads, time bounds, events, import, activity, the
queries and a `FrameCursor` over `/frames`. The admin API is `daemons`,
`stored_catalogue`, `assign_catalogue` and `unassign_catalogue`, the last two
answering an `AssignOutcome`: `Done` with any warnings, `Rejected` with its
findings, or `Conflict` with the SHA assigned now. A failure is a
`ClientError`, whose text is the gateway's own `error` when it sent one.

## Features

None is on by default.

- `ts`: derives `ts_rs::TS` on every public serde type under the names its
  consumers import: `Protocol` as `ArchiveProtocol`, `ImportResult` as
  `ArchiveImportResult`, and each `…Catalogue…` admin type as its `…Catalog…`
  name.
- `client`: the client, on reqwest 0.12 and the caller's tokio runtime. It
  brings no TLS backend; the app enables one on reqwest for `https://`, and
  Cargo unifies it in.

```toml
wslib-wiretap-gateway = { version = "0.2", registry = "wired-square", features = ["client"] }
reqwest = { version = "0.12", default-features = false, features = ["rustls-tls"] }
```
