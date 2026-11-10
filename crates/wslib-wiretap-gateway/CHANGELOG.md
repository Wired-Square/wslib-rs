# Changelog

## 0.2.2

- `TimeRangeQuery::bus` asks `/inventory` for one bus's rows, and
  `QuerySpec::FrameInventory` carries it; `InventoryEntry::bus` is absent from
  gateways that group every bus together. Struct literals of `InventoryEntry`
  and `TimeRangeQuery` gain the field.

## 0.2.1

- serde's floor is 1.0.228.

## 0.2.0

- `client`, off by default: `GatewayClient`, its `Db` and `FrameCursor`, and
  the admin calls, moved from `wiretap-gateway` at v0.10.2. The requests and
  bodies it sends are unchanged. It runs on reqwest 0.12 with no TLS backend;
  the app enables one.
- `InventoryEntry::max_len_for`, under `client`.

## 0.1.0

- The gateway's HTTP types, moved from `wiretap-gateway` at v0.10.2: query
  results, the archive, events, activity, health and admin endpoints, the
  request bodies and query strings, `QuerySpec` and its request. The JSON and
  the TS declarations are unchanged.
- `Protocol` is wslib-wiretap-protocol's archive `Protocol`, re-exported: the
  same serde (`can`, `modbus`, `serial`) and TS name (`ArchiveProtocol`), with
  `ModbusRtu` for the old `Modbus` variant.
- The admin types say catalogue (`ActiveCatalogue`, `AssignCatalogue`,
  `CatalogueFinding` and the rest), each keeping its TS name.
- Left behind: the SQLite row filter (`FrameRowFilter`, `CaptureProtocol`,
  `QuerySpec::row_filters`), which belongs to the capture store, and the HTTP
  client, which comes later.
