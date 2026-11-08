# Changelog

## 0.1.2

- `Docker::events`: the events from `since` to `until` that pass an
  `EventFilters` (type, event, label, container), as `Event`s with their
  `EventActor`'s ID and attributes.
- Dependency floors raised to match the crates it shares a graph with:
  bytes 1.7.1, futures-util 0.3.34, hyper 1.8, hyper-util 0.1.18, tokio
  1.47, tokio-util 0.7.19.

## 0.1.1

- Builds on Windows, where `Docker` and `exchange` talk to a named pipe,
  `\\.\pipe\docker_engine` by default. `testing` is Unix only.

## 0.1.0

- `Docker`: the Docker Engine over its Unix socket, API version 1.44.
  `ping`, `image`, `container`, `network` (inspection as JSON, `None` when
  absent), `create_network`, `create`, `start`, `stop`, `stop_for_good`,
  `remove`, `remove_image`, `load` (a streamed archive, giving the
  references loaded) and `pull` (one image). Calls wait 60 s, loads and
  pulls 10 min, both settable.
- `DockerError` keeps `Unreachable`, `Http`, `Timeout`, `Refused`, `Json`
  and `Name` apart; names that would change a request's path are refused
  before sending.
- `exchange`: one HTTP/1.1 request over a Unix socket with a deadline;
  hyper's `Request`, `Method`, `StatusCode` and `header` re-exported for it.
- `ImageReference` and `Pin`: references as `docker pull` takes them, with
  `registry()`. Always present; everything else is behind the default
  `client` feature.
- `trust::RegistryTrust`: extra authorities in `certs.d/<registry>/`.
- `testing::FakeEngine` behind the `testing` feature: recorded requests,
  answers by method and path, and held requests.
