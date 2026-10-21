# wslib-docker

A Docker Engine client over its Unix socket, by hyper with no bollard:
inspect, create, start, stop and remove containers, networks and images, and
load or pull images. Image references parsed as `docker pull` takes them.
Registry trust kept in `certs.d`. A fake engine for tests comes with the
`testing` feature. Unix only.

```rust
let docker = wslib_docker::Docker::default();
let busybox = wslib_docker::ImageReference::parse("busybox:1.37").unwrap();
let pulled = docker.pull(&busybox).await?;
if docker.container("hello").await?.is_none() {
    docker.create("hello", &serde_json::json!({"Image": pulled})).await?;
}
docker.start("hello").await?;
```

## What's here

- **`Docker`**: the engine at `/var/run/docker.sock` by default
  (`with_socket` for another), every path under API version 1.44
  (`Docker::API_VERSION`), the oldest Docker 29 accepts. `ping`; `image`,
  `container` and `network` inspect as `serde_json::Value`, with `None` for
  what the engine doesn't have; `create_network` and `create` take the
  engine's request body as JSON; `start` and `stop` succeed when it is
  already so; `stop_for_good` drops the restart policy, then stops;
  `remove` forces; `remove_image`. `load` streams a `docker save` archive
  and gives the references loaded. `pull` takes one `ImageReference`, never
  every tag of it, and gives the reference to inspect it by. Calls wait 60 s
  and loads and pulls 10 min, both settable. A load's or a pull's progress
  is read whole; an error anywhere in it fails the call.
- **`DockerError`** keeps `Unreachable` (no socket, or no permission),
  `Http`, `Timeout`, `Refused` (the engine's status and message; status 200
  for an error inside a progress stream), `Json` and `Name` apart. Nothing
  is logged.
- **Names are checked, not escaped**: a name or reference with a character
  no engine object has, or a `.`, `..` or empty path segment, is a
  `DockerError::Name` and nothing is sent.
- **`exchange`**: one HTTP/1.1 request to whatever serves a Unix socket,
  with a deadline, for the other daemons an app talks to that way.
- **`ImageReference`**: `repository`, `repository:tag` or
  `repository@sha256:…`, with no tag read as `latest`. The repository is
  checked by the engine's rules (lowercase path components, a host with an
  optional port, 255 bytes at most), the tag by its 128-byte rule; sha256
  digests only, and a tag together with a digest is refused. `registry()`
  is Docker Hub unless the first part names a host.
- **`trust::RegistryTrust`**: extra authorities for the engine. The engine
  reads a registry's authorities from `certs.d/<registry>/*.crt` alone, so
  `set_authorities` writes the bundle into every registry added, and
  `add_registry` before a pull adds one. Files are 0600 and written whole
  (`wslib-file-atomic`); no authorities removes them. Link
  `/etc/docker/certs.d` to `certs_d()`.
- **`testing::FakeEngine`** (feature `testing`): an HTTP/1.1 server on a
  socket path that records each request as `Seen` and answers it with
  `answer(method, uri)`. `holding` keeps requests under a prefix waiting
  until `release`. `docker()` is a client for it. It answers anything, so it
  also fakes other daemons reached through `exchange`.

## What isn't

Typed inspection results, streaming pull progress to a caller, exec,
logs, events, volumes, registry login, compose. Container specs are the
caller's JSON. Windows named pipes.
