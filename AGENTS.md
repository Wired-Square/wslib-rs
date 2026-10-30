# wslib-rs

Shared Rust crates for Wired Square projects, published to the private
`wired-square` Cargo registry (never crates.io). `README.md` covers using and
publishing them.

## Layout

- One workspace, `crates/*`, edition 2024, MSRV 1.99, MIT.
- Each crate keeps its own `version` and `CHANGELOG.md`; nothing is lockstep.
  The `wslib-appliance` facade pins every family member with `=` at its
  current version, so it is bumped with any member. A family crate pins
  `wslib-appliance-core` with `=`.
- A dependency on a sibling names `path`, `version` and
  `registry = "wired-square"`. The dependency is published before its
  dependant.
- Neighbouring crates share a prefix (`wslib-auth-*`, `wslib-http-*`). A crate
  stays unprefixed only while it has no neighbour.

## Gates

- `scripts/ci.sh` is the CI, and the pre-push hook runs it
  (`git config core.hooksPath scripts/hooks`). By default it checks the crates
  changed since their last tag, plus their dependants.
- `scripts/ci.sh --tag` checks every crate, including each crate's direct
  dependency floors on nightly (`-Z direct-minimal-versions`). A release runs
  it first.
- The floor check resolves siblings by path, so a sibling floor that is too
  low still passes. Check the sibling's CHANGELOG for the API you use.
  Where crates meet in one graph, their floors for a shared dependency agree;
  raise the lower floor rather than lower the higher one.
- Pins for transitive floors live in `scripts/floor-pins.txt`.

## Rules

- Australian English everywhere, identifiers included: colour, behaviour,
  serialise, licence.
- No consumer is named in the tree or in a commit message
  (`scripts/forbidden-names.txt`; ci.sh enforces it). State the constraint,
  not who has it.
- No links into the project's notes (`[[...]]`; ci.sh enforces it). Say what
  the code needs in the code.
- Comments only for what the code cannot say: a non-obvious why, an invariant,
  an external spec. Public docs are one sentence unless the contract is
  subtle.
- A dependency earns its place: security-critical code, a spec we would
  otherwise track, a platform binding, the ecosystem's foundation, or more
  than an afternoon's work. Otherwise write it. Turn off default features you
  don't use.
- No crate enables a rustls crypto provider by default; the app installs one.
- Storage goes through sqlx. A crate that stores ships its sqlx stores behind
  `sqlite` / `postgres` features and leaves migrations to the app. Only the
  `wslib-appliance-*` family may keep one concrete SQLite store.
- A crate that ships non-Rust sources gets a † in the README table and a
  "Not pure Rust" line in its own README.
- A new crate is trialled before its first publish: one consumer adopts it by
  path dependency on a branch and reports back. That path dependency never
  merges.

## Changes and releases

- Work goes on a branch and lands through a squash-merged PR.
- Commit messages: an imperative subject under about 70 characters, and a body
  only when the why needs one.
- The version bump and its CHANGELOG entry move in the PR. The CHANGELOG
  heading is the version itself, with no "unreleased" marker. A new crate
  starts at 0.1.0.
- A release runs from `main` after the merge. `scripts/release.sh <crate> ...
  --execute` tags the crates named, pushes the tags, publishes and mirrors
  the registry. Every published version has its tag on `main`.
