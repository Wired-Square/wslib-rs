# wslib-appliance-client

For a Windows desktop app: connects to an appliance's control pipe, served
by `wslib-appliance-service`, and refuses a pipe its service does not own.

**`connect(pipe, service)`** opens `\\.\pipe\…` on this machine and returns
the Tokio `NamedPipeClient` once the pipe's owner is `NT SERVICE\<service>`.
Any process can create a pipe by that name first, so a pipe owned by anyone
else, SYSTEM included, is refused. The connection is opened at
identification level, so a squatter cannot act as the user. An administrator
can set any owner, so this stops only unprivileged squatters.

`ConnectError` says why there is no connection: not a local pipe, the
service not running, busy for two seconds, this user refused by the pipe's
security, a pipe the service does not own, or an OS error.

The crate is empty on every other target, so a cross-platform client may
depend on it unconditionally. It brings in no axum, sqlx or rustls.
