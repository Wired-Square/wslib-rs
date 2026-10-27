# Changelog

## 0.1.1

Moved from `appliance-core` 0.17.1 in wslib-appliance-rs; what differs:

- No rustls crypto provider is enabled or installed: the consumer installs
  one before serving. `Chassis::build`, and loading or minting the serving
  pair, refuse with the new `ServeError::NoCryptoProvider` when none is
  installed, where 0.17.1 installed ring itself.
  `backend::install_crypto_provider` is gone. `tls::pair_at` needs one too: an offline backup in its own
  process without one fails as `TlsError::Internal`. So do `testing`'s TLS
  peers, `Authority` and `self_signed`.
- `box_id` takes its HMAC-SHA256 from `hmac` and `sha2` instead of `ring`:
  the same id for the same machine.
- The log ring captures `wslib_appliance_*`, `wslib_db_sqlite`,
  `wslib_http_server` and `wslib_tls`, and no longer `appliance_*`. This
  crate's own events, the `audit` ones included, are under the
  `wslib_appliance_core` target (was `appliance_core`).
- The `test-support` feature is `testing`. `testing::TempDir` is gone: use
  `tempfile`. `testing::group_of` is defined here, and
  `testing::assert_sentences` is new. `backend::minted_in` takes any
  `AsRef<Path>`.
- A reserved name in an ingress caller's identity, or in the
  `Appliance-Identity` a console or hooks caller asserts, is refused as "a
  user name reserved for the appliance" (was "for the chassis").
- The `sessions` feature turns on nothing else: `wslib-appliance-auth`
  always carries `Sessions`.
- `files` is gone. `keep_mode` is `wslib_file_atomic::keep_mode` (0.1.6),
  which returns the bits it replaced and logs nothing, so the caller writes
  the "was/now" line. `attachment` is `wslib_http_scaffold::attachment`
  (0.1.3), which escapes `\` and `"` in the filename, where 0.17.1's sent
  them as they were, so a `"` ended the quoted name early and a `\` escaped
  what followed.
- On Windows, serving an endpoint `owned_by_service` a name that is no
  installed service's own account, such as `ALL SERVICES` or one containing
  `\` or `/`, fails as "the socket at … could not be created: no service
  account NT SERVICE\<name>: it is not one installed service's account".
