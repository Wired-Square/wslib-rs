# wslib-api-error

One error body on the wire for every HTTP API, so a frontend handles every
failure the same way:

```json
{ "error": "the username is already taken", "code": "username_taken" }
```

`error` is a sentence for a person. `code` is optional, `snake_case`, and the
app's own vocabulary; no status gets one by default. Any other fields sit
beside them.

```rust
use wslib_api_error::ApiError;
use wslib_api_error::extract::{Json, Path, method_not_allowed};

async fn rename(Path(id): Path<u64>, Json(body): Json<Rename>) -> Result<Json<User>, ApiError> {
    let user = store::user(id).await.map_err(|e| ApiError::internal("read the user", e))?;
    let user = user.ok_or_else(|| ApiError::not_found(format!("no such user: {id}")))?;
    if user.name == body.name {
        return Err(ApiError::conflict("that is already its name").with_code("unchanged"));
    }
    // ...
}

let app = Router::new()
    .route("/api/users/{id}", patch(rename))
    .method_not_allowed_fallback(method_not_allowed);
```

## What's here

- **`ApiErrorBody`**: the body, with `extra` flattened beside `error` and
  `code`. Feature `ts` derives its TypeScript with ts-rs 11.
- **`ApiError`**: a status, a body and headers. A constructor per common
  status (`bad_request`, `unauthorised`, `forbidden`, `not_found`,
  `method_not_allowed`, `conflict`, `payload_too_large`,
  `unsupported_media_type`, `unprocessable`, `too_many_requests` with
  `Retry-After`), then `with_code`, `with_field` and `with_header`.
  `internal(what, cause)` and `unavailable` answer "could not {what}" and log
  the cause through `tracing`, never sending it.
- **`extract`** (feature `axum`, on by default): `Json`, `Query` and `Path`
  whose rejections are `ApiError`s at axum's status (400, 413, 415 or 422),
  and `method_not_allowed` for `Router::method_not_allowed_fallback`.
  `ApiError` is an axum `IntoResponse` under the same feature.

Without `axum`, the crate is the body and the error alone, for a types crate
that generates the frontend's TypeScript.
