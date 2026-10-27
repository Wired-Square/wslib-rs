//! The response half of the encoder cap, for a handler serving a body stored
//! compressed: call `wslib_http_scaffold::restore_accept_encoding` before
//! choosing, and pass the response through [`negotiated`].

use axum::http::{HeaderValue, header};
use axum::response::Response;

/// A response whose encoding follows the request's `Accept-Encoding`: `Vary`
/// names that header, and a body stored encoded holds no permit.
pub(crate) fn negotiated(mut response: Response) -> Response {
    let headers = response.headers_mut();
    let varies = headers
        .get_all(header::VARY)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|name| {
            let name = name.trim();
            name == "*" || name.eq_ignore_ascii_case(header::ACCEPT_ENCODING.as_str())
        });
    if !varies {
        headers.append(header::VARY, HeaderValue::from_static("accept-encoding"));
    }
    wslib_http_scaffold::mark_stored(response)
}

#[cfg(test)]
mod tests {
    use axum::body::Body;

    use super::*;

    #[test]
    fn a_negotiated_response_adds_to_a_vary_it_already_had_and_never_repeats_it() {
        let varying = |values: &[&'static str]| {
            let mut response = Response::new(Body::empty());
            for value in values {
                response
                    .headers_mut()
                    .append(header::VARY, HeaderValue::from_static(value));
            }
            let response = negotiated(response);
            response
                .headers()
                .get_all(header::VARY)
                .iter()
                .map(|v| v.to_str().expect("ascii").to_owned())
                .collect::<Vec<_>>()
        };

        assert_eq!(varying(&[]), ["accept-encoding"]);
        assert_eq!(varying(&["origin"]), ["origin", "accept-encoding"]);
        assert_eq!(
            varying(&["Origin, Accept-Encoding"]),
            ["Origin, Accept-Encoding"]
        );
        assert_eq!(varying(&["*"]), ["*"]);
    }
}
