use axum::body::Body;
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};

/// `body` as a download a browser saves under `filename` rather than renders,
/// marked `no-store` so nothing between keeps it.
///
/// `filename` is sent as an RFC 9110 quoted string. A name a header cannot
/// carry, such as one with a control character, falls back to `download`
/// rather than failing the request.
pub fn attachment(content_type: &'static str, filename: &str, body: impl Into<Body>) -> Response {
    let quoted = filename.replace('\\', "\\\\").replace('"', "\\\"");
    let disposition = HeaderValue::from_str(&format!("attachment; filename=\"{quoted}\""))
        .unwrap_or_else(|_| HeaderValue::from_static("attachment; filename=\"download\""));
    (
        [
            (header::CONTENT_TYPE, HeaderValue::from_static(content_type)),
            (header::CONTENT_DISPOSITION, disposition),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
        body.into(),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn disposition(filename: &str) -> HeaderValue {
        attachment("text/plain", filename, "").headers()[header::CONTENT_DISPOSITION].clone()
    }

    #[test]
    fn a_download_names_its_file_and_asks_not_to_be_kept() {
        let response = attachment("application/json", "box-backup.json", "{}");
        let headers = response.headers();
        assert_eq!(headers[header::CONTENT_TYPE], "application/json");
        assert_eq!(
            headers[header::CONTENT_DISPOSITION],
            "attachment; filename=\"box-backup.json\""
        );
        assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    }

    #[test]
    fn a_quote_in_the_name_is_escaped_and_a_name_no_header_carries_falls_back() {
        assert_eq!(
            disposition(r#"a "b" \c"#),
            r#"attachment; filename="a \"b\" \\c""#
        );
        assert_eq!(disposition("a\nb"), "attachment; filename=\"download\"");
    }
}
