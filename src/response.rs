use http::header::{self, HeaderMap, HeaderName};

/// Request/response header fields that describe a single connection and
/// are therefore illegal in HTTP/2 and HTTP/3 messages (RFC 9113
/// Section 8.1.2.2, RFC 9114 Section 4.2).
pub(crate) const CONNECTION_SPECIFIC: [HeaderName; 5] = [
    HeaderName::from_static("keep-alive"),
    HeaderName::from_static("proxy-connection"),
    header::CONNECTION,
    header::TRANSFER_ENCODING,
    header::UPGRADE,
];

/// Removes connection-specific fields from a response or trailer block,
/// keeping `TE` only when it asks for trailers.
#[inline]
pub(crate) fn sanitize_response_headers(headers: &mut HeaderMap) {
    for name in &CONNECTION_SPECIFIC {
        headers.remove(name);
    }
    if headers
        .get(header::TE)
        .is_some_and(|value| value != "trailers")
    {
        headers.remove(header::TE);
    }
}
