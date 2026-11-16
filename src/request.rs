//! Validation shared by the HTTP/2 and HTTP/3 request decoders.

use http::header::HeaderName;

/// Field names that are connection-specific and therefore illegal in
/// HTTP/2 and HTTP/3 requests (RFC 9113 Section 8.1.2.2, RFC 9114
/// Section 4.2).
const CONNECTION_SPECIFIC: [&[u8]; 5] = [
    b"connection",
    b"keep-alive",
    b"proxy-connection",
    b"transfer-encoding",
    b"upgrade",
];

/// `TE` is the one connection-specific field allowed through, and only
/// when it asks for trailers.
#[inline]
fn te_is_trailers(value: &[u8]) -> bool {
    std::str::from_utf8(value).ok().is_some_and(|value| {
        value
            .split(',')
            .all(|part| part.trim().eq_ignore_ascii_case("trailers"))
    })
}

/// Whether a regular request field violates the connection-specific
/// header rules.
#[inline]
pub(crate) fn is_invalid_field(name: &[u8], value: &[u8]) -> bool {
    CONNECTION_SPECIFIC
        .iter()
        .any(|forbidden| name.eq_ignore_ascii_case(forbidden))
        || (name.eq_ignore_ascii_case(b"te") && !te_is_trailers(value))
}

/// Parses a `content-length` value: bare digits, optionally framed by
/// optional whitespace. Anything else (including overflow) is invalid.
#[inline]
pub(crate) fn parse_content_length(value: &[u8]) -> Option<u64> {
    let start = value
        .iter()
        .position(|byte| *byte != b' ' && *byte != b'\t')?;
    let end = value
        .iter()
        .rposition(|byte| *byte != b' ' && *byte != b'\t')
        .unwrap_or(start);
    let value = &value[start..=end];
    if value.is_empty() || value.iter().any(|byte| !byte.is_ascii_digit()) {
        return None;
    }
    let mut result: u64 = 0;
    for &byte in value {
        result = result
            .checked_mul(10)
            .and_then(|n| n.checked_add(u64::from(byte - b'0')))?;
    }
    Some(result)
}

/// Converts a wire field name to a [`HeaderName`]. Uppercase letters are
/// rejected rather than normalized (RFC 9113 Section 8.1.2.1).
#[inline]
pub(crate) fn field_name(name: &[u8]) -> Option<HeaderName> {
    if name.iter().any(u8::is_ascii_uppercase) {
        return None;
    }
    HeaderName::from_bytes(name).ok()
}
