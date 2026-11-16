//! QPACK static table (RFC 9204 Appendix A).
//!
//! The 99 entries are identical for every connection. Names are lowercase
//! ASCII and values preserve their exact bytes from the RFC.

/// Number of entries in the static table (indices `0..99`).
pub(crate) const STATIC_TABLE_SIZE: usize = 99;

/// `(name, value)` pairs of the static table, by index.
const STATIC_TABLE: [(&[u8], &[u8]); STATIC_TABLE_SIZE] = [
    (b":authority", b""),
    (b":path", b"/"),
    (b"age", b"0"),
    (b"content-disposition", b""),
    (b"content-length", b"0"),
    (b"cookie", b""),
    (b"date", b""),
    (b"etag", b""),
    (b"if-modified-since", b""),
    (b"if-none-match", b""),
    (b"last-modified", b""),
    (b"link", b""),
    (b"location", b""),
    (b"referer", b""),
    (b"set-cookie", b""),
    (b":method", b"CONNECT"),
    (b":method", b"DELETE"),
    (b":method", b"GET"),
    (b":method", b"HEAD"),
    (b":method", b"OPTIONS"),
    (b":method", b"POST"),
    (b":method", b"PUT"),
    (b":scheme", b"http"),
    (b":scheme", b"https"),
    (b":status", b"103"),
    (b":status", b"200"),
    (b":status", b"304"),
    (b":status", b"404"),
    (b":status", b"503"),
    (b"accept", b"*/*"),
    (b"accept", b"application/dns-message"),
    (b"accept-encoding", b"gzip, deflate, br"),
    (b"accept-ranges", b"bytes"),
    (b"access-control-allow-headers", b"cache-control"),
    (b"access-control-allow-headers", b"content-type"),
    (b"access-control-allow-origin", b"*"),
    (b"cache-control", b"max-age=0"),
    (b"cache-control", b"max-age=2592000"),
    (b"cache-control", b"max-age=604800"),
    (b"cache-control", b"no-cache"),
    (b"cache-control", b"no-store"),
    (b"cache-control", b"public, max-age=31536000"),
    (b"content-encoding", b"br"),
    (b"content-encoding", b"gzip"),
    (b"content-type", b"application/dns-message"),
    (b"content-type", b"application/javascript"),
    (b"content-type", b"application/json"),
    (b"content-type", b"application/x-www-form-urlencoded"),
    (b"content-type", b"image/gif"),
    (b"content-type", b"image/jpeg"),
    (b"content-type", b"image/png"),
    (b"content-type", b"text/css"),
    (b"content-type", b"text/html; charset=utf-8"),
    (b"content-type", b"text/plain"),
    (b"content-type", b"text/plain;charset=utf-8"),
    (b"range", b"bytes=0-"),
    (b"strict-transport-security", b"max-age=31536000"),
    (
        b"strict-transport-security",
        b"max-age=31536000; includesubdomains",
    ),
    (
        b"strict-transport-security",
        b"max-age=31536000; includesubdomains; preload",
    ),
    (b"vary", b"accept-encoding"),
    (b"vary", b"origin"),
    (b"x-content-type-options", b"nosniff"),
    (b"x-xss-protection", b"1; mode=block"),
    (b":status", b"100"),
    (b":status", b"204"),
    (b":status", b"206"),
    (b":status", b"302"),
    (b":status", b"400"),
    (b":status", b"403"),
    (b":status", b"421"),
    (b":status", b"425"),
    (b":status", b"500"),
    (b"accept-language", b""),
    (b"access-control-allow-credentials", b"FALSE"),
    (b"access-control-allow-credentials", b"TRUE"),
    (b"access-control-allow-headers", b"*"),
    (b"access-control-allow-methods", b"get"),
    (b"access-control-allow-methods", b"get, post, options"),
    (b"access-control-allow-methods", b"options"),
    (b"access-control-expose-headers", b"content-length"),
    (b"access-control-request-headers", b"content-type"),
    (b"access-control-request-method", b"get"),
    (b"access-control-request-method", b"post"),
    (b"alt-svc", b"clear"),
    (b"authorization", b""),
    (
        b"content-security-policy",
        b"script-src 'none'; object-src 'none'; base-uri 'none'",
    ),
    (b"early-data", b"1"),
    (b"expect-ct", b""),
    (b"forwarded", b""),
    (b"if-range", b""),
    (b"origin", b""),
    (b"purpose", b"prefetch"),
    (b"server", b""),
    (b"timing-allow-origin", b"*"),
    (b"upgrade-insecure-requests", b"1"),
    (b"user-agent", b""),
    (b"x-forwarded-for", b""),
    (b"x-frame-options", b"deny"),
    (b"x-frame-options", b"sameorigin"),
];

/// Returns the static table entry at `index`.
#[inline]
pub(crate) fn get(index: usize) -> Option<(&'static [u8], &'static [u8])> {
    STATIC_TABLE.get(index).copied()
}

/// Returns the index of the first exact `(name, value)` match.
#[cfg(test)]
#[inline]
pub(crate) fn find(name: &[u8], value: &[u8]) -> Option<usize> {
    STATIC_TABLE
        .iter()
        .position(|&(table_name, table_value)| table_name == name && table_value == value)
}

/// Finds an exact match and the lowest-indexed name match in one pass.
#[inline]
pub(crate) fn find_full_or_name(name: &[u8], value: &[u8]) -> (Option<usize>, Option<usize>) {
    let mut name_match = None;
    for (index, &(table_name, table_value)) in STATIC_TABLE.iter().enumerate() {
        if table_name != name {
            continue;
        }
        name_match.get_or_insert(index);
        if table_value == value {
            return (Some(index), name_match);
        }
    }
    (None, name_match)
}

/// Returns the index of the first entry whose name matches.
#[inline]
pub(crate) fn find_name(name: &[u8]) -> Option<usize> {
    STATIC_TABLE
        .iter()
        .position(|&(table_name, _)| table_name == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundary_entries_match_the_rfc() {
        // First entry.
        assert_eq!(get(0), Some((&b":authority"[..], &b""[..])));
        // Last entry.
        assert_eq!(get(98), Some((&b"x-frame-options"[..], &b"sameorigin"[..])));
        // Multi-line values from the RFC table (Appendix A).
        assert_eq!(
            get(44),
            Some((&b"content-type"[..], &b"application/dns-message"[..]))
        );
        assert_eq!(
            get(58),
            Some((
                &b"strict-transport-security"[..],
                &b"max-age=31536000; includesubdomains; preload"[..]
            ))
        );
        assert_eq!(
            get(85),
            Some((
                &b"content-security-policy"[..],
                &b"script-src 'none'; object-src 'none'; base-uri 'none'"[..]
            ))
        );
    }

    #[test]
    fn find_matches_exact_name_and_value() {
        assert_eq!(find(b":status", b"200"), Some(25));
        assert_eq!(find(b":method", b"GET"), Some(17));
        assert_eq!(find(b":method", b"get"), None);
        assert_eq!(find(b":status", b"201"), None);
        assert_eq!(find(b"user-agent", b""), Some(95));
        assert_eq!(find(b"x-frame-options", b"deny"), Some(97));
    }

    #[test]
    fn find_name_returns_lowest_index() {
        assert_eq!(find_name(b":authority"), Some(0));
        assert_eq!(find_name(b"content-type"), Some(44));
        assert_eq!(find_name(b"cache-control"), Some(36));
        assert_eq!(find_name(b"no-such-header"), None);
    }

    #[test]
    fn every_entry_round_trips_through_find() {
        // Guards against transcription errors: each entry must be found by
        // its own name/value pair, and no two entries may share a pair
        // (find must return the entry's own index).
        for index in 0..STATIC_TABLE_SIZE {
            let (name, value) = get(index).expect("entry within range");
            assert_eq!(
                find(name, value),
                Some(index),
                "static table entry {index} is not uniquely findable"
            );
        }
    }
}
