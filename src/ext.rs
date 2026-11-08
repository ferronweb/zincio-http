/// The `:protocol` of an extended CONNECT request (RFC 8441 for HTTP/2, RFC 9220 for
/// HTTP/3), such as `websocket`, in the request's extensions.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Protocol(Box<str>);

impl Protocol {
    /// A protocol from a static name.
    #[inline]
    pub fn from_static(name: &'static str) -> Self {
        Self(name.into())
    }

    /// The protocol's name, as the client sent it.
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The pseudo-header's value, which must be a token (RFC 9110 Section 5.6.2).
    #[inline]
    pub(crate) fn from_bytes(value: &[u8]) -> Option<Self> {
        const DELIMITERS: &[u8] = b"\"(),/:;<=>?@[\\]{}";
        let token = !value.is_empty()
            && value
                .iter()
                .all(|b| b.is_ascii_graphic() && !DELIMITERS.contains(b));
        token
            .then(|| std::str::from_utf8(value).ok())
            .flatten()
            .map(|s| Self(s.into()))
    }
}

impl std::fmt::Display for Protocol {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
