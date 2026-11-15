//! Primitives shared between HPACK (RFC 7541) and QPACK (RFC 9204).
//!
//! Both header-compression schemes use the same Huffman code
//! (RFC 7541 Appendix B, reused verbatim by RFC 9204 Section 4.2) and the
//! same prefix-integer representation (RFC 7541 Section 5.1, reused by
//! RFC 9204 Section 4.3). These live here, one level up from the protocol
//! modules that consume them, so neither codec needs to depend on the other.
//!
//! Consumers: `h2::hpack` (HPACK) and `h3::qpack` (QPACK).
//!
//! This module is also the public `zincio_http::hpack` path: the HPACK
//! codec surface (`Decoder`, `Encoder`, `Header`) is re-exported from
//! `h2::hpack`.

pub(crate) mod huffman;
pub(crate) mod huffman_table;
pub(crate) mod integer;

#[cfg(all(feature = "unstable-internals", feature = "h2"))]
pub use crate::h2::hpack::{Decoder, Encoder, Header};

/// Errors produced by the shared HPACK/QPACK primitives.
///
/// The integer and Huffman variants are produced by the shared code; the
/// remaining variants are produced by the HPACK decoder itself. Callers map
/// these to protocol errors (`COMPRESSION_ERROR` for HTTP/2, the `0x2xx`
/// QPACK error family for HTTP/3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)]
pub enum HpackError {
    /// An integer representation overflowed or ran out of input.
    InvalidInteger,
    /// A string literal violated framing constraints.
    InvalidString,
    /// A Huffman-encoded string violated RFC 7541 Section 5.2 rules
    /// (EOS symbol in the data, over-long or malformed padding, or
    /// truncation).
    InvalidHuffman,
    /// An indexed header field referenced a non-existent table entry.
    InvalidIndex,
    /// A dynamic table size update exceeded the protocol maximum or
    /// appeared after a header field representation.
    InvalidMaxSize,
    /// The decoded header list exceeded the configured maximum size.
    HeaderListTooLarge,
    /// The first octet of a representation matched no known pattern.
    InvalidRepresentation,
}
