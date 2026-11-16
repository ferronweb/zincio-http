//! Primitives shared between HPACK (RFC 7541) and QPACK (RFC 9204).
//!
//! Both header-compression schemes use the same Huffman code
//! (RFC 7541 Appendix B, reused verbatim by RFC 9204 Section 4.2) and the
//! same prefix-integer representation (RFC 7541 Section 5.1, reused by
//! RFC 9204 Section 4.3).

pub(crate) mod huffman;
pub(crate) mod huffman_table;
pub(crate) mod integer;

#[cfg(all(feature = "unstable-internals", feature = "h2"))]
pub use crate::h2::hpack::{Decoder, Encoder, Header};

/// Errors produced by the shared HPACK/QPACK primitives.
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
