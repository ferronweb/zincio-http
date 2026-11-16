//! QPACK (RFC 9204) header compression for HTTP/3.
//!
//! Encoder and decoder with full dynamic-table support, encoder/decoder
//! streams, and blocked-stream handling. The Huffman code and prefix-integer
//! representation are shared with HPACK via [`crate::hpack`].

pub mod decoder;
pub mod encoder;
pub mod error;

pub use decoder::{Decoder, UnblockedSection};
pub use encoder::Encoder;
pub use error::QpackError;

pub(crate) mod static_table;
pub(crate) mod table;
