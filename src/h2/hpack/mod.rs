//! HPACK (RFC 7541) header compression.

pub(crate) use crate::hpack::{huffman, integer};

pub(crate) mod decode;
pub(crate) mod encode;
pub(crate) mod string;
pub(crate) mod table;

pub use crate::hpack::HpackError;
pub use decode::Decoder;
pub use encode::Encoder;
pub use table::Header;
