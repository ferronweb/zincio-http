//! QPACK error codes (RFC 9114 Section 8.1, reused by RFC 9204 Section 6).

/// Errors raised while QPACK state is inconsistent or a representation is
/// malformed. All are fatal for the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QpackError {
    /// `QPACK_DECOMPRESSION_FAILED` (0x0200): a field section could not be
    /// decoded or exceeded the advertised size limit.
    DecompressionFailed,
    /// `QPACK_ENCODER_STREAM_ERROR` (0x0201): an encoder stream instruction
    /// was malformed or violated table constraints.
    EncoderStream,
    /// `QPACK_DECODER_STREAM_ERROR` (0x0202): a decoder stream instruction
    /// was malformed.
    DecoderStream,
}

impl QpackError {
    /// The HTTP/3 CONNECTION_CLOSE error code (RFC 9204 Section 6).
    #[inline]
    pub fn code(self) -> u16 {
        match self {
            QpackError::DecompressionFailed => 0x0200,
            QpackError::EncoderStream => 0x0201,
            QpackError::DecoderStream => 0x0202,
        }
    }
}
