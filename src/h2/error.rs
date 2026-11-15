//! HTTP/2 error types (RFC 9113 Section 7).

/// HTTP/2 error codes (RFC 9113 Section 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Reason {
    NoError = 0x00,
    ProtocolError = 0x01,
    InternalError = 0x02,
    FlowControlError = 0x03,
    SettingsTimeout = 0x04,
    StreamClosed = 0x05,
    FrameSizeError = 0x06,
    RefusedStream = 0x07,
    Cancel = 0x08,
    CompressionError = 0x09,
    ConnectError = 0x0a,
    EnhanceYourCalm = 0x0b,
    InadequateSecurity = 0x0c,
    Http11Required = 0x0d,
}

impl Reason {
    /// The numeric wire value of this error code.
    pub const fn code(self) -> u32 {
        self as u32
    }

    /// Looks up a wire value; unknown codes are `None` (they are
    /// forwarded as opaque numbers by GOAWAY/RST_STREAM).
    pub const fn from_code(code: u32) -> Option<Reason> {
        match code {
            0x00 => Some(Reason::NoError),
            0x01 => Some(Reason::ProtocolError),
            0x02 => Some(Reason::InternalError),
            0x03 => Some(Reason::FlowControlError),
            0x04 => Some(Reason::SettingsTimeout),
            0x05 => Some(Reason::StreamClosed),
            0x06 => Some(Reason::FrameSizeError),
            0x07 => Some(Reason::RefusedStream),
            0x08 => Some(Reason::Cancel),
            0x09 => Some(Reason::CompressionError),
            0x0a => Some(Reason::ConnectError),
            0x0b => Some(Reason::EnhanceYourCalm),
            0x0c => Some(Reason::InadequateSecurity),
            0x0d => Some(Reason::Http11Required),
            _ => None,
        }
    }
}

/// An HTTP/2 protocol error: a rule violation with the connection or
/// stream error code to report, and a human-readable description.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H2Error {
    pub reason: Reason,
    pub message: &'static str,
}

impl H2Error {
    /// Creates a protocol error with the given connection/stream error
    /// code.
    pub const fn new(reason: Reason, message: &'static str) -> H2Error {
        H2Error { reason, message }
    }

    /// A generic protocol violation.
    pub const fn protocol(message: &'static str) -> H2Error {
        H2Error::new(Reason::ProtocolError, message)
    }

    /// A framing violation (oversized or malformed frame).
    pub const fn frame_size(message: &'static str) -> H2Error {
        H2Error::new(Reason::FrameSizeError, message)
    }
}
