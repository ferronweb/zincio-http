//! HTTP/3 error types and the QUIC transport error abstraction.
//!
//! Two families of errors exist in the HTTP/3 stack:
//!
//! - [`TransportError`]: failures surfaced by the QUIC transport
//!   abstraction ([`crate::h3::transport`]). The HTTP/3 layer translates
//!   these into connection closes and stream resets with typed HTTP/3
//!   codes, and into `io::Error` at the `HttpProtocol` boundary.
//! - [`H3Error`]: the typed application errors of RFC 9114 Section 8.1,
//!   each with its wire code. QPACK errors ([`crate::h3::qpack::QpackError`])
//!   form the RFC 9204 Section 6 family (codes `0x200`-`0x202`) and live
//!   with the QPACK codec; the connection driver maps both families onto
//!   reset/shutdown codes and `io::Error`.
//!
//! Error codes of the format `0x1f * N + 0x21` are reserved; per RFC 9114
//! Section 8.1 they are treated as equivalent to `H3_NO_ERROR`.

use std::{error::Error, fmt, io};

/// Errors surfaced by the QUIC transport abstraction
/// ([`crate::h3::transport`]).
///
/// Adapters translate their stack's error types into these variants; the
/// HTTP/3 layer never inspects stack-specific errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    /// The connection was closed by the peer with an application error
    /// `code` (an HTTP/3 error code, or 0 for `H3_NO_ERROR`).
    Closed { code: u64 },
    /// The connection was closed by transport-level events (for example a
    /// transport error, idle timeout, or a local close) without an
    /// application error code.
    Transport,
    /// The connection timed out.
    Timeout,
    /// The peer reset the stream (`RESET_STREAM`) with the given error
    /// `code`; the read side of the stream is terminated.
    Reset { code: u64 },
    /// The peer sent `STOP_SENDING` with the given error `code`; the write
    /// side of the stream is terminated.
    Stopped { code: u64 },
    /// Any other transport-level failure.
    Other,
}

impl fmt::Display for TransportError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::Closed { code } => write!(f, "connection closed with code {code:#x}"),
            TransportError::Transport => write!(f, "transport closed the connection"),
            TransportError::Timeout => write!(f, "transport timed out"),
            TransportError::Reset { code } => write!(f, "stream reset with code {code:#x}"),
            TransportError::Stopped { code } => write!(f, "stream stopped with code {code:#x}"),
            TransportError::Other => write!(f, "transport error"),
        }
    }
}

impl Error for TransportError {}

impl From<TransportError> for io::Error {
    #[inline]
    fn from(err: TransportError) -> io::Error {
        match err {
            TransportError::Closed { .. } => io::Error::new(io::ErrorKind::ConnectionAborted, err),
            TransportError::Reset { .. } | TransportError::Stopped { .. } => {
                io::Error::new(io::ErrorKind::ConnectionReset, err)
            }
            TransportError::Timeout => io::Error::new(io::ErrorKind::TimedOut, err),
            // Same conversion strategy as the previous `h3` wrapper: any
            // other error surfaces as `io::Error::other`.
            TransportError::Transport | TransportError::Other => io::Error::other(err),
        }
    }
}

/// Typed HTTP/3 application errors (RFC 9114 Section 8.1).
///
/// Each variant carries the error code it is sent as in `RESET_STREAM`,
/// `STOP_SENDING`, and `CONNECTION_CLOSE` frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H3Error {
    /// `H3_NO_ERROR` (0x0100): no error; used to close cleanly.
    NoError,
    /// `H3_GENERAL_PROTOCOL_ERROR` (0x0101): a protocol violation that no
    /// more specific code covers.
    GeneralProtocol,
    /// `H3_INTERNAL_ERROR` (0x0102): an internal error in the HTTP stack.
    Internal,
    /// `H3_STREAM_CREATION_ERROR` (0x0103): the peer created a stream this
    /// endpoint will not accept.
    StreamCreation,
    /// `H3_CLOSED_CRITICAL_STREAM` (0x0104): a stream required by the
    /// connection (control, QPACK encoder or decoder) was closed or reset.
    ClosedCriticalStream,
    /// `H3_FRAME_UNEXPECTED` (0x0105): a frame that is not permitted in
    /// the current state or on the current stream.
    FrameUnexpected,
    /// `H3_FRAME_ERROR` (0x0106): a frame that violates layout requirements
    /// or has an invalid size.
    FrameError,
    /// `H3_EXCESSIVE_LOAD` (0x0107): the peer is generating excessive load.
    ExcessiveLoad,
    /// `H3_ID_ERROR` (0x0108): a stream ID or push ID used incorrectly.
    Id,
    /// `H3_SETTINGS_ERROR` (0x0109): an error in the payload of a SETTINGS
    /// frame.
    Settings,
    /// `H3_MISSING_SETTINGS` (0x010a): no SETTINGS frame at the start of
    /// the control stream.
    MissingSettings,
    /// `H3_REQUEST_REJECTED` (0x010b): a server rejected a request without
    /// application processing.
    RequestRejected,
    /// `H3_REQUEST_CANCELLED` (0x010c): the request or its response was
    /// cancelled.
    RequestCancelled,
    /// `H3_REQUEST_INCOMPLETE` (0x010d): a stream terminated without a
    /// fully formed request.
    RequestIncomplete,
    /// `H3_MESSAGE_ERROR` (0x010e): an HTTP message was malformed.
    Message,
    /// `H3_CONNECT_ERROR` (0x010f): the TCP connection behind a CONNECT
    /// request was reset or abnormally closed.
    Connect,
    /// `H3_VERSION_FALLBACK` (0x0110): the requested operation cannot be
    /// served over HTTP/3; the peer should retry over HTTP/1.1.
    VersionFallback,
}

impl H3Error {
    /// The RFC 9114 Section 8.1 error code for this error.
    pub const fn code(self) -> u64 {
        use H3Error::*;
        match self {
            NoError => 0x0100,
            GeneralProtocol => 0x0101,
            Internal => 0x0102,
            StreamCreation => 0x0103,
            ClosedCriticalStream => 0x0104,
            FrameUnexpected => 0x0105,
            FrameError => 0x0106,
            ExcessiveLoad => 0x0107,
            Id => 0x0108,
            Settings => 0x0109,
            MissingSettings => 0x010a,
            RequestRejected => 0x010b,
            RequestCancelled => 0x010c,
            RequestIncomplete => 0x010d,
            Message => 0x010e,
            Connect => 0x010f,
            VersionFallback => 0x0110,
        }
    }

    /// Looks up a known HTTP/3 error by its RFC 9114 Section 8.1 code.
    ///
    /// Returns `None` for unknown codes. Per RFC 9114 Section 8.1, unknown
    /// codes — including the reserved `0x1f * N + 0x21` family — are
    /// treated as equivalent to [`H3Error::NoError`] by the wire protocol.
    pub const fn from_code(code: u64) -> Option<H3Error> {
        use H3Error::*;
        Some(match code {
            0x0100 => NoError,
            0x0101 => GeneralProtocol,
            0x0102 => Internal,
            0x0103 => StreamCreation,
            0x0104 => ClosedCriticalStream,
            0x0105 => FrameUnexpected,
            0x0106 => FrameError,
            0x0107 => ExcessiveLoad,
            0x0108 => Id,
            0x0109 => Settings,
            0x010a => MissingSettings,
            0x010b => RequestRejected,
            0x010c => RequestCancelled,
            0x010d => RequestIncomplete,
            0x010e => Message,
            0x010f => Connect,
            0x0110 => VersionFallback,
            _ => return None,
        })
    }
}

impl fmt::Display for H3Error {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} ({:#06x})", self, self.code())
    }
}

impl Error for H3Error {}

impl From<H3Error> for io::Error {
    #[inline]
    fn from(err: H3Error) -> io::Error {
        io::Error::other(err)
    }
}
