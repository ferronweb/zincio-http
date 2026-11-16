//! QUIC transport abstraction for the HTTP/3 implementation.
//!
//! The HTTP/3 layer writes against these polling-based traits instead of a
//! concrete QUIC stack, so adapters are mechanical. Streams are boxed because
//! the connection driver hands them to per-request tasks.

use std::task::{Context, Poll};

use bytes::Bytes;

use crate::h3::error::TransportError;

/// The receive half of a QUIC stream.
pub trait RecvStream: Unpin + Send {
    /// Polls for the next chunk of data.
    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>, TransportError>>;

    /// The QUIC stream ID (RFC 9000 Section 2.1).
    fn id(&self) -> u64;
}

/// The send half of a QUIC stream.
pub trait SendStream: Unpin + Send {
    /// Polls to send `data`, consuming it entirely.
    fn poll_send(&mut self, cx: &mut Context<'_>, data: &[u8]) -> Poll<Result<(), TransportError>>;

    /// Polls until the peer stops the stream or reads it to completion.
    #[allow(unused_variables)]
    #[inline]
    fn poll_stopped(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), TransportError>> {
        Poll::Ready(Ok(()))
    }

    /// Polls to finish the sending side (`FIN`).
    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), TransportError>>;

    /// Polls to reset the sending side with an application error `code`.
    fn poll_reset(&mut self, cx: &mut Context<'_>, code: u64) -> Poll<Result<(), TransportError>>;

    /// Polls to send `STOP_SENDING` for the stream.
    fn poll_stop_sending(
        &mut self,
        cx: &mut Context<'_>,
        code: u64,
    ) -> Poll<Result<(), TransportError>>;
}

/// A bidirectional QUIC stream: an HTTP/3 request stream.
pub trait BidiStream: RecvStream + SendStream {}

/// A unidirectional QUIC stream.
pub trait UniStream: RecvStream + SendStream {}

/// Opens outbound unidirectional streams.
pub trait OpenStreams {
    /// Polls the connection to open a new unidirectional stream.
    fn poll_open_uni(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Box<dyn UniStream>, TransportError>>;
}

/// Accepts inbound streams in the order the peer created them.
pub trait Accept {
    /// Polls for the next inbound bidirectional request stream.
    fn poll_accept(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Box<dyn BidiStream>>, TransportError>>;

    /// Polls for the next inbound unidirectional stream.
    fn poll_accept_uni(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Box<dyn UniStream>>, TransportError>>;
}

/// A QUIC connection as seen by the HTTP/3 layer.
pub trait Connection: OpenStreams + Accept {
    /// Whether the handshake has completed.
    fn is_handshake_complete(&self) -> bool;

    /// Polls to shut down the connection gracefully with an application error
    /// `code`.
    fn poll_shutdown(
        &mut self,
        cx: &mut Context<'_>,
        error_code: u64,
    ) -> Poll<Result<(), TransportError>>;
}
