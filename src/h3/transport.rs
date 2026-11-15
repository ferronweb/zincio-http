//! QUIC transport abstraction for the HTTP/3 implementation.
//!
//! The HTTP/3 layer (RFC 9114) is written against these traits instead of a
//! concrete QUIC stack, so any QUIC implementation can be adapted (the
//! `quinn` adapter behind the `h3-quinn` feature is one such adapter). The
//! shape mirrors the `h3` crate's `quic` module so adapters are mechanical:
//! polling only, `Unpin`, fallible operations returning
//! [`TransportError`].
//!
//! The HTTP/3 layer needs three things from a QUIC stack:
//!
//! - this endpoint's own outbound unidirectional streams (control stream,
//!   QPACK encoder/decoder streams) via [`OpenStreams`];
//! - the peer's inbound streams — request streams via [`Accept`], plus the
//!   peer's unidirectional streams (their control stream and QPACK
//!   streams) — and
//! - connection-level state: handshake completion and graceful shutdown.
//!
//! Streams are consumed as trait objects (`Box<dyn BidiStream>`,
//! `Box<dyn UniStream>`): the connection driver is a single task that
//! spawns per-request tasks, so the boxes it hands off must be neither
//! generic-bound nor borrowed. QUIC stream handles are cheap to move, so
//! boxing adds no meaningful cost.

use std::task::{Context, Poll};

use bytes::Bytes;

use crate::h3::error::TransportError;

/// The receive half of a QUIC stream.
///
/// Polls for the next chunk of received bytes; the stream is finished when
/// `Ok(None)` is returned (the peer closed its sending side with `FIN`).
/// A `TransportError::Reset` is returned when the peer resets the stream
/// instead.
pub trait RecvStream: Unpin + Send {
    /// Polls for the next chunk of data on the stream.
    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>, TransportError>>;

    /// The QUIC stream ID (RFC 9000 Section 2.1).
    ///
    /// Each bidirectional stream is a distinct HTTP/3 request stream, and
    /// the HTTP/3 layer keys QPACK state (blocked field sections, section
    /// acknowledgements) by stream ID.
    fn id(&self) -> u64;
}

/// The send half of a QUIC stream.
pub trait SendStream: Unpin + Send {
    /// Polls to send `data` on the stream, consuming it entirely.
    ///
    /// `Poll::Pending` means the stream's flow-control window is exhausted;
    /// the caller must poll again later. A `TransportError::Stopped` is
    /// returned when the peer sends `STOP_SENDING`.
    fn poll_send(&mut self, cx: &mut Context<'_>, data: &[u8]) -> Poll<Result<(), TransportError>>;

    /// Polls until the peer stops the stream or reads the stream to
    /// completion.
    #[allow(unused_variables)]
    #[inline]
    fn poll_stopped(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), TransportError>> {
        Poll::Ready(Ok(()))
    }

    /// Polls to finish the sending side of the stream (`FIN`). The peer
    /// then observes `Ok(None)` from its receive side when all data is
    /// delivered.
    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), TransportError>>;

    /// Polls to reset the sending side of the stream with an application
    /// error `code` (RFC 9114 error codes), discarding buffered data.
    fn poll_reset(&mut self, cx: &mut Context<'_>, code: u64) -> Poll<Result<(), TransportError>>;

    /// Polls to stop the peer from sending on the stream (`STOP_SENDING`)
    /// with an application error `code`.
    fn poll_stop_sending(
        &mut self,
        cx: &mut Context<'_>,
        code: u64,
    ) -> Poll<Result<(), TransportError>>;
}

/// A bidirectional QUIC stream: an HTTP/3 request stream.
pub trait BidiStream: RecvStream + SendStream {}

/// A unidirectional QUIC stream: the control stream, the QPACK encoder and
/// decoder streams, and any extension stream types.
pub trait UniStream: RecvStream + SendStream {}

/// Opens outbound unidirectional streams.
///
/// The HTTP/3 layer uses this to create its control stream and QPACK
/// encoder/decoder streams.
pub trait OpenStreams {
    /// Polls the connection to open a new unidirectional stream.
    fn poll_open_uni(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Box<dyn UniStream>, TransportError>>;
}

/// Accepts inbound streams.
///
/// Inbound streams must not be accepted out of order: the HTTP/3 layer
/// assigns meanings to unidirectional streams by stream type and to
/// request streams by stream ID (RFC 9114 Section 6), so an adapter must
/// deliver streams in the order the peer created them.
pub trait Accept {
    /// Polls for the next accepted bidirectional (request) stream.
    ///
    /// `Ok(None)` means no more streams will be accepted (the connection is
    /// closing or closed).
    fn poll_accept(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Box<dyn BidiStream>>, TransportError>>;

    /// Polls for the next accepted unidirectional stream (the peer's
    /// control stream and QPACK streams).
    ///
    /// `Ok(None)` means no more streams will be accepted.
    fn poll_accept_uni(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Box<dyn UniStream>>, TransportError>>;
}

/// A QUIC connection as seen by the HTTP/3 layer.
pub trait Connection: OpenStreams + Accept {
    /// Whether the handshake has completed.
    ///
    /// The accept and handshake timeouts of the HTTP/3 layer are measured
    /// against this: a connection must not be timed out before its
    /// handshake completes.
    fn is_handshake_complete(&self) -> bool;

    /// Polls to shut down the connection gracefully with an application
    /// error `code`, allowing in-flight streams to drain.
    fn poll_shutdown(
        &mut self,
        cx: &mut Context<'_>,
        error_code: u64,
    ) -> Poll<Result<(), TransportError>>;
}
