//! `quinn` transport adapter (behind the `h3-quinn` feature).
//!
//! Maps the transport traits onto quinn's stateful streams. Persistent
//! accept/open futures preserve wakeups, and partial writes are buffered so
//! the HTTP/3 side can send whole buffers.

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf, Bytes};
use futures_util::{ready, stream, Stream, StreamExt};
use tokio_util::sync::ReusableBoxFuture;

use crate::h3::error::TransportError;
use crate::h3::transport::{
    self, Accept, BidiStream as BidiStreamTrait, OpenStreams, RecvStream as RecvStreamTrait,
    SendStream as SendStreamTrait, UniStream as UniStreamTrait,
};

/// An infinite stream of `quinn` accept/open outcomes.
type BoxStream<T> = Pin<Box<dyn Stream<Item = T> + std::marker::Send + 'static>>;
type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + std::marker::Send + 'static>>;

type AcceptBiItem = Result<(quinn::SendStream, quinn::RecvStream), quinn::ConnectionError>;
type AcceptUniItem = Result<quinn::RecvStream, quinn::ConnectionError>;
type OpenUniItem = Result<quinn::SendStream, quinn::ConnectionError>;

/// A `quinn` connection adapted to the HTTP/3 transport traits.
pub struct Connection {
    conn: quinn::Connection,
    /// Persistent `accept_bi` futures; quinn's accept futures are stateful
    /// and must survive across polls.
    accept_bi: BoxStream<AcceptBiItem>,
    accept_uni: BoxStream<AcceptUniItem>,
    /// Lazily created the first time a stream is opened.
    open_uni: Option<BoxStream<OpenUniItem>>,
}

impl Connection {
    /// Adapts an established `quinn` connection.
    #[inline]
    pub fn new(conn: quinn::Connection) -> Self {
        let accept_bi = Box::pin(stream::unfold(conn.clone(), |conn| async move {
            Some((conn.accept_bi().await, conn))
        }));
        let accept_uni = Box::pin(stream::unfold(conn.clone(), |conn| async move {
            Some((conn.accept_uni().await, conn))
        }));
        Self {
            conn,
            accept_bi,
            accept_uni,
            open_uni: None,
        }
    }

    /// The reason the connection was closed, if it has been.
    #[inline]
    pub fn close_reason(&self) -> Option<quinn::ConnectionError> {
        self.conn.close_reason()
    }
}

impl OpenStreams for Connection {
    #[inline]
    fn poll_open_uni(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Box<dyn UniStreamTrait>, TransportError>> {
        let stream = self.open_uni.get_or_insert_with(|| {
            let conn = self.conn.clone();
            Box::pin(stream::unfold(conn, |conn| async move {
                Some((conn.open_uni().await, conn))
            }))
        });
        match ready!(stream.poll_next_unpin(cx)) {
            Some(Ok(stream)) => Poll::Ready(Ok(Box::new(UniStream::Send(Send::new(stream))))),
            Some(Err(err)) => Poll::Ready(Err(map_connection_error(err))),
            None => unreachable!("unfold stream never ends"),
        }
    }
}

impl Accept for Connection {
    #[inline]
    fn poll_accept(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Box<dyn BidiStreamTrait>>, TransportError>> {
        match ready!(self.accept_bi.as_mut().poll_next_unpin(cx)) {
            Some(Ok((send, recv))) => Poll::Ready(Ok(Some(Box::new(BidiStream {
                send: Send::new(send),
                recv: Recv::new(recv),
            })))),
            // A closed or drained accept stream is the end of accepts.
            Some(Err(_)) => Poll::Ready(Ok(None)),
            None => unreachable!("unfold stream never ends"),
        }
    }

    #[inline]
    fn poll_accept_uni(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Box<dyn UniStreamTrait>>, TransportError>> {
        match ready!(self.accept_uni.as_mut().poll_next_unpin(cx)) {
            Some(Ok(stream)) => Poll::Ready(Ok(Some(Box::new(UniStream::Recv(Recv::new(stream)))))),
            Some(Err(_)) => Poll::Ready(Ok(None)),
            None => unreachable!("unfold stream never ends"),
        }
    }
}

impl transport::Connection for Connection {
    #[inline]
    fn is_handshake_complete(&self) -> bool {
        self.conn.handshake_data().is_some()
    }

    #[inline]
    fn poll_shutdown(
        &mut self,
        _cx: &mut Context<'_>,
        error_code: u64,
    ) -> Poll<Result<(), TransportError>> {
        let code = match quinn::VarInt::from_u64(error_code) {
            Ok(code) => code,
            Err(_) => return Poll::Ready(Err(TransportError::Other)),
        };
        // quinn's `close` is synchronous and idempotent; it sends
        // CONNECTION_CLOSE immediately.
        self.conn.close(code, b"");
        Poll::Ready(Ok(()))
    }
}

/// The send half of a QUIC stream, adapted to [`SendStreamTrait`].
pub(crate) struct Send {
    stream: quinn::SendStream,
    /// Bytes accepted by `poll_write` but not yet sent.
    buf: bytes::BytesMut,
    /// Identity of the caller slice still buffered, preventing duplicate
    /// appends when a pending write is re-polled.
    in_flight: Option<(usize, usize)>,
    stopped_future: Option<BoxFuture<Result<Option<quinn::VarInt>, quinn::StoppedError>>>,
}

impl Send {
    #[inline]
    fn new(stream: quinn::SendStream) -> Self {
        Self {
            stream,
            buf: bytes::BytesMut::new(),
            in_flight: None,
            stopped_future: None,
        }
    }

    #[inline]
    fn id(&self) -> u64 {
        self.stream.id().into()
    }

    #[inline]
    fn poll_send(&mut self, cx: &mut Context<'_>, data: &[u8]) -> Poll<Result<(), TransportError>> {
        // Buffer only a fresh caller slice; re-appending a re-polled slice
        // would grow `buf` without bound.
        let id = (data.as_ptr() as usize, data.len());
        if !data.is_empty() && self.in_flight != Some(id) {
            self.buf.extend_from_slice(data);
            self.in_flight = Some(id);
        }
        loop {
            if self.buf.is_empty() {
                self.in_flight = None;
                return Poll::Ready(Ok(()));
            }
            // quinn writes a non-empty prefix or returns Pending without
            // writing, so this loop cannot spin.
            let written = ready!(Pin::new(&mut self.stream).poll_write(cx, &self.buf))
                .map_err(map_write_error)?;
            debug_assert!(written > 0);
            self.buf.advance(written);
        }
    }

    #[inline]
    fn poll_stopped(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), TransportError>> {
        let mut fut = self
            .stopped_future
            .get_or_insert_with(|| Box::pin(self.stream.stopped()));
        match Pin::new(&mut fut).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
            Poll::Ready(Err(_)) => Poll::Ready(Err(TransportError::Other)),
        }
    }

    #[inline]
    fn poll_finish(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), TransportError>> {
        // quinn's `finish` is synchronous; failure means already finished or
        // reset, which is harmless here.
        let _ = self.stream.finish();
        Poll::Ready(Ok(()))
    }

    #[inline]
    fn poll_reset(&mut self, _cx: &mut Context<'_>, code: u64) -> Poll<Result<(), TransportError>> {
        let code = match quinn::VarInt::from_u64(code) {
            Ok(code) => code,
            Err(_) => return Poll::Ready(Err(TransportError::Other)),
        };
        if self.stream.reset(code).is_err() {
            return Poll::Ready(Err(TransportError::Other));
        }
        Poll::Ready(Ok(()))
    }
}

type ReadChunkFuture = ReusableBoxFuture<
    'static,
    (
        quinn::RecvStream,
        Result<Option<quinn::Chunk>, quinn::ReadError>,
    ),
>;

/// The receive half of a QUIC stream, adapted to [`RecvStreamTrait`].
pub(crate) struct Recv {
    stream: Option<quinn::RecvStream>,
    /// In-flight `read_chunk` future, reused across polls.
    read_chunk_fut: ReadChunkFuture,
}

impl Recv {
    #[inline]
    fn new(stream: quinn::RecvStream) -> Self {
        Self {
            stream: Some(stream),
            read_chunk_fut: ReusableBoxFuture::new(async { unreachable!("armed before poll") }),
        }
    }

    #[inline]
    fn id(&self) -> u64 {
        self.stream.as_ref().map_or(0, |stream| stream.id().into())
    }

    #[inline]
    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>, TransportError>> {
        if let Some(mut stream) = self.stream.take() {
            self.read_chunk_fut.set(async move {
                let chunk = stream.read_chunk(usize::MAX, true).await;
                (stream, chunk)
            });
        }
        let (stream, chunk) = ready!(self.read_chunk_fut.poll(cx));
        self.stream = Some(stream);
        Poll::Ready(
            chunk
                .map_err(map_read_error)
                .map(|chunk| chunk.map(|chunk| chunk.bytes)),
        )
    }

    #[inline]
    fn stop_sending(&mut self, code: u64) -> Result<(), TransportError> {
        let code = match quinn::VarInt::from_u64(code) {
            Ok(code) => code,
            Err(_) => return Err(TransportError::Other),
        };
        match self.stream.as_mut() {
            Some(stream) => stream.stop(code).map_err(|_| TransportError::Other),
            None => Err(TransportError::Other),
        }
    }
}

/// A bidirectional QUIC stream (an HTTP/3 request stream).
pub(crate) struct BidiStream {
    send: Send,
    recv: Recv,
}

impl RecvStreamTrait for BidiStream {
    #[inline]
    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>, TransportError>> {
        self.recv.poll_recv(cx)
    }

    #[inline]
    fn id(&self) -> u64 {
        self.send.id()
    }
}

impl SendStreamTrait for BidiStream {
    #[inline]
    fn poll_send(&mut self, cx: &mut Context<'_>, data: &[u8]) -> Poll<Result<(), TransportError>> {
        self.send.poll_send(cx, data)
    }

    #[inline]
    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), TransportError>> {
        self.send.poll_finish(cx)
    }

    #[inline]
    fn poll_stopped(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), TransportError>> {
        self.send.poll_stopped(cx)
    }

    #[inline]
    fn poll_reset(&mut self, cx: &mut Context<'_>, code: u64) -> Poll<Result<(), TransportError>> {
        self.send.poll_reset(cx, code)
    }

    #[inline]
    fn poll_stop_sending(
        &mut self,
        _cx: &mut Context<'_>,
        code: u64,
    ) -> Poll<Result<(), TransportError>> {
        // STOP_SENDING applies to our receive direction, which quinn keeps
        // on the receive half.
        Poll::Ready(self.recv.stop_sending(code))
    }
}

impl BidiStreamTrait for BidiStream {}

/// A unidirectional QUIC stream, write-only when opened and read-only when
/// accepted.
pub(crate) enum UniStream {
    /// A stream this endpoint opened: write-only.
    Send(Send),
    /// A stream the peer opened: read-only.
    Recv(Recv),
}

impl RecvStreamTrait for UniStream {
    #[inline]
    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>, TransportError>> {
        match self {
            UniStream::Recv(recv) => recv.poll_recv(cx),
            UniStream::Send(_) => Poll::Ready(Err(TransportError::Transport)),
        }
    }

    #[inline]
    fn id(&self) -> u64 {
        match self {
            UniStream::Send(send) => send.id(),
            UniStream::Recv(recv) => recv.id(),
        }
    }
}

impl SendStreamTrait for UniStream {
    #[inline]
    fn poll_send(&mut self, cx: &mut Context<'_>, data: &[u8]) -> Poll<Result<(), TransportError>> {
        match self {
            UniStream::Send(send) => send.poll_send(cx, data),
            UniStream::Recv(_) => Poll::Ready(Err(TransportError::Transport)),
        }
    }

    #[inline]
    fn poll_stopped(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), TransportError>> {
        match self {
            UniStream::Send(send) => send.poll_stopped(cx),
            UniStream::Recv(_) => Poll::Ready(Err(TransportError::Transport)),
        }
    }

    #[inline]
    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), TransportError>> {
        match self {
            UniStream::Send(send) => send.poll_finish(cx),
            UniStream::Recv(_) => Poll::Ready(Err(TransportError::Transport)),
        }
    }

    #[inline]
    fn poll_reset(&mut self, cx: &mut Context<'_>, code: u64) -> Poll<Result<(), TransportError>> {
        match self {
            UniStream::Send(send) => send.poll_reset(cx, code),
            UniStream::Recv(_) => Poll::Ready(Err(TransportError::Transport)),
        }
    }

    #[inline]
    fn poll_stop_sending(
        &mut self,
        _cx: &mut Context<'_>,
        code: u64,
    ) -> Poll<Result<(), TransportError>> {
        match self {
            UniStream::Recv(recv) => Poll::Ready(recv.stop_sending(code)),
            UniStream::Send(_) => Poll::Ready(Err(TransportError::Transport)),
        }
    }
}

impl UniStreamTrait for UniStream {}

#[inline]
fn map_connection_error(err: quinn::ConnectionError) -> TransportError {
    match err {
        quinn::ConnectionError::ApplicationClosed(close) => TransportError::Closed {
            code: close.error_code.into_inner(),
        },
        quinn::ConnectionError::TimedOut => TransportError::Timeout,
        // VersionMismatch, TransportError, ConnectionClosed, Reset,
        // LocallyClosed and CidsExhausted carry no application error code.
        _ => TransportError::Transport,
    }
}

#[inline]
fn map_read_error(err: quinn::ReadError) -> TransportError {
    match err {
        quinn::ReadError::Reset(code) => TransportError::Reset {
            code: code.into_inner(),
        },
        quinn::ReadError::ConnectionLost(err) => map_connection_error(err),
        // The stream was stopped, finished, or reset before any read.
        quinn::ReadError::ClosedStream => TransportError::Closed { code: 0 },
        // The adapter only performs ordered reads, so this cannot arise.
        quinn::ReadError::IllegalOrderedRead => TransportError::Transport,
        quinn::ReadError::ZeroRttRejected => TransportError::Transport,
    }
}

#[inline]
fn map_write_error(err: quinn::WriteError) -> TransportError {
    match err {
        quinn::WriteError::Stopped(code) => TransportError::Stopped {
            code: code.into_inner(),
        },
        quinn::WriteError::ConnectionLost(err) => map_connection_error(err),
        // The stream was finished or reset locally before the write.
        quinn::WriteError::ClosedStream => TransportError::Closed { code: 0 },
        quinn::WriteError::ZeroRttRejected => TransportError::Transport,
    }
}
