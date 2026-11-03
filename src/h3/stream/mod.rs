//! HTTP/3 request stream handling (RFC 9114 Sections 4.1, 4.2 and 6.1).
//!
//! A request stream is a bidirectional QUIC stream that carries a single
//! HTTP message exchange: the client's request HEADERS, body DATA and
//! trailers, then the server's response HEADERS, DATA and trailers. This
//! module wraps such a stream in a [`RequestStream`] that owns the frame
//! decoder, decodes the requests' and response field sections with the
//! connection's shared QPACK codecs, and abides by the RFC 9114 frame
//! ordering rules:
//!
//! - the first frame must be HEADERS (anything else is
//!   `H3_FRAME_UNEXPECTED`); the field section must form a valid request
//!   with exactly the RFC 9114 Section 4.1 pseudo-headers, appearing
//!   before any regular field
//!   (`H3_MESSAGE_ERROR` otherwise);
//! - DATA frames follow; then at most one trailing HEADERS frame, after
//!   which only unknown frames may still appear
//!   (`H3_FRAME_UNEXPECTED` otherwise);
//! - control-plane frames (SETTINGS, GOAWAY, MAX_PUSH_ID, PUSH_PROMISE,
//!   CANCEL_PUSH) are `H3_FRAME_UNEXPECTED` on a request stream.
//!
//! The response side encodes the response field section with the shared
//! encoder (queuing its encoder-stream instructions for the control
//! plane) and respects the peer's `SETTINGS_MAX_FIELD_SECTION_SIZE`.
//!
//! All methods are polling-based: the connection driver runs the request
//! stream on its own task, and the transport's flow control shows up as
//! `Pending`.
#![allow(dead_code)]

use std::collections::VecDeque;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use bytes::{Bytes, BytesMut};
use futures_util::ready;
use http::header::{HeaderMap, HeaderName, HeaderValue};
use http::{Method, Request, StatusCode, Uri, Version};
use parking_lot::Mutex;
use rustc_hash::FxHashMap;
use tokio::sync::Notify;

use crate::h3::error::{H3Error, TransportError};
use crate::h3::frame::{
    write_varint, Frame, FrameDecoder, FrameError, FRAME_CANCEL_PUSH, FRAME_DATA, FRAME_GOAWAY,
    FRAME_HEADERS, FRAME_MAX_PUSH_ID, FRAME_PUSH_PROMISE, FRAME_SETTINGS,
};
use crate::h3::qpack::{Decoder, Encoder, QpackError, UnblockedSection};
use crate::h3::settings::LocalSettings;
use crate::h3::transport::BidiStream;

/// A failure on a request stream.
///
/// [`StreamError::Transport`] with a `Reset`/`Stopped` error and
/// [`StreamError::Message`] are stream-scoped: the driver abandons the
/// stream (counting it against the connection's reset budgets). Most
/// other variants are connection-scoped protocol errors: the driver
/// closes the connection with [`StreamError::h3_code`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StreamError {
    /// The transport failed: the stream was reset by the peer
    /// (`TransportError::Reset`), it stopped our sending side (`Stopped`),
    /// or the connection closed underneath the stream.
    Transport(TransportError),
    /// A malformed frame or payload (`H3_FRAME_ERROR`).
    Frame,
    /// A frame longer than this endpoint buffers (`H3_EXCESSIVE_LOAD`;
    /// RFC 9114 Section 7.1).
    ExcessiveLoad,
    /// An invalid message: malformed, duplicated or missing pseudo-headers,
    /// a field section that violates RFC 9114 Section 4.1, or trailers
    /// with pseudo-headers (`H3_MESSAGE_ERROR`).
    Message,
    /// A frame that is not permitted on a request stream
    /// (`H3_FRAME_UNEXPECTED`).
    FrameUnexpected,
    /// The peer's QPACK encoder stream state made a field section
    /// undecodable (RFC 9204 Section 6).
    Qpack(QpackError),
    /// An encoded field section larger than the peer's announced
    /// `SETTINGS_MAX_FIELD_SECTION_SIZE`; the peer will likely refuse it
    /// (RFC 9114 Sections 4.2.2 and 7.2.4.1).
    HeadersTooBig { size: u64, limit: u64 },
}

impl StreamError {
    /// The connection error code to close with, when the error is
    /// connection-scoped.
    #[inline]
    pub(crate) fn h3_code(&self) -> u64 {
        match self {
            StreamError::Transport(TransportError::Closed { code }) => *code,
            StreamError::Transport(_) => H3Error::Internal.code(),
            StreamError::Frame => H3Error::FrameError.code(),
            StreamError::ExcessiveLoad => H3Error::ExcessiveLoad.code(),
            StreamError::Message => H3Error::Message.code(),
            StreamError::FrameUnexpected => H3Error::FrameUnexpected.code(),
            StreamError::Qpack(err) => u64::from(err.code()),
            StreamError::HeadersTooBig { .. } => H3Error::Message.code(),
        }
    }

    /// Whether the failure is stream-scoped (a reset or stop-sending from
    /// the peer), rather than a connection error.
    #[inline]
    pub(crate) fn is_stream_scoped(&self) -> bool {
        matches!(
            self,
            StreamError::Transport(TransportError::Reset { .. } | TransportError::Stopped { .. })
        )
    }
}

impl From<TransportError> for StreamError {
    #[inline]
    fn from(err: TransportError) -> Self {
        StreamError::Transport(err)
    }
}

impl std::fmt::Display for StreamError {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for StreamError {}

#[inline]
fn map_frame_error(err: FrameError) -> StreamError {
    match err {
        // A malformed frame payload anywhere is H3_FRAME_ERROR.
        FrameError::Frame => StreamError::Frame,
        FrameError::ExcessiveLoad => StreamError::ExcessiveLoad,
        // Any control-plane frame on a request stream is
        // H3_FRAME_UNEXPECTED (RFC 9114 Sections 7.2.3-7.2.7).
        FrameError::Unexpected(_) | FrameError::Settings => StreamError::FrameUnexpected,
    }
}

/// The connection's QPACK codecs plus the state they exchange with the
/// control plane and the request streams.
///
/// One instance per connection: the control plane ([`super::control`])
/// feeds the peer's encoder stream into the decoder and drains
/// [`SharedCodecs::encoder_stream`] onto the QPACK encoder stream; every
/// request stream decodes and encodes through the same instances, so
/// dynamic table state stays coherent across the connection.
///
/// `decoder` and `encoder` are split into separate `Mutex`es so that
/// `poll_send_response` (encoder) and `decode_block` (decoder) do not
/// convoy on a single lock at high throughput.
#[derive(Debug)]
pub(crate) struct SharedCodecs {
    /// Decoder for the peer's field sections, sized by our own SETTINGS.
    pub(crate) decoder: Mutex<Decoder>,
    /// Encoder for our field sections, created once the peer's SETTINGS
    /// bound its dynamic table; `None` before that (RFC 9204 Section 5).
    pub(crate) encoder: Mutex<Option<Encoder>>,
    /// Encoder stream instructions (RFC 9204 Section 4.2) queued by the
    /// send path; the control plane writes them on the QPACK encoder
    /// stream.
    pub(crate) encoder_stream: Mutex<VecDeque<Bytes>>,
    /// Field sections the peer's encoder stream unblocked, per stream.
    /// Each stream's sections are queued in arrival order; `take_unblocked_for`
    /// pops the oldest for that stream in O(1).
    pub(crate) unblocked: Mutex<FxHashMap<u64, VecDeque<UnblockedSection>>>,
    /// The peer's `SETTINGS_MAX_FIELD_SECTION_SIZE` once its SETTINGS
    /// frame arrived; `None` means unlimited.
    pub(crate) peer_max_field_section_size: Mutex<Option<u64>>,
    /// This endpoint's advertised limit, which request streams' frame
    /// decoders enforce before buffering.
    pub(crate) local_max_field_section_size: Option<u64>,
    /// Wakers of request-stream tasks parked on blocked QPACK sections.
    /// Keyed by stream ID; the control plane wakes only the streams whose
    /// sections were unblocked.
    pub(crate) waiters: Mutex<FxHashMap<u64, Waker>>,
    /// Notifier for tasks waiting for the encoder to be created (peer's
    /// SETTINGS). `wait_for_encoder` awaits this; the control plane calls
    /// `notify_waiters` once.
    pub(crate) encoder_notify: Notify,
}

impl SharedCodecs {
    /// Creates the codecs for a connection with the given local settings.
    #[inline]
    pub(crate) fn new(local: &LocalSettings) -> Self {
        let mut decoder = Decoder::new(
            local.qpack_max_table_capacity,
            local.qpack_blocked_streams as usize,
        );
        // The decoder rejects inbound field sections larger than the limit
        // this endpoint advertised (RFC 9114 Section 7.2.4.1); `None` means
        // unlimited.
        decoder.set_max_field_section_size(
            local
                .max_field_section_size
                .map(|v| v as usize)
                .unwrap_or(usize::MAX),
        );
        Self {
            decoder: Mutex::new(decoder),
            encoder: Mutex::new(None),
            encoder_stream: Mutex::new(VecDeque::new()),
            unblocked: Mutex::new(FxHashMap::default()),
            peer_max_field_section_size: Mutex::new(None),
            local_max_field_section_size: local.max_field_section_size,
            waiters: Mutex::new(FxHashMap::default()),
            encoder_notify: Notify::new(),
        }
    }

    /// Drains and returns every waiter parked on shared codec state, so
    /// the caller can wake them after releasing the lock.
    ///
    /// Waking a waiter whose section is still blocked is harmless: it
    /// re-polls, finds nothing, and re-registers.
    #[inline]
    pub(crate) fn take_waiters(&self) -> Vec<Waker> {
        self.waiters
            .lock()
            .drain()
            .map(|(_, waker)| waker)
            .collect()
    }

    /// Drains and returns waiters only for the given stream IDs.
    #[inline]
    pub(crate) fn take_waiters_for(&self, ids: &[u64]) -> Vec<Waker> {
        let mut waiters = self.waiters.lock();
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(waker) = waiters.remove(id) {
                out.push(waker);
            }
        }
        out
    }
}

/// One HTTP/3 request stream: the request/response exchange on a single
/// bidirectional QUIC stream.
///
/// Owned by the connection driver, which reads the request
/// Tracks an in-progress write so that a re-poll after a `Pending` transport
/// drains the send buffer instead of re-encoding (which would duplicate bytes).
enum PendingSend {
    None,
    ResponseHeaders(StatusCode),
    Data,
    Trailers,
}

/// The largest combined size for which a frame's header and payload are
/// coalesced into a single contiguous buffer. Coalescing turns two
/// `poll_send` calls (and their per-call transport overhead) into one at the
/// cost of copying the payload; beyond this size the copy is not worth it and
/// the payload is written on its own.
///
/// Increased from 1024 to 16384 (quinn's max datagram/frame coalesce):
/// 1k-16k responses incurred two copies (coalesce in `poll_write_parts` +
/// copy into `BytesMut buf` in `quinn::Send::poll_write`). 16k covers
/// typical small responses (<16 KiB) in one write; larger payloads
/// stay vectored to avoid copy.
const WRITE_INLINE_LIMIT: usize = 16384;

/// A bidirectional HTTP/3 request stream.
///
/// Wraps a QUIC bidirectional stream ([`transport::BidiStream`]) and
/// implements the HTTP/3 framing layer: reading the request
/// ([`RequestStream::poll_headers`]), streaming the body
/// ([`RequestStream::poll_recv_data`], [`RequestStream::poll_recv_trailers`])
/// and writes the response ([`RequestStream::poll_send_response`],
/// [`RequestStream::poll_send_data`], [`RequestStream::poll_send_trailers`],
/// [`RequestStream::poll_finish`]).
pub(crate) struct RequestStream {
    stream: Box<dyn BidiStream>,
    stream_id: u64,
    frame_decoder: FrameDecoder,
    shared: Arc<SharedCodecs>,

    // Receive state.
    awaiting_headers: bool,
    headers_blocked: bool,
    recv_data: VecDeque<Bytes>,
    trailers_lines: Option<Vec<(Bytes, Bytes)>>,
    trailers_blocked: bool,
    trailers_done: bool,
    recv_finished: bool,

    // Send state.
    sent_headers: bool,
    sent_trailers: bool,
    sent_fin: bool,
    pending_send: PendingSend,
    send_buf: VecDeque<Bytes>,
}

impl RequestStream {
    /// Wraps an accepted request stream. `stream.id()` is its QUIC stream
    /// ID, used to correlate QPACK state (blocked field sections, section
    /// acknowledgements).
    #[inline]
    pub(crate) fn new(stream: Box<dyn BidiStream>, shared: Arc<SharedCodecs>) -> Self {
        let stream_id = stream.id();
        Self {
            stream,
            stream_id,
            frame_decoder: FrameDecoder::with_max_field_section(
                shared.local_max_field_section_size,
            ),
            shared,
            awaiting_headers: true,
            headers_blocked: false,
            recv_data: VecDeque::new(),
            trailers_lines: None,
            trailers_blocked: false,
            trailers_done: false,
            recv_finished: false,
            sent_headers: false,
            sent_trailers: false,
            sent_fin: false,
            pending_send: PendingSend::None,
            send_buf: VecDeque::new(),
        }
    }

    /// The QUIC stream ID of this request stream.
    #[allow(dead_code)] // consumed by the connection driver (step 15)
    #[inline]
    pub(crate) fn id(&self) -> u64 {
        self.stream_id
    }

    /// Polls for the initial HEADERS frame and decodes it into the
    /// request. `Ok(None)` when the stream ended without one.
    ///
    /// While the field section is blocked on a QPACK dynamic table entry,
    /// polls `Pending`; it returns once the control plane's processing of
    /// the peer's encoder stream unblocks it.
    #[inline]
    pub(crate) fn poll_headers(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Request<()>>, StreamError>> {
        if self.headers_blocked {
            let section = take_unblocked_for(&self.shared, self.stream_id, cx);
            if let Some(section) = section {
                self.headers_blocked = false;
                self.awaiting_headers = false;
                return Poll::Ready(build_request(section.headers).map(Some));
            }
            return Poll::Pending;
        }
        if !self.awaiting_headers {
            return Poll::Ready(Ok(None));
        }
        match ready!(self.poll_frame(cx)?) {
            None => {
                self.awaiting_headers = false;
                self.finish_recv();
                Poll::Ready(Ok(None))
            }
            Some(Frame::Headers(block)) => match self.decode_block(&block) {
                Ok(Some(headers)) => match build_request(headers) {
                    Ok(request) => {
                        self.awaiting_headers = false;
                        Poll::Ready(Ok(Some(request)))
                    }
                    Err(err) => Poll::Ready(Err(err)),
                },
                Ok(None) => {
                    self.headers_blocked = true;
                    Poll::Pending
                }
                Err(err) => Poll::Ready(Err(err)),
            },
            Some(_) => {
                // RFC 9114 Section 4.1: the first frame on a request
                // stream must be HEADERS.
                Poll::Ready(Err(StreamError::FrameUnexpected))
            }
        }
    }

    /// Polls for the next chunk of the request body.
    ///
    /// `Ok(None)` when the body is complete (the stream ended or the
    /// trailers HEADERS frame arrived); any buffered trailers are then
    /// available via [`RequestStream::poll_recv_trailers`]. A frame after
    /// the trailers is `H3_FRAME_UNEXPECTED`.
    #[inline]
    pub(crate) fn poll_recv_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>, StreamError>> {
        if let Some(data) = self.recv_data.pop_front() {
            return Poll::Ready(Ok(Some(data)));
        }
        if self.recv_finished {
            return Poll::Ready(Ok(None));
        }
        if self.awaiting_headers || self.headers_blocked || self.trailers_blocked {
            // The request is not past its HEADERS yet; the driver must
            // poll headers first.
            return Poll::Pending;
        }
        if self.trailers_done {
            // After the trailers, only unknown frames may appear.
            match ready!(self.poll_after_trailers(cx)?) {
                Some(()) => {
                    self.finish_recv();
                    return Poll::Ready(Ok(None));
                }
                None => return Poll::Pending,
            }
        }
        match ready!(self.poll_frame(cx)?) {
            None => {
                self.finish_recv();
                Poll::Ready(Ok(None))
            }
            Some(Frame::Data(data)) => Poll::Ready(Ok(Some(data))),
            Some(Frame::Headers(block)) => {
                // Trailers: the body is over. The field section is
                // buffered and validated by poll_recv_trailers.
                match self.decode_block(&block) {
                    Ok(Some(headers)) => {
                        self.trailers_done = true;
                        self.trailers_lines = Some(headers);
                        Poll::Ready(Ok(None))
                    }
                    Ok(None) => {
                        self.trailers_blocked = true;
                        Poll::Ready(Ok(None))
                    }
                    Err(err) => Poll::Ready(Err(err)),
                }
            }
            Some(_) => Poll::Ready(Err(StreamError::FrameUnexpected)),
        }
    }

    /// Polls for the request's trailers, decoded into a `HeaderMap`.
    ///
    /// `Ok(None)` when there were none. Any known frame after the trailers
    /// is `H3_FRAME_UNEXPECTED` (RFC 9114 Section 4.1).
    #[inline]
    pub(crate) fn poll_recv_trailers(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<HeaderMap>, StreamError>> {
        if let Some(lines) = self.trailers_lines.take() {
            return Poll::Ready(header_map(lines).map(Some));
        }
        if self.trailers_blocked {
            if let Some(section) = take_unblocked_for(&self.shared, self.stream_id, cx) {
                self.trailers_blocked = false;
                self.trailers_done = true;
                return Poll::Ready(header_map(section.headers).map(Some));
            }
            return Poll::Pending;
        }
        if self.recv_finished {
            return Poll::Ready(Ok(None));
        }
        if self.awaiting_headers || self.headers_blocked {
            return Poll::Pending;
        }
        if self.trailers_done {
            match ready!(self.poll_after_trailers(cx)?) {
                Some(()) => {
                    self.finish_recv();
                    return Poll::Ready(Ok(None));
                }
                None => return Poll::Pending,
            }
        }
        match ready!(self.poll_frame(cx)?) {
            None => {
                self.finish_recv();
                Poll::Ready(Ok(None))
            }
            Some(Frame::Headers(block)) => match self.decode_block(&block) {
                Ok(Some(headers)) => {
                    self.trailers_done = true;
                    Poll::Ready(header_map(headers).map(Some))
                }
                Ok(None) => {
                    self.trailers_blocked = true;
                    Poll::Pending
                }
                Err(err) => Poll::Ready(Err(err)),
            },
            Some(Frame::Data(_)) => {
                // Data after the body was reported over: the caller
                // polled trailers before the body was done, or the
                // peer violated the frame ordering.
                Poll::Ready(Err(StreamError::FrameUnexpected))
            }
            Some(_) => Poll::Ready(Err(StreamError::FrameUnexpected)),
        }
    }

    /// Writes the response: the HEADERS frame for `status` and `headers`.
    ///
    /// The field section is encoded with the shared encoder (queuing its
    /// encoder-stream instructions) and must fit the peer's
    /// `SETTINGS_MAX_FIELD_SECTION_SIZE`. Informational responses (1xx:
    /// 100 Continue, 103 Early Hints) may precede the final one; only one
    /// final response may be sent.
    #[inline]
    pub(crate) fn poll_send_response(
        &mut self,
        cx: &mut Context<'_>,
        status: StatusCode,
        headers: &HeaderMap,
    ) -> Poll<Result<(), StreamError>> {
        if self.sent_headers && !status.is_informational() {
            // RFC 9114 Section 4.1: a second response on the same stream
            // is invalid; the server resets it.
            return Poll::Ready(Err(StreamError::Message));
        }
        match &self.pending_send {
            PendingSend::ResponseHeaders(_) => {
                // Re-poll after a Pending transport: just drain send_buf.
                ready!(self.poll_write(cx, Bytes::new()))?;
                let pending = std::mem::replace(&mut self.pending_send, PendingSend::None);
                if let PendingSend::ResponseHeaders(s) = pending {
                    if !s.is_informational() {
                        self.sent_headers = true;
                    }
                }
                Poll::Ready(Ok(()))
            }
            PendingSend::None => {
                let mut lines = Vec::with_capacity(headers.len() + 1);
                lines.push((
                    Bytes::from_static(b":status"),
                    Bytes::copy_from_slice(status.as_str().as_bytes()),
                ));
                for (name, value) in headers {
                    if name.as_str().starts_with(':') {
                        return Poll::Ready(Err(StreamError::Message));
                    }
                    lines.push((
                        Bytes::copy_from_slice(name.as_str().as_bytes()),
                        Bytes::copy_from_slice(value.as_bytes()),
                    ));
                }
                let (frame_header, field_section) = self.encode_headers(&lines)?;
                self.pending_send = PendingSend::ResponseHeaders(status);
                ready!(self.poll_write_parts(cx, frame_header, field_section))?;
                let pending = std::mem::replace(&mut self.pending_send, PendingSend::None);
                if let PendingSend::ResponseHeaders(s) = pending {
                    if !s.is_informational() {
                        self.sent_headers = true;
                    }
                }
                Poll::Ready(Ok(()))
            }
            _ => Poll::Ready(Err(StreamError::Message)),
        }
    }

    /// Writes one DATA frame with `data`.
    #[inline]
    pub(crate) fn poll_send_data(
        &mut self,
        cx: &mut Context<'_>,
        data: Bytes,
    ) -> Poll<Result<(), StreamError>> {
        match &self.pending_send {
            PendingSend::Data => {
                // Re-poll after a Pending transport: just drain send_buf.
                ready!(self.poll_write(cx, Bytes::new()))?;
                self.pending_send = PendingSend::None;
                Poll::Ready(Ok(()))
            }
            PendingSend::None => {
                let mut frame_header =
                    BytesMut::with_capacity(1 + crate::h3::frame::varint_size(data.len() as u64));
                write_varint(FRAME_DATA, &mut frame_header);
                write_varint(data.len() as u64, &mut frame_header);
                self.pending_send = PendingSend::Data;
                ready!(self.poll_write_parts(cx, frame_header.freeze(), data))?;
                self.pending_send = PendingSend::None;
                Poll::Ready(Ok(()))
            }
            _ => Poll::Ready(Err(StreamError::Message)),
        }
    }

    /// Writes the trailers HEADERS frame. No DATA may follow.
    #[inline]
    pub(crate) fn poll_send_trailers(
        &mut self,
        cx: &mut Context<'_>,
        trailers: &HeaderMap,
    ) -> Poll<Result<(), StreamError>> {
        if !self.sent_headers {
            return Poll::Ready(Err(StreamError::Message));
        }
        match &self.pending_send {
            PendingSend::Trailers => {
                // Re-poll after a Pending transport: just drain send_buf.
                ready!(self.poll_write(cx, Bytes::new()))?;
                self.pending_send = PendingSend::None;
                Poll::Ready(Ok(()))
            }
            PendingSend::None => {
                let mut lines = Vec::with_capacity(trailers.len());
                for (name, value) in trailers {
                    if name.as_str().starts_with(':') {
                        return Poll::Ready(Err(StreamError::Message));
                    }
                    lines.push((
                        Bytes::copy_from_slice(name.as_str().as_bytes()),
                        Bytes::copy_from_slice(value.as_bytes()),
                    ));
                }
                let (frame_header, field_section) = self.encode_headers(&lines)?;
                self.pending_send = PendingSend::Trailers;
                ready!(self.poll_write_parts(cx, frame_header, field_section))?;
                self.pending_send = PendingSend::None;
                self.sent_trailers = true;
                Poll::Ready(Ok(()))
            }
            _ => Poll::Ready(Err(StreamError::Message)),
        }
    }

    /// Finishes the response (`FIN`), after all queued data was written.
    #[inline]
    pub(crate) fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamError>> {
        ready!(self.poll_write(cx, Bytes::new())?);
        self.stream.poll_finish(cx).map_err(StreamError::Transport)
    }

    /// Waits until the peer stops the stream or reads the stream to completion.
    #[inline]
    pub(crate) fn poll_stopped(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamError>> {
        self.stream.poll_stopped(cx).map_err(StreamError::Transport)
    }

    /// Resets the sending side of the stream with `code` (RFC 9114
    /// Section 4.1), discarding buffered data.
    #[inline]
    pub(crate) fn poll_reset(
        &mut self,
        cx: &mut Context<'_>,
        code: u64,
    ) -> Poll<Result<(), StreamError>> {
        self.stream
            .poll_reset(cx, code)
            .map_err(StreamError::Transport)
    }

    /// Stops the peer from sending on the stream with `code`.
    #[inline]
    pub(crate) fn poll_stop_sending(
        &mut self,
        cx: &mut Context<'_>,
        code: u64,
    ) -> Poll<Result<(), StreamError>> {
        self.stream
            .poll_stop_sending(cx, code)
            .map_err(StreamError::Transport)
    }

    /// Encodes a field section with the shared encoder, enforces the peer's
    /// field-section size limit, and returns the HEADERS frame header plus
    /// its field section as separate byte ranges. Keeping the body separate
    /// lets the transport write the QPACK output without copying it again.
    #[inline]
    fn encode_headers(&mut self, lines: &[(Bytes, Bytes)]) -> Result<(Bytes, Bytes), StreamError> {
        let section = {
            let mut encoder_guard = self.shared.encoder.lock();
            let encoder = encoder_guard.as_mut().ok_or(StreamError::Message)?;
            encoder.encode_section_with_ack_base(self.stream_id, lines)
        };
        let size = section.block.len() as u64;
        if let Some(limit) = *self.shared.peer_max_field_section_size.lock() {
            if size > limit {
                return Err(StreamError::HeadersTooBig { size, limit });
            }
        }
        let block = section.block;
        let encoder_stream = section.encoder_stream;
        if !encoder_stream.is_empty() {
            self.shared.encoder_stream.lock().push_back(encoder_stream);
        }
        let mut frame_header =
            BytesMut::with_capacity(1 + crate::h3::frame::varint_size(block.len() as u64));
        write_varint(FRAME_HEADERS, &mut frame_header);
        write_varint(block.len() as u64, &mut frame_header);
        Ok((frame_header.freeze(), block))
    }

    /// Decodes one encoded field section with the shared decoder, marking
    /// it blocked when a dynamic table entry is missing.
    #[inline]
    fn decode_block(&self, block: &[u8]) -> Result<Option<Vec<(Bytes, Bytes)>>, StreamError> {
        self.shared
            .decoder
            .lock()
            .decode_block(block, self.stream_id, now())
            .map_err(StreamError::Qpack)
    }

    /// Marks the stream's receive side complete: the peer ended its send
    /// side, so no further field sections can arrive on this stream. The
    /// decoder's per-stream field-section budget for it is released.
    ///
    /// Only the peer's stream end triggers this, so every field section of
    /// the stream (headers, trailers) has decoded by now; a blocked
    /// section would have suspended frame reads before the end was
    /// observable.
    #[inline]
    fn finish_recv(&mut self) {
        self.recv_finished = true;
        self.shared.decoder.lock().stream_finished(self.stream_id);
    }

    /// After the trailers, reads and discards unknown frames; a known
    /// frame is `H3_FRAME_UNEXPECTED` (RFC 9114 Section 4.1).
    ///
    /// `Ok(Some(()))` when the stream ended cleanly after the trailers.
    #[inline]
    fn poll_after_trailers(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<()>, StreamError>> {
        loop {
            match ready!(self.poll_frame(cx)?) {
                None => return Poll::Ready(Ok(Some(()))),
                Some(frame) => {
                    if frame.is_known() {
                        return Poll::Ready(Err(StreamError::FrameUnexpected));
                    }
                    // Unknown frames are ignored.
                }
            }
        }
    }

    /// Reads frames until one is available (buffering chunks into the
    /// frame decoder, the way a real transport delivers them). A stream
    /// that ends mid-frame is `H3_FRAME_ERROR`.
    #[inline]
    fn poll_frame(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Frame>, StreamError>> {
        loop {
            // RFC 9114 Sections 7.2.3-7.2.7: control-plane frames (CANCEL_PUSH,
            // SETTINGS, PUSH_PROMISE, GOAWAY, MAX_PUSH_ID) MUST NOT appear on a
            // request stream and are H3_FRAME_UNEXPECTED — even when malformed,
            // so reject them at the type level before the decoder parses them.
            if let Some(ty) = self.frame_decoder.peek_frame_type() {
                if matches!(
                    ty,
                    FRAME_CANCEL_PUSH
                        | FRAME_SETTINGS
                        | FRAME_PUSH_PROMISE
                        | FRAME_GOAWAY
                        | FRAME_MAX_PUSH_ID
                ) {
                    return Poll::Ready(Err(StreamError::FrameUnexpected));
                }
            }
            match self.frame_decoder.next_frame() {
                Ok(Some(frame)) => return Poll::Ready(Ok(Some(frame))),
                Ok(None) => {}
                Err(err) => return Poll::Ready(Err(map_frame_error(err))),
            }
            match ready!(self.stream.poll_recv(cx))? {
                Some(chunk) => self.frame_decoder.extend(chunk),
                None => {
                    if self.frame_decoder.buffered() != 0 {
                        return Poll::Ready(Err(StreamError::Frame));
                    }
                    self.recv_finished = true;
                    return Poll::Ready(Ok(None));
                }
            }
        }
    }

    /// Queues `bytes` behind any bytes already waiting on the transport
    /// and drains the queue.
    #[inline]
    fn poll_write(&mut self, cx: &mut Context<'_>, bytes: Bytes) -> Poll<Result<(), StreamError>> {
        if !bytes.is_empty() {
            self.send_buf.push_back(bytes);
        }
        while let Some(bytes) = self.send_buf.front() {
            match self.stream.poll_send(cx, bytes) {
                Poll::Ready(Ok(())) => {
                    self.send_buf.pop_front();
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err.into())),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }

    /// Queues two adjacent byte ranges before draining. HTTP/3 frame headers
    /// are tiny while DATA and QPACK field sections can be large. A small
    /// pair is coalesced into one contiguous buffer so the transport sees a
    /// single write; a large payload stays separate to avoid copying it.
    #[inline]
    fn poll_write_parts(
        &mut self,
        cx: &mut Context<'_>,
        first: Bytes,
        second: Bytes,
    ) -> Poll<Result<(), StreamError>> {
        if first.is_empty() {
            if second.is_empty() {
                return self.poll_write(cx, Bytes::new());
            }
            self.send_buf.push_back(second);
            return self.poll_write(cx, Bytes::new());
        }
        if second.is_empty() {
            self.send_buf.push_back(first);
            return self.poll_write(cx, Bytes::new());
        }
        if first.len() + second.len() <= WRITE_INLINE_LIMIT {
            let mut combined = BytesMut::with_capacity(first.len() + second.len());
            combined.extend_from_slice(&first);
            combined.extend_from_slice(&second);
            self.send_buf.push_back(combined.freeze());
        } else {
            self.send_buf.push_back(first);
            self.send_buf.push_back(second);
        }
        self.poll_write(cx, Bytes::new())
    }
}

/// Takes the oldest unblocked field section for `stream_id`.
#[inline]
fn take_unblocked_for(
    shared: &Arc<SharedCodecs>,
    stream_id: u64,
    cx: &mut Context<'_>,
) -> Option<UnblockedSection> {
    {
        let mut unblocked = shared.unblocked.lock();
        if let Some(queue) = unblocked.get_mut(&stream_id) {
            if let Some(section) = queue.pop_front() {
                if queue.is_empty() {
                    unblocked.remove(&stream_id);
                }
                return Some(section);
            }
        }
    }
    // No unblocked section yet: park this task until the control
    // plane feeds the peer's encoder stream and unblocks it.
    shared.waiters.lock().insert(stream_id, cx.waker().clone());
    None
}

/// The monotonic clock the QPACK decoder records blocked sections with.
#[inline]
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

/// Builds an `http::Request` from a decoded field section, enforcing the
/// RFC 9114 Section 4.1 pseudo-header rules:
///
/// - pseudo-headers must precede all regular fields;
/// - duplicate pseudo-headers and unknown ones are `H3_MESSAGE_ERROR`;
/// - `:method`, `:scheme` and `:path` are required (except CONNECT, which
///   requires only `:authority`, plus `:scheme` and `:protocol` for an
///   extended CONNECT; a plain CONNECT must not carry `:scheme`/`:path`);
/// - `:protocol` is only valid on CONNECT requests (RFC 9220).
#[inline]
fn build_request(headers: Vec<(Bytes, Bytes)>) -> Result<Request<()>, StreamError> {
    let mut method = None;
    let mut scheme = None;
    let mut authority = None;
    let mut path = None;
    let mut protocol = None;
    let mut regular = Vec::new();
    let mut pseudo_done = false;

    for (name, value) in headers {
        if name.first() == Some(&b':') {
            if pseudo_done {
                // RFC 9114 Section 4.1: pseudo-headers must precede
                // regular fields.
                return Err(StreamError::Message);
            }
            match name.as_ref() {
                b":method" => take_pseudo(&mut method, value)?,
                b":scheme" => take_pseudo(&mut scheme, value)?,
                b":authority" => take_pseudo(&mut authority, value)?,
                b":path" => take_pseudo(&mut path, value)?,
                b":protocol" => take_pseudo(&mut protocol, value)?,
                _ => return Err(StreamError::Message),
            }
        } else {
            pseudo_done = true;
            if connection_specific(&name, &value) {
                return Err(StreamError::Message);
            }
            regular.push((
                HeaderName::from_bytes(&name).map_err(|_| StreamError::Message)?,
                HeaderValue::from_maybe_shared(value).map_err(|_| StreamError::Message)?,
            ));
        }
    }

    let method = Method::from_bytes(&method.ok_or(StreamError::Message)?)
        .map_err(|_| StreamError::Message)?;
    let connect = method == Method::CONNECT;
    let extended = protocol.is_some();
    if extended && !connect {
        // RFC 9220 Section 3: `:protocol` only in CONNECT requests.
        return Err(StreamError::Message);
    }
    if connect {
        if extended {
            // RFC 9220 Section 3: an extended CONNECT carries `:scheme`,
            // `:authority`, `:method` and `:protocol`, never `:path`.
            if scheme.is_none() || authority.is_none() || path.is_some() {
                return Err(StreamError::Message);
            }
        } else {
            // RFC 9114 Section 4.1: a plain CONNECT carries only `:method`
            // and `:authority`; `:scheme` and `:path` must be omitted.
            if authority.is_none() || scheme.is_some() || path.is_some() {
                return Err(StreamError::Message);
            }
        }
    } else if scheme.is_none() || path.is_none() || authority.is_none() {
        return Err(StreamError::Message);
    }

    let uri = build_uri(connect, &scheme, &authority, &path)?;

    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .version(Version::HTTP_3)
        .body(())
        .expect("validated parts build a request");
    for (name, value) in regular {
        // `try_append` reports the header map's capacity instead of
        // panicking: a field section can carry more distinct names than the
        // map holds, and the size budget alone does not rule that out.
        if request.headers_mut().try_append(name, value).is_err() {
            return Err(StreamError::Message);
        }
    }
    Ok(request)
}

#[inline]
fn take_pseudo(slot: &mut Option<Bytes>, value: Bytes) -> Result<(), StreamError> {
    if slot.is_some() {
        // RFC 9114 Section 4.1: duplicate pseudo-headers are invalid.
        return Err(StreamError::Message);
    }
    *slot = Some(value);
    Ok(())
}

#[inline]
fn build_uri(
    connect: bool,
    scheme: &Option<Bytes>,
    authority: &Option<Bytes>,
    path: &Option<Bytes>,
) -> Result<Uri, StreamError> {
    if connect {
        // RFC 9220: the target is (scheme, authority). The request URI
        // conventionally carries the authority; step 15 passes the tunnel
        // target on.
        let authority = authority.as_ref().expect("CONNECT authority validated");
        let scheme = scheme
            .as_ref()
            .map(|s| String::from_utf8_lossy(s))
            .unwrap_or_else(|| std::borrow::Cow::from("http"));
        return Uri::builder()
            .scheme(scheme.as_ref())
            .authority(String::from_utf8_lossy(authority).as_ref())
            .path_and_query("")
            .build()
            .map_err(|_| StreamError::Message);
    }
    let scheme = scheme.as_ref().expect("scheme validated");
    let path = path.as_ref().expect("path validated");
    // Assemble the URI from validated parts rather than `format!` + a full
    // URI string parse: the builder converts each part once and skips the
    // combined-string allocation.
    match authority {
        Some(authority) => Uri::builder()
            .scheme(String::from_utf8_lossy(scheme).as_ref())
            .authority(String::from_utf8_lossy(authority).as_ref())
            .path_and_query(String::from_utf8_lossy(path).as_ref())
            .build()
            .map_err(|_| StreamError::Message),
        None => Uri::builder()
            .path_and_query(String::from_utf8_lossy(path).as_ref())
            .build()
            .map_err(|_| StreamError::Message),
    }
}

/// A connection-specific field, which makes an HTTP/3 message malformed (RFC 9114
/// Section 4.2): `TE` is allowed only as `trailers` (h3spec
/// "MUST treat a request with connection as malformed" and its siblings.)
#[inline]
fn connection_specific(name: &[u8], value: &[u8]) -> bool {
    const FIELDS: [&[u8]; 5] = [
        b"connection",
        b"keep-alive",
        b"proxy-connection",
        b"transfer-encoding",
        b"upgrade",
    ];
    FIELDS.iter().any(|f| name.eq_ignore_ascii_case(f))
        || (name.eq_ignore_ascii_case(b"te") && !value.eq_ignore_ascii_case(b"trailers"))
}

/// Converts a decoded header list into a `HeaderMap`; pseudo-headers are
/// invalid in a trailer section (RFC 9114 Section 4.1).
#[inline]
fn header_map(headers: Vec<(Bytes, Bytes)>) -> Result<HeaderMap, StreamError> {
    // `try_with_capacity` reports the map's capacity instead of panicking
    // on a section with more fields than the map can ever hold.
    let mut map = HeaderMap::try_with_capacity(headers.len()).unwrap_or_default();
    for (name, value) in headers {
        if name.first() == Some(&b':') || connection_specific(&name, &value) {
            return Err(StreamError::Message);
        }
        let name = HeaderName::from_bytes(&name).map_err(|_| StreamError::Message)?;
        let value = HeaderValue::from_maybe_shared(value).map_err(|_| StreamError::Message)?;
        // `try_append` reports the map's capacity instead of panicking.
        if map.try_append(name, value).is_err() {
            return Err(StreamError::Message);
        }
    }
    Ok(map)
}

#[cfg(test)]
mod tests;
