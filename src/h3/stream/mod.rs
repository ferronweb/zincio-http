//! HTTP/3 request stream handling (RFC 9114 Sections 4.1, 4.2 and 6.1).
//!
//! [`RequestStream`] wraps a bidirectional QUIC stream, decodes request and
//! response field sections with the shared QPACK codecs, and enforces the
//! required frame order. All methods are polling-based.

use std::collections::VecDeque;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use bytes::{Bytes, BytesMut};
use futures_util::ready;
use http::header::{HeaderMap, HeaderValue};
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
use crate::request::{field_name, is_invalid_field, parse_content_length};

/// A failure on a request stream.
///
/// Transport resets and message errors are stream-scoped; most other
/// variants close the connection with [`StreamError::h3_code`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StreamError {
    /// The transport failed or the stream was reset.
    Transport(TransportError),
    /// A malformed frame or payload.
    Frame,
    /// A frame longer than this endpoint buffers.
    ExcessiveLoad,
    /// An invalid message or pseudo-header set.
    Message,
    /// A frame that is not permitted on a request stream.
    FrameUnexpected,
    /// The peer's QPACK state made a field section undecodable.
    Qpack(QpackError),
    /// An encoded field section exceeds the peer's advertised limit.
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

/// The connection's QPACK codecs and the state exchanged with the control
/// plane.
#[derive(Debug)]
pub(crate) struct SharedCodecs {
    /// Decoder for the peer's field sections.
    pub(crate) decoder: Mutex<Decoder>,
    /// Encoder for our field sections; `None` until the peer's SETTINGS
    /// arrive.
    pub(crate) encoder: Mutex<Option<Encoder>>,
    /// Encoder stream instructions queued by the send path.
    pub(crate) encoder_stream: Mutex<VecDeque<Bytes>>,
    /// Field sections unblocked by the peer's encoder stream, per stream.
    pub(crate) unblocked: Mutex<FxHashMap<u64, VecDeque<UnblockedSection>>>,
    /// The peer's `SETTINGS_MAX_FIELD_SECTION_SIZE`; `None` means unlimited.
    pub(crate) peer_max_field_section_size: Mutex<Option<u64>>,
    /// This endpoint's advertised field-section limit.
    pub(crate) local_max_field_section_size: Option<u64>,
    /// Wakers of tasks parked on blocked QPACK sections, keyed by stream ID.
    pub(crate) waiters: Mutex<FxHashMap<u64, Waker>>,
    /// Notifies tasks waiting for the encoder to be created.
    pub(crate) encoder_notify: Notify,
    /// Waker for the connection driver when encoder instructions are queued.
    pub(crate) driver_waiter: Mutex<Option<Waker>>,
}

impl SharedCodecs {
    /// Creates the codecs for a connection with the given local settings.
    #[inline]
    pub(crate) fn new(local: &LocalSettings) -> Self {
        let mut decoder = Decoder::new(
            local.qpack_max_table_capacity,
            local.qpack_blocked_streams as usize,
        );
        // Reject inbound field sections larger than our advertised limit.
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
            driver_waiter: Mutex::new(None),
        }
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

/// The in-progress write, so a re-poll drains the send buffer instead of
/// re-encoding.
enum PendingSend {
    None,
    ResponseHeaders(StatusCode),
    Data,
    Trailers,
}

/// Largest header-plus-payload pair coalesced into one write. Larger payloads
/// stay vectored to avoid copying.
const WRITE_INLINE_LIMIT: usize = 16384;

/// A bidirectional HTTP/3 request stream.
pub(crate) struct RequestStream {
    stream: Box<dyn BidiStream>,
    stream_id: u64,
    frame_decoder: FrameDecoder,
    shared: Arc<SharedCodecs>,
    enable_connect: bool,

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
    pending_send: PendingSend,
    send_buf: VecDeque<Bytes>,
}

impl RequestStream {
    /// Wraps an accepted request stream.
    #[inline]
    pub(crate) fn new(
        stream: Box<dyn BidiStream>,
        shared: Arc<SharedCodecs>,
        enable_connect: bool,
    ) -> Self {
        let stream_id = stream.id();
        Self {
            stream,
            stream_id,
            frame_decoder: FrameDecoder::with_max_field_section(
                shared.local_max_field_section_size,
            ),
            shared,
            enable_connect,
            awaiting_headers: true,
            headers_blocked: false,
            recv_data: VecDeque::new(),
            trailers_lines: None,
            trailers_blocked: false,
            trailers_done: false,
            recv_finished: false,
            sent_headers: false,
            sent_trailers: false,
            pending_send: PendingSend::None,
            send_buf: VecDeque::new(),
        }
    }

    /// Polls for the initial HEADERS and decodes the request. Returns
    /// `Ok(None)` if the stream ends first.
    #[allow(clippy::type_complexity)]
    #[inline]
    pub(crate) fn poll_headers(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<(Request<()>, Option<u64>)>, StreamError>> {
        if self.headers_blocked {
            let section = take_unblocked_for(&self.shared, self.stream_id, cx);
            if let Some(section) = section {
                self.headers_blocked = false;
                self.awaiting_headers = false;
                return Poll::Ready(build_request(section.headers, self.enable_connect).map(Some));
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
                Ok(Some(headers)) => match build_request(headers, self.enable_connect) {
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

    /// Polls for the next request body chunk. `Ok(None)` means the body is
    /// complete; buffered trailers are then available from
    /// [`RequestStream::poll_recv_trailers`].
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

    /// Polls for the request trailers. `Ok(None)` when there were none.
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
                // DATA after the body was reported complete is an ordering
                // violation.
                Poll::Ready(Err(StreamError::FrameUnexpected))
            }
            Some(_) => Poll::Ready(Err(StreamError::FrameUnexpected)),
        }
    }

    /// Writes the response HEADERS. Informational responses may precede the
    /// final one; a second final response is invalid.
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

    /// Encodes a field section and returns the HEADERS header and block as
    /// separate byte ranges, avoiding a copy in the transport.
    #[inline]
    fn encode_headers(&mut self, lines: &[(Bytes, Bytes)]) -> Result<(Bytes, Bytes), StreamError> {
        let size = lines.iter().fold(0u64, |acc, (k, v)| {
            acc + k.len() as u64 + v.len() as u64 + 32
        });
        if let Some(limit) = *self.shared.peer_max_field_section_size.lock() {
            if size > limit {
                return Err(StreamError::HeadersTooBig { size, limit });
            }
        }
        let section = {
            let mut encoder_guard = self.shared.encoder.lock();
            let encoder = encoder_guard.as_mut().ok_or(StreamError::Message)?;
            encoder.encode_section_with_ack_base(self.stream_id, lines)
        };
        let block = section.block;
        let encoder_stream = section.encoder_stream;
        if !encoder_stream.is_empty() {
            self.shared.encoder_stream.lock().push_back(encoder_stream);
            if let Some(waiter) = self.shared.driver_waiter.lock().take() {
                waiter.wake();
            }
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

    /// Marks the receive side complete and releases the stream's
    /// field-section budget.
    #[inline]
    fn finish_recv(&mut self) {
        self.recv_finished = true;
        self.shared.decoder.lock().stream_finished(self.stream_id);
    }

    /// After trailers, discards unknown frames and rejects known ones.
    ///
    /// Returns `Some(())` when the stream ends cleanly.
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

    /// Reads frames until one is available. A stream ending mid-frame is a
    /// frame error.
    #[inline]
    fn poll_frame(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Frame>, StreamError>> {
        loop {
            // Control-plane frames are rejected before parsing, even when
            // malformed (RFC 9114 Sections 7.2.3-7.2.7).
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

    /// Queues two byte ranges, coalescing small pairs into one write.
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

/// Builds an `http::Request` from a decoded field section, enforcing RFC
/// 9114 Section 4.1 pseudo-header rules.
#[inline]
fn build_request(
    headers: Vec<(Bytes, Bytes)>,
    enable_connect: bool,
) -> Result<(Request<()>, Option<u64>), StreamError> {
    let mut method = None;
    let mut scheme = None;
    let mut authority = None;
    let mut path = None;
    let mut protocol = None;
    let mut regular = Vec::new();
    let mut content_length: Option<u64> = None;
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
            if is_invalid_field(&name, &value) {
                return Err(StreamError::Message);
            }
            if name.as_ref() == b"content-length" {
                let value = parse_content_length(value.as_ref()).ok_or(StreamError::Message)?;
                if let Some(previous) = content_length {
                    if previous != value {
                        // Content-Length ambiguity
                        return Err(StreamError::Message);
                    }
                } else {
                    content_length = Some(value);
                }
            }
            regular.push((
                field_name(&name).ok_or(StreamError::Message)?,
                HeaderValue::from_maybe_shared(value).map_err(|_| StreamError::Message)?,
            ));
        }
    }

    let method = Method::from_bytes(&method.ok_or(StreamError::Message)?)
        .map_err(|_| StreamError::Message)?;
    let connect = method == Method::CONNECT;
    let extended = protocol.is_some();
    if extended && (!connect || !enable_connect) {
        // RFC 9220 Section 3: `:protocol` only in CONNECT requests.
        // This would indicate an extended CONNECT request.
        return Err(StreamError::Message);
    }
    if connect {
        if !extended {
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
        // `try_append` reports capacity exhaustion instead of panicking.
        if request.headers_mut().try_append(name, value).is_err() {
            return Err(StreamError::Message);
        }
    }
    if let Some(proto) = protocol
        .as_deref()
        .and_then(crate::ext::Protocol::from_bytes)
    {
        request.extensions_mut().insert(proto);
    }
    Ok((request, content_length))
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
        // conventionally carries the authority
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
    // Build the URI from validated parts, avoiding a combined-string parse.
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

#[inline]
fn header_map(headers: Vec<(Bytes, Bytes)>) -> Result<HeaderMap, StreamError> {
    // `try_with_capacity` reports the map's capacity instead of panicking
    // on a section with more fields than the map can ever hold.
    let mut map = HeaderMap::try_with_capacity(headers.len()).unwrap_or_default();
    for (name, value) in headers {
        if name.first() == Some(&b':') || is_invalid_field(&name, &value) {
            return Err(StreamError::Message);
        }
        let name = field_name(&name).ok_or(StreamError::Message)?;
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
