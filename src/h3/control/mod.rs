//! HTTP/3 control plane: the control stream, QPACK streams, and their
//! connection-level state (RFC 9114 Section 6).
//!
//! The control plane owns this endpoint's outbound unidirectional streams,
//! the peer's inbound streams, and the QPACK codecs shared with request
//! streams. RFC 9114 Section 6.2 stream-type and frame-ordering rules are
//! enforced here; unknown stream types are drained and ignored.

use std::collections::VecDeque;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
use futures_util::ready;

use crate::h3::error::{H3Error, TransportError};
use crate::h3::frame::{self, Frame, FrameDecoder, FrameError};
#[cfg(test)]
use crate::h3::qpack::UnblockedSection;
use crate::h3::qpack::{Encoder, QpackError};
use crate::h3::settings::{LocalSettings, PeerSettings};
use crate::h3::stream::SharedCodecs;
use crate::h3::transport::{Connection, UniStream};

/// Uni stream type: control stream (RFC 9114 Section 6.2.1).
pub(crate) const STREAM_TYPE_CONTROL: u64 = 0x0;
/// Uni stream type: push stream (RFC 9114 Section 6.2.2).
pub(crate) const STREAM_TYPE_PUSH: u64 = 0x1;
/// Uni stream type: QPACK encoder stream (RFC 9204 Section 4.2).
pub(crate) const STREAM_TYPE_QPACK_ENCODER: u64 = 0x2;
/// Uni stream type: QPACK decoder stream (RFC 9204 Section 4.4).
pub(crate) const STREAM_TYPE_QPACK_DECODER: u64 = 0x3;

/// A control-plane failure with its connection error code.
#[derive(Debug)]
pub(crate) enum ControlError {
    /// The transport failed.
    Transport(#[allow(dead_code)] TransportError),
    /// A critical stream was closed or reset by the peer.
    ClosedCriticalStream,
    /// The control stream did not start with SETTINGS.
    MissingSettings,
    /// An unknown stream type or a duplicate control/QPACK stream.
    StreamCreation,
    /// A frame that is not permitted on the control stream.
    FrameUnexpected,
    /// A malformed frame payload.
    Frame,
    /// Reserved or duplicate setting identifiers.
    Settings,
    /// A frame longer than this endpoint buffers.
    ExcessiveLoad,
    /// A CANCEL_PUSH for a never-promised push, or a reduced MAX_PUSH_ID.
    Id,
    /// The peer's QPACK encoder stream was malformed.
    Qpack(QpackError),
}

impl ControlError {
    /// The connection error code to close with.
    #[inline]
    pub(crate) fn h3_code(&self) -> u64 {
        match self {
            ControlError::Transport(_) => H3Error::GeneralProtocol.code(),
            ControlError::ClosedCriticalStream => H3Error::ClosedCriticalStream.code(),
            ControlError::MissingSettings => H3Error::MissingSettings.code(),
            ControlError::StreamCreation => H3Error::StreamCreation.code(),
            ControlError::FrameUnexpected => H3Error::FrameUnexpected.code(),
            ControlError::Frame => H3Error::FrameError.code(),
            ControlError::Settings => H3Error::Settings.code(),
            ControlError::ExcessiveLoad => H3Error::ExcessiveLoad.code(),
            ControlError::Id => H3Error::Id.code(),
            ControlError::Qpack(err) => u64::from(err.code()),
        }
    }
}

impl From<TransportError> for ControlError {
    #[inline]
    fn from(err: TransportError) -> Self {
        ControlError::Transport(err)
    }
}

impl std::fmt::Display for ControlError {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for ControlError {}

#[inline]
fn map_frame_error(err: FrameError) -> ControlError {
    match err {
        FrameError::Frame => ControlError::Frame,
        FrameError::Unexpected(_) => ControlError::FrameUnexpected,
        FrameError::Settings => ControlError::Settings,
        FrameError::ExcessiveLoad => ControlError::ExcessiveLoad,
    }
}

/// A control-plane event for the connection driver.
#[derive(Debug)]
pub(crate) enum ControlEvent {
    /// The peer's SETTINGS, the first frame of its control stream.
    Settings(#[allow(dead_code)] PeerSettings),
    /// The peer's GOAWAY. In the server-to-client direction `id` is a
    /// stream ID; in the client-to-server direction a push ID.
    Goaway {
        #[allow(dead_code)]
        id: u64,
    },
    /// The peer's MAX_PUSH_ID (client to server; a server never sends it).
    MaxPushId {
        #[allow(dead_code)]
        id: u64,
    },
}

/// The peer's control stream plus its frame decoder.
struct PeerControl {
    stream: Box<dyn UniStream>,
    decoder: FrameDecoder,
}

/// A freshly accepted uni stream whose type varint is still being read.
struct PendingUni {
    stream: Box<dyn UniStream>,
    buf: BytesMut,
}

/// The connection's control plane (RFC 9114 Section 6).
pub(crate) struct ControlStreams {
    local: LocalSettings,
    peer: PeerSettings,

    // Outbound streams and their pending bytes.
    out_control: Option<Box<dyn UniStream>>,
    control_buf: BytesMut,
    out_encoder: Option<Box<dyn UniStream>>,
    out_decoder: Option<Box<dyn UniStream>>,
    encoder_pending: VecDeque<Bytes>,
    decoder_pending: VecDeque<Bytes>,

    // Inbound streams.
    in_control: Option<PeerControl>,
    in_encoder: Option<Box<dyn UniStream>>,
    in_decoder: Option<Box<dyn UniStream>>,
    pending_uni: Option<PendingUni>,
    // A uni stream of unknown (including grease) type, drained and ignored
    // (RFC 9114 Section 6.2).
    in_discard: Option<Box<dyn UniStream>>,

    // QPACK codecs shared with request streams.
    shared: Arc<SharedCodecs>,

    settings_received: bool,
    max_push_id: Option<u64>,
    goaway_sent: Option<u64>,

    events: VecDeque<ControlEvent>,
}

impl ControlStreams {
    /// Creates the control plane with the given local settings.
    #[inline]
    pub(crate) fn new(local: LocalSettings) -> Self {
        let shared = Arc::new(SharedCodecs::new(&local));
        Self {
            local,
            peer: PeerSettings::default(),
            out_control: None,
            control_buf: BytesMut::new(),
            out_encoder: None,
            out_decoder: None,
            encoder_pending: VecDeque::new(),
            decoder_pending: VecDeque::new(),
            in_control: None,
            in_encoder: None,
            in_decoder: None,
            pending_uni: None,
            in_discard: None,
            shared,
            settings_received: false,
            max_push_id: None,
            goaway_sent: None,
            events: VecDeque::new(),
        }
    }

    /// The QPACK codecs shared with request streams.
    #[inline]
    pub(crate) fn shared(&self) -> &Arc<SharedCodecs> {
        &self.shared
    }

    /// Field sections the peer's encoder stream unblocked, drained for the
    /// request-stream handler.
    #[cfg(test)]
    #[inline]
    pub(crate) fn take_unblocked(&mut self) -> Vec<UnblockedSection> {
        let mut map = self.shared.unblocked.lock();
        let mut out = Vec::new();
        for (_, mut deque) in map.drain() {
            out.extend(deque.drain(..));
        }
        out
    }

    /// Whether the peer's SETTINGS frame was received.
    #[cfg(test)]
    #[inline]
    pub(crate) fn settings_received(&self) -> bool {
        self.settings_received
    }

    /// The peer's MAX_PUSH_ID, once received.
    #[cfg(test)]
    #[inline]
    pub(crate) fn max_push_id(&self) -> Option<u64> {
        self.max_push_id
    }

    /// The ID this endpoint announced in its GOAWAY, once sent.
    #[inline]
    pub(crate) fn goaway_sent(&self) -> Option<u64> {
        self.goaway_sent
    }

    /// Whether a GOAWAY has been sent.
    #[cfg(test)]
    #[inline]
    pub(crate) fn shutting_down(&self) -> bool {
        self.goaway_sent.is_some()
    }

    /// Opens the control stream and queues its SETTINGS frame. Idempotent;
    /// call until `Ready`.
    #[inline]
    pub(crate) fn poll_init(
        &mut self,
        conn: &mut dyn Connection,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), ControlError>> {
        if self.out_control.is_none() {
            let stream = ready!(conn.poll_open_uni(cx).map_err(ControlError::from))?;
            self.out_control = Some(stream);
            // RFC 9114 Section 6.2.1: the stream type comes first, then
            // SETTINGS.
            let mut settings = BytesMut::new();
            frame::write_varint(STREAM_TYPE_CONTROL, &mut settings);
            Frame::Settings(self.local.to_frame()).encode(&mut settings);
            self.control_buf.extend_from_slice(&settings);
        }
        if self.out_encoder.is_none() {
            let stream = ready!(conn.poll_open_uni(cx).map_err(ControlError::from))?;
            self.out_encoder = Some(stream);
            // RFC 9204 Section 4.2: the encoder stream starts with its type.
            self.encoder_pending
                .push_back(Bytes::from_static(&[STREAM_TYPE_QPACK_ENCODER as u8]));
        }
        if self.out_decoder.is_none() {
            let stream = ready!(conn.poll_open_uni(cx).map_err(ControlError::from))?;
            self.out_decoder = Some(stream);
            // RFC 9204 Section 4.4: the decoder stream starts with its
            // type byte before any instruction.
            self.decoder_pending
                .push_back(Bytes::from_static(&[STREAM_TYPE_QPACK_DECODER as u8]));
        }
        Poll::Ready(Ok(()))
    }

    /// Writes everything queued on the outbound control and QPACK streams.
    /// Call until `Ready`.
    #[inline]
    pub(crate) fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), ControlError>> {
        if let Some(stream) = self.out_control.as_mut() {
            if !self.control_buf.is_empty() {
                ready!(stream
                    .poll_send(cx, &self.control_buf)
                    .map_err(ControlError::from)?);
                self.control_buf.clear();
            }
        }
        if let Some(stream) = self.out_encoder.as_mut() {
            while let Some(bytes) = self.encoder_pending.front() {
                match stream.poll_send(cx, bytes).map_err(ControlError::from)? {
                    Poll::Ready(()) => {
                        self.encoder_pending.pop_front();
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }
        }
        if let Some(stream) = self.out_decoder.as_mut() {
            while let Some(bytes) = self.decoder_pending.front() {
                match stream.poll_send(cx, bytes).map_err(ControlError::from)? {
                    Poll::Ready(()) => {
                        self.decoder_pending.pop_front();
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }
        }
        Poll::Ready(Ok(()))
    }

    /// Feeds a chunk from the peer's QPACK encoder stream to the decoder and
    /// queues decoder-stream acknowledgements.
    #[inline]
    fn feed_encoder_stream(&mut self, chunk: &[u8]) -> Result<(), ControlError> {
        let (mut unblocked, acks) = {
            let mut decoder = self.shared.decoder.lock();
            let unblocked = decoder
                .feed_encoder_stream(chunk)
                .map_err(ControlError::Qpack)?;
            let acks = decoder.take_decoder_stream();
            (unblocked, acks)
        };
        // Wake only the streams whose sections were unblocked.
        let ids: Vec<u64> = unblocked.iter().map(|s| s.stream_id).collect();
        let waiters = self.shared.take_waiters_for(&ids);
        if !unblocked.is_empty() {
            let mut map = self.shared.unblocked.lock();
            for section in unblocked.drain(..) {
                map.entry(section.stream_id).or_default().push_back(section);
            }
        }
        for waker in waiters {
            waker.wake();
        }
        if !acks.is_empty() {
            self.decoder_pending.push_back(acks);
        }
        Ok(())
    }

    /// Feeds a chunk from the peer's QPACK decoder stream to the encoder
    /// and decoder (RFC 9204 Sections 2.1.1 and 4.4).
    #[inline]
    fn feed_decoder_stream(&mut self, chunk: &[u8]) -> Result<(), ControlError> {
        let mut encoder_guard = self.shared.encoder.lock();
        if let Some(encoder) = encoder_guard.as_mut() {
            encoder
                .feed_decoder_stream(chunk)
                .map_err(ControlError::Qpack)?;
        }
        drop(encoder_guard);
        self.shared
            .decoder
            .lock()
            .feed_decoder_stream(chunk)
            .map_err(ControlError::Qpack)
    }

    /// Queues a GOAWAY frame. Only the first call takes effect.
    #[inline]
    pub(crate) fn send_goaway(&mut self, id: u64) {
        if self.goaway_sent.is_some() {
            return;
        }
        let mut buf = BytesMut::new();
        Frame::Goaway(id).encode(&mut buf);
        self.control_buf.extend_from_slice(&buf);
        self.goaway_sent = Some(id);
    }

    /// Queues a MAX_PUSH_ID frame (client side only).
    #[cfg(test)]
    #[inline]
    pub(crate) fn send_max_push_id(&mut self, id: u64) {
        let mut buf = BytesMut::new();
        Frame::MaxPushId(id).encode(&mut buf);
        self.control_buf.extend_from_slice(&buf);
    }

    /// Queues a CANCEL_PUSH frame (client side only).
    #[cfg(test)]
    #[inline]
    pub(crate) fn send_cancel_push(&mut self, push_id: u64) {
        let mut buf = BytesMut::new();
        Frame::CancelPush(push_id).encode(&mut buf);
        self.control_buf.extend_from_slice(&buf);
    }

    /// Drains the shared encoder stream queue (split-Mutex version).
    #[inline]
    pub(crate) fn queue_encoder_streams_from_shared(&mut self, shared: &SharedCodecs) {
        let mut pending = shared.encoder_stream.lock();
        if !pending.is_empty() {
            self.encoder_pending.append(&mut *pending);
        }
    }

    /// Accepts and services the peer's unidirectional streams, yielding at
    /// most one event per call.
    #[inline]
    pub(crate) fn poll_read(
        &mut self,
        conn: &mut dyn Connection,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<ControlEvent>, ControlError>> {
        loop {
            if let Some(event) = self.events.pop_front() {
                return Poll::Ready(Ok(Some(event)));
            }
            let mut progressed = false;

            // Accept one new peer stream once the previous is classified.
            if self.pending_uni.is_none() {
                match conn.poll_accept_uni(cx).map_err(ControlError::from)? {
                    Poll::Ready(Some(stream)) => {
                        self.pending_uni = Some(PendingUni {
                            stream,
                            buf: BytesMut::new(),
                        });
                        progressed = true;
                    }
                    Poll::Ready(None) | Poll::Pending => {}
                }
            }

            // Advance classification of the pending stream's type varint.
            if self.pending_uni.is_some() {
                if let Poll::Ready(()) = self.classify_uni(cx)? {
                    progressed = true;
                }
            }

            // Read the peer's control stream and validate its frames.
            if let Some(control) = self.in_control.as_mut() {
                match control.stream.poll_recv(cx).map_err(ControlError::from)? {
                    Poll::Ready(Some(chunk)) => {
                        control.decoder.extend(chunk);
                        progressed = true;
                    }
                    Poll::Ready(None) => {
                        // Closing a critical stream is always a connection
                        // error (RFC 9114 Section 6.2).
                        return Poll::Ready(Err(ControlError::ClosedCriticalStream));
                    }
                    Poll::Pending => {}
                }
            }
            loop {
                // QPACK streams may arrive before the control stream; only
                // drain frames once it exists.
                let frame = {
                    let control = match self.in_control.as_mut() {
                        Some(control) => control,
                        None => break,
                    };
                    match control.decoder.next_frame() {
                        Ok(Some(frame)) => Some(frame),
                        Ok(None) => None,
                        Err(err) => return Poll::Ready(Err(map_frame_error(err))),
                    }
                };
                match frame {
                    Some(frame) => {
                        progressed = true;
                        self.handle_control_frame(frame)?;
                    }
                    None => break,
                }
            }

            // Feed the peer's QPACK encoder stream to the decoder.
            if let Some(stream) = self.in_encoder.as_mut() {
                match stream.poll_recv(cx).map_err(ControlError::from)? {
                    Poll::Ready(Some(chunk)) => {
                        self.feed_encoder_stream(&chunk)?;
                        progressed = true;
                    }
                    Poll::Ready(None) => {
                        return Poll::Ready(Err(ControlError::ClosedCriticalStream));
                    }
                    Poll::Pending => {}
                }
            }

            // Feed the peer's QPACK decoder stream to the encoder and
            // decoder (RFC 9204 Sections 2.1.1 and 4.4).
            if let Some(stream) = self.in_decoder.as_mut() {
                match stream.poll_recv(cx).map_err(ControlError::from)? {
                    Poll::Ready(Some(chunk)) => {
                        self.feed_decoder_stream(&chunk)?;
                        progressed = true;
                    }
                    Poll::Ready(None) => {
                        return Poll::Ready(Err(ControlError::ClosedCriticalStream));
                    }
                    Poll::Pending => {}
                }
            }

            // Drain a stream of unknown type; this is never a connection
            // error (RFC 9114 Section 6.2).
            if let Some(stream) = self.in_discard.as_mut() {
                match stream.poll_recv(cx).map_err(ControlError::from)? {
                    Poll::Ready(Some(_)) => progressed = true,
                    Poll::Ready(None) => {
                        self.in_discard = None;
                        progressed = true;
                    }
                    Poll::Pending => {}
                }
            }

            if !progressed {
                return Poll::Pending;
            }
        }
    }

    /// Reads the type varint of the pending stream and wires it to its
    /// handler.
    #[inline]
    fn classify_uni(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), ControlError>> {
        loop {
            let chunk = {
                let pending = self.pending_uni.as_mut().expect("pending uni stream");
                match pending.stream.poll_recv(cx).map_err(ControlError::from)? {
                    Poll::Ready(Some(chunk)) => chunk,
                    Poll::Ready(None) => {
                        // An incomplete stream type is an unknown type
                        // (RFC 9114 Section 6.2).
                        self.pending_uni = None;
                        return Poll::Ready(Err(ControlError::StreamCreation));
                    }
                    Poll::Pending => return Poll::Pending,
                }
            };
            self.pending_uni
                .as_mut()
                .expect("pending uni stream")
                .buf
                .extend_from_slice(&chunk);
            let (ty, used) = {
                let pending = self.pending_uni.as_ref().expect("pending uni stream");
                match frame::parse_varint(&pending.buf) {
                    Some((ty, used)) => (ty, used),
                    None => continue,
                }
            };
            let mut pending = self.pending_uni.take().expect("pending uni stream");
            let leftover = pending.buf.split_off(used);
            let stream = pending.stream;
            match ty {
                STREAM_TYPE_CONTROL => {
                    if self.in_control.is_some() {
                        return Poll::Ready(Err(ControlError::StreamCreation));
                    }
                    let mut decoder = FrameDecoder::new();
                    decoder.extend(leftover.freeze());
                    self.in_control = Some(PeerControl { stream, decoder });
                }
                STREAM_TYPE_PUSH => return Poll::Ready(Err(ControlError::StreamCreation)),
                STREAM_TYPE_QPACK_ENCODER => {
                    if self.in_encoder.is_some() {
                        return Poll::Ready(Err(ControlError::StreamCreation));
                    }
                    if !leftover.is_empty() {
                        self.feed_encoder_stream(&leftover)?;
                    }
                    self.in_encoder = Some(stream);
                }
                STREAM_TYPE_QPACK_DECODER => {
                    if self.in_decoder.is_some() {
                        return Poll::Ready(Err(ControlError::StreamCreation));
                    }
                    if !leftover.is_empty() {
                        self.feed_decoder_stream(&leftover)?;
                    }
                    self.in_decoder = Some(stream);
                }
                _ => {
                    // Unknown or grease stream type: discard its data
                    // (RFC 9114 Section 6.2).
                    self.in_discard = Some(stream);
                }
            }
            return Poll::Ready(Ok(()));
        }
    }

    /// Validates one frame read from the peer's control stream.
    #[inline]
    fn handle_control_frame(&mut self, frame: Frame) -> Result<(), ControlError> {
        // RFC 9114 Section 6.2.1: SETTINGS must be the first frame.
        if !self.settings_received && !matches!(&frame, Frame::Settings(_)) {
            return Err(ControlError::MissingSettings);
        }
        match frame {
            Frame::Settings(mut settings) => {
                if self.settings_received {
                    // RFC 9114 Section 7.2.4: a second SETTINGS frame is
                    // H3_FRAME_UNEXPECTED.
                    return Err(ControlError::FrameUnexpected);
                }
                self.settings_received = true;
                settings.normalize();
                self.peer.apply(&settings);
                {
                    *self.shared.encoder.lock() = Some(Encoder::with_max_blocked(
                        self.peer.qpack_max_table_capacity(),
                        self.peer.qpack_blocked_streams(),
                        true,
                    ));
                    *self.shared.peer_max_field_section_size.lock() =
                        self.peer.max_field_section_size();
                }
                self.shared.encoder_notify.notify_waiters();
                self.events
                    .push_back(ControlEvent::Settings(self.peer.clone()));
            }
            Frame::Goaway(id) => {
                self.events.push_back(ControlEvent::Goaway { id });
            }
            Frame::MaxPushId(id) => {
                // RFC 9114 Section 7.2.7: the maximum push ID must not be
                // reduced.
                if let Some(prev) = self.max_push_id {
                    if id < prev {
                        return Err(ControlError::Id);
                    }
                }
                self.max_push_id = Some(id);
                self.events.push_back(ControlEvent::MaxPushId { id });
            }
            Frame::CancelPush(_push_id) => {
                // RFC 9114 Section 7.2.3: a server that never sends
                // PUSH_PROMISE treats any CANCEL_PUSH as referencing a
                // push ID it never mentioned, i.e. H3_ID_ERROR.
                return Err(ControlError::Id);
            }
            Frame::Data(_) | Frame::Headers(_) | Frame::PushPromise { .. } => {
                // RFC 9114 Sections 7.2.1, 7.2.2 and 7.2.5: not permitted
                // on the control stream.
                return Err(ControlError::FrameUnexpected);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
