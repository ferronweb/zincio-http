//! HTTP/3 control plane: the control stream, QPACK streams, and the
//! connection-level state that governs them (RFC 9114 Section 6).
//!
//! This is the connection driver's control half. It owns:
//!
//! - the three outbound unidirectional streams this endpoint must open
//!   (control, QPACK encoder, QPACK decoder) via [`ControlStreams::poll_init`],
//!   the SETTINGS frame that must be its control stream's first frame, and
//!   the GOAWAY/CANCEL_PUSH/MAX_PUSH_ID frames the driver queues with the
//!   `send_*` methods and writes with [`ControlStreams::poll_flush`];
//! - the peer's inbound unidirectional streams, classified by stream
//!   type, and the peer's control stream, validated frame by frame
//!   ([`ControlStreams::poll_read`]);
//! - the QPACK decoder (sized by our own SETTINGS at construction) and
//!   encoder (created once the peer's SETTINGS bound its dynamic table).
//!   The encoder's stream instructions and the decoder's acknowledgements
//!   flow out on the QPACK streams; field sections the decoder unblocks
//!   are queued for the request-stream handler.
//!
//! Rules enforced here, all from RFC 9114 Section 6.2: a second control
//! stream, a push stream (server side), or a duplicate QPACK stream is
//! `H3_STREAM_CREATION_ERROR`; an unknown (including reserved/grease) stream
//! type is ignored, its data drained and discarded (never a connection
//! error); the first frame of the control stream must be SETTINGS
//! (`H3_MISSING_SETTINGS` otherwise);
//! a second SETTINGS or any DATA/HEADERS/PUSH_PROMISE on the control
//! stream is `H3_FRAME_UNEXPECTED`; a CANCEL_PUSH for a push this endpoint
//! never promised is `H3_ID_ERROR`; a reduced MAX_PUSH_ID is `H3_ID_ERROR`;
//! the peer closing any critical stream is `H3_CLOSED_CRITICAL_STREAM` (a
//! control stream that ends before SETTINGS is `H3_MISSING_SETTINGS`).
//!
//! The peer's QPACK decoder stream is drained and discarded: the encoder
//! emits instructions without tracking acknowledgements, so the stream is
//! consumed only to keep flow control moving.
#![allow(dead_code)]

use std::collections::VecDeque;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
use futures_util::ready;

use crate::h3::error::{H3Error, TransportError};
use crate::h3::frame::{self, Frame, FrameDecoder, FrameError};
use crate::h3::qpack::{Encoder, QpackError, UnblockedSection};
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

/// A control-plane failure, each mapped to the connection error code the
/// driver closes with (see [`ControlError::h3_code`]).
#[derive(Debug)]
pub(crate) enum ControlError {
    /// The transport failed.
    Transport(TransportError),
    /// A critical stream (control, QPACK encoder or decoder) was closed or
    /// reset by the peer (`H3_CLOSED_CRITICAL_STREAM`).
    ClosedCriticalStream,
    /// The control stream's first frame was not SETTINGS, or the control
    /// stream ended without any (`H3_MISSING_SETTINGS`).
    MissingSettings,
    /// An unknown uni stream type, a duplicate control/QPACK stream, or a
    /// push stream on the server (`H3_STREAM_CREATION_ERROR`).
    StreamCreation,
    /// A second SETTINGS, or a frame that is not permitted on the control
    /// stream (`H3_FRAME_UNEXPECTED`).
    FrameUnexpected,
    /// A malformed frame payload (`H3_FRAME_ERROR`).
    Frame,
    /// Reserved or duplicate setting identifiers (`H3_SETTINGS_ERROR`).
    Settings,
    /// A frame longer than this endpoint buffers (`H3_EXCESSIVE_LOAD`;
    /// RFC 9114 Section 7.1).
    ExcessiveLoad,
    /// A CANCEL_PUSH for a never-promised push, or a reduced MAX_PUSH_ID
    /// (`H3_ID_ERROR`).
    Id,
    /// The peer's QPACK encoder stream was malformed (RFC 9204 Section 6
    /// error family `0x02xx`).
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
    Settings(PeerSettings),
    /// The peer's GOAWAY. In the server-to-client direction `id` is a
    /// stream ID; in the client-to-server direction a push ID.
    Goaway { id: u64 },
    /// The peer's MAX_PUSH_ID (client to server; a server never sends it).
    MaxPushId { id: u64 },
    /// The peer's CANCEL_PUSH (client to server; it is `H3_ID_ERROR` for a
    /// server that never promised the push).
    CancelPush { push_id: u64 },
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
///
/// Owned by the connection driver on its single task: `poll_init` opens
/// and primes the outbound streams, `poll_read` accepts and services the
/// peer's streams and yields [`ControlEvent`]s, `poll_flush` writes
/// everything queued on the outbound streams.
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
    // A uni stream of unknown (or reserved, i.e. grease) type: drained and
    // discarded (RFC 9114 Section 6.2: recipients of unknown stream types
    // MUST discard the data or abort reading, and MUST NOT treat them as a
    // connection error of any kind).
    in_discard: Option<Box<dyn UniStream>>,

    // The connection's QPACK codecs, shared with the request streams. The
    // decoder's capacity is fixed by our own SETTINGS; the encoder is
    // created when the peer's SETTINGS bound its table.
    shared: Arc<SharedCodecs>,

    settings_received: bool,
    max_push_id: Option<u64>,
    goaway_sent: Option<u64>,

    events: VecDeque<ControlEvent>,
}

impl ControlStreams {
    /// Creates the control plane for a connection with the given local
    /// settings. The QPACK decoder is sized by them; nothing is sent until
    /// [`ControlStreams::poll_init`].
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

    /// The peer's settings once its SETTINGS frame arrived (defaults
    /// before that).
    #[inline]
    pub(crate) fn peer_settings(&self) -> &PeerSettings {
        &self.peer
    }

    /// The QPACK codecs shared with the connection's request streams.
    ///
    /// The decoder's capacity is fixed by our own SETTINGS; the encoder is
    /// created once the peer's SETTINGS bound its table (see
    /// [`ControlStreams::poll_read`]).
    #[inline]
    pub(crate) fn shared(&self) -> &Arc<SharedCodecs> {
        &self.shared
    }

    /// Field sections the peer's encoder stream unblocked, drained for the
    /// request-stream handler.
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
    #[inline]
    pub(crate) fn settings_received(&self) -> bool {
        self.settings_received
    }

    /// The peer's MAX_PUSH_ID, once received.
    #[inline]
    pub(crate) fn max_push_id(&self) -> Option<u64> {
        self.max_push_id
    }

    /// The ID this endpoint announced in its GOAWAY, once sent.
    #[inline]
    pub(crate) fn goaway_sent(&self) -> Option<u64> {
        self.goaway_sent
    }

    /// Whether a GOAWAY has been sent; the driver then rejects request
    /// streams above the announced ID and closes with `H3_NO_ERROR` once
    /// they drain.
    #[inline]
    pub(crate) fn shutting_down(&self) -> bool {
        self.goaway_sent.is_some()
    }

    /// Opens the control, QPACK encoder, and QPACK decoder streams and
    /// queues the SETTINGS frame that must open the control stream.
    /// Idempotent; call until `Ready`.
    #[inline]
    pub(crate) fn poll_init(
        &mut self,
        conn: &mut dyn Connection,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), ControlError>> {
        if self.out_control.is_none() {
            let stream = ready!(conn.poll_open_uni(cx).map_err(ControlError::from))?;
            self.out_control = Some(stream);
            // RFC 9114 Section 6.2.1: the control stream's first byte is
            // its type; the SETTINGS frame that opens it comes right after.
            let mut settings = BytesMut::new();
            frame::write_varint(STREAM_TYPE_CONTROL, &mut settings);
            Frame::Settings(self.local.to_frame()).encode(&mut settings);
            self.control_buf.extend_from_slice(&settings);
        }
        if self.out_encoder.is_none() {
            let stream = ready!(conn.poll_open_uni(cx).map_err(ControlError::from))?;
            self.out_encoder = Some(stream);
            // RFC 9204 Section 4.2: the encoder stream starts with its
            // type byte before any instruction.
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

    /// Queues a GOAWAY frame for the control stream and remembers `id` as
    /// the last request stream this endpoint will process. Only the first
    /// GOAWAY is sent; later calls are no-ops.
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
    #[inline]
    pub(crate) fn send_max_push_id(&mut self, id: u64) {
        let mut buf = BytesMut::new();
        Frame::MaxPushId(id).encode(&mut buf);
        self.control_buf.extend_from_slice(&buf);
    }

    /// Queues a CANCEL_PUSH frame (client side only).
    #[inline]
    pub(crate) fn send_cancel_push(&mut self, push_id: u64) {
        let mut buf = BytesMut::new();
        Frame::CancelPush(push_id).encode(&mut buf);
        self.control_buf.extend_from_slice(&buf);
    }

    /// Queues encoder stream instructions (e.g. the section-encoding
    /// output of [`Encoder::encode_section`]) for the QPACK encoder
    /// stream; [`ControlStreams::poll_flush`] writes them.
    #[inline]
    pub(crate) fn queue_encoder_stream(&mut self, bytes: Bytes) {
        if !bytes.is_empty() {
            self.encoder_pending.push_back(bytes);
        }
    }

    /// Moves all queued QPACK encoder instructions from the shared codecs.
    /// The connection driver uses this to transfer a whole burst without an
    /// intermediate allocation or per-instruction lock handoff.
    #[inline]
    pub(crate) fn queue_encoder_streams(&mut self, bytes: &mut VecDeque<Bytes>) {
        self.encoder_pending.append(bytes);
    }

    /// Drains the shared encoder stream queue (split-Mutex version).
    #[inline]
    pub(crate) fn queue_encoder_streams_from_shared(&mut self, shared: &SharedCodecs) {
        let mut pending = shared.encoder_stream.lock();
        if !pending.is_empty() {
            self.encoder_pending.append(&mut *pending);
        }
    }

    /// Accepts and services the peer's unidirectional streams and reads
    /// its control stream, yielding at most one event per call.
    ///
    /// Polling this in a loop drains everything the peer sent; `Pending`
    /// means all inbound inputs are idle and the transport registered a
    /// wakeup for the next chunk.
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

            // Accept one new peer uni stream; only when the previous one
            // has been classified (the transport delivers in order).
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
                        // Closing the control stream (a critical stream) is
                        // always a connection error, regardless of whether
                        // SETTINGS was seen first (RFC 9114 Section 6.2).
                        return Poll::Ready(Err(ControlError::ClosedCriticalStream));
                    }
                    Poll::Pending => {}
                }
            }
            loop {
                // The peer may open and send on its QPACK streams before
                // its control stream exists; only drain frames when it
                // does.
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
                        let (mut unblocked, acks) = {
                            let mut decoder = self.shared.decoder.lock();
                            let unblocked = match decoder.feed_encoder_stream(&chunk) {
                                Ok(unblocked) => unblocked,
                                Err(err) => return Poll::Ready(Err(ControlError::Qpack(err))),
                            };
                            let acks = decoder.take_decoder_stream();
                            (unblocked, acks)
                        };
                        // Wake only the streams whose sections were unblocked.
                        let ids: Vec<u64> = unblocked.iter().map(|s| s.stream_id).collect();
                        let waiters = self.shared.take_waiters_for(&ids);
                        if !unblocked.is_empty() {
                            let mut map = self.shared.unblocked.lock();
                            for sec in unblocked.drain(..) {
                                map.entry(sec.stream_id).or_default().push_back(sec);
                            }
                        }
                        for waker in waiters {
                            waker.wake();
                        }
                        if !acks.is_empty() {
                            self.decoder_pending.push_back(acks);
                        }
                        progressed = true;
                    }
                    Poll::Ready(None) => {
                        return Poll::Ready(Err(ControlError::ClosedCriticalStream));
                    }
                    Poll::Pending => {}
                }
            }

            // Feed the peer's QPACK decoder stream to the decoder. Its
            // instructions (Section Acknowledgments, Stream Cancellations,
            // Insert Count Increments) acknowledge our encoder's output; the
            // decoder validates them and the encoder tracks what they free
            // (RFC 9204 Sections 2.1.1 and 4.4).
            if let Some(stream) = self.in_decoder.as_mut() {
                match stream.poll_recv(cx).map_err(ControlError::from)? {
                    Poll::Ready(Some(chunk)) => {
                        {
                            let mut encoder_guard = self.shared.encoder.lock();
                            if let Some(encoder) = encoder_guard.as_mut() {
                                if let Err(err) = encoder.feed_decoder_stream(&chunk) {
                                    return Poll::Ready(Err(ControlError::Qpack(err)));
                                }
                            }
                        }
                        {
                            let mut decoder = self.shared.decoder.lock();
                            if let Err(err) = decoder.feed_decoder_stream(&chunk) {
                                return Poll::Ready(Err(ControlError::Qpack(err)));
                            }
                        }
                        progressed = true;
                    }
                    Poll::Ready(None) => {
                        return Poll::Ready(Err(ControlError::ClosedCriticalStream));
                    }
                    Poll::Pending => {}
                }
            }

            // Drain a stream of unknown type: its semantics are unknown,
            // so every byte is discarded until it ends or is reset (RFC
            // 9114 Section 6.2). Only one discard stream is serviced at a
            // time; when it ends, the next poll accepts the peer's next
            // stream.
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

    /// Reads the type varint of the stream under classification and wires
    /// it to its handler. The stream stays pending while the varint is
    /// incomplete.
    #[inline]
    fn classify_uni(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), ControlError>> {
        loop {
            let chunk = {
                let pending = self.pending_uni.as_mut().expect("pending uni stream");
                match pending.stream.poll_recv(cx).map_err(ControlError::from)? {
                    Poll::Ready(Some(chunk)) => chunk,
                    Poll::Ready(None) => {
                        // The stream ended without a complete type: an
                        // unknown stream type (RFC 9114 Section 6.2).
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
                match frame::parse_varint(&pending.buf).map_err(map_frame_error)? {
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
                        let (mut unblocked, acks) = {
                            let mut decoder = self.shared.decoder.lock();
                            let unblocked = match decoder.feed_encoder_stream(&leftover) {
                                Ok(unblocked) => unblocked,
                                Err(err) => return Poll::Ready(Err(ControlError::Qpack(err))),
                            };
                            let acks = decoder.take_decoder_stream();
                            (unblocked, acks)
                        };
                        let ids: Vec<u64> = unblocked.iter().map(|s| s.stream_id).collect();
                        let waiters = self.shared.take_waiters_for(&ids);
                        if !unblocked.is_empty() {
                            let mut map = self.shared.unblocked.lock();
                            for sec in unblocked.drain(..) {
                                map.entry(sec.stream_id).or_default().push_back(sec);
                            }
                        }
                        for waker in waiters {
                            waker.wake();
                        }
                        if !acks.is_empty() {
                            self.decoder_pending.push_back(acks);
                        }
                    }
                    self.in_encoder = Some(stream);
                }
                STREAM_TYPE_QPACK_DECODER => {
                    if self.in_decoder.is_some() {
                        return Poll::Ready(Err(ControlError::StreamCreation));
                    }
                    if !leftover.is_empty() {
                        let mut decoder = self.shared.decoder.lock();
                        if let Err(err) = decoder.feed_decoder_stream(&leftover) {
                            return Poll::Ready(Err(ControlError::Qpack(err)));
                        }
                    }
                    self.in_decoder = Some(stream);
                }
                _ => {
                    // Unknown or reserved (grease) stream type: its data
                    // has no meaning to us, so it is discarded as it
                    // arrives (RFC 9114 Section 6.2). This is never a
                    // connection error.
                    self.in_discard = Some(stream);
                }
            }
            return Poll::Ready(Ok(()));
        }
    }

    /// Validates one frame read from the peer's control stream.
    #[inline]
    fn handle_control_frame(&mut self, frame: Frame) -> Result<(), ControlError> {
        // RFC 9114 Section 6.2.1: the first frame must be SETTINGS; any
        // other first frame is H3_MISSING_SETTINGS.
        if !self.settings_received && !matches!(&frame, Frame::Settings(_)) {
            return Err(ControlError::MissingSettings);
        }
        match frame {
            Frame::Settings(settings) => {
                if self.settings_received {
                    // RFC 9114 Section 7.2.4: a second SETTINGS frame is
                    // H3_FRAME_UNEXPECTED.
                    return Err(ControlError::FrameUnexpected);
                }
                self.settings_received = true;
                self.peer.apply(&settings);
                {
                    *self.shared.encoder.lock() =
                        Some(Encoder::new(self.peer.qpack_max_table_capacity(), true));
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

    /// Moves the QPACK decoder's accumulated acknowledgements (Section
    /// Acknowledgment, Insert Count Increment) to the outbound decoder
    /// stream queue.
    #[inline]
    fn queue_decoder_acks(&mut self) {
        let acks = self.shared.decoder.lock().take_decoder_stream();
        if !acks.is_empty() {
            self.decoder_pending.push_back(acks);
        }
    }
}

#[cfg(test)]
mod tests;
