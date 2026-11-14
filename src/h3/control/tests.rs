use super::*;
use crate::h3::frame::{Settings as FrameSettings, SETTINGS_QPACK_MAX_TABLE_CAPACITY};
use crate::h3::transport::{Accept, Connection, OpenStreams, RecvStream, SendStream};
use futures_util::task::noop_waker_ref;

#[inline]
fn cx() -> Context<'static> {
    Context::from_waker(noop_waker_ref())
}

/// Shared send log: every stream this endpoint opens records the bytes
/// written to it, in order.
type SendLog = std::sync::Arc<parking_lot::Mutex<Vec<Bytes>>>;

/// In-memory uni stream: the test feeds peer data into `inbound`; bytes
/// this endpoint sends land in the shared log and per-stream
/// `outbound`. An empty inbound queue reads as `Pending`; a `None`
/// marker means the peer finished the stream. `inbound` is shared so a
/// stream can be fed even after it was moved into the plane.
struct MockStream {
    inbound: std::sync::Arc<parking_lot::Mutex<VecDeque<Option<Bytes>>>>,
    outbound: VecDeque<Bytes>,
    log: SendLog,
}

impl MockStream {
    #[inline]
    fn new(log: SendLog) -> Self {
        Self {
            inbound: std::sync::Arc::new(parking_lot::Mutex::new(VecDeque::new())),
            outbound: VecDeque::new(),
            log,
        }
    }

    #[inline]
    fn feed(&mut self, bytes: &[u8]) {
        self.inbound
            .lock()
            .push_back(Some(Bytes::copy_from_slice(bytes)));
    }

    #[inline]
    fn finish(&mut self) {
        self.inbound.lock().push_back(None);
    }

    /// A handle to the inbound queue, to feed the stream after it has
    /// been moved into the plane.
    #[inline]
    fn sink(&self) -> std::sync::Arc<parking_lot::Mutex<VecDeque<Option<Bytes>>>> {
        self.inbound.clone()
    }

    #[inline]
    fn take_outbound(&mut self) -> Bytes {
        let mut joined = BytesMut::new();
        for chunk in self.outbound.drain(..) {
            joined.extend_from_slice(&chunk);
        }
        joined.freeze()
    }
}

impl RecvStream for MockStream {
    #[inline]
    fn poll_recv(&mut self, _cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>, TransportError>> {
        match self.inbound.lock().pop_front() {
            Some(chunk) => Poll::Ready(Ok(chunk)),
            None => Poll::Pending,
        }
    }

    #[inline]
    fn id(&self) -> u64 {
        0
    }
}

impl SendStream for MockStream {
    #[inline]
    fn poll_send(
        &mut self,
        _cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<Result<(), TransportError>> {
        let bytes = Bytes::copy_from_slice(data);
        self.log.lock().push(bytes.clone());
        self.outbound.push_back(bytes);
        Poll::Ready(Ok(()))
    }

    #[inline]
    fn poll_finish(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), TransportError>> {
        Poll::Ready(Ok(()))
    }

    #[inline]
    fn poll_reset(
        &mut self,
        _cx: &mut Context<'_>,
        _code: u64,
    ) -> Poll<Result<(), TransportError>> {
        Poll::Ready(Ok(()))
    }

    #[inline]
    fn poll_stop_sending(
        &mut self,
        _cx: &mut Context<'_>,
        _code: u64,
    ) -> Poll<Result<(), TransportError>> {
        Poll::Ready(Ok(()))
    }
}

impl UniStream for MockStream {}

/// In-memory QUIC connection: queues the peer's uni streams and hands
/// out fresh streams for this endpoint's opens.
struct MockConn {
    peer_unis: VecDeque<Box<dyn UniStream>>,
    opened: usize,
    log: SendLog,
    shutdown_code: Option<u64>,
}

impl MockConn {
    #[inline]
    fn new() -> Self {
        Self {
            peer_unis: VecDeque::new(),
            opened: 0,
            log: std::sync::Arc::new(parking_lot::Mutex::new(Vec::new())),
            shutdown_code: None,
        }
    }

    /// Queues a peer uni stream preloaded with a mock reader.
    #[inline]
    fn peer_uni(log: SendLog) -> Box<dyn UniStream> {
        Box::new(MockStream::new(log))
    }
}

impl OpenStreams for MockConn {
    #[inline]
    fn poll_open_uni(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<Box<dyn UniStream>, TransportError>> {
        self.opened += 1;
        Poll::Ready(Ok(Box::new(MockStream::new(self.log.clone()))))
    }
}

impl Accept for MockConn {
    #[inline]
    fn poll_accept(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Box<dyn crate::h3::transport::BidiStream>>, TransportError>> {
        Poll::Pending
    }

    #[inline]
    fn poll_accept_uni(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Box<dyn UniStream>>, TransportError>> {
        Poll::Ready(Ok(self.peer_unis.pop_front()))
    }
}

impl Connection for MockConn {
    #[inline]
    fn is_handshake_complete(&self) -> bool {
        true
    }

    #[inline]
    fn poll_shutdown(
        &mut self,
        _cx: &mut Context<'_>,
        error_code: u64,
    ) -> Poll<Result<(), TransportError>> {
        self.shutdown_code = Some(error_code);
        Poll::Ready(Ok(()))
    }
}

#[inline]
fn encode_frames(frames: &[Frame]) -> Bytes {
    let mut buf = BytesMut::new();
    for frame in frames {
        frame.encode(&mut buf);
    }
    buf.freeze()
}

#[inline]
fn settings_frame(settings: &FrameSettings) -> Frame {
    Frame::Settings(settings.clone())
}

/// Bytes for a peer control stream: the control stream type byte then
/// the frames.
#[inline]
fn control_wire(frames: &[Frame]) -> Bytes {
    let mut buf = BytesMut::from(&[STREAM_TYPE_CONTROL as u8][..]);
    for frame in frames {
        frame.encode(&mut buf);
    }
    buf.freeze()
}

/// Polls `poll_read` until Pending, collecting every event yielded.
#[inline]
fn drain_events(
    plane: &mut ControlStreams,
    conn: &mut MockConn,
) -> Result<Vec<ControlEvent>, ControlError> {
    let mut cx = cx();
    let mut events = Vec::new();
    loop {
        // The `?` unwraps the Result nested in the Poll, leaving
        // Poll<Option<ControlEvent>>.
        match plane.poll_read(conn, &mut cx)? {
            Poll::Ready(Some(event)) => events.push(event),
            Poll::Ready(None) => panic!("poll_read yields events or Pending"),
            Poll::Pending => break,
        }
    }
    Ok(events)
}

#[inline]
fn init_with(plane: &mut ControlStreams, conn: &mut MockConn) {
    let mut cx = cx();
    assert!(plane.poll_init(conn, &mut cx).is_ready());
    assert!(plane.poll_flush(&mut cx).is_ready());
}

#[test]
fn init_opens_three_streams_and_sends_settings_first() {
    let mut plane = ControlStreams::new(LocalSettings::default());
    let mut conn = MockConn::new();
    init_with(&mut plane, &mut conn);

    assert_eq!(conn.opened, 3);
    let log = conn.log.lock();
    assert_eq!(
        log.len(),
        3,
        "stream preludes and SETTINGS are written at init"
    );
    // RFC 9114 Section 6.2.1 / RFC 9204 Sections 4.2 and 4.4: every
    // unidirectional stream must open with its type byte.
    assert_eq!(log[0][0], STREAM_TYPE_CONTROL as u8);
    assert_eq!(log[1][0], STREAM_TYPE_QPACK_ENCODER as u8);
    assert_eq!(log[2][0], STREAM_TYPE_QPACK_DECODER as u8);
    // The control stream's first frame is SETTINGS.
    assert_eq!(
        &log[0][1..],
        &encode_frames(&[settings_frame(&LocalSettings::default().to_frame())])[..]
    );
}

#[test]
fn peer_settings_then_goaway_events() {
    let mut plane = ControlStreams::new(LocalSettings::default());
    let mut conn = MockConn::new();
    let mut peer = MockStream::new(conn.log.clone());
    let mut settings = FrameSettings::new();
    settings.insert(SETTINGS_QPACK_MAX_TABLE_CAPACITY, 4096);
    peer.feed(&control_wire(&[
        settings_frame(&settings),
        Frame::Goaway(7),
    ]));
    conn.peer_unis.push_back(Box::new(peer));

    let events = drain_events(&mut plane, &mut conn).expect("control stream is valid");
    assert_eq!(events.len(), 2);
    match &events[0] {
        ControlEvent::Settings(peer_settings) => {
            assert_eq!(peer_settings.qpack_max_table_capacity(), 4096);
        }
        other => panic!("expected Settings, got {other:?}"),
    }
    assert!(matches!(events[1], ControlEvent::Goaway { id: 7 }));
    assert!(plane.settings_received());
    // The encoder is created once the peer's SETTINGS bound its table.
    assert_eq!(
        plane
            .shared()
            .encoder
            .lock()
            .as_ref()
            .expect("encoder")
            .max_capacity(),
        4096
    );
}

#[test]
fn unknown_frames_on_control_stream_are_skipped() {
    let mut plane = ControlStreams::new(LocalSettings::default());
    let mut conn = MockConn::new();
    let mut peer = MockStream::new(conn.log.clone());
    let mut wire = BytesMut::from(&[STREAM_TYPE_CONTROL as u8][..]);
    settings_frame(&LocalSettings::default().to_frame()).encode(&mut wire);
    // Unknown frame type 0x42 with payload, between SETTINGS and GOAWAY.
    frame::write_varint(0x42, &mut wire);
    frame::write_varint(3, &mut wire);
    wire.extend_from_slice(b"xyz");
    Frame::Goaway(1).encode(&mut wire);
    peer.feed(&wire);
    conn.peer_unis.push_back(Box::new(peer));

    let events = drain_events(&mut plane, &mut conn).expect("unknown frames are skipped");
    assert_eq!(events.len(), 2);
    assert!(matches!(&events[1], ControlEvent::Goaway { id: 1 }));
}

#[test]
fn second_settings_is_frame_unexpected() {
    let mut plane = ControlStreams::new(LocalSettings::default());
    let mut conn = MockConn::new();
    let mut peer = MockStream::new(conn.log.clone());
    let settings = settings_frame(&LocalSettings::default().to_frame());
    peer.feed(&control_wire(&[settings.clone(), settings]));
    conn.peer_unis.push_back(Box::new(peer));

    let err = drain_events(&mut plane, &mut conn).unwrap_err();
    assert!(matches!(err, ControlError::FrameUnexpected));
    assert_eq!(err.h3_code(), 0x0105);
}

#[test]
fn non_settings_first_frame_is_missing_settings() {
    let mut plane = ControlStreams::new(LocalSettings::default());
    let mut conn = MockConn::new();
    let mut peer = MockStream::new(conn.log.clone());
    peer.feed(&control_wire(&[Frame::Goaway(0)]));
    conn.peer_unis.push_back(Box::new(peer));

    let err = drain_events(&mut plane, &mut conn).unwrap_err();
    assert!(matches!(err, ControlError::MissingSettings));
    assert_eq!(err.h3_code(), 0x010a);
}

#[test]
fn data_and_push_promise_on_control_stream_are_frame_unexpected() {
    for frame in [
        Frame::Data(Bytes::from_static(b"x")),
        Frame::PushPromise {
            push_id: 0,
            field_section: Bytes::new(),
        },
    ] {
        let mut plane = ControlStreams::new(LocalSettings::default());
        let mut conn = MockConn::new();
        let mut peer = MockStream::new(conn.log.clone());
        peer.feed(&control_wire(&[
            settings_frame(&LocalSettings::default().to_frame()),
            frame,
        ]));
        conn.peer_unis.push_back(Box::new(peer));
        let err = drain_events(&mut plane, &mut conn).unwrap_err();
        assert!(matches!(err, ControlError::FrameUnexpected));
    }
}

#[test]
fn cancel_push_for_never_promised_push_is_id_error() {
    let mut plane = ControlStreams::new(LocalSettings::default());
    let mut conn = MockConn::new();
    let mut peer = MockStream::new(conn.log.clone());
    peer.feed(&control_wire(&[
        settings_frame(&LocalSettings::default().to_frame()),
        Frame::CancelPush(0),
    ]));
    conn.peer_unis.push_back(Box::new(peer));

    let err = drain_events(&mut plane, &mut conn).unwrap_err();
    assert!(matches!(err, ControlError::Id));
    assert_eq!(err.h3_code(), 0x0108);
}

#[test]
fn max_push_id_must_not_decrease() {
    let mut plane = ControlStreams::new(LocalSettings::default());
    let mut conn = MockConn::new();
    let mut peer = MockStream::new(conn.log.clone());
    peer.feed(&control_wire(&[
        settings_frame(&LocalSettings::default().to_frame()),
        Frame::MaxPushId(5),
        Frame::MaxPushId(7),
    ]));
    conn.peer_unis.push_back(Box::new(peer));

    let events = drain_events(&mut plane, &mut conn).expect("growing MAX_PUSH_ID is fine");
    assert_eq!(events.len(), 3);
    assert!(matches!(events[1], ControlEvent::MaxPushId { id: 5 }));
    assert!(matches!(events[2], ControlEvent::MaxPushId { id: 7 }));
    assert_eq!(plane.max_push_id(), Some(7));

    // A reduction is H3_ID_ERROR.
    let mut plane = ControlStreams::new(LocalSettings::default());
    let mut conn = MockConn::new();
    let mut peer = MockStream::new(conn.log.clone());
    peer.feed(&control_wire(&[
        settings_frame(&LocalSettings::default().to_frame()),
        Frame::MaxPushId(5),
        Frame::MaxPushId(3),
    ]));
    conn.peer_unis.push_back(Box::new(peer));
    let err = drain_events(&mut plane, &mut conn).unwrap_err();
    assert!(matches!(err, ControlError::Id));
}

#[test]
fn control_stream_fin_after_settings_is_closed_critical_stream() {
    let mut plane = ControlStreams::new(LocalSettings::default());
    let mut conn = MockConn::new();
    let mut peer = MockStream::new(conn.log.clone());
    // The type byte arrives in its own chunk, as it does on a real
    // stream: classification consumes it, then the frame bytes come
    // through the wired control stream.
    peer.feed(&[STREAM_TYPE_CONTROL as u8]);
    peer.feed(&encode_frames(&[settings_frame(
        &LocalSettings::default().to_frame(),
    )]));
    peer.finish();
    conn.peer_unis.push_back(Box::new(peer));

    let mut cx = cx();
    let first = plane.poll_read(&mut conn, &mut cx);
    assert!(matches!(
        &first,
        Poll::Ready(Ok(Some(ControlEvent::Settings(_))))
    ));
    let then = plane.poll_read(&mut conn, &mut cx);
    assert!(matches!(
        then,
        Poll::Ready(Err(ControlError::ClosedCriticalStream))
    ));
}

#[test]
fn unknown_uni_stream_type_is_discarded() {
    let mut plane = ControlStreams::new(LocalSettings::default());
    let mut conn = MockConn::new();
    let mut unknown = MockStream::new(conn.log.clone());
    unknown.feed(&[0x42, 0x01, 0x00]);
    unknown.finish();
    conn.peer_unis.push_back(Box::new(unknown));
    let mut control = MockStream::new(conn.log.clone());
    control.feed(&control_wire(&[settings_frame(
        &LocalSettings::default().to_frame(),
    )]));
    conn.peer_unis.push_back(Box::new(control));

    let events = drain_events(&mut plane, &mut conn).expect("no error");
    assert!(matches!(events.first(), Some(ControlEvent::Settings(_))));
    assert!(plane.in_discard.is_none(), "discard stream drained");
}

#[test]
fn push_uni_stream_is_stream_creation_error() {
    let mut plane = ControlStreams::new(LocalSettings::default());
    let mut conn = MockConn::new();
    let mut peer = MockStream::new(conn.log.clone());
    peer.feed(&[STREAM_TYPE_PUSH as u8, 0x01, 0x00]);
    conn.peer_unis.push_back(Box::new(peer));

    let err = drain_events(&mut plane, &mut conn).unwrap_err();
    assert!(matches!(err, ControlError::StreamCreation));
    assert_eq!(err.h3_code(), 0x0103);
}

#[test]
fn duplicate_control_stream_is_stream_creation_error() {
    let mut plane = ControlStreams::new(LocalSettings::default());
    let mut conn = MockConn::new();
    let settings = settings_frame(&LocalSettings::default().to_frame());
    let mut peer1 = MockStream::new(conn.log.clone());
    peer1.feed(&control_wire(std::slice::from_ref(&settings)));
    let mut peer2 = MockStream::new(conn.log.clone());
    peer2.feed(&control_wire(&[settings]));
    conn.peer_unis.push_back(Box::new(peer1));
    conn.peer_unis.push_back(Box::new(peer2));

    let err = drain_events(&mut plane, &mut conn).unwrap_err();
    assert!(matches!(err, ControlError::StreamCreation));
}

#[test]
fn multi_byte_uni_stream_type_is_classified_incrementally() {
    let mut plane = ControlStreams::new(LocalSettings::default());
    let mut conn = MockConn::new();
    let mut peer = MockStream::new(conn.log.clone());
    let sink = peer.sink();
    peer.feed(&[0x7f]); // first byte of a 2-byte type (0x7f00 = 16128)
    conn.peer_unis.push_back(Box::new(peer));

    // Type varint incomplete: classification is still pending, and the
    // stream stays queued for the rest of its type byte.
    assert!(plane.poll_read(&mut conn, &mut cx()).is_pending());
    assert!(plane.pending_uni.is_some());

    // The second byte completes type 16128, which is unknown: the
    // stream is discarded, not a connection error (RFC 9114 Section
    // 6.2).
    sink.lock().push_back(Some(Bytes::from_static(&[0x00])));
    sink.lock().push_back(None);
    let events = drain_events(&mut plane, &mut conn).expect("no error");
    assert!(events.is_empty());
    assert!(plane.in_discard.is_none(), "discard stream drained");
}

#[test]
fn peer_encoder_stream_feeds_the_qpack_decoder() {
    let mut plane = ControlStreams::new(LocalSettings {
        qpack_max_table_capacity: 4096,
        ..LocalSettings::default()
    });
    let mut conn = MockConn::new();
    let mut peer = MockStream::new(conn.log.clone());
    // Type byte + a Set Capacity (0x3f 0x45 = 100) + Insert with
    // Literal Name "foo"="bar" in one chunk: leftover bytes after the
    // type must be fed to the decoder. Capacity 100 is big enough for
    // the 38-byte entry (RFC 9204 Section 3.2.1).
    peer.feed(&[
        STREAM_TYPE_QPACK_ENCODER as u8,
        0x3f,
        0x45,
        0x43,
        b'f',
        b'o',
        b'o',
        0x03,
        b'b',
        b'a',
        b'r',
    ]);
    conn.peer_unis.push_back(Box::new(peer));

    let events = drain_events(&mut plane, &mut conn).expect("encoder stream is valid");
    assert!(events.is_empty());
    assert_eq!(plane.shared().decoder.lock().inserted(), 1);
    // Nothing was blocked, so nothing was unblocked, and a plain insert
    // needs no acknowledgement yet.
    assert!(plane.take_unblocked().is_empty());
}

#[test]
fn malformed_encoder_stream_is_qpack_error() {
    let mut plane = ControlStreams::new(LocalSettings::default());
    let mut conn = MockConn::new();
    let mut peer = MockStream::new(conn.log.clone());
    // Duplicate instruction (index 0) on an empty table.
    peer.feed(&[STREAM_TYPE_QPACK_ENCODER as u8, 0x00]);
    conn.peer_unis.push_back(Box::new(peer));

    let err = drain_events(&mut plane, &mut conn).unwrap_err();
    assert!(matches!(err, ControlError::Qpack(_)));
    assert_eq!(err.h3_code(), 0x0201);
}

#[test]
fn peer_encoder_stream_fin_is_closed_critical_stream() {
    let mut plane = ControlStreams::new(LocalSettings {
        qpack_max_table_capacity: 4096,
        ..LocalSettings::default()
    });
    let mut conn = MockConn::new();
    let mut peer = MockStream::new(conn.log.clone());
    peer.feed(&[STREAM_TYPE_QPACK_ENCODER as u8, 0x2a]);
    peer.finish();
    conn.peer_unis.push_back(Box::new(peer));

    let err = drain_events(&mut plane, &mut conn).unwrap_err();
    assert!(matches!(err, ControlError::ClosedCriticalStream));
}

#[test]
fn peer_decoder_stream_zero_insert_count_increment_is_decoder_stream_error() {
    // h3spec QPACK 4.4.3: a single 0x00 byte on the peer's decoder
    // stream is an Insert Count Increment of 0 -> QPACK_DECODER_STREAM_ERROR.
    let mut plane = ControlStreams::new(LocalSettings::default());
    let mut conn = MockConn::new();
    let mut peer = MockStream::new(conn.log.clone());
    peer.feed(&[STREAM_TYPE_QPACK_DECODER as u8, 0x00]);
    conn.peer_unis.push_back(Box::new(peer));

    let err = drain_events(&mut plane, &mut conn).unwrap_err();
    match err {
        ControlError::Qpack(QpackError::DecoderStream) => {}
        other => panic!("expected DecoderStream, got {:?}", other),
    }
}

#[test]
fn send_goaway_queues_the_frame_and_marks_shutdown() {
    let mut plane = ControlStreams::new(LocalSettings::default());
    let mut conn = MockConn::new();
    init_with(&mut plane, &mut conn);

    plane.send_goaway(7);
    assert!(plane.shutting_down());
    assert_eq!(plane.goaway_sent(), Some(7));
    let mut cx = cx();
    assert!(plane.poll_flush(&mut cx).is_ready());

    {
        let log = conn.log.lock();
        assert_eq!(log.len(), 4);
        assert_eq!(log[3], encode_frames(&[Frame::Goaway(7)]));
    }
    assert_eq!(conn.shutdown_code, None, "closing is the driver's job");

    // Only one GOAWAY is ever sent.
    plane.send_goaway(9);
    assert_eq!(plane.goaway_sent(), Some(7));

    // Client-only frames queue for the control stream too; the flush
    // coalesces them into a single write.
    plane.send_max_push_id(2);
    plane.send_cancel_push(1);
    assert!(plane.poll_flush(&mut cx).is_ready());
    {
        let log = conn.log.lock();
        assert_eq!(log.len(), 5);
        assert_eq!(
            log[4],
            encode_frames(&[Frame::MaxPushId(2), Frame::CancelPush(1)])
        );
    }
}
