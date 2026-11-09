use super::*;
use crate::h3::frame;
use crate::h3::frame::{FrameDecoder, Settings as FrameSettings};
use futures_util::task::noop_waker_ref;
use http::header::CONTENT_TYPE;

#[inline]
fn cx() -> Context<'static> {
    Context::from_waker(noop_waker_ref())
}

/// In-memory bidirectional stream for a request exchange. Outbound
/// bytes go into a shared sink so a test can inspect the wire after
/// moving the stream into a `Box<dyn BidiStream>`.
struct MockBidi {
    inbound: VecDeque<Option<Bytes>>,
    outbound: std::sync::Arc<parking_lot::Mutex<VecDeque<Bytes>>>,
    id: u64,
    reset_code: Option<u64>,
    stop_code: Option<u64>,
    finished: bool,
}

impl MockBidi {
    #[inline]
    fn new(id: u64) -> Self {
        Self::with_sink(
            id,
            std::sync::Arc::new(parking_lot::Mutex::new(VecDeque::new())),
        )
    }

    #[inline]
    fn with_sink(id: u64, outbound: std::sync::Arc<parking_lot::Mutex<VecDeque<Bytes>>>) -> Self {
        Self {
            inbound: VecDeque::new(),
            outbound,
            id,
            reset_code: None,
            stop_code: None,
            finished: false,
        }
    }

    #[inline]
    fn feed(&mut self, bytes: &[u8]) {
        self.inbound.push_back(Some(Bytes::copy_from_slice(bytes)));
    }

    #[inline]
    fn finish(&mut self) {
        self.inbound.push_back(None);
    }
}

impl crate::h3::transport::RecvStream for MockBidi {
    #[inline]
    fn poll_recv(&mut self, _cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>, TransportError>> {
        match self.inbound.pop_front() {
            Some(chunk) => Poll::Ready(Ok(chunk)),
            None => Poll::Pending,
        }
    }

    #[inline]
    fn id(&self) -> u64 {
        self.id
    }
}

impl crate::h3::transport::SendStream for MockBidi {
    #[inline]
    fn poll_send(
        &mut self,
        _cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<Result<(), TransportError>> {
        self.outbound.lock().push_back(Bytes::copy_from_slice(data));
        Poll::Ready(Ok(()))
    }

    #[inline]
    fn poll_finish(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), TransportError>> {
        self.finished = true;
        Poll::Ready(Ok(()))
    }

    #[inline]
    fn poll_reset(&mut self, _cx: &mut Context<'_>, code: u64) -> Poll<Result<(), TransportError>> {
        self.reset_code = Some(code);
        Poll::Ready(Ok(()))
    }

    #[inline]
    fn poll_stop_sending(
        &mut self,
        _cx: &mut Context<'_>,
        code: u64,
    ) -> Poll<Result<(), TransportError>> {
        self.stop_code = Some(code);
        Poll::Ready(Ok(()))
    }
}

impl crate::h3::transport::BidiStream for MockBidi {}

#[inline]
fn local_settings() -> LocalSettings {
    LocalSettings {
        qpack_max_table_capacity: 4096,
        qpack_blocked_streams: 16,
        ..LocalSettings::default()
    }
}

/// A shared codec pair where the encoder is already usable (the peer's
/// SETTINGS arrived).
#[inline]
fn shared_with_encoder() -> Arc<SharedCodecs> {
    let shared = SharedCodecs::new(&local_settings());
    *shared.encoder.lock() = Some(Encoder::new(4096, true));
    Arc::new(shared)
}

/// Returns the encoder for hand-encoding wire blocks, plus the shared
/// handle.
#[inline]
fn shared_and_peer_encoder() -> (Arc<SharedCodecs>, Encoder) {
    let shared = SharedCodecs::new(&local_settings());
    *shared.encoder.lock() = Some(Encoder::new(4096, true));
    let peer_encoder = Encoder::new(4096, true);
    (Arc::new(shared), peer_encoder)
}

#[inline]
fn request_lines(method: &str, path: &str) -> Vec<(Bytes, Bytes)> {
    vec![
        (
            Bytes::from_static(b":method"),
            Bytes::copy_from_slice(method.as_bytes()),
        ),
        (Bytes::from_static(b":scheme"), Bytes::from_static(b"https")),
        (
            Bytes::from_static(b":authority"),
            Bytes::from_static(b"example.com"),
        ),
        (
            Bytes::from_static(b":path"),
            Bytes::copy_from_slice(path.as_bytes()),
        ),
    ]
}

#[test]
fn full_request_exchange() {
    let (shared, mut enc) = shared_and_peer_encoder();
    let mut wire = BytesMut::new();
    let section = enc.encode_section(0, &request_lines("POST", "/submit"));
    shared
        .decoder
        .lock()
        .feed_encoder_stream(&section.encoder_stream)
        .expect("valid");
    Frame::Headers(section.block).encode(&mut wire);
    Frame::Data(Bytes::from_static(b"hello")).encode(&mut wire);
    let body2 = Bytes::from_static(b"world");
    Frame::Data(body2).encode(&mut wire);
    let section = enc.encode_section(
        0,
        &[(
            Bytes::from_static(b"x-checksum"),
            Bytes::from_static(b"sum"),
        )],
    );
    shared
        .decoder
        .lock()
        .feed_encoder_stream(&section.encoder_stream)
        .expect("valid");
    Frame::Headers(section.block).encode(&mut wire);

    let mut stream = MockBidi::new(11);
    stream.feed(&wire);
    stream.finish();
    let mut request = RequestStream::new(Box::new(stream), shared.clone());

    let mut cx = cx();
    let req = match request.poll_headers(&mut cx) {
        Poll::Ready(Ok(Some(request))) => request,
        other => panic!("expected request, got {other:?}"),
    };
    assert_eq!(req.method(), Method::POST);
    assert_eq!(req.uri().path(), "/submit");
    assert_eq!(req.uri().scheme_str(), Some("https"));
    assert_eq!(
        req.uri().authority().map(|a| a.as_str()),
        Some("example.com")
    );
    assert_eq!(req.version(), Version::HTTP_3);

    assert_eq!(
        request.poll_recv_data(&mut cx),
        Poll::Ready(Ok(Some(Bytes::from_static(b"hello"))))
    );
    assert_eq!(
        request.poll_recv_data(&mut cx),
        Poll::Ready(Ok(Some(Bytes::from_static(b"world"))))
    );
    assert_eq!(request.poll_recv_data(&mut cx), Poll::Ready(Ok(None)));

    let trailers = match request.poll_recv_trailers(&mut cx) {
        Poll::Ready(Ok(Some(trailers))) => trailers,
        other => panic!("expected trailers, got {other:?}"),
    };
    assert_eq!(
        trailers.get("x-checksum"),
        Some(&HeaderValue::from_static("sum"))
    );
}

#[test]
fn request_without_body_is_finished_by_fin() {
    let (shared, mut enc) = shared_and_peer_encoder();
    let mut wire = BytesMut::new();
    let section = enc.encode_section(0, &request_lines("GET", "/index"));
    shared
        .decoder
        .lock()
        .feed_encoder_stream(&section.encoder_stream)
        .expect("valid");
    Frame::Headers(section.block).encode(&mut wire);

    let mut stream = MockBidi::new(13);
    stream.feed(&wire);
    stream.finish();
    let mut request = RequestStream::new(Box::new(stream), shared);

    let mut cx = cx();
    let req = match request.poll_headers(&mut cx) {
        Poll::Ready(Ok(Some(request))) => request,
        other => panic!("expected request, got {other:?}"),
    };
    assert_eq!(req.method(), Method::GET);
    assert_eq!(request.poll_recv_data(&mut cx), Poll::Ready(Ok(None)));
}

#[test]
fn data_before_headers_is_frame_unexpected() {
    let shared = shared_with_encoder();
    let mut wire = BytesMut::new();
    Frame::Data(Bytes::from_static(b"x")).encode(&mut wire);
    let mut stream = MockBidi::new(15);
    stream.feed(&wire);
    let mut request = RequestStream::new(Box::new(stream), shared);

    let mut cx = cx();
    let result = request.poll_headers(&mut cx);
    assert!(matches!(
        result,
        Poll::Ready(Err(StreamError::FrameUnexpected))
    ));
    // The error is not cached as a completion: a re-poll waits for more
    // input.
    assert!(request.poll_headers(&mut cx).is_pending());
}

#[test]
fn control_frames_on_request_stream_are_frame_unexpected() {
    for frame in [
        Frame::Settings(FrameSettings::new()),
        Frame::Goaway(0),
        Frame::MaxPushId(3),
        Frame::CancelPush(0),
    ] {
        let shared = shared_with_encoder();
        let mut wire = BytesMut::new();
        frame.encode(&mut wire);
        let mut stream = MockBidi::new(17);
        stream.feed(&wire);
        let mut request = RequestStream::new(Box::new(stream), shared.clone());
        let mut cx = cx();
        let result = request.poll_headers(&mut cx);
        assert!(
            matches!(result, Poll::Ready(Err(StreamError::FrameUnexpected))),
            "{frame:?}: {result:?}"
        );
    }
}

#[test]
fn truncated_frame_is_frame_error() {
    let shared = shared_with_encoder();
    let mut stream = MockBidi::new(19);
    // HEADERS frame with length 5 but no payload.
    stream.feed(&[0x01, 0x05]);
    stream.finish();
    let mut request = RequestStream::new(Box::new(stream), shared);

    let mut cx = cx();
    let result = request.poll_headers(&mut cx);
    assert!(matches!(result, Poll::Ready(Err(StreamError::Frame))));
    // The truncated frame is still buffered: a re-poll waits rather
    // than fabricating a request.
    assert!(request.poll_headers(&mut cx).is_pending());
}

#[test]
fn empty_body_with_trailers() {
    let (shared, mut enc) = shared_and_peer_encoder();
    let mut wire = BytesMut::new();
    let section = enc.encode_section(0, &request_lines("PUT", "/x"));
    shared
        .decoder
        .lock()
        .feed_encoder_stream(&section.encoder_stream)
        .expect("valid");
    Frame::Headers(section.block).encode(&mut wire);
    let section = enc.encode_section(0, &[(Bytes::from_static(b"x-a"), Bytes::from_static(b"1"))]);
    shared
        .decoder
        .lock()
        .feed_encoder_stream(&section.encoder_stream)
        .expect("valid");
    Frame::Headers(section.block).encode(&mut wire);
    let mut stream = MockBidi::new(21);
    stream.feed(&wire);
    stream.finish();
    let mut request = RequestStream::new(Box::new(stream), shared);

    let mut cx = cx();
    assert!(request.poll_headers(&mut cx).is_ready());
    assert_eq!(request.poll_recv_data(&mut cx), Poll::Ready(Ok(None)));
    let trailers = match request.poll_recv_trailers(&mut cx) {
        Poll::Ready(Ok(Some(trailers))) => trailers,
        other => panic!("expected trailers, got {other:?}"),
    };
    assert_eq!(trailers.get("x-a"), Some(&HeaderValue::from_static("1")));
}

#[test]
fn trailers_with_pseudo_headers_are_message_error() {
    let (shared, mut enc) = shared_and_peer_encoder();
    let mut wire = BytesMut::new();
    let section = enc.encode_section(0, &request_lines("GET", "/x"));
    shared
        .decoder
        .lock()
        .feed_encoder_stream(&section.encoder_stream)
        .expect("valid");
    Frame::Headers(section.block).encode(&mut wire);
    let section = enc.encode_section(
        0,
        &[(Bytes::from_static(b":status"), Bytes::from_static(b"200"))],
    );
    shared
        .decoder
        .lock()
        .feed_encoder_stream(&section.encoder_stream)
        .expect("valid");
    Frame::Headers(section.block).encode(&mut wire);
    let mut stream = MockBidi::new(23);
    stream.feed(&wire);
    stream.finish();
    let mut request = RequestStream::new(Box::new(stream), shared);

    let mut cx = cx();
    assert!(request.poll_headers(&mut cx).is_ready());
    assert_eq!(request.poll_recv_data(&mut cx), Poll::Ready(Ok(None)));
    let result = request.poll_recv_trailers(&mut cx);
    assert!(matches!(result, Poll::Ready(Err(StreamError::Message))));
}

#[test]
fn known_frame_after_trailers_is_frame_unexpected() {
    let (shared, mut enc) = shared_and_peer_encoder();
    let mut wire = BytesMut::new();
    let section = enc.encode_section(0, &request_lines("GET", "/x"));
    shared
        .decoder
        .lock()
        .feed_encoder_stream(&section.encoder_stream)
        .expect("valid");
    Frame::Headers(section.block).encode(&mut wire);
    let section = enc.encode_section(0, &[]);
    shared
        .decoder
        .lock()
        .feed_encoder_stream(&section.encoder_stream)
        .expect("valid");
    Frame::Headers(section.block).encode(&mut wire);
    // A DATA frame after the trailers is invalid.
    Frame::Data(Bytes::from_static(b"late")).encode(&mut wire);
    let mut stream = MockBidi::new(25);
    stream.feed(&wire);
    stream.finish();
    let mut request = RequestStream::new(Box::new(stream), shared);

    let mut cx = cx();
    assert!(request.poll_headers(&mut cx).is_ready());
    assert_eq!(request.poll_recv_data(&mut cx), Poll::Ready(Ok(None)));
    let _ = request.poll_recv_trailers(&mut cx);
    let result = request.poll_recv_data(&mut cx);
    assert!(matches!(
        result,
        Poll::Ready(Err(StreamError::FrameUnexpected))
    ));
}

#[test]
fn unknown_frames_after_trailers_are_ignored() {
    let (shared, mut enc) = shared_and_peer_encoder();
    let mut wire = BytesMut::new();
    let section = enc.encode_section(0, &request_lines("GET", "/x"));
    shared
        .decoder
        .lock()
        .feed_encoder_stream(&section.encoder_stream)
        .expect("valid");
    Frame::Headers(section.block).encode(&mut wire);
    let section = enc.encode_section(0, &[]);
    shared
        .decoder
        .lock()
        .feed_encoder_stream(&section.encoder_stream)
        .expect("valid");
    Frame::Headers(section.block).encode(&mut wire);
    // An unknown frame type 0x42 (grease-shaped but fine) after the
    // trailers is skipped.
    frame::write_varint(0x42, &mut wire);
    frame::write_varint(1, &mut wire);
    wire.extend_from_slice(b"z");
    let mut stream = MockBidi::new(27);
    stream.feed(&wire);
    stream.finish();
    let mut request = RequestStream::new(Box::new(stream), shared);

    let mut cx = cx();
    assert!(request.poll_headers(&mut cx).is_ready());
    assert_eq!(request.poll_recv_data(&mut cx), Poll::Ready(Ok(None)));
    let _ = request.poll_recv_trailers(&mut cx);
    assert_eq!(request.poll_recv_data(&mut cx), Poll::Ready(Ok(None)));
}

#[test]
fn headers_blocked_then_unblocked_by_encoder_stream() {
    let shared = shared_with_encoder();
    // A request whose field section references a dynamic table entry:
    // `x-warmup` is absent from the static table, so the peer's
    // encoder inserts it and the section carries a non-zero Required
    // Insert Count.
    let mut lines = request_lines("GET", "/blocked");
    lines.push((
        Bytes::from_static(b"x-warmup"),
        Bytes::from_static(b"wednesday"),
    ));
    let mut peer_enc = Encoder::new(64, true);
    let section = peer_enc.encode_section(0, &lines);
    assert!(!section.encoder_stream.is_empty());

    let mut wire = BytesMut::new();
    Frame::Headers(section.block).encode(&mut wire);
    let mut stream = MockBidi::new(33);
    stream.feed(&wire);
    stream.finish();
    let mut request = RequestStream::new(Box::new(stream), shared.clone());

    let mut cx = cx();
    // The encoder stream instructions have not arrived yet: the
    // section is blocked.
    let result = request.poll_headers(&mut cx);
    assert!(result.is_pending(), "expected blocked, got {result:?}");

    // The control plane feeds the peer's encoder stream (as it would
    // on the QPACK encoder stream).
    let unblocked = {
        let mut decoder = shared.decoder.lock();
        decoder
            .feed_encoder_stream(&section.encoder_stream)
            .expect("valid encoder stream")
    };
    assert_eq!(unblocked.len(), 1);
    assert_eq!(unblocked[0].stream_id, 33);
    {
        let mut map = shared.unblocked.lock();
        for sec in unblocked {
            map.entry(sec.stream_id).or_default().push_back(sec);
        }
    }

    let req = match request.poll_headers(&mut cx) {
        Poll::Ready(Ok(Some(request))) => request,
        other => panic!("expected unblocked request, got {other:?}"),
    };
    assert_eq!(req.uri().path(), "/blocked");
    assert_eq!(
        req.headers().get("x-warmup"),
        Some(&HeaderValue::from_static("wednesday"))
    );
    // The body was buffered behind the blocked section and is still
    // read in order.
    assert_eq!(request.poll_recv_data(&mut cx), Poll::Ready(Ok(None)));
}

#[test]
fn send_response_encodes_headers_and_queue_encoder_stream() {
    let shared = shared_with_encoder();
    let sink = std::sync::Arc::new(parking_lot::Mutex::new(VecDeque::new()));
    let mut request = RequestStream::new(
        Box::new(MockBidi::with_sink(41, sink.clone())),
        shared.clone(),
    );

    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
    headers.insert("x-server", HeaderValue::from_static("zincio"));
    let mut cx = cx();
    assert!(matches!(
        request.poll_send_response(&mut cx, StatusCode::OK, &headers),
        Poll::Ready(Ok(()))
    ));

    // The encoder produced encoder-stream instructions for the control
    // plane.
    assert!(!shared.encoder_stream.lock().is_empty());

    // The wire carries one HEADERS frame with a QPACK-encoded field
    // section (never empty: it encodes `:status` and the headers).
    let mut outbound = BytesMut::new();
    let mut sent = sink.lock();
    while let Some(chunk) = sent.pop_front() {
        outbound.extend_from_slice(&chunk);
    }
    let mut decoder = FrameDecoder::new();
    decoder.extend(outbound.freeze());
    match decoder.next_frame().expect("valid frame").expect("a frame") {
        Frame::Headers(block) => assert!(!block.is_empty()),
        other => panic!("expected HEADERS frame, got {other:?}"),
    }
    assert!(decoder.next_frame().expect("valid frame").is_none());
}

#[test]
fn send_data_writes_data_frame() {
    let shared = shared_with_encoder();
    let stream = MockBidi::new(43);
    let mut request = RequestStream::new(Box::new(stream), shared);
    let mut cx = cx();
    let result = request.poll_send_data(&mut cx, Bytes::from_static(b"abc"));
    assert!(result.is_ready());
    assert!(matches!(result, Poll::Ready(Ok(()))));
}

#[test]
fn send_trailers_after_response() {
    let shared = shared_with_encoder();
    let stream = MockBidi::new(45);
    let mut request = RequestStream::new(Box::new(stream), shared.clone());
    let mut cx = cx();

    let mut headers = HeaderMap::new();
    headers.insert("x-a", HeaderValue::from_static("1"));
    assert!(matches!(
        request.poll_send_response(&mut cx, StatusCode::NO_CONTENT, &headers),
        Poll::Ready(Ok(()))
    ));

    let mut trailers = HeaderMap::new();
    trailers.insert("x-sum", HeaderValue::from_static("7"));
    assert!(matches!(
        request.poll_send_trailers(&mut cx, &trailers),
        Poll::Ready(Ok(()))
    ));
    assert!(matches!(request.poll_finish(&mut cx), Poll::Ready(Ok(()))));
}

#[test]
fn response_before_peer_settings_is_message_error() {
    let shared = Arc::new(SharedCodecs::new(&local_settings()));
    let stream = MockBidi::new(47);
    let mut request = RequestStream::new(Box::new(stream), shared);
    let mut cx = cx();
    let headers = HeaderMap::new();
    let result = request.poll_send_response(&mut cx, StatusCode::OK, &headers);
    assert!(matches!(result, Poll::Ready(Err(StreamError::Message))));
}

#[test]
fn response_over_peer_field_section_limit() {
    let shared = SharedCodecs::new(&local_settings());
    // Capacity 0 disables the dynamic table (RFC 9204 Section 3.2.3),
    // so the field section is encoded inline as literal lines instead
    // of shrinking to a dynamic-table reference.
    *shared.encoder.lock() = Some(Encoder::new(0, true));
    *shared.peer_max_field_section_size.lock() = Some(10);
    let shared = Arc::new(shared);
    let stream = MockBidi::new(49);
    let mut request = RequestStream::new(Box::new(stream), shared);
    let mut cx = cx();

    let mut headers = HeaderMap::new();
    headers.insert(
        "x-long-header",
        HeaderValue::from_static("something bigger than ten bytes"),
    );
    let result = request.poll_send_response(&mut cx, StatusCode::OK, &headers);
    assert!(matches!(
        result,
        Poll::Ready(Err(StreamError::HeadersTooBig { .. }))
    ));
}

#[test]
fn duplicate_response_is_message_error() {
    let shared = shared_with_encoder();
    let stream = MockBidi::new(51);
    let mut request = RequestStream::new(Box::new(stream), shared);
    let mut cx = cx();
    let headers = HeaderMap::new();
    assert!(matches!(
        request.poll_send_response(&mut cx, StatusCode::OK, &headers),
        Poll::Ready(Ok(()))
    ));
    assert!(matches!(
        request.poll_send_response(&mut cx, StatusCode::OK, &headers),
        Poll::Ready(Err(StreamError::Message))
    ));
}

#[test]
fn missing_method_is_message_error() {
    let shared = shared_with_encoder();
    let mut peer_enc = Encoder::new(4096, true);
    let section = peer_enc.encode_section(
        0,
        &[
            (Bytes::from_static(b":scheme"), Bytes::from_static(b"https")),
            (Bytes::from_static(b":authority"), Bytes::from_static(b"x")),
            (Bytes::from_static(b":path"), Bytes::from_static(b"/")),
        ],
    );
    shared
        .decoder
        .lock()
        .feed_encoder_stream(&section.encoder_stream)
        .expect("valid");
    let mut wire = BytesMut::new();
    Frame::Headers(section.block).encode(&mut wire);
    let mut stream = MockBidi::new(53);
    stream.feed(&wire);
    let mut request = RequestStream::new(Box::new(stream), shared);

    let mut cx = cx();
    let result = request.poll_headers(&mut cx);
    match result {
        Poll::Ready(Err(err)) => assert_eq!(err.h3_code(), H3Error::Message.code()),
        other => panic!("expected message error, got {other:?}"),
    }
}

#[test]
fn unknown_pseudo_header_is_message_error() {
    let shared = shared_with_encoder();
    let mut peer_enc = Encoder::new(4096, true);
    let section = peer_enc.encode_section(
        0,
        &[
            (Bytes::from_static(b":method"), Bytes::from_static(b"GET")),
            (Bytes::from_static(b":scheme"), Bytes::from_static(b"https")),
            (Bytes::from_static(b":authority"), Bytes::from_static(b"x")),
            (Bytes::from_static(b":path"), Bytes::from_static(b"/")),
            (Bytes::from_static(b":frobnicate"), Bytes::from_static(b"1")),
        ],
    );
    shared
        .decoder
        .lock()
        .feed_encoder_stream(&section.encoder_stream)
        .expect("valid");
    let mut wire = BytesMut::new();
    Frame::Headers(section.block).encode(&mut wire);
    let mut stream = MockBidi::new(55);
    stream.feed(&wire);
    let mut request = RequestStream::new(Box::new(stream), shared);

    let mut cx = cx();
    let result = request.poll_headers(&mut cx);
    assert!(matches!(result, Poll::Ready(Err(StreamError::Message))));
}

#[test]
fn pseudo_header_after_regular_is_message_error() {
    let shared = shared_with_encoder();
    let mut peer_enc = Encoder::new(4096, true);
    let section = peer_enc.encode_section(
        0,
        &[
            (Bytes::from_static(b":method"), Bytes::from_static(b"GET")),
            (Bytes::from_static(b":scheme"), Bytes::from_static(b"https")),
            (Bytes::from_static(b":authority"), Bytes::from_static(b"x")),
            (Bytes::from_static(b":path"), Bytes::from_static(b"/")),
            (Bytes::from_static(b"host"), Bytes::from_static(b"x")),
            (
                Bytes::from_static(b":trailer-late"),
                Bytes::from_static(b"1"),
            ),
        ],
    );
    shared
        .decoder
        .lock()
        .feed_encoder_stream(&section.encoder_stream)
        .expect("valid");
    let mut wire = BytesMut::new();
    Frame::Headers(section.block).encode(&mut wire);
    let mut stream = MockBidi::new(57);
    stream.feed(&wire);
    let mut request = RequestStream::new(Box::new(stream), shared);

    let mut cx = cx();
    let result = request.poll_headers(&mut cx);
    assert!(matches!(result, Poll::Ready(Err(StreamError::Message))));
}

#[test]
fn connect_request_shape() {
    // Plain CONNECT: only :method and :authority.
    let shared = shared_with_encoder();
    let mut peer_enc = Encoder::new(4096, true);
    let section = peer_enc.encode_section(
        0,
        &[
            (
                Bytes::from_static(b":method"),
                Bytes::from_static(b"CONNECT"),
            ),
            (
                Bytes::from_static(b":authority"),
                Bytes::from_static(b"example.com:443"),
            ),
        ],
    );
    shared
        .decoder
        .lock()
        .feed_encoder_stream(&section.encoder_stream)
        .expect("valid");
    let mut wire = BytesMut::new();
    Frame::Headers(section.block).encode(&mut wire);
    let mut stream = MockBidi::new(59);
    stream.feed(&wire);
    let mut request = RequestStream::new(Box::new(stream), shared);

    let mut cx1 = cx();
    let req = match request.poll_headers(&mut cx1) {
        Poll::Ready(Ok(Some(request))) => request,
        other => panic!("expected CONNECT request, got {other:?}"),
    };
    assert_eq!(req.method(), Method::CONNECT);
    assert_eq!(
        req.uri().authority().map(|a| a.as_str()),
        Some("example.com:443")
    );

    // Extended CONNECT: adds :scheme and :protocol, never :path.
    let shared = shared_with_encoder();
    let mut peer_enc = Encoder::new(4096, true);
    let section = peer_enc.encode_section(
        0,
        &[
            (
                Bytes::from_static(b":method"),
                Bytes::from_static(b"CONNECT"),
            ),
            (Bytes::from_static(b":scheme"), Bytes::from_static(b"https")),
            (
                Bytes::from_static(b":authority"),
                Bytes::from_static(b"example.com"),
            ),
            (
                Bytes::from_static(b":protocol"),
                Bytes::from_static(b"webtransport"),
            ),
        ],
    );
    shared
        .decoder
        .lock()
        .feed_encoder_stream(&section.encoder_stream)
        .expect("valid");
    let mut wire = BytesMut::new();
    Frame::Headers(section.block).encode(&mut wire);
    let mut stream = MockBidi::new(61);
    stream.feed(&wire);
    let mut request = RequestStream::new(Box::new(stream), shared.clone());
    let mut cx2 = cx();
    let req2 = match request.poll_headers(&mut cx2) {
        Poll::Ready(Ok(Some(request))) => request,
        other => panic!("expected extended CONNECT, got {other:?}"),
    };
    assert_eq!(req2.method(), Method::CONNECT);
    assert_eq!(req2.headers().get(":protocol"), None);
}

#[test]
fn connect_with_path_is_message_error() {
    let shared = shared_with_encoder();
    let mut peer_enc = Encoder::new(4096, true);
    let section = peer_enc.encode_section(
        0,
        &[
            (
                Bytes::from_static(b":method"),
                Bytes::from_static(b"CONNECT"),
            ),
            (Bytes::from_static(b":scheme"), Bytes::from_static(b"https")),
            (Bytes::from_static(b":authority"), Bytes::from_static(b"x")),
            (Bytes::from_static(b":path"), Bytes::from_static(b"/")),
        ],
    );
    shared
        .decoder
        .lock()
        .feed_encoder_stream(&section.encoder_stream)
        .expect("valid");
    let mut wire = BytesMut::new();
    Frame::Headers(section.block).encode(&mut wire);
    let mut stream = MockBidi::new(63);
    stream.feed(&wire);
    let mut request = RequestStream::new(Box::new(stream), shared);

    let mut cx = cx();
    let result = request.poll_headers(&mut cx);
    assert!(matches!(result, Poll::Ready(Err(StreamError::Message))));
}

#[test]
fn reset_by_peer_is_stream_scoped() {
    // A reset surfaces through the transport; the stream scope is
    // detected by the driver.
    let err = StreamError::Transport(TransportError::Reset { code: 0x010c });
    assert!(err.is_stream_scoped());
    let err = StreamError::Transport(TransportError::Stopped { code: 0x010c });
    assert!(err.is_stream_scoped());
    assert!(!StreamError::Frame.is_stream_scoped());
}

#[test]
fn connection_codes_map_per_rfc() {
    assert_eq!(StreamError::Frame.h3_code(), 0x0106);
    assert_eq!(StreamError::Message.h3_code(), 0x010e);
    assert_eq!(StreamError::FrameUnexpected.h3_code(), 0x0105);
    assert_eq!(
        StreamError::Qpack(QpackError::DecompressionFailed).h3_code(),
        0x0200
    );
    assert_eq!(
        StreamError::HeadersTooBig { size: 5, limit: 3 }.h3_code(),
        0x010e
    );
}

#[test]
fn build_request_rejects_more_headers_than_the_header_map_holds() {
    // `http::HeaderMap` holds at most 24 576 entries and panics when it
    // is overfilled. A field section can carry more distinct names than
    // that, so the request is rejected instead of panicking.
    let mut headers = vec![
        (Bytes::from_static(b":method"), Bytes::from_static(b"GET")),
        (Bytes::from_static(b":scheme"), Bytes::from_static(b"https")),
        (Bytes::from_static(b":path"), Bytes::from_static(b"/")),
        (
            Bytes::from_static(b":authority"),
            Bytes::from_static(b"example.com"),
        ),
    ];
    for i in 0..30_000 {
        headers.push((Bytes::from(format!("x{i:05}")), Bytes::from_static(b"v")));
    }
    assert!(matches!(build_request(headers), Err(StreamError::Message)));
}

#[test]
fn header_map_rejects_more_headers_than_the_header_map_holds() {
    // The trailer field section goes through the same container; a
    // section with more fields than the map can hold is a message error,
    // not a panic.
    let headers: Vec<(Bytes, Bytes)> = (0..30_000)
        .map(|i| (Bytes::from(format!("x{i:05}")), Bytes::from_static(b"v")))
        .collect();
    assert!(matches!(header_map(headers), Err(StreamError::Message)));
}

#[test]
fn header_map_accepts_repeated_names() {
    // Repeated names are stored as extra values, which the map does not
    // count against its entry capacity.
    let headers: Vec<(Bytes, Bytes)> = (0..30_000)
        .map(|_| (Bytes::from_static(b"x-repeat"), Bytes::from_static(b"v")))
        .collect();
    let map = header_map(headers).expect("repeated names fit");
    assert_eq!(map.len(), 30_000);
    assert_eq!(map.keys().count(), 1);
}

#[test]
fn oversized_trailer_section_is_rejected() {
    // A trailer field section that exceeds the field-section budget is a
    // QPACK decompression failure, not a message that reaches the header
    // map: the decoder rejects it while it is decoded.
    let (shared, mut enc) = shared_and_peer_encoder();
    let mut wire = BytesMut::new();
    let section = enc.encode_section(0, &request_lines("PUT", "/x"));
    shared
        .decoder
        .lock()
        .feed_encoder_stream(&section.encoder_stream)
        .expect("valid");
    Frame::Headers(section.block).encode(&mut wire);

    // A trailer section with more fields than the budget allows.
    let mut trailer_lines = Vec::new();
    for i in 0..4_000 {
        trailer_lines.push((Bytes::from(format!("x{i:05}")), Bytes::from_static(b"v")));
    }
    let section = enc.encode_section(0, &trailer_lines);
    shared
        .decoder
        .lock()
        .feed_encoder_stream(&section.encoder_stream)
        .expect("valid");
    Frame::Headers(section.block).encode(&mut wire);

    let mut stream = MockBidi::new(22);
    stream.feed(&wire);
    stream.finish();
    let mut request = RequestStream::new(Box::new(stream), shared);

    let mut cx = cx();
    assert!(request.poll_headers(&mut cx).is_ready());
    assert_eq!(
        request.poll_recv_data(&mut cx),
        Poll::Ready(Err(StreamError::Qpack(QpackError::DecompressionFailed)))
    );
}
