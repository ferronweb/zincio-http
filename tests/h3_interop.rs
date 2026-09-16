//! Interop test: real `h3` client (over quinn) and a raw quinn fixture
//! client against the **native** HTTP/3 server over a real QUIC loopback
//! connection.
//!
//! The server runs on the `zincio` runtime in its own thread (the native
//! driver spawns per-request tasks via `zincio::spawn`); both quinn
//! endpoints live on the `tokio` runtime of the test thread, which pumps
//! the loopback. The `h3`-crate scenarios exercise request/response
//! streaming, trailers, concurrency, cancellation and graceful shutdown
//! against the reference implementation; the fixture-client scenarios pin
//! wire behavior (control/QPACK streams, SETTINGS, `100 Continue` and
//! `103 Early Hints` interims, a CONNECT request without `:scheme`/
//! `:path`) with hand-crafted frames.

#![cfg(feature = "h3-quinn")]

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::{mpsc, Arc},
    time::Duration,
};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use quinn::Endpoint;
use tokio_util::sync::CancellationToken;
use zincio::RuntimeBuilder;
use zincio_http::{
    qpack::{Decoder, Encoder, UnblockedSection},
    Frame, FrameDecoder, Http3, Http3Options, HttpProtocol, Incoming, Settings,
};

const H3_NO_ERROR: u64 = 0x0100;

const SETTINGS_QPACK_MAX_TABLE_CAPACITY: u64 = 0x1;
const SETTINGS_MAX_FIELD_SECTION_SIZE: u64 = 0x6;
const SETTINGS_QPACK_BLOCKED_STREAMS: u64 = 0x7;

fn loopback() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
}

/// A connected loopback pair plus the endpoints that keep both halves
/// alive (quinn tears the connections down if the endpoint is dropped).
async fn loopback_pair() -> (Endpoint, Endpoint, quinn::Connection, quinn::Connection) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der: quinn::rustls::pki_types::CertificateDer<'static> = cert.cert.into();

    let server_config = quinn::ServerConfig::with_single_cert(
        vec![cert_der.clone()],
        quinn::rustls::pki_types::PrivateKeyDer::from(cert.signing_key),
    )
    .unwrap();
    let server_endpoint = Endpoint::server(server_config, loopback()).unwrap();
    let server_addr = server_endpoint.local_addr().unwrap();

    let mut roots = quinn::rustls::RootCertStore::empty();
    roots.add(cert_der).unwrap();
    let client_config = quinn::ClientConfig::with_root_certificates(Arc::new(roots)).unwrap();
    let mut client_endpoint = Endpoint::client(loopback()).unwrap();
    client_endpoint.set_default_client_config(client_config);

    let connecting = client_endpoint
        .connect(server_addr, "localhost")
        .expect("connect");
    let incoming = server_endpoint
        .accept()
        .await
        .expect("accept must eventually yield");
    let (client_conn, server_conn) = tokio::join!(
        async { connecting.await.expect("client handshake") },
        async { incoming.await.expect("server handshake") },
    );
    (server_endpoint, client_endpoint, client_conn, server_conn)
}

/// Runs the native server on a `zincio` runtime in a dedicated thread.
///
/// The server is shut down by cancelling `cancel`; the thread then exits
/// once the connection drains, and `handle`'s result is sent on the
/// returned channel.
fn spawn_native_server<F, Fut, ResB, ResBE, ResE>(
    server_conn: quinn::Connection,
    options: Http3Options,
    cancel: CancellationToken,
    handler: F,
) -> (
    std::thread::JoinHandle<()>,
    mpsc::Receiver<Result<(), std::io::Error>>,
)
where
    F: Fn(Request<Incoming>) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<Response<ResB>, ResE>> + Send + 'static,
    ResB: http_body::Body<Data = Bytes, Error = ResBE> + Send + Unpin + 'static,
    ResBE: std::error::Error + Send + 'static,
    ResE: std::error::Error + Send + 'static,
{
    let (result_tx, result_rx) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        let rt = RuntimeBuilder::new()
            .enable_timer(true)
            .build()
            .expect("zincio runtime");
        let result = rt.block_on(async move {
            Http3::new(zincio_http::quinn::Connection::new(server_conn), options)
                .graceful_shutdown_token(cancel)
                .handle(handler)
                .await
        });
        result_tx.send(result).ok();
    });
    (thread, result_rx)
}

/// Drains the request body, collecting data and any trailers.
async fn read_body_and_trailers(body: Incoming) -> (Vec<u8>, Option<HeaderMap>) {
    let mut body = Pin::from(Box::new(body));
    let mut bytes = Vec::new();
    let mut trailers = None;
    while let Some(frame) =
        std::future::poll_fn(|cx| <Incoming as http_body::Body>::poll_frame(body.as_mut(), cx))
            .await
    {
        match frame {
            Ok(frame) => {
                if let Some(data) = frame.data_ref() {
                    bytes.extend_from_slice(data.as_ref());
                } else if let Some(t) = frame.trailers_ref() {
                    trailers = Some(t.clone());
                }
            }
            Err(_) => break,
        }
    }
    (bytes, trailers)
}

/// RFC 9000 Section 16 variable-length integer encoding.
fn write_varint(dst: &mut BytesMut, value: u64) {
    match value {
        0..=63 => dst.put_u8(value as u8),
        64..=16_383 => {
            dst.put_u8(0x40 | (value >> 8) as u8);
            dst.put_u8(value as u8);
        }
        16_384..=1_073_741_823 => {
            dst.put_u8(0x80 | (value >> 24) as u8);
            dst.put_u32(value as u32);
        }
        _ => {
            dst.put_u8(0xc0 | (value >> 56) as u8);
            dst.put_u64(value);
        }
    }
}

/// A raw quinn client that speaks HTTP/3 at the frame level: it opens the
/// control, QPACK encoder and decoder streams with their preludes and
/// SETTINGS, then sends hand-encoded request HEADERS/DATA on request
/// streams. The QPACK codecs are this crate's own, so the fixture pins the
/// wire behavior of the native implementation end to end.
struct Fixture {
    conn: quinn::Connection,
    encoder: Encoder,
    decoder: Decoder,
    /// Kept alive for the fixture's lifetime: quinn auto-FINishes a
    /// `SendStream` on drop, and closing a critical stream is a connection
    /// error for the server.
    #[allow(dead_code)]
    control: quinn::SendStream,
    encoder_stream: quinn::SendStream,
    #[allow(dead_code)]
    decoder_stream: quinn::SendStream,
    /// The server's QPACK encoder stream (type 0x02), fed to `decoder`.
    server_encoder: Option<quinn::RecvStream>,
    started_at: std::time::Instant,
}

impl Fixture {
    async fn new(conn: quinn::Connection) -> Self {
        Self::new_with_capacity(conn, 0, 0).await
    }

    /// Like [`Fixture::new`], but advertises `capacity` in
    /// SETTINGS_QPACK_MAX_TABLE_CAPACITY (like Chromium's 65536), so the
    /// server's encoder may use its dynamic table.
    async fn new_with_capacity(conn: quinn::Connection, capacity: u64, blocked: u64) -> Self {
        let mut control = conn.open_uni().await.expect("control stream");
        let mut encoder_stream = conn.open_uni().await.expect("encoder stream");
        let mut decoder_stream = conn.open_uni().await.expect("decoder stream");

        let mut settings = Settings::new();
        settings.insert(SETTINGS_QPACK_MAX_TABLE_CAPACITY, capacity);
        settings.insert(SETTINGS_QPACK_BLOCKED_STREAMS, blocked);
        settings.insert(SETTINGS_MAX_FIELD_SECTION_SIZE, 262_144);
        let mut buf = BytesMut::new();
        write_varint(&mut buf, 0x00);
        Frame::Settings(settings).encode(&mut buf);
        control.write_all(&buf).await.expect("write settings");

        let mut buf = BytesMut::new();
        write_varint(&mut buf, 0x02);
        encoder_stream
            .write_all(&buf)
            .await
            .expect("encoder prelude");

        let mut buf = BytesMut::new();
        write_varint(&mut buf, 0x03);
        decoder_stream
            .write_all(&buf)
            .await
            .expect("decoder prelude");

        Fixture {
            conn,
            encoder: Encoder::new(0, false),
            decoder: Decoder::new(capacity, blocked as usize),
            control,
            encoder_stream,
            decoder_stream,
            server_encoder: None,
            started_at: std::time::Instant::now(),
        }
    }

    /// Opens a request stream and writes the HEADERS frame for `headers`.
    /// The send half is returned unfinished so the caller can stream DATA.
    async fn request_open(
        &mut self,
        headers: &[(Bytes, Bytes)],
    ) -> (quinn::SendStream, quinn::RecvStream) {
        let (mut send, recv) = self.conn.open_bi().await.expect("open request stream");
        let section = self.encoder.encode_section(0, headers);
        if !section.encoder_stream.is_empty() {
            self.encoder_stream
                .write_all(&section.encoder_stream)
                .await
                .expect("encoder instructions");
        }
        let mut buf = BytesMut::new();
        Frame::Headers(section.block).encode(&mut buf);
        send.write_all(&buf).await.expect("write headers");
        (send, recv)
    }

    /// Writes one DATA frame.
    async fn write_data(send: &mut quinn::SendStream, data: &[u8]) {
        let mut buf = BytesMut::new();
        Frame::Data(Bytes::copy_from_slice(data)).encode(&mut buf);
        send.write_all(&buf).await.expect("write data");
    }

    /// Decodes a response HEADERS block. The server is advertised a QPACK
    /// table capacity of 0, so blocks decode statelessly.
    fn decode(&mut self, block: &Bytes, stream_id: u64) -> Vec<(Bytes, Bytes)> {
        let now = self.started_at.elapsed().as_nanos() as u64;
        self.decoder
            .decode_block(block, stream_id, now)
            .expect("decode response headers")
            .expect("blocked without a dynamic table")
    }

    /// Accepts whatever unidirectional streams the server has opened so far
    /// and routes them: the QPACK encoder stream (type 0x02) is retained and
    /// fed to `decoder` by [`Self::feed_server_encoder`]; control, decoder,
    /// push and unknown streams are drained and dropped.
    async fn pump_server_unis(&mut self) {
        loop {
            let accept =
                tokio::time::timeout(Duration::from_millis(250), self.conn.accept_uni()).await;
            let Ok(uni) = accept else { break };
            let mut recv = uni.expect("server uni stream");
            let mut type_byte = [0u8; 1];
            recv.read_exact(&mut type_byte)
                .await
                .expect("uni stream type");
            match type_byte[0] {
                0x02 => self.server_encoder = Some(recv),
                other => {
                    // Control (0x00), decoder (0x03), push (0x01) or grease:
                    // nothing to decode here. These streams stay open for
                    // the connection's lifetime, so drain only what is
                    // buffered right now (a short timeout), then drop.
                    let _ = other;
                    let mut buf = [0u8; 16 * 1024];
                    loop {
                        let read =
                            tokio::time::timeout(Duration::from_millis(100), recv.read(&mut buf))
                                .await;
                        match read {
                            Ok(Ok(Some(n))) if n > 0 => {}
                            _ => break,
                        }
                    }
                }
            }
        }
    }

    /// Reads one chunk of the server's QPACK encoder stream into the
    /// decoder, which unblocks any field section whose Required Insert
    /// Count has been reached. Returns the field sections that unblocked.
    async fn feed_server_encoder(&mut self) -> Vec<UnblockedSection> {
        let recv = match self.server_encoder.as_mut() {
            Some(recv) => recv,
            None => return Vec::new(),
        };
        if let Some(chunk) = recv
            .read_chunk(64 * 1024, true)
            .await
            .expect("read encoder stream")
        {
            self.decoder
                .feed_encoder_stream(&chunk.bytes)
                .expect("valid encoder instructions")
        } else {
            Vec::new()
        }
    }

    /// Decodes a response HEADERS block against a dynamic-table-capable
    /// decoder, pumping the server's encoder stream until the block
    /// unblocks. This mirrors Chromium's blocked-decoding flow.
    async fn decode_dynamic(&mut self, block: &[u8], stream_id: u64) -> Vec<(Bytes, Bytes)> {
        let now = self.started_at.elapsed().as_nanos() as u64;
        if let Some(headers) = self
            .decoder
            .decode_block(block, stream_id, now)
            .expect("decode response headers")
        {
            // A real client acknowledges decoded field sections on its
            // decoder stream, which lets the server's encoder evict and
            // reuse dynamic-table entries (RFC 9204 Section 2.1.1).
            self.flush_acks().await;
            return headers;
        }
        // The block was buffered as blocked. Pump the server's encoder
        // stream: `feed_encoder_stream` unblocks and decodes the section
        // exactly once (and the decoder queues its Section Acknowledgment),
        // so we return that result instead of re-decoding the block, which
        // would re-acknowledge the same section and abort the connection.
        loop {
            if self.server_encoder.is_none() {
                self.pump_server_unis().await;
            }
            let unblocked = self.feed_server_encoder().await;
            if let Some(section) = unblocked
                .into_iter()
                .find(|section| section.stream_id == stream_id)
            {
                self.flush_acks().await;
                return section.headers;
            }
        }
    }

    /// Flushes any accumulated QPACK decoder-stream instructions (section
    /// acknowledgements) to the server.
    async fn flush_acks(&mut self) {
        let ack = self.decoder.take_decoder_stream();
        if !ack.is_empty() {
            self.decoder_stream
                .write_all(&ack)
                .await
                .expect("write decoder stream ack");
        }
    }
}

/// Incremental frame reader over a quinn receive stream.
struct FrameReader {
    decoder: FrameDecoder,
}

impl FrameReader {
    fn new() -> Self {
        Self {
            decoder: FrameDecoder::new(),
        }
    }

    async fn next(&mut self, recv: &mut quinn::RecvStream) -> Option<Frame> {
        loop {
            match self.decoder.next_frame() {
                Ok(Some(frame)) => return Some(frame),
                Ok(None) => match recv.read_chunk(64 * 1024, true).await.expect("read chunk") {
                    Some(chunk) => self.decoder.extend(chunk.bytes),
                    None => return None,
                },
                Err(err) => panic!("fixture frame decode failed: {err:?}"),
            }
        }
    }
}

/// Reads the whole response: all HEADERS sections (decoded) plus the DATA.
async fn fixture_response(
    fixture: &mut Fixture,
    mut recv: quinn::RecvStream,
) -> (Vec<HashMap<String, String>>, Vec<u8>) {
    let stream_id = u64::from(recv.id());
    let mut reader = FrameReader::new();
    let mut sections = Vec::new();
    let mut data = Vec::new();
    while let Some(frame) = reader.next(&mut recv).await {
        match frame {
            Frame::Headers(block) => sections.push(field_map(fixture.decode(&block, stream_id))),
            Frame::Data(chunk) => data.extend_from_slice(&chunk),
            other => panic!("unexpected frame on request stream: {other:?}"),
        }
    }
    (sections, data)
}

fn field_map(fields: Vec<(Bytes, Bytes)>) -> HashMap<String, String> {
    fields
        .into_iter()
        .map(|(name, value)| {
            (
                String::from_utf8_lossy(&name).into_owned(),
                String::from_utf8_lossy(&value).into_owned(),
            )
        })
        .collect()
}

fn pseudo(headers: &[(&str, &str)]) -> Vec<(Bytes, Bytes)> {
    headers
        .iter()
        .map(|(name, value)| {
            (
                Bytes::copy_from_slice(name.as_bytes()),
                Bytes::copy_from_slice(value.as_bytes()),
            )
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn h3_client_get_post_trailers_and_date() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let (_server_ep, _client_ep, client_conn, server_conn) = loopback_pair().await;
        let cancel = CancellationToken::new();
        let (server_thread, server_result) =
            spawn_native_server(
                server_conn,
                Http3Options::new(),
                cancel.clone(),
                |request| async move {
                    let (parts, body) = request.into_parts();

                    let (bytes, trailers) = read_body_and_trailers(body).await;

                    let trailer = trailers
                        .as_ref()
                        .and_then(|t| t.get("x-request-trailer"))
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("none");
                    let payload = format!(
                        "{} {} {} {}",
                        parts.method,
                        parts.uri.path(),
                        bytes.len(),
                        trailer
                    );
                    let mut response_trailers = HeaderMap::new();
                    response_trailers
                        .insert("x-response-trailer", HeaderValue::from_static("echoed"));
                    let body = Full::new(Bytes::from(payload)).with_trailers(std::future::ready(
                        Some(Ok::<HeaderMap, std::convert::Infallible>(response_trailers)),
                    ));
                    Ok::<_, std::convert::Infallible>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .body(body)
                            .expect("response"),
                    )
                },
            );

        let (mut conn, mut send_request) = h3::client::builder()
            .build(h3_quinn::Connection::new(client_conn))
            .await
            .expect("h3 client");
        let drive = tokio::spawn(async move {
            let _ = conn.wait_idle().await;
            std::future::pending::<()>().await;
        });

        let request = Request::get("https://localhost/echo").body(()).unwrap();
        let mut stream = send_request.send_request(request).await.expect("GET");

        stream.finish().await.expect("finish GET");
        let response = stream.recv_response().await.expect("GET response");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.version(), http::Version::HTTP_3);
        assert!(
            response.headers().contains_key(http::header::DATE),
            "native server adds a Date header"
        );
        let mut body = Vec::new();
        while let Some(chunk) = stream.recv_data().await.expect("GET data") {
            body.extend_from_slice(chunk.chunk());
        }
        assert_eq!(body, b"GET /echo 0 none");

        assert_eq!(
            stream.recv_trailers().await.expect("GET trailers"),
            Some({
                let mut trailers = HeaderMap::new();
                trailers.insert("x-response-trailer", HeaderValue::from_static("echoed"));
                trailers
            })
        );

        let mut request = Request::post("https://localhost/post").body(()).unwrap();
        request
            .headers_mut()
            .insert("x-request-trailer", HeaderValue::from_static("yes"));

        let mut stream = send_request.send_request(request).await.expect("POST");

        stream
            .send_data(Bytes::from_static(b"hello "))
            .await
            .expect("POST data 1");

        stream
            .send_data(Bytes::from_static(b"world"))
            .await
            .expect("POST data 2");

        let mut trailers = HeaderMap::new();
        trailers.insert("x-request-trailer", HeaderValue::from_static("yes"));
        stream.send_trailers(trailers).await.expect("POST trailers");

        stream.finish().await.expect("POST finish");

        let response = stream.recv_response().await.expect("POST response");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(http::header::CONTENT_LENGTH)
                .map(|v| v.to_str().unwrap()),
            Some("17")
        );
        let mut body = Vec::new();
        while let Some(chunk) = stream.recv_data().await.expect("POST data") {
            body.extend_from_slice(chunk.chunk());
        }
        assert_eq!(body, b"POST /post 11 yes");
        assert_eq!(
            stream.recv_trailers().await.expect("POST trailers"),
            Some({
                let mut trailers = HeaderMap::new();
                trailers.insert("x-response-trailer", HeaderValue::from_static("echoed"));
                trailers
            })
        );

        drop(stream);
        cancel.cancel();
        let result = server_result
            .recv_timeout(Duration::from_secs(10))
            .expect("server finished");
        assert!(result.is_ok(), "server handle: {result:?}");
        drive.abort();
        drop(send_request);
        server_thread.join().expect("join server");
    })
    .await
    .expect("h3_client_get_post_trailers_and_date timed out");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn h3_client_concurrent_streams_and_abort() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let (_server_ep, _client_ep, client_conn, server_conn) = loopback_pair().await;
        let cancel = CancellationToken::new();
        let (server_thread, server_result) = spawn_native_server(
            server_conn,
            Http3Options::new(),
            cancel.clone(),
            |request| async move {
                let (_, body) = request.into_parts();
                let (bytes, _) = read_body_and_trailers(body).await;
                let payload = format!("{}", bytes.len());
                Ok::<_, std::convert::Infallible>(
                    Response::builder()
                        .status(StatusCode::OK)
                        .body(Full::new(Bytes::from(payload)))
                        .expect("response"),
                )
            },
        );

        let (mut conn, mut send_request) = h3::client::builder()
            .build(h3_quinn::Connection::new(client_conn))
            .await
            .expect("h3 client");
        let drive = tokio::spawn(async move {
            let _ = conn.wait_idle().await;
            std::future::pending::<()>().await;
        });

        let mut streams = Vec::new();
        for i in 0..25usize {
            let request = Request::post("https://localhost/echo").body(()).unwrap();
            let mut stream = send_request
                .send_request(request)
                .await
                .expect("send request");
            stream
                .send_data(Bytes::from(vec![b'x'; i * 100]))
                .await
                .expect("send data");
            stream.finish().await.expect("finish");
            streams.push((i, stream));
        }

        let request = Request::post("https://localhost/abort").body(()).unwrap();
        let mut abort = send_request
            .send_request(request)
            .await
            .expect("abort request");
        abort
            .send_data(Bytes::from_static(b"partial body"))
            .await
            .expect("abort data");
        abort.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
        drop(abort);

        for (i, mut stream) in streams {
            let response = stream.recv_response().await.expect("response");
            assert_eq!(response.status(), StatusCode::OK);
            let mut body = Vec::new();
            while let Some(chunk) = stream.recv_data().await.expect("data") {
                body.extend_from_slice(chunk.chunk());
            }
            assert_eq!(body, format!("{}", i * 100).as_bytes());
        }

        cancel.cancel();
        let result = server_result
            .recv_timeout(Duration::from_secs(10))
            .expect("server finished");
        assert!(result.is_ok(), "server handle: {result:?}");
        drive.abort();
        drop(send_request);
        server_thread.join().expect("join server");
    })
    .await
    .expect("h3_client_concurrent_streams_and_abort timed out");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn h3_client_goaway_graceful_shutdown() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let (_server_ep, _client_ep, client_conn, server_conn) = loopback_pair().await;
        let cancel = CancellationToken::new();
        let (start_tx, start_rx) = mpsc::channel::<()>();
        let (server_thread, server_result) = spawn_native_server(
            server_conn,
            Http3Options::new(),
            cancel.clone(),
            move |request| {
                let start_tx = start_tx.clone();
                async move {
                    start_tx.send(()).ok();
                    let (_, body) = request.into_parts();
                    let (bytes, _) = read_body_and_trailers(body).await;
                    let payload = format!("got {} bytes", bytes.len());
                    Ok::<_, std::convert::Infallible>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .body(Full::new(Bytes::from(payload)))
                            .expect("response"),
                    )
                }
            },
        );

        let client_raw = client_conn.clone();
        let (mut conn, mut send_request) = h3::client::builder()
            .build(h3_quinn::Connection::new(client_conn))
            .await
            .expect("h3 client");
        let drive = tokio::spawn(async move {
            let _ = conn.wait_idle().await;
            std::future::pending::<()>().await;
        });

        let request = Request::post("https://localhost/slow").body(()).unwrap();
        let mut a: h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes> =
            send_request.send_request(request).await.expect("request A");
        a.send_data(Bytes::from_static(b"first chunk"))
            .await
            .expect("A data");
        start_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("handler started");

        cancel.cancel();
        a.send_data(Bytes::from_static(b"rest chunk"))
            .await
            .expect("A rest data");
        a.finish().await.expect("finish A");

        let response = a.recv_response().await.expect("A response");
        assert_eq!(response.status(), StatusCode::OK);
        let mut body = Vec::new();
        while let Some(chunk) = a.recv_data().await.expect("A data") {
            body.extend_from_slice(chunk.chunk());
        }
        assert_eq!(body, b"got 21 bytes");
        let closed = client_raw.closed().await;
        match closed {
            quinn::ConnectionError::ApplicationClosed(close) => {
                assert_eq!(close.error_code.into_inner(), H3_NO_ERROR);
            }
            other => panic!("unexpected close: {other:?}"),
        }

        drop(a);
        drive.abort();
        drop(send_request);
        let result = server_result
            .recv_timeout(Duration::from_secs(10))
            .expect("server finished");
        assert!(result.is_ok(), "server handle: {result:?}");
        server_thread.join().expect("join server");
    })
    .await
    .expect("h3_client_goaway_graceful_shutdown timed out");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fixture_client_wire_get() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let (_server_ep, _client_ep, client_conn, server_conn) = loopback_pair().await;
        let cancel = CancellationToken::new();
        let (server_thread, server_result) = spawn_native_server(
            server_conn,
            Http3Options::new(),
            cancel.clone(),
            |request| async move {
                let (parts, _) = request.into_parts();
                let payload = format!("wire-ok {}", parts.uri.path());
                Ok::<_, std::convert::Infallible>(
                    Response::builder()
                        .status(StatusCode::OK)
                        .body(Full::new(Bytes::from(payload)))
                        .expect("response"),
                )
            },
        );

        let mut fixture = Fixture::new(client_conn).await;
        let (mut send, recv) = fixture
            .request_open(&pseudo(&[
                (":method", "GET"),
                (":scheme", "https"),
                (":authority", "localhost"),
                (":path", "/wire"),
            ]))
            .await;
        send.finish().expect("finish request");

        let (sections, data) = fixture_response(&mut fixture, recv).await;
        assert_eq!(sections.len(), 1, "no interim responses for a plain GET");
        let headers = &sections[0];
        assert_eq!(headers.get(":status").map(String::as_str), Some("200"));
        assert_eq!(
            headers.get("content-length").map(String::as_str),
            Some("13")
        );
        assert!(headers.contains_key("date"), "native server adds Date");
        assert_eq!(data, b"wire-ok /wire");

        cancel.cancel();
        let result = server_result
            .recv_timeout(Duration::from_secs(10))
            .expect("server finished");
        assert!(result.is_ok(), "server handle: {result:?}");
        server_thread.join().expect("join server");
    })
    .await
    .expect("fixture_client_wire_get timed out");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fixture_client_dynamic_table_unblocks() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let (_server_ep, _client_ep, client_conn, server_conn) = loopback_pair().await;
        let cancel = CancellationToken::new();
        let (server_thread, server_result) = spawn_native_server(
            server_conn,
            Http3Options::new(),
            cancel.clone(),
            |request| async move {
                let (parts, _) = request.into_parts();
                let payload = format!("dyn-ok {}", parts.uri.path());
                Ok::<_, std::convert::Infallible>(
                    Response::builder()
                        .status(StatusCode::OK)
                        // A name outside the static table: the server's
                        // encoder must insert it and reference it, so the
                        // response's Required Insert Count is non-zero.
                        .header("x-dyn-token", "rendered-dynamically")
                        .body(Full::new(Bytes::from(payload)))
                        .expect("response"),
                )
            },
        );

        // Chromium advertises 65536 / 100; the fixture's decoder is sized
        // the same way so it can materialize the server's dynamic entries.
        let mut fixture = Fixture::new_with_capacity(client_conn, 65_536, 100).await;
        let (mut send, mut recv) = fixture
            .request_open(&pseudo(&[
                (":method", "GET"),
                (":scheme", "https"),
                (":authority", "localhost"),
                (":path", "/dyn"),
            ]))
            .await;
        send.finish().expect("finish request");

        let stream_id = u64::from(recv.id());
        let mut reader = FrameReader::new();
        let mut sections = Vec::new();
        let mut data = Vec::new();
        while let Some(frame) = reader.next(&mut recv).await {
            match frame {
                Frame::Headers(block) => {
                    sections.push(field_map(fixture.decode_dynamic(&block, stream_id).await))
                }
                Frame::Data(chunk) => data.extend_from_slice(&chunk),
                other => panic!("unexpected frame on request stream: {other:?}"),
            }
        }
        assert_eq!(sections.len(), 1, "no interim responses for a plain GET");
        let headers = &sections[0];
        assert_eq!(headers.get(":status").map(String::as_str), Some("200"));
        assert_eq!(
            headers.get("x-dyn-token").map(String::as_str),
            Some("rendered-dynamically")
        );
        assert_eq!(data, b"dyn-ok /dyn");

        cancel.cancel();
        let result = server_result
            .recv_timeout(Duration::from_secs(10))
            .expect("server finished");
        assert!(result.is_ok(), "server handle: {result:?}");
        server_thread.join().expect("join server");
    })
    .await
    .expect("fixture_client_dynamic_table_unblocks timed out");
}

/// One GET against a dynamic-table-capable fixture: the response headers
/// carry the non-static `x-dyn-token` name, so every response forces the
/// server's encoder to emit inserts (and, from the second response on, to
/// reference the entries it inserted for earlier responses).
async fn dyn_exchange(fixture: &mut Fixture, path: &str, expect_token: &str) -> Vec<u8> {
    let (mut send, mut recv) = fixture
        .request_open(&pseudo(&[
            (":method", "GET"),
            (":scheme", "https"),
            (":authority", "localhost"),
            (":path", path),
        ]))
        .await;
    send.finish().expect("finish request");

    let stream_id = u64::from(recv.id());
    let mut reader = FrameReader::new();
    let mut sections = Vec::new();
    let mut data = Vec::new();
    while let Some(frame) = reader.next(&mut recv).await {
        match frame {
            Frame::Headers(block) => {
                sections.push(field_map(fixture.decode_dynamic(&block, stream_id).await))
            }
            Frame::Data(chunk) => data.extend_from_slice(&chunk),
            other => panic!("unexpected frame on request stream: {other:?}"),
        }
    }
    let headers = &sections[0];
    assert_eq!(headers.get(":status").map(String::as_str), Some("200"));
    assert_eq!(
        headers.get("x-dyn-token").map(String::as_str),
        Some(expect_token)
    );
    data
}

/// A request handler echoing the path, with the dynamic-table-forcing
/// `x-dyn-token` response header.
async fn dyn_handler(
    request: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let (parts, _) = request.into_parts();
    let payload = format!("dyn-ok {}", parts.uri.path());
    Ok::<_, std::convert::Infallible>(
        Response::builder()
            .status(StatusCode::OK)
            .header("x-dyn-token", "rendered-dynamically")
            .body(Full::new(Bytes::from(payload)))
            .expect("response"),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fixture_client_dynamic_table_reload_and_reconnect() {
    tokio::time::timeout(Duration::from_secs(60), async {
        // Connection 1: the "reload" pattern — the same page twice, so the
        // second response references the entries the first one inserted.
        let (_server_ep, _client_ep, client_conn, server_conn) = loopback_pair().await;
        let cancel = CancellationToken::new();
        let (server_thread, server_result) = spawn_native_server(
            server_conn,
            Http3Options::new(),
            cancel.clone(),
            dyn_handler,
        );
        let mut fixture = Fixture::new_with_capacity(client_conn, 65_536, 100).await;
        assert_eq!(
            dyn_exchange(&mut fixture, "/page", "rendered-dynamically").await,
            b"dyn-ok /page"
        );
        assert_eq!(
            dyn_exchange(&mut fixture, "/page", "rendered-dynamically").await,
            b"dyn-ok /page"
        );
        drop(fixture);
        cancel.cancel();
        let result = server_result
            .recv_timeout(Duration::from_secs(10))
            .expect("server 1 finished");
        assert!(result.is_ok(), "server 1 handle: {result:?}");
        server_thread.join().expect("join server 1");

        // Connection 2: the browser closed and reopened; the fresh
        // connection must serve the dynamic-table response on its first
        // request.
        let (_server_ep, _client_ep, client_conn, server_conn) = loopback_pair().await;
        let cancel = CancellationToken::new();
        let (server_thread, server_result) = spawn_native_server(
            server_conn,
            Http3Options::new(),
            cancel.clone(),
            dyn_handler,
        );
        let mut fixture = Fixture::new_with_capacity(client_conn, 65_536, 100).await;
        assert_eq!(
            dyn_exchange(&mut fixture, "/page", "rendered-dynamically").await,
            b"dyn-ok /page"
        );
        drop(fixture);
        cancel.cancel();
        let result = server_result
            .recv_timeout(Duration::from_secs(10))
            .expect("server 2 finished");
        assert!(result.is_ok(), "server 2 handle: {result:?}");
        server_thread.join().expect("join server 2");
    })
    .await
    .expect("fixture_client_dynamic_table_reload_and_reconnect timed out");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fixture_client_expect_100_continue() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let (_server_ep, _client_ep, client_conn, server_conn) = loopback_pair().await;
        let cancel = CancellationToken::new();
        let (server_thread, server_result) = spawn_native_server(
            server_conn,
            Http3Options::new(),
            cancel.clone(),
            |request| async move {
                let (_, body) = request.into_parts();
                let (bytes, _) = read_body_and_trailers(body).await;
                let payload = format!("got {} bytes", bytes.len());
                Ok::<_, std::convert::Infallible>(
                    Response::builder()
                        .status(StatusCode::OK)
                        .body(Full::new(Bytes::from(payload)))
                        .expect("response"),
                )
            },
        );

        let mut fixture = Fixture::new(client_conn).await;
        let (mut send, mut recv) = fixture
            .request_open(&pseudo(&[
                (":method", "POST"),
                (":scheme", "https"),
                (":authority", "localhost"),
                (":path", "/continue"),
                ("expect", "100-continue"),
            ]))
            .await;
        let stream_id = u64::from(recv.id());
        let mut reader = FrameReader::new();

        let first = reader.next(&mut recv).await.expect("interim response");
        let Frame::Headers(block) = first else {
            panic!("first frame is not HEADERS: {first:?}");
        };
        let interim = fixture.decode(&block, stream_id);
        assert_eq!(
            interim
                .iter()
                .find(|(name, _)| name.as_ref() == b":status")
                .map(|(_, value)| value.as_ref()),
            Some(b"100".as_slice()),
            "server sends 100 Continue before the body is sent"
        );

        Fixture::write_data(&mut send, b"continue-body").await;
        send.finish().expect("finish request");

        let (sections, data) = fixture_response(&mut fixture, recv).await;
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].get(":status").map(String::as_str), Some("200"));
        assert_eq!(data, b"got 13 bytes");

        cancel.cancel();
        let result = server_result
            .recv_timeout(Duration::from_secs(10))
            .expect("server finished");
        assert!(result.is_ok(), "server handle: {result:?}");
        server_thread.join().expect("join server");
    })
    .await
    .expect("fixture_client_expect_100_continue timed out");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fixture_client_early_hints() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let (_server_ep, _client_ep, client_conn, server_conn) = loopback_pair().await;
        let cancel = CancellationToken::new();
        let (server_thread, server_result) = spawn_native_server(
            server_conn,
            Http3Options::new(),
            cancel.clone(),
            |mut request| async move {
                let mut link = HeaderMap::new();
                link.insert(
                    http::header::LINK,
                    HeaderValue::from_static("</style.css>; rel=preload; as=style"),
                );
                zincio_http::send_early_hints(&mut request, link)
                    .await
                    .expect("early hints");
                Ok::<_, std::convert::Infallible>(
                    Response::builder()
                        .status(StatusCode::OK)
                        .body(Full::new(Bytes::from_static(b"done")))
                        .expect("response"),
                )
            },
        );

        let mut fixture = Fixture::new(client_conn).await;
        let (mut send, recv) = fixture
            .request_open(&pseudo(&[
                (":method", "GET"),
                (":scheme", "https"),
                (":authority", "localhost"),
                (":path", "/hints"),
            ]))
            .await;
        send.finish().expect("finish request");

        let (sections, data) = fixture_response(&mut fixture, recv).await;
        assert_eq!(sections.len(), 2, "103 Early Hints then the final response");
        assert_eq!(sections[0].get(":status").map(String::as_str), Some("103"));
        assert_eq!(
            sections[0].get("link").map(String::as_str),
            Some("</style.css>; rel=preload; as=style")
        );
        assert_eq!(sections[1].get(":status").map(String::as_str), Some("200"));
        assert_eq!(data, b"done");

        cancel.cancel();
        let result = server_result
            .recv_timeout(Duration::from_secs(10))
            .expect("server finished");
        assert!(result.is_ok(), "server handle: {result:?}");
        server_thread.join().expect("join server");
    })
    .await
    .expect("fixture_client_early_hints timed out");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fixture_client_connect() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let (_server_ep, _client_ep, client_conn, server_conn) = loopback_pair().await;
        let cancel = CancellationToken::new();
        let (server_thread, server_result) = spawn_native_server(
            server_conn,
            Http3Options::new().enable_connect_protocol(true),
            cancel.clone(),
            |request| async move {
                let (parts, _) = request.into_parts();
                let payload = format!("connect={}", parts.method == Method::CONNECT);
                Ok::<_, std::convert::Infallible>(
                    Response::builder()
                        .status(StatusCode::OK)
                        .body(Full::new(Bytes::from(payload)))
                        .expect("response"),
                )
            },
        );

        let mut fixture = Fixture::new(client_conn).await;
        let (mut send, recv) = fixture
            .request_open(&pseudo(&[
                (":method", "CONNECT"),
                (":authority", "localhost:443"),
            ]))
            .await;
        send.finish().expect("finish request");

        let (sections, data) = fixture_response(&mut fixture, recv).await;
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].get(":status").map(String::as_str), Some("200"));
        assert_eq!(data, b"connect=true");

        cancel.cancel();
        let result = server_result
            .recv_timeout(Duration::from_secs(10))
            .expect("server finished");
        assert!(result.is_ok(), "server handle: {result:?}");
        server_thread.join().expect("join server");
    })
    .await
    .expect("fixture_client_connect timed out");
}

/// Like [`dyn_handler`], but the `x-dyn-token` value is derived from the
/// request path, so every distinct path forces the server's encoder to
/// insert a *new* dynamic entry rather than reference an existing one.
async fn dyn_handler_unique(
    request: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let (parts, _) = request.into_parts();
    let token = format!("token-{}", parts.uri.path());
    let payload = format!("dyn-ok {}", parts.uri.path());
    Ok::<_, std::convert::Infallible>(
        Response::builder()
            .status(StatusCode::OK)
            .header("x-dyn-token", token)
            .body(Full::new(Bytes::from(payload)))
            .expect("response"),
    )
}

/// Many requests, each with a unique `x-dyn-token` value, against a *small*
/// dynamic table. The server must keep inserting and evicting entries; with
/// the RFC 9204 §2.1.1 fix the server evicts only acknowledged entries
/// (the fixture acknowledges every decoded section on its decoder stream)
/// and the connection survives. Without the fix the server would evict
/// unacknowledged entries and a strict peer would abort the connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fixture_client_dynamic_table_eviction_pressure() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let (_server_ep, _client_ep, client_conn, server_conn) = loopback_pair().await;
        let cancel = CancellationToken::new();
        let (server_thread, server_result) = spawn_native_server(
            server_conn,
            Http3Options::new(),
            cancel.clone(),
            dyn_handler_unique,
        );
        // A small capacity forces eviction after a handful of inserts.
        let mut fixture = Fixture::new_with_capacity(client_conn, 600, 100).await;
        let count = 200;
        for i in 0..count {
            let path = format!("/p{i}");
            let (mut send, mut recv) = fixture
                .request_open(&pseudo(&[
                    (":method", "GET"),
                    (":scheme", "https"),
                    (":authority", "localhost"),
                    (":path", &path),
                ]))
                .await;
            send.finish().expect("finish request");
            let stream_id = u64::from(recv.id());
            let mut reader = FrameReader::new();
            let mut token = String::new();
            let mut data = Vec::new();
            while let Some(frame) = reader.next(&mut recv).await {
                match frame {
                    Frame::Headers(block) => {
                        let headers = field_map(fixture.decode_dynamic(&block, stream_id).await);
                        assert_eq!(
                            headers.get(":status").map(String::as_str),
                            Some("200"),
                            "request {i} headers"
                        );
                        token = headers
                            .get("x-dyn-token")
                            .cloned()
                            .expect("x-dyn-token present");
                    }
                    Frame::Data(chunk) => data.extend_from_slice(&chunk),
                    other => panic!("unexpected frame on request stream: {other:?}"),
                }
            }
            assert_eq!(
                token,
                format!("token-{path}"),
                "request {i} token matches path"
            );
            assert_eq!(data, format!("dyn-ok {path}").into_bytes());
        }
        drop(fixture);
        cancel.cancel();
        let result = server_result
            .recv_timeout(Duration::from_secs(10))
            .expect("server finished");
        assert!(result.is_ok(), "server handle: {result:?}");
        server_thread.join().expect("join server");
    })
    .await
    .expect("fixture_client_dynamic_table_eviction_fix timed out");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fixture_client_malformed_message_resets_stream_and_connection_survives() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let (_server_ep, _client_ep, client_conn, server_conn) = loopback_pair().await;
        let cancel = CancellationToken::new();
        let (server_thread, server_result) = spawn_native_server(
            server_conn,
            Http3Options::new(),
            cancel.clone(),
            |request| async move {
                let (_parts, _) = request.into_parts();
                Ok::<_, std::convert::Infallible>(
                    Response::builder()
                        .status(StatusCode::OK)
                        .body(Full::new(Bytes::from(b"still-alive".to_vec())))
                        .expect("response"),
                )
            },
        );

        let mut fixture = Fixture::new(client_conn).await;
        // A request without `:method` is a malformed message: the server
        // must abort the stream with H3_MESSAGE_ERROR, not the connection
        // (RFC 9114 Section 4.1.2).
        let (mut send, mut recv) = fixture
            .request_open(&pseudo(&[
                (":scheme", "https"),
                (":authority", "localhost"),
                (":path", "/malformed"),
            ]))
            .await;
        let _ = send.finish();
        let stream_id = u64::from(recv.id());
        let mut buf = [0u8; 1];
        let reset_code = match recv.read(&mut buf).await {
            Err(quinn::ReadError::Reset(code)) => code.into_inner(),
            other => panic!("expected stream reset, got {other:?}"),
        };
        assert_eq!(reset_code, 0x010e, "H3_MESSAGE_ERROR expected");
        assert_eq!(stream_id, u64::from(recv.id()));

        // The connection survived the malformed stream: a valid request
        // on another stream is served normally.
        let (mut send, recv) = fixture
            .request_open(&pseudo(&[
                (":method", "GET"),
                (":scheme", "https"),
                (":authority", "localhost"),
                (":path", "/ok"),
            ]))
            .await;
        send.finish().expect("finish request");
        let (sections, data) = fixture_response(&mut fixture, recv).await;
        assert_eq!(sections[0].get(":status").map(String::as_str), Some("200"));
        assert_eq!(data, b"still-alive");

        cancel.cancel();
        let result = server_result
            .recv_timeout(Duration::from_secs(10))
            .expect("server finished");
        assert!(result.is_ok(), "server handle: {result:?}");
        server_thread.join().expect("join server");
    })
    .await
    .expect("fixture_client_malformed_message_resets_stream_and_connection_survives timed out");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fixture_client_local_error_reset_budget_closes_with_excessive_load() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let (_server_ep, _client_ep, client_conn, server_conn) = loopback_pair().await;
        let cancel = CancellationToken::new();
        let (server_thread, server_result) = spawn_native_server(
            server_conn,
            Http3Options::new().max_local_error_reset_streams(Some(2)),
            cancel.clone(),
            |request| async move {
                let (_parts, _) = request.into_parts();
                Ok::<_, std::convert::Infallible>(
                    Response::builder()
                        .status(StatusCode::OK)
                        .body(Full::new(Bytes::from(b"unused".to_vec())))
                        .expect("response"),
                )
            },
        );

        let mut fixture = Fixture::new(client_conn.clone()).await;
        // Two malformed messages fit the local-reset budget; the third
        // costs the connection: RESET_STREAM gives way to a close with
        // H3_EXCESSIVE_LOAD (RFC 9114 Section 10.5).
        for i in 0..3 {
            let (mut send, _recv) = fixture
                .request_open(&pseudo(&[
                    (":scheme", "https"),
                    (":authority", "localhost"),
                    (":path", &format!("/bad-{i}")),
                ]))
                .await;
            let _ = send.finish();
        }
        let closed = client_conn.closed().await;
        match closed {
            quinn::ConnectionError::ApplicationClosed(close) => {
                assert_eq!(close.error_code.into_inner(), 0x0107, "H3_EXCESSIVE_LOAD");
            }
            other => panic!("expected application close with H3_EXCESSIVE_LOAD, got {other:?}"),
        }

        cancel.cancel();
        let result = server_result
            .recv_timeout(Duration::from_secs(10))
            .expect("server finished");
        server_thread.join().expect("join server");
    })
    .await
    .expect("fixture_client_local_error_reset_budget_closes_with_excessive_load timed out");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fixture_client_pending_accept_reset_budget_closes_with_excessive_load() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let (_server_ep, _client_ep, client_conn, server_conn) = loopback_pair().await;
        let cancel = CancellationToken::new();
        let (server_thread, server_result) = spawn_native_server(
            server_conn,
            Http3Options::new().max_pending_accept_reset_streams(Some(2)),
            cancel.clone(),
            |request| async move {
                let (_parts, _) = request.into_parts();
                Ok::<_, std::convert::Infallible>(
                    Response::builder()
                        .status(StatusCode::OK)
                        .body(Full::new(Bytes::from(b"unused".to_vec())))
                        .expect("response"),
                )
            },
        );

        let fixture = Fixture::new(client_conn.clone()).await;
        // Streams opened and terminated before any request bytes were
        // sent never reach the handler: they churn through the
        // pending-accept budget (RFC 9114 Sections 4.1.2, 10.5), and the
        // third one costs the connection.
        for _ in 0..3 {
            let (mut send, _recv) = fixture.conn.open_bi().await.expect("open request stream");
            let _ = send.reset(0x010cu32.into()); // H3_REQUEST_CANCELLED
        }
        let closed = client_conn.closed().await;
        match closed {
            quinn::ConnectionError::ApplicationClosed(close) => {
                assert_eq!(close.error_code.into_inner(), 0x0107, "H3_EXCESSIVE_LOAD");
            }
            other => panic!("expected application close with H3_EXCESSIVE_LOAD, got {other:?}"),
        }

        cancel.cancel();
        let result = server_result
            .recv_timeout(Duration::from_secs(10))
            .expect("server finished");
        server_thread.join().expect("join server");
    })
    .await
    .expect("fixture_client_pending_accept_reset_budget_closes_with_excessive_load timed out");
}
