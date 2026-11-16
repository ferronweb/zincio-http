//! HTTP/3 interop tests: an `h3` client and a frame-level QUIC fixture against
//! the native server.
//!
//! In the `zincio-http` repository, there is "interop" directory containing
//! a test setup that is used to test interop with more HTTP/3 clients.

#![cfg(feature = "h3-quinn")]

use std::{
    collections::{HashMap, VecDeque},
    future::Future,
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

type H3SendRequest = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;
type H3RequestStream = h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

fn loopback() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
}

/// A connected loopback pair plus the endpoints that keep both halves alive.
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

async fn with_timeout_secs<F: Future>(secs: u64, future: F) {
    tokio::time::timeout(Duration::from_secs(secs), future)
        .await
        .expect("test timed out");
}

async fn with_timeout<F: Future>(future: F) {
    with_timeout_secs(30, future).await;
}

/// The native server, running on a zincio runtime in a dedicated thread.
struct NativeServer {
    cancel: CancellationToken,
    thread: std::thread::JoinHandle<()>,
    result: mpsc::Receiver<Result<(), std::io::Error>>,
}

impl NativeServer {
    fn start<F, Fut, ResB, ResBE, ResE>(
        server_conn: quinn::Connection,
        options: Http3Options,
        handler: F,
    ) -> Self
    where
        F: Fn(Request<Incoming>) -> Fut + Send + 'static,
        Fut: Future<Output = Result<Response<ResB>, ResE>> + Send + 'static,
        ResB: http_body::Body<Data = Bytes, Error = ResBE> + Send + Unpin + 'static,
        ResBE: std::error::Error + Send + 'static,
        ResE: std::error::Error + Send + 'static,
    {
        let cancel = CancellationToken::new();
        let thread_cancel = cancel.clone();
        let (result_tx, result) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            let rt = RuntimeBuilder::new()
                .enable_timer(true)
                .build()
                .expect("zincio runtime");
            let result = rt.block_on(async move {
                Http3::new(zincio_http::quinn::Connection::new(server_conn), options)
                    .graceful_shutdown_token(thread_cancel)
                    .handle(handler)
                    .await
            });
            result_tx.send(result).ok();
        });
        Self {
            cancel,
            thread,
            result,
        }
    }

    fn cancel(&self) {
        self.cancel.cancel();
    }

    fn finish(self) {
        let result = self
            .result
            .recv_timeout(Duration::from_secs(10))
            .expect("server finished");
        assert!(result.is_ok(), "server handle: {result:?}");
        self.thread.join().expect("join server");
    }

    fn finish_err(self) -> std::io::Error {
        let result = self
            .result
            .recv_timeout(Duration::from_secs(10))
            .expect("server finished");
        let error = result.expect_err("server should fail");
        self.thread.join().expect("join server");
        error
    }

    fn shutdown(self) {
        self.cancel.cancel();
        self.finish();
    }
}

/// An `h3` client plus the task that drives its connection.
struct H3Client {
    send: H3SendRequest,
    drive: tokio::task::JoinHandle<()>,
}

impl H3Client {
    async fn connect(conn: quinn::Connection) -> Self {
        let (mut conn, send) = h3::client::builder()
            .build(h3_quinn::Connection::new(conn))
            .await
            .expect("h3 client");
        let drive = tokio::spawn(async move {
            let _ = conn.wait_idle().await;
            std::future::pending::<()>().await;
        });
        Self { send, drive }
    }

    async fn request(&mut self, request: Request<()>) -> H3RequestStream {
        self.send.send_request(request).await.expect("send request")
    }

    async fn get(&mut self, path: &str) -> H3RequestStream {
        self.request(
            Request::get(format!("https://localhost{path}"))
                .body(())
                .unwrap(),
        )
        .await
    }

    async fn post(&mut self, path: &str) -> H3RequestStream {
        self.request(
            Request::post(format!("https://localhost{path}"))
                .body(())
                .unwrap(),
        )
        .await
    }

    fn shutdown(self) {
        self.drive.abort();
    }
}

async fn read_response_body(stream: &mut H3RequestStream) -> Vec<u8> {
    let mut body = Vec::new();
    while let Some(chunk) = stream.recv_data().await.expect("response data") {
        body.extend_from_slice(chunk.chunk());
    }
    body
}

async fn expect_app_close(conn: &quinn::Connection, code: u64) {
    match conn.closed().await {
        quinn::ConnectionError::ApplicationClosed(close) => {
            assert_eq!(close.error_code.into_inner(), code);
        }
        other => panic!("unexpected close: {other:?}"),
    }
}

/// Drains the request body, collecting data and any trailers.
async fn read_body_and_trailers(body: Incoming) -> (Vec<u8>, Option<HeaderMap>) {
    let mut body = Pin::from(Box::new(body));
    let mut bytes = Vec::new();
    let mut trailers = None;
    while let Some(frame) = body.frame().await {
        let Ok(frame) = frame else { break };
        if let Some(data) = frame.data_ref() {
            bytes.extend_from_slice(data.as_ref());
        } else if let Some(t) = frame.trailers_ref() {
            trailers = Some(t.clone());
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

/// A raw quinn client that speaks HTTP/3 at the frame level.
struct Fixture {
    conn: quinn::Connection,
    encoder: Encoder,
    decoder: Decoder,
    /// Kept alive so quinn does not FIN a critical stream.
    #[allow(dead_code)]
    control: quinn::SendStream,
    encoder_stream: quinn::SendStream,
    #[allow(dead_code)]
    decoder_stream: quinn::SendStream,
    /// The server's QPACK encoder stream (type 0x02).
    server_encoder: Option<quinn::RecvStream>,
    started_at: std::time::Instant,
}

impl Fixture {
    async fn new(conn: quinn::Connection) -> Self {
        Self::new_with_capacity(conn, 0, 0).await
    }

    /// Advertises a QPACK table capacity, allowing dynamic-table encoding.
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

    async fn request_get(&mut self, path: &str) -> (quinn::SendStream, quinn::RecvStream) {
        self.request_open(&pseudo(&[
            (":method", "GET"),
            (":scheme", "https"),
            (":authority", "localhost"),
            (":path", path),
        ]))
        .await
    }

    /// Reads a complete response with a stateless decoder.
    async fn response(
        &mut self,
        mut recv: quinn::RecvStream,
    ) -> (Vec<HashMap<String, String>>, Vec<u8>) {
        let stream_id = u64::from(recv.id());
        let mut reader = FrameReader::new();
        let mut sections = Vec::new();
        let mut data = Vec::new();
        while let Some(frame) = reader.next(&mut recv).await {
            match frame {
                Frame::Headers(block) => sections.push(field_map(self.decode(&block, stream_id))),
                Frame::Data(chunk) => data.extend_from_slice(&chunk),
                other => panic!("unexpected frame on request stream: {other:?}"),
            }
        }
        (sections, data)
    }

    /// Reads a complete response, unblocking dynamic-table references.
    async fn response_dynamic(
        &mut self,
        mut recv: quinn::RecvStream,
    ) -> (Vec<HashMap<String, String>>, Vec<u8>) {
        let stream_id = u64::from(recv.id());
        let mut reader = FrameReader::new();
        let mut sections = Vec::new();
        let mut data = Vec::new();
        while let Some(frame) = reader.next(&mut recv).await {
            match frame {
                Frame::Headers(block) => {
                    sections.push(field_map(self.decode_dynamic(&block, stream_id).await))
                }
                Frame::Data(chunk) => data.extend_from_slice(&chunk),
                other => panic!("unexpected frame on request stream: {other:?}"),
            }
        }
        (sections, data)
    }

    /// Writes one DATA frame.
    async fn write_data(send: &mut quinn::SendStream, data: &[u8]) {
        let mut buf = BytesMut::new();
        Frame::Data(Bytes::copy_from_slice(data)).encode(&mut buf);
        send.write_all(&buf).await.expect("write data");
    }

    /// Decodes a response HEADERS block. The server sees a table capacity of
    /// zero, so blocks decode statelessly.
    fn decode(&mut self, block: &Bytes, stream_id: u64) -> Vec<(Bytes, Bytes)> {
        let now = self.started_at.elapsed().as_nanos() as u64;
        self.decoder
            .decode_block(block, stream_id, now)
            .expect("decode response headers")
            .expect("blocked without a dynamic table")
    }

    /// Accepts and routes the server's unidirectional streams.
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
                    // Control, decoder, push, or grease: drain what the
                    // server already buffered, then drop the stream.
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

    /// Reads the server's QPACK encoder stream and returns newly unblocked
    /// field sections.
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

    /// Decodes a response HEADERS block, pumping the server's encoder stream
    /// until a blocked block unblocks.
    async fn decode_dynamic(&mut self, block: &[u8], stream_id: u64) -> Vec<(Bytes, Bytes)> {
        let now = self.started_at.elapsed().as_nanos() as u64;
        if let Some(headers) = self
            .decoder
            .decode_block(block, stream_id, now)
            .expect("decode response headers")
        {
            self.flush_acks().await;
            return headers;
        }
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

    /// Sends queued QPACK section acknowledgements.
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
    with_timeout(async {
        let (_server_ep, _client_ep, client_conn, server_conn) = loopback_pair().await;
        let server = NativeServer::start(server_conn, Http3Options::new(), |request| async move {
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
            response_trailers.insert("x-response-trailer", HeaderValue::from_static("echoed"));
            let body =
                Full::new(Bytes::from(payload)).with_trailers(std::future::ready(Some(Ok::<
                    HeaderMap,
                    std::convert::Infallible,
                >(
                    response_trailers,
                ))));
            Ok::<_, std::convert::Infallible>(
                Response::builder()
                    .status(StatusCode::OK)
                    .body(body)
                    .expect("response"),
            )
        });

        let mut client = H3Client::connect(client_conn).await;

        let mut stream = client.get("/echo").await;
        stream.finish().await.expect("finish GET");
        let response = stream.recv_response().await.expect("GET response");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.version(), http::Version::HTTP_3);
        assert!(response.headers().contains_key(http::header::DATE));
        assert_eq!(read_response_body(&mut stream).await, b"GET /echo 0 none");

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
        let mut stream = client.request(request).await;
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
        assert_eq!(read_response_body(&mut stream).await, b"POST /post 11 yes");
        assert_eq!(
            stream.recv_trailers().await.expect("POST trailers"),
            Some({
                let mut trailers = HeaderMap::new();
                trailers.insert("x-response-trailer", HeaderValue::from_static("echoed"));
                trailers
            })
        );

        drop(stream);
        client.shutdown();
        server.shutdown();
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn h3_client_concurrent_streams_and_abort() {
    with_timeout(async {
        let (_server_ep, _client_ep, client_conn, server_conn) = loopback_pair().await;
        let server = NativeServer::start(server_conn, Http3Options::new(), |request| async move {
            let (_, body) = request.into_parts();
            let (bytes, _) = read_body_and_trailers(body).await;
            Ok::<_, std::convert::Infallible>(
                Response::builder()
                    .status(StatusCode::OK)
                    .body(Full::new(Bytes::from(bytes.len().to_string())))
                    .expect("response"),
            )
        });

        let mut client = H3Client::connect(client_conn).await;

        let mut streams = Vec::new();
        for i in 0..25usize {
            let mut stream = client.post("/echo").await;
            stream
                .send_data(Bytes::from(vec![b'x'; i * 100]))
                .await
                .expect("send data");
            stream.finish().await.expect("finish");
            streams.push((i, stream));
        }

        let mut abort = client.post("/abort").await;
        abort
            .send_data(Bytes::from_static(b"partial body"))
            .await
            .expect("abort data");
        abort.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
        drop(abort);

        for (i, mut stream) in streams {
            let response = stream.recv_response().await.expect("response");
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                read_response_body(&mut stream).await,
                (i * 100).to_string().as_bytes()
            );
        }

        client.shutdown();
        server.shutdown();
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn h3_client_goaway_graceful_shutdown() {
    with_timeout(async {
        let (_server_ep, _client_ep, client_conn, server_conn) = loopback_pair().await;
        let (start_tx, start_rx) = mpsc::channel::<()>();
        let server = NativeServer::start(server_conn, Http3Options::new(), move |request| {
            let start_tx = start_tx.clone();
            async move {
                start_tx.send(()).ok();
                let (_, body) = request.into_parts();
                let (bytes, _) = read_body_and_trailers(body).await;
                Ok::<_, std::convert::Infallible>(
                    Response::builder()
                        .status(StatusCode::OK)
                        .body(Full::new(Bytes::from(format!("got {} bytes", bytes.len()))))
                        .expect("response"),
                )
            }
        });

        let client_raw = client_conn.clone();
        let mut client = H3Client::connect(client_conn).await;

        let mut stream: H3RequestStream = client.post("/slow").await;
        stream
            .send_data(Bytes::from_static(b"first chunk"))
            .await
            .expect("A data");
        start_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("handler started");

        server.cancel();
        stream
            .send_data(Bytes::from_static(b"rest chunk"))
            .await
            .expect("A rest data");
        stream.finish().await.expect("finish A");

        let response = stream.recv_response().await.expect("A response");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(read_response_body(&mut stream).await, b"got 21 bytes");
        expect_app_close(&client_raw, H3_NO_ERROR).await;

        drop(stream);
        client.shutdown();
        server.finish();
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn h3_client_idle_connection_closes_after_accept_timeout() {
    with_timeout(async {
        let (_server_ep, _client_ep, client_conn, server_conn) = loopback_pair().await;
        let server = NativeServer::start(
            server_conn,
            Http3Options::new().accept_timeout(Some(Duration::from_millis(300))),
            |_request| async move {
                Ok::<_, std::convert::Infallible>(
                    Response::builder()
                        .status(StatusCode::OK)
                        .body(Full::new(Bytes::from_static(b"ok")))
                        .expect("response"),
                )
            },
        );

        let client_raw = client_conn.clone();
        let mut client = H3Client::connect(client_conn).await;

        let mut stream = client.get("/").await;
        stream.finish().await.expect("finish");
        let response = stream.recv_response().await.expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        while stream.recv_data().await.expect("data").is_some() {}
        drop(stream);

        tokio::time::timeout(
            Duration::from_secs(5),
            expect_app_close(&client_raw, H3_NO_ERROR),
        )
        .await
        .expect("the server closes the idle connection");

        let error = server.finish_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);

        client.shutdown();
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn h3_accept_timeout_ignores_in_flight_requests() {
    // The accept timeout only applies while no request is in flight.
    with_timeout(async {
        let (_server_ep, _client_ep, client_conn, server_conn) = loopback_pair().await;
        let server = NativeServer::start(
            server_conn,
            Http3Options::new().accept_timeout(Some(Duration::from_millis(300))),
            |request| async move {
                if request.uri().path() == "/slow" {
                    // Wait on a thread so the handler future stays `Send`.
                    let (done, wait) = tokio::sync::oneshot::channel();
                    std::thread::spawn(move || {
                        std::thread::sleep(Duration::from_secs(1));
                        let _ = done.send(());
                    });
                    let _ = wait.await;
                }
                Ok::<_, std::convert::Infallible>(
                    Response::builder()
                        .status(StatusCode::OK)
                        .body(Full::new(Bytes::from_static(b"done")))
                        .expect("response"),
                )
            },
        );

        let mut client = H3Client::connect(client_conn).await;

        for path in ["/slow", "/after"] {
            let mut stream = client.get(path).await;
            stream.finish().await.expect("finish");
            let response = stream.recv_response().await.expect("response");
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            assert_eq!(read_response_body(&mut stream).await, b"done", "{path}");
        }

        client.shutdown();
        server.shutdown();
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fixture_client_wire_get() {
    with_timeout(async {
        let (_server_ep, _client_ep, client_conn, server_conn) = loopback_pair().await;
        let server = NativeServer::start(server_conn, Http3Options::new(), |request| async move {
            let (parts, _) = request.into_parts();
            Ok::<_, std::convert::Infallible>(
                Response::builder()
                    .status(StatusCode::OK)
                    .body(Full::new(Bytes::from(format!(
                        "wire-ok {}",
                        parts.uri.path()
                    ))))
                    .expect("response"),
            )
        });

        let mut fixture = Fixture::new(client_conn).await;
        let (mut send, recv) = fixture.request_get("/wire").await;
        send.finish().expect("finish request");

        let (sections, data) = fixture.response(recv).await;
        assert_eq!(sections.len(), 1, "no interim responses for a plain GET");
        let headers = &sections[0];
        assert_eq!(headers.get(":status").map(String::as_str), Some("200"));
        assert_eq!(
            headers.get("content-length").map(String::as_str),
            Some("13")
        );
        assert!(headers.contains_key("date"));
        assert_eq!(data, b"wire-ok /wire");

        server.shutdown();
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fixture_client_dynamic_table_unblocks() {
    with_timeout(async {
        let (_server_ep, _client_ep, client_conn, server_conn) = loopback_pair().await;
        let server = NativeServer::start(server_conn, Http3Options::new(), dyn_handler);

        let mut fixture = Fixture::new_with_capacity(client_conn, 65_536, 100).await;
        let (mut send, recv) = fixture.request_get("/dyn").await;
        send.finish().expect("finish request");

        let (sections, data) = fixture.response_dynamic(recv).await;
        assert_eq!(sections.len(), 1, "no interim responses for a plain GET");
        let headers = &sections[0];
        assert_eq!(headers.get(":status").map(String::as_str), Some("200"));
        assert_eq!(
            headers.get("x-dyn-token").map(String::as_str),
            Some("rendered-dynamically")
        );
        assert_eq!(data, b"dyn-ok /dyn");

        server.shutdown();
    })
    .await;
}

/// One GET against a dynamic-table fixture, returning the response body.
async fn dyn_exchange(fixture: &mut Fixture, path: &str, expect_token: &str) -> Vec<u8> {
    let (mut send, recv) = fixture.request_get(path).await;
    send.finish().expect("finish request");

    let (sections, data) = fixture.response_dynamic(recv).await;
    let headers = &sections[0];
    assert_eq!(headers.get(":status").map(String::as_str), Some("200"));
    assert_eq!(
        headers.get("x-dyn-token").map(String::as_str),
        Some(expect_token)
    );
    data
}

/// A handler that forces a dynamic-table insert via `x-dyn-token`.
async fn dyn_handler(
    request: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let (parts, _) = request.into_parts();
    Ok::<_, std::convert::Infallible>(
        Response::builder()
            .status(StatusCode::OK)
            .header("x-dyn-token", "rendered-dynamically")
            .body(Full::new(Bytes::from(format!(
                "dyn-ok {}",
                parts.uri.path()
            ))))
            .expect("response"),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fixture_client_dynamic_table_reload_and_reconnect() {
    with_timeout_secs(60, async {
        let (_server_ep, _client_ep, client_conn, server_conn) = loopback_pair().await;
        let server = NativeServer::start(server_conn, Http3Options::new(), dyn_handler);
        let mut fixture = Fixture::new_with_capacity(client_conn, 65_536, 100).await;

        for _ in 0..2 {
            assert_eq!(
                dyn_exchange(&mut fixture, "/page", "rendered-dynamically").await,
                b"dyn-ok /page"
            );
        }

        // Keep the peer alive until the server has shut down.
        server.shutdown();
        drop(fixture);

        // A fresh connection must still serve the dynamic-table response.
        let (_server_ep, _client_ep, client_conn, server_conn) = loopback_pair().await;
        let server = NativeServer::start(server_conn, Http3Options::new(), dyn_handler);
        let mut fixture = Fixture::new_with_capacity(client_conn, 65_536, 100).await;
        assert_eq!(
            dyn_exchange(&mut fixture, "/page", "rendered-dynamically").await,
            b"dyn-ok /page"
        );

        server.shutdown();
        drop(fixture);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fixture_client_expect_100_continue() {
    with_timeout(async {
        let (_server_ep, _client_ep, client_conn, server_conn) = loopback_pair().await;
        let server = NativeServer::start(server_conn, Http3Options::new(), |request| async move {
            let (_, body) = request.into_parts();
            let (bytes, _) = read_body_and_trailers(body).await;
            Ok::<_, std::convert::Infallible>(
                Response::builder()
                    .status(StatusCode::OK)
                    .body(Full::new(Bytes::from(format!("got {} bytes", bytes.len()))))
                    .expect("response"),
            )
        });

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
        let status = interim
            .iter()
            .find(|(name, _)| name.as_ref() == b":status")
            .map(|(_, value)| value.as_ref());
        assert_eq!(status, Some(b"100".as_slice()));

        Fixture::write_data(&mut send, b"continue-body").await;
        send.finish().expect("finish request");

        let (sections, data) = fixture.response(recv).await;
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].get(":status").map(String::as_str), Some("200"));
        assert_eq!(data, b"got 13 bytes");

        server.shutdown();
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fixture_client_early_hints() {
    with_timeout(async {
        let (_server_ep, _client_ep, client_conn, server_conn) = loopback_pair().await;
        let server =
            NativeServer::start(server_conn, Http3Options::new(), |mut request| async move {
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
            });

        let mut fixture = Fixture::new(client_conn).await;
        let (mut send, recv) = fixture.request_get("/hints").await;
        send.finish().expect("finish request");

        let (sections, data) = fixture.response(recv).await;
        assert_eq!(sections.len(), 2, "103 Early Hints then the final response");
        assert_eq!(sections[0].get(":status").map(String::as_str), Some("103"));
        assert_eq!(
            sections[0].get("link").map(String::as_str),
            Some("</style.css>; rel=preload; as=style")
        );
        assert_eq!(sections[1].get(":status").map(String::as_str), Some("200"));
        assert_eq!(data, b"done");

        server.shutdown();
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fixture_client_connect() {
    with_timeout(async {
        let (_server_ep, _client_ep, client_conn, server_conn) = loopback_pair().await;
        let server = NativeServer::start(
            server_conn,
            Http3Options::new().enable_connect_protocol(true),
            |request| async move {
                let (parts, _) = request.into_parts();
                Ok::<_, std::convert::Infallible>(
                    Response::builder()
                        .status(StatusCode::OK)
                        .body(Full::new(Bytes::from(format!(
                            "connect={}",
                            parts.method == Method::CONNECT
                        ))))
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

        let (sections, data) = fixture.response(recv).await;
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].get(":status").map(String::as_str), Some("200"));
        assert_eq!(data, b"connect=true");

        server.shutdown();
    })
    .await;
}

/// Like [`dyn_handler`], but the `x-dyn-token` value is derived from the
/// request path, so every distinct path forces the server's encoder to
/// insert a new dynamic entry rather than reference an existing one.
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

/// Many requests, each with a unique `x-dyn-token` value, against a small
/// dynamic table.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fixture_client_dynamic_table_eviction_pressure() {
    with_timeout_secs(60, async {
        let (_server_ep, _client_ep, client_conn, server_conn) = loopback_pair().await;
        let server = NativeServer::start(server_conn, Http3Options::new(), dyn_handler_unique);

        // A small capacity forces eviction after a handful of inserts.
        let mut fixture = Fixture::new_with_capacity(client_conn, 600, 100).await;
        for i in 0..200 {
            let path = format!("/p{i}");
            let (mut send, recv) = fixture.request_get(&path).await;
            send.finish().expect("finish request");

            let (sections, data) = fixture.response_dynamic(recv).await;
            let headers = &sections[0];
            assert_eq!(
                headers.get(":status").map(String::as_str),
                Some("200"),
                "request {i} headers"
            );
            assert_eq!(
                headers.get("x-dyn-token").map(String::as_str),
                Some(format!("token-{path}").as_str()),
                "request {i} token matches path"
            );
            assert_eq!(data, format!("dyn-ok {path}").into_bytes());
        }

        // Keep the peer alive until the server has shut down.
        server.shutdown();
        drop(fixture);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fixture_client_malformed_message_resets_stream_and_connection_survives() {
    with_timeout(async {
        let (_server_ep, _client_ep, client_conn, server_conn) = loopback_pair().await;
        let server = NativeServer::start(server_conn, Http3Options::new(), |request| async move {
            let (_parts, _) = request.into_parts();
            Ok::<_, std::convert::Infallible>(
                Response::builder()
                    .status(StatusCode::OK)
                    .body(Full::new(Bytes::from_static(b"still-alive")))
                    .expect("response"),
            )
        });

        let mut fixture = Fixture::new(client_conn).await;
        // A request without `:method` is malformed.
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

        // The malformed stream did not take the connection down.
        let (mut send, recv) = fixture.request_get("/ok").await;
        send.finish().expect("finish request");
        let (sections, data) = fixture.response(recv).await;
        assert_eq!(sections[0].get(":status").map(String::as_str), Some("200"));
        assert_eq!(data, b"still-alive");

        server.shutdown();
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fixture_client_connection_specific_fields_reset_the_stream() {
    with_timeout(async {
        let (_server_ep, _client_ep, client_conn, server_conn) = loopback_pair().await;
        let server = NativeServer::start(server_conn, Http3Options::new(), |request| async move {
            let (_parts, _) = request.into_parts();
            Ok::<_, std::convert::Infallible>(
                Response::builder()
                    .status(StatusCode::OK)
                    .body(Full::new(Bytes::from_static(b"still-alive")))
                    .expect("response"),
            )
        });

        let mut fixture = Fixture::new(client_conn).await;

        // Connection-specific fields make a request malformed (RFC 9114 4.2).
        for (name, value) in [
            ("connection", "close"),
            ("keep-alive", "timeout=5"),
            ("transfer-encoding", "chunked"),
            ("upgrade", "websocket"),
            ("te", "gzip"),
        ] {
            let (mut send, mut recv) = fixture
                .request_open(&pseudo(&[
                    (":method", "GET"),
                    (":scheme", "https"),
                    (":authority", "localhost"),
                    (":path", "/"),
                    (name, value),
                ]))
                .await;
            let _ = send.finish();
            let mut buf = [0u8; 1];
            match recv.read(&mut buf).await {
                Err(quinn::ReadError::Reset(code)) => {
                    assert_eq!(
                        code.into_inner(),
                        0x010e,
                        "{name}: H3_MESSAGE_ERROR expected"
                    );
                }
                other => panic!("{name}: expected stream reset, got {other:?}"),
            }
        }

        // `TE: trailers` is allowed, and the connection is still usable.
        let (mut send, recv) = fixture
            .request_open(&pseudo(&[
                (":method", "GET"),
                (":scheme", "https"),
                (":authority", "localhost"),
                (":path", "/ok"),
                ("te", "trailers"),
            ]))
            .await;
        send.finish().expect("finish request");
        let (sections, data) = fixture.response(recv).await;
        assert_eq!(sections[0].get(":status").map(String::as_str), Some("200"));
        assert_eq!(data, b"still-alive");

        server.shutdown();
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fixture_client_local_error_reset_budget_closes_with_excessive_load() {
    with_timeout(async {
        let (_server_ep, _client_ep, client_conn, server_conn) = loopback_pair().await;
        let server = NativeServer::start(
            server_conn,
            Http3Options::new().max_local_error_reset_streams(Some(2)),
            |request| async move {
                let (_parts, _) = request.into_parts();
                Ok::<_, std::convert::Infallible>(
                    Response::builder()
                        .status(StatusCode::OK)
                        .body(Full::new(Bytes::from_static(b"unused")))
                        .expect("response"),
                )
            },
        );

        let mut fixture = Fixture::new(client_conn.clone()).await;
        // Two malformed messages fit the local-reset budget; the third does not.
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
        expect_app_close(&client_conn, 0x0107).await;

        server.cancel();
        let error = server.finish_err();
        let message = error.to_string();
        assert!(
            message.contains("ExcessiveLoad") && message.contains("0x107"),
            "unexpected server error: {message}"
        );
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fixture_client_pending_accept_reset_budget_closes_with_excessive_load() {
    with_timeout(async {
        let (_server_ep, _client_ep, client_conn, server_conn) = loopback_pair().await;
        let server = NativeServer::start(
            server_conn,
            Http3Options::new().max_pending_accept_reset_streams(Some(2)),
            |request| async move {
                let (_parts, _) = request.into_parts();
                Ok::<_, std::convert::Infallible>(
                    Response::builder()
                        .status(StatusCode::OK)
                        .body(Full::new(Bytes::from_static(b"unused")))
                        .expect("response"),
                )
            },
        );

        let fixture = Fixture::new(client_conn.clone()).await;
        // Streams that end before sending request bytes never reach the handler.
        for _ in 0..3 {
            let (mut send, _recv) = fixture.conn.open_bi().await.expect("open request stream");
            let _ = send.reset(0x010cu32.into()); // H3_REQUEST_CANCELLED
        }
        expect_app_close(&client_conn, 0x0107).await;

        server.cancel();
        let error = server.finish_err();
        let message = error.to_string();
        assert!(
            message.contains("ExcessiveLoad") && message.contains("0x107"),
            "unexpected server error: {message}"
        );
    })
    .await;
}

/// A body that yields its frames in turn; the last may be an error.
struct Frames(VecDeque<Result<http_body::Frame<Bytes>, std::io::Error>>);

impl http_body::Body for Frames {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Bytes>, std::io::Error>>> {
        std::task::Poll::Ready(self.get_mut().0.pop_front())
    }
}

/// Reads a request stream to its end: the reset code, or `None` when it finished.
async fn reset_code(mut recv: quinn::RecvStream) -> Option<u64> {
    let mut buf = [0u8; 4096];
    loop {
        match recv.read(&mut buf).await {
            Ok(Some(_)) => {}
            Ok(None) => return None,
            Err(quinn::ReadError::Reset(code)) => return Some(code.into_inner()),
            Err(other) => panic!("unexpected read error: {other:?}"),
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fixture_client_response_cut_short_is_reset_not_finished() {
    with_timeout(async {
        let (_server_ep, _client_ep, client_conn, server_conn) = loopback_pair().await;
        let server = NativeServer::start(server_conn, Http3Options::new(), |request| async move {
            let frames = match request.uri().path() {
                "/fail" => return Err(std::io::Error::other("the handler failed")),
                "/broken" => vec![
                    Ok(http_body::Frame::data(Bytes::from_static(b"part"))),
                    Err(std::io::Error::other("the body broke")),
                ],
                _ => vec![Ok(http_body::Frame::data(Bytes::from_static(b"whole")))],
            };
            Ok(Response::builder()
                .status(StatusCode::OK)
                .body(Frames(frames.into()))
                .expect("response"))
        });

        let mut fixture = Fixture::new(client_conn).await;
        // A failed handler or body must reset the stream rather than finish it.
        for path in ["/fail", "/broken"] {
            let (mut send, recv) = fixture.request_get(path).await;
            send.finish().expect("finish request");
            assert_eq!(
                reset_code(recv).await,
                Some(0x0102),
                "{path}: H3_INTERNAL_ERROR expected"
            );
        }

        let (mut send, recv) = fixture.request_get("/ok").await;
        send.finish().expect("finish request");
        let (sections, data) = fixture.response(recv).await;
        assert_eq!(sections[0].get(":status").map(String::as_str), Some("200"));
        assert_eq!(data, b"whole");

        server.shutdown();
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fixture_client_uppercase_field_name_is_malformed() {
    with_timeout(async {
        let (_server_ep, _client_ep, client_conn, server_conn) = loopback_pair().await;
        let server = NativeServer::start(server_conn, Http3Options::new(), |_request| async move {
            Ok::<_, std::convert::Infallible>(
                Response::builder()
                    .status(StatusCode::OK)
                    .body(Full::new(Bytes::from_static(b"served")))
                    .expect("response"),
            )
        });

        let mut fixture = Fixture::new(client_conn).await;
        // `HeaderName` would accept and lowercase this.
        let (mut send, recv) = fixture
            .request_open(&pseudo(&[
                (":method", "GET"),
                (":scheme", "https"),
                (":authority", "localhost"),
                (":path", "/"),
                ("X-Upper", "1"),
            ]))
            .await;
        let _ = send.finish();
        assert_eq!(reset_code(recv).await, Some(0x010e));

        server.shutdown();
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fixture_client_pending_accept_resets_over_time_keep_the_connection() {
    with_timeout(async {
        let (_server_ep, _client_ep, client_conn, server_conn) = loopback_pair().await;
        let server = NativeServer::start(
            server_conn,
            Http3Options::new().max_pending_accept_reset_streams(Some(2)),
            |request| async move {
                let (parts, _) = request.into_parts();
                Ok::<_, std::convert::Infallible>(
                    Response::builder()
                        .status(StatusCode::OK)
                        .body(Full::new(Bytes::from(format!(
                            "still-open {}",
                            parts.uri.path()
                        ))))
                        .expect("response"),
                )
            },
        );

        let mut fixture = Fixture::new(client_conn).await;
        // More than the budget in total, but never more than two at once.
        for _ in 0..10 {
            let (mut send, _recv) = fixture.conn.open_bi().await.expect("open request stream");
            let _ = send.reset(0x010cu32.into()); // H3_REQUEST_CANCELLED
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let (mut send, recv) = fixture.request_get("/after").await;
        send.finish().expect("finish request");
        let (sections, data) = fixture.response(recv).await;
        assert_eq!(sections[0].get(":status").map(String::as_str), Some("200"));
        assert_eq!(data, b"still-open /after");

        server.shutdown();
    })
    .await;
}
