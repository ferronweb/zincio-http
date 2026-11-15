//! Transport-adapter correctness over a real `quinn` loopback connection.
//!
//! Drives the `h3-quinn` adapter (`zincio_http::quinn::Connection`) end to
//! end: open/accept unidirectional and bidirectional streams, bidirectional
//! data flow, FIN, stream-id parity, `reset`/`stop_sending` propagation,
//! handshake completion, and graceful shutdown (`CONNECTION_CLOSE` with an
//! application code). The server side exercises the adapter for everything
//! the HTTP/3 layer needs; the client side uses raw `quinn` where the
//! transport abstraction deliberately has no surface (opening a request
//! stream).
//!
//! Every scenario runs the two sides as separate spawned tasks, which is
//! what makes the connections actually drive their I/O.

#![cfg(all(feature = "h3", feature = "h3-quinn", feature = "unstable-internals"))]

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use quinn::{Endpoint, TransportConfig, VarInt};
use zincio_http::quinn::Connection as QuinnConnection;
use zincio_http::transport::{
    Accept, BidiStream, Connection as TransportConnection, OpenStreams, RecvStream, SendStream,
    UniStream,
};
use zincio_http::TransportError;

const H3_NO_ERROR: u64 = 0x0100;
const H3_REQUEST_CANCELLED: u64 = 0x010c;

fn loopback() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
}

/// A connected loopback pair. Both endpoints are kept alive (cloned into the
/// scenario) so neither side's connections are torn down early.
struct Loopback {
    _server_endpoint: Endpoint,
    _client_endpoint: Endpoint,
    /// The server-side adapter (HTTP/3 server role).
    server: QuinnConnection,
    /// The client-side adapter.
    client: QuinnConnection,
    /// The raw client connection, for stream-opening the transport traits do
    /// not expose (e.g. request streams).
    client_raw: quinn::Connection,
}

async fn loopback_pair() -> Loopback {
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
    // Both halves must be driven concurrently: the client's `Connecting`
    // needs the server's connection to be polled to answer each handshake
    // flight, so awaiting them sequentially would deadlock on the handshake
    // timeout.
    let (client_conn, server_conn) = tokio::join!(
        async { connecting.await.expect("client handshake") },
        async { incoming.await.expect("server handshake") },
    );

    Loopback {
        _server_endpoint: server_endpoint,
        _client_endpoint: client_endpoint,
        server: QuinnConnection::new(server_conn),
        client: QuinnConnection::new(client_conn.clone()),
        client_raw: client_conn,
    }
}

/// Like [`loopback_pair`] but with a tiny receive window on the client, so a
/// modest payload forces the server's `Send` into repeated flow-control
/// `Pending` re-polls — the exact path that used to duplicate buffered bytes
/// and grow the internal buffer without bound for large responses.
async fn loopback_pair_tiny_window() -> Loopback {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der: quinn::rustls::pki_types::CertificateDer<'static> = cert.cert.into();

    let server_config = quinn::ServerConfig::with_single_cert(
        vec![cert_der.clone()],
        quinn::rustls::pki_types::PrivateKeyDer::from(cert.signing_key),
    )
    .unwrap();
    let server_endpoint = Endpoint::server(server_config, loopback()).unwrap();
    let server_addr = server_endpoint.local_addr().unwrap();

    let mut client_tc = TransportConfig::default();
    client_tc.stream_receive_window(VarInt::from_u32(16384));
    client_tc.receive_window(VarInt::from_u32(16384));
    let mut roots = quinn::rustls::RootCertStore::empty();
    roots.add(cert_der).unwrap();
    let mut client_config = quinn::ClientConfig::with_root_certificates(Arc::new(roots)).unwrap();
    client_config.transport_config(Arc::new(client_tc));
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

    Loopback {
        _server_endpoint: server_endpoint,
        _client_endpoint: client_endpoint,
        server: QuinnConnection::new(server_conn),
        client: QuinnConnection::new(client_conn.clone()),
        client_raw: client_conn,
    }
}

async fn send_all(stream: &mut dyn SendStream, data: &[u8]) {
    std::future::poll_fn(|cx| stream.poll_send(cx, data))
        .await
        .expect("send all")
}

async fn finish(stream: &mut dyn SendStream) {
    std::future::poll_fn(|cx| stream.poll_finish(cx))
        .await
        .expect("finish")
}

async fn recv_all(stream: &mut dyn RecvStream) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(bytes) = std::future::poll_fn(|cx| stream.poll_recv(cx))
        .await
        .expect("recv")
    {
        out.extend_from_slice(&bytes);
    }
    out
}

async fn poll_open_uni(conn: &mut QuinnConnection) -> Box<dyn UniStream> {
    std::future::poll_fn(|cx| conn.poll_open_uni(cx))
        .await
        .expect("open uni")
}

/// Polls `conn.poll_accept_uni` until a stream arrives or the connection
/// closes (`Ok(None)`), which is then an error.
async fn poll_accept_uni(conn: &mut QuinnConnection) -> Box<dyn UniStream> {
    loop {
        if let Some(stream) = std::future::poll_fn(|cx| conn.poll_accept_uni(cx))
            .await
            .expect("accept uni")
        {
            return stream;
        }
        tokio::task::yield_now().await;
    }
}

async fn poll_accept(conn: &mut QuinnConnection) -> Box<dyn BidiStream> {
    loop {
        if let Some(stream) = std::future::poll_fn(|cx| conn.poll_accept(cx))
            .await
            .expect("accept bidi")
        {
            return stream;
        }
        tokio::task::yield_now().await;
    }
}

/// The 2-bit stream-type discriminator of RFC 9000 Section 2.1.
fn stream_type(id: u64) -> u64 {
    id & 0b11
}

fn assert_type(stream: &dyn RecvStream, expected: u64) {
    assert_eq!(stream_type(stream.id()), expected, "stream {}", stream.id());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn uni_streams_flow_both_ways_and_parity_holds() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let pair = loopback_pair().await;

        let server_task = tokio::spawn(async move {
            let mut server = pair.server;
            let mut control = poll_open_uni(&mut server).await;
            assert_type(&*control, 0b11);
            send_all(&mut *control, b"server-control").await;
            finish(&mut *control).await;

            // And it accepts the client's unidirectional stream (type 0b10).
            let mut client_uni = poll_accept_uni(&mut server).await;
            assert_type(&*client_uni, 0b10);
            let body = recv_all(&mut *client_uni).await;
            assert_eq!(body, b"client-control");
            server
        });

        let client_task = tokio::spawn(async move {
            let mut client = pair.client;
            let mut server_uni = poll_accept_uni(&mut client).await;
            assert_type(&*server_uni, 0b11);
            let body = recv_all(&mut *server_uni).await;
            assert_eq!(body, b"server-control");

            let mut own = poll_open_uni(&mut client).await;
            assert_type(&*own, 0b10);
            send_all(&mut *own, b"client-control").await;
            finish(&mut *own).await;
            client
        });

        // Keep the endpoints alive and the adapters off the main task.
        let (_server_ep, _client_ep) = (pair._server_endpoint, pair._client_endpoint);
        let (_server, _client) = tokio::join!(server_task, client_task);
    })
    .await
    .expect("scenario must finish in time");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bidi_request_response_round_trips() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let pair = loopback_pair().await;

        let server_task = tokio::spawn(async move {
            let mut server = pair.server;
            let mut request = poll_accept(&mut server).await;
            // Request streams are client-initiated bidirectional: type 0b00.
            assert_type(&*request, 0b00);
            let body = recv_all(&mut *request).await;
            assert_eq!(body, b"GET / HTTP/3\r\n");
            send_all(&mut *request, b"200 OK\r\n").await;
            finish(&mut *request).await;
            server
        });

        let client_task = tokio::spawn(async move {
            let conn = pair.client_raw;
            let (mut send, mut recv) = conn.open_bi().await.unwrap();
            send.write_all(b"GET / HTTP/3\r\n").await.unwrap();
            send.finish().unwrap();

            let mut response = Vec::new();
            while let Some(chunk) = recv.read_chunk(usize::MAX, true).await.unwrap() {
                response.extend_from_slice(&chunk.bytes);
            }
            assert_eq!(response, b"200 OK\r\n");
            conn
        });

        let (_server_ep, _client_ep) = (pair._server_endpoint, pair._client_endpoint);
        let (_server, _client) = tokio::join!(server_task, client_task);
    })
    .await
    .expect("scenario must finish in time");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reset_propagates_as_transport_error() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let pair = loopback_pair().await;

        let server_task = tokio::spawn(async move {
            let mut server = pair.server;
            let mut accepted = poll_accept_uni(&mut server).await;
            loop {
                match std::future::poll_fn(|cx| accepted.poll_recv(cx)).await {
                    Err(TransportError::Reset { code }) => {
                        assert_eq!(code, H3_REQUEST_CANCELLED);
                        break;
                    }
                    Ok(_) => tokio::task::yield_now().await,
                    Err(other) => panic!("expected Reset, got {other:?}"),
                }
            }
            server
        });

        let client_task = tokio::spawn(async move {
            let conn = pair.client_raw;
            let mut send = conn.open_uni().await.unwrap();
            // Reset before any data is transmitted so the server only ever
            // observes the reset.
            send.reset(quinn::VarInt::from_u64(H3_REQUEST_CANCELLED).unwrap())
                .unwrap();
            conn
        });

        let (_server_ep, _client_ep) = (pair._server_endpoint, pair._client_endpoint);
        let (_server, _client) = tokio::join!(server_task, client_task);
    })
    .await
    .expect("scenario must finish in time");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stop_sending_propagates_as_transport_error() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let pair = loopback_pair().await;

        let server_task = tokio::spawn(async move {
            let mut server = pair.server;
            let mut request = poll_accept(&mut server).await;

            // Read just the first body bytes; the client never finishes, so
            // reading to FIN would deadlock.
            let mut body = Vec::new();
            while body.len() < b"start".len() {
                let chunk = std::future::poll_fn(|cx| request.poll_recv(cx))
                    .await
                    .expect("recv start");
                body.extend_from_slice(&chunk.expect("data before stop"));
                tokio::task::yield_now().await;
            }
            assert_eq!(&body[..b"start".len()], b"start");

            std::future::poll_fn(|cx| request.poll_stop_sending(cx, H3_REQUEST_CANCELLED))
                .await
                .expect("stop_sending");
            server
        });

        let client_task = tokio::spawn(async move {
            let conn = pair.client_raw;
            let (mut send, _recv) = conn.open_bi().await.unwrap();
            send.write_all(b"start").await.unwrap();

            // Keep writing; the server's STOP_SENDING must eventually fail a
            // write with the propagated code.
            let payload = vec![0u8; 1024 * 1024];
            let mut seen_stopped = false;
            for _ in 0..64 {
                match send.write_all(&payload).await {
                    Ok(()) => tokio::task::yield_now().await,
                    Err(quinn::WriteError::Stopped(code)) => {
                        assert_eq!(code.into_inner(), H3_REQUEST_CANCELLED);
                        seen_stopped = true;
                        break;
                    }
                    Err(err) => panic!("unexpected write error: {err}"),
                }
            }
            assert!(seen_stopped, "STOP_SENDING never reached the client");
            conn
        });

        let (_server_ep, _client_ep) = (pair._server_endpoint, pair._client_endpoint);
        let (_server, _client) = tokio::join!(server_task, client_task);
    })
    .await
    .expect("scenario must finish in time");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shutdown_closes_both_sides_gracefully() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let pair = loopback_pair().await;

        let server_task = tokio::spawn(async move {
            let mut server = pair.server;
            assert!(server.is_handshake_complete());
            // Graceful shutdown: H3_NO_ERROR application close.
            std::future::poll_fn(|cx| server.poll_shutdown(cx, H3_NO_ERROR))
                .await
                .expect("shutdown");
            server
        });

        let client_task = tokio::spawn(async move {
            let mut client = pair.client;
            assert!(client.is_handshake_complete());

            // The client observes the application close code ...
            loop {
                match client.close_reason() {
                    None => tokio::task::yield_now().await,
                    Some(reason) => {
                        let quinn::ConnectionError::ApplicationClosed(close) = reason else {
                            panic!("expected application close, got {reason:?}");
                        };
                        assert_eq!(close.error_code.into_inner(), H3_NO_ERROR);
                        break;
                    }
                }
            }

            // ... and stream acceptance ends in Ok(None).
            assert!(std::future::poll_fn(|cx| client.poll_accept(cx))
                .await
                .expect("accept after close")
                .is_none());
            client
        });

        let (_server_ep, _client_ep) = (pair._server_endpoint, pair._client_endpoint);
        let (_server, _client) = tokio::join!(server_task, client_task);
    })
    .await
    .expect("scenario must finish in time");
}

/// A large response under flow-control backpressure must not duplicate or
/// corrupt bytes. The pre-fix `Send::poll_send` re-appended the whole buffer
/// on every re-poll after a `Pending`, so a stalled large body (e.g. a big
/// `.mp4` the client buffers without consuming) grew the internal buffer
/// without bound and starved the connection. With the fix, the receiver gets
/// exactly the bytes that were sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn large_send_under_backpressure_is_not_duplicated() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let pair = loopback_pair_tiny_window().await;
        // 64 KiB, far larger than the 4 KiB receive window, so the server
        // must re-poll after every 4 KiB it is allowed to send.
        let payload = vec![0xABu8; 64 * 1024];
        let expected_len = payload.len();

        let server_done = std::sync::Arc::new(tokio::sync::Notify::new());
        let client_done = std::sync::Arc::new(tokio::sync::Notify::new());
        let server_done_tx = std::sync::Arc::clone(&server_done);
        let client_done_rx = std::sync::Arc::clone(&client_done);

        let server_task = tokio::spawn(async move {
            let mut server = pair.server;
            let mut uni = poll_open_uni(&mut server).await;
            send_all(&mut *uni, &payload).await;
            finish(&mut *uni).await;
            // Hold the connection open until the client has drained quinn's
            // receive buffer; otherwise dropping `server` mid-flight truncates
            // the stream with a reset.
            client_done_rx.notified().await;
            drop(server);
            server_done_tx.notify_one();
        });

        let mut client = pair.client;
        let mut client_uni = poll_accept_uni(&mut client).await;
        let received = recv_all(&mut *client_uni).await;
        client_done.notify_one();
        server_done.notified().await;
        server_task.await.unwrap();

        assert_eq!(
            received.len(),
            expected_len,
            "received byte count must equal sent (no duplication under backpressure)"
        );
        assert!(
            received.iter().all(|&b| b == 0xAB),
            "received bytes must match"
        );
    })
    .await
    .expect("scenario must finish in time");
}
