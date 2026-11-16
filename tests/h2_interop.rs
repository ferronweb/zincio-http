//! Interop test: drive a `h2` client against `zincio-http`'s HTTP/2 server
//! over a real TCP socket.
//!
//! The server runs on the `zincio` runtime, and the `h2` client
//! runs on its own `tokio` runtime in a separate thread.
//!
//! This covers the frame codec, preface/settings exchange, HEADERS + DATA,
//! and flow control end to end against a reference implementation, on the
//! same transport path the h2spec script uses.
//!
//! In the `zincio-http` repository, there is "interop" directory containing
//! a test setup that is used to test interop with more HTTP/2 clients.

#![cfg(feature = "h2")]

use std::sync::mpsc;
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body::Body;
use http_body_util::Full;
use zincio::net::TcpListener;
use zincio::RuntimeBuilder;
use zincio_http::{Http2, Http2Options, HttpProtocol, Incoming};

#[test]
fn h2_client_talks_to_native_server() {
    let (addr_tx, addr_rx) = mpsc::channel::<std::net::SocketAddr>();

    let server_thread = std::thread::spawn(move || {
        let rt = RuntimeBuilder::new()
            .enable_timer(true)
            .build()
            .expect("zincio runtime");
        rt.block_on(async move {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
            let addr = listener.local_addr().expect("local addr");
            addr_tx.send(addr).expect("send addr");
            let (stream, _) = listener.accept().await.expect("accept");
            stream.set_nodelay(true).expect("nodelay");
            let conn = Http2::new(
                stream.into_poll().expect("into_poll"),
                Http2Options::default(),
            );
            let _ = conn
                .handle(|request| async move {
                    // Echo the request method + path + body length so the
                    // client can confirm the native server received the
                    // request intact.
                    let (parts, body) = request.into_parts();
                    let mut body = std::pin::Pin::from(Box::new(body));
                    let mut bytes = Vec::new();
                    while let Some(chunk) =
                        std::future::poll_fn(|cx| <Incoming as Body>::poll_frame(body.as_mut(), cx))
                            .await
                    {
                        match chunk {
                            Ok(frame) => {
                                if let Some(data) = frame.data_ref() {
                                    bytes.extend_from_slice(data.as_ref());
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    let payload = format!("{} {} {}", parts.method, parts.uri.path(), bytes.len());
                    let response = Response::builder()
                        .status(StatusCode::OK)
                        .body(Full::new(Bytes::from(payload)))
                        .expect("valid response");
                    Ok::<_, std::convert::Infallible>(response)
                })
                .await;
        });
    });

    let addr = addr_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("server never bound");

    let client_thread = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        rt.block_on(async move {
            let stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
            stream.set_nodelay(true).expect("nodelay");

            let (mut send_request, conn) = h2::client::handshake(stream).await.expect("handshake");
            tokio::spawn(async move {
                let _ = conn.await;
            });

            // GET: server echoes method + path + body length ("GET / 0").
            let request = Request::builder()
                .uri("https://example.example/")
                .body(())
                .unwrap();
            let (response_fut, _send_stream) = send_request.send_request(request, true).unwrap();
            let response = response_fut.await.expect("GET response");
            assert_eq!(response.status(), StatusCode::OK);
            let payload = collect(&mut response.into_body()).await;
            assert_eq!(payload, b"GET / 0");

            // POST with a body: server echoes "POST /echo 11".
            let request = Request::builder()
                .method("POST")
                .uri("https://example.example/echo")
                .body(())
                .unwrap();
            let (response_fut, mut send_stream) =
                send_request.send_request(request, false).unwrap();
            send_stream
                .send_data(Bytes::from_static(b"hello world"), true)
                .expect("send data");
            let response = response_fut.await.expect("POST response");
            assert_eq!(response.status(), StatusCode::OK);
            let payload = collect(&mut response.into_body()).await;
            assert_eq!(payload, b"POST /echo 11");
        });
    });

    client_thread.join().expect("client thread panicked");
    server_thread.join().expect("server thread panicked");
}

async fn collect(body: &mut h2::RecvStream) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(chunk) = body.data().await {
        out.extend_from_slice(&chunk.expect("response body chunk"));
    }
    out
}
