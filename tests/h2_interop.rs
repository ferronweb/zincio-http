//! Interop test: the `h2` reference client against the HTTP/2 server over TCP.
//!
//! In the `zincio-http` repository, there is "interop" directory containing
//! a test setup that is used to test interop with more HTTP/2 clients.

#![cfg(feature = "h2")]

use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use zincio::net::TcpListener;
use zincio::RuntimeBuilder;
use zincio_http::{Http2, Http2Options, HttpProtocol};

#[test]
fn h2_client_talks_to_native_server() {
    let (addr_tx, addr_rx) = std::sync::mpsc::channel::<std::net::SocketAddr>();

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
                    let (parts, body) = request.into_parts();
                    let len = body.collect().await.expect("request body").to_bytes().len();
                    let payload = format!("{} {} {len}", parts.method, parts.uri.path());
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

            let request = Request::builder()
                .uri("https://example.example/")
                .body(())
                .unwrap();
            let (response, _) = send_request.send_request(request, true).unwrap();
            let response = response.await.expect("GET response");
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(collect(&mut response.into_body()).await, b"GET / 0");

            let request = Request::builder()
                .method("POST")
                .uri("https://example.example/echo")
                .body(())
                .unwrap();
            let (response, mut body) = send_request.send_request(request, false).unwrap();
            body.send_data(Bytes::from_static(b"hello world"), true)
                .expect("send data");
            let response = response.await.expect("POST response");
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(collect(&mut response.into_body()).await, b"POST /echo 11");
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
