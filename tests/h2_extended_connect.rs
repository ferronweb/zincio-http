//! Extended CONNECT over HTTP/2 (RFC 8441), against the `h2` crate's client: the
//! request reaches the handler with its path and `:protocol`, and the stream carries
//! the tunnel both ways (the request body up, the response body down).

#![cfg(feature = "h2")]

use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use zincio_http::{Http2, Http2Options, HttpProtocol, Incoming, Protocol};

#[test]
fn websocket_over_h2_reaches_the_handler_and_tunnels_both_ways() {
    zincio::RuntimeBuilder::new()
        .enable_timer(true)
        .build()
        .unwrap()
        .block_on(async {
            let (client_io, server_io) = tokio::io::duplex(1 << 16);
            let server = zincio::spawn(async move {
                Http2::new(
                    server_io,
                    Http2Options::default().enable_connect_protocol(true),
                )
                .handle(|request: Request<Incoming>| async move {
                    let protocol = request.extensions().get::<Protocol>().cloned();
                    let target = (request.method().clone(), request.uri().clone());
                    let status = if protocol.as_ref().map(Protocol::as_str) == Some("websocket")
                        && target.0 == Method::CONNECT
                        && target.1.path() == "/chat"
                        && target.1.query() == Some("room=1")
                        && target.1.host() == Some("example.com")
                    {
                        StatusCode::OK
                    } else {
                        StatusCode::BAD_REQUEST
                    };
                    // An echo: what the client sends comes back as it arrives.
                    let mut response = Response::new(request.into_body());
                    *response.status_mut() = status;
                    Ok::<_, std::io::Error>(response)
                })
                .await
            });

            let (client, connection) = h2::client::handshake(client_io).await.unwrap();
            zincio::spawn(async move {
                let _ = connection.await;
            });
            let mut client = client.ready().await.unwrap();
            // The server's SETTINGS (with ENABLE_CONNECT_PROTOCOL) arrive after the
            // handshake future resolves.
            for _ in 0..100 {
                if client.is_extended_connect_protocol_enabled() {
                    break;
                }
                zincio::time::sleep(Duration::from_millis(10)).await;
            }
            assert!(client.is_extended_connect_protocol_enabled());

            let mut request = Request::builder()
                .method(Method::CONNECT)
                .uri("https://example.com/chat?room=1")
                .body(())
                .unwrap();
            request
                .extensions_mut()
                .insert(h2::ext::Protocol::from_static("websocket"));
            let (response, mut up) = client.send_request(request, false).unwrap();
            let response = zincio::time::timeout(Duration::from_secs(5), response)
                .await
                .expect("the response head comes before any tunnel data")
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let mut down = response.into_body();

            // Interactive: each message comes back before the next is sent, with the
            // stream still open both ways.
            for message in [&b"ping"[..], b"pong", b"bye"] {
                up.send_data(Bytes::copy_from_slice(message), false)
                    .unwrap();
                let mut echoed = Vec::new();
                while echoed.len() < message.len() {
                    let chunk = zincio::time::timeout(Duration::from_secs(5), down.data())
                        .await
                        .expect("the echo arrives")
                        .expect("the stream is open")
                        .unwrap();
                    let _ = down.flow_control().release_capacity(chunk.len());
                    echoed.extend_from_slice(&chunk);
                }
                assert_eq!(echoed, message);
            }
            // The client ends its side: so does the echo.
            up.send_data(Bytes::new(), true).unwrap();
            // (The empty frame that carried the end may come back as one.)
            loop {
                match zincio::time::timeout(Duration::from_secs(5), down.data())
                    .await
                    .expect("the stream ends")
                {
                    None => break,
                    Some(chunk) => assert!(chunk.unwrap().is_empty(), "nothing after the end"),
                }
            }
            drop((client, server));
        });
}
