//! A handler that fails gives its HTTP/2 stream no response: the stream is reset, so
//! the client hears of it and the connection does not keep the stream forever.

#![cfg(feature = "h2")]

use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response};
use zincio_http::{Http2, Http2Options, HttpProtocol, Incoming};

#[test]
fn a_failed_handler_resets_its_stream_and_shutdown_completes() {
    zincio::RuntimeBuilder::new()
        .enable_timer(true)
        .build()
        .unwrap()
        .block_on(async {
            let (client_io, server_io) = tokio::io::duplex(1 << 16);
            let shutdown = tokio_util::sync::CancellationToken::new();
            let server = zincio::spawn({
                let shutdown = shutdown.clone();
                async move {
                    Http2::new(server_io, Http2Options::default())
                        .graceful_shutdown_token(shutdown)
                        .handle(|request: Request<Incoming>| async move {
                            if request.uri().path() == "/fail" {
                                return Err(std::io::Error::other("no answer"));
                            }
                            Ok(Response::new(http_body_util::Full::new(
                                Bytes::from_static(b"ok"),
                            )))
                        })
                        .await
                }
            });

            let (client, connection) = h2::client::handshake(client_io).await.unwrap();
            zincio::spawn(async move {
                let _ = connection.await;
            });
            let mut client = client.ready().await.unwrap();
            let get = |path: &str| {
                Request::get(format!("https://example.com{path}"))
                    .body(())
                    .unwrap()
            };

            let (failed, _) = client.send_request(get("/fail"), true).unwrap();
            let failed = zincio::time::timeout(Duration::from_secs(5), failed)
                .await
                .expect("the client hears of the failed stream");
            let reason = failed.expect_err("no response").reason();
            assert_eq!(reason, Some(h2::Reason::INTERNAL_ERROR));

            // The connection serves on.
            let mut client = client.ready().await.unwrap();
            let (ok, _) = client.send_request(get("/ok"), true).unwrap();
            let ok = zincio::time::timeout(Duration::from_secs(5), ok)
                .await
                .expect("the next request is answered")
                .unwrap();
            assert_eq!(ok.status(), 200);
            let mut body = ok.into_body();
            while body.data().await.is_some() {}

            // No stream is left over, so a graceful shutdown ends.
            shutdown.cancel();
            zincio::time::timeout(Duration::from_secs(5), server)
                .await
                .expect("the connection closes after its GOAWAY")
                .expect("the connection ended cleanly");
        });
}
