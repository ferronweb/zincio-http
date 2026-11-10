//! A response body waiting on a zero window goes out once the client raises the window
//! with SETTINGS_INITIAL_WINDOW_SIZE, not only after a WINDOW_UPDATE (RFC 9113
//! Section 6.9.2; h2spec 6.9.2/1 when the response is ready before the SETTINGS).

#![cfg(feature = "h2")]

use std::future::Future;
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response};
use zincio_http::{Http2, Http2Options, HttpProtocol, Incoming};

#[test]
fn a_raised_initial_window_releases_a_waiting_body() {
    zincio::RuntimeBuilder::new()
        .enable_timer(true)
        .build()
        .unwrap()
        .block_on(async {
            let (client_io, server_io) = tokio::io::duplex(1 << 16);
            zincio::spawn(async move {
                Http2::new(server_io, Http2Options::default())
                    .handle(|_request: Request<Incoming>| async move {
                        Ok::<_, std::io::Error>(Response::new(http_body_util::Full::new(
                            Bytes::from_static(b"x"),
                        )))
                    })
                    .await
            });

            let (client, mut connection) = h2::client::Builder::new()
                .initial_window_size(0)
                .handshake::<_, Bytes>(client_io)
                .await
                .unwrap();
            let (raise_tx, raise_rx) = tokio::sync::oneshot::channel::<()>();
            zincio::spawn(async move {
                let mut raise_rx = raise_rx;
                let mut raised = false;
                std::future::poll_fn(|cx| {
                    if !raised && std::pin::Pin::new(&mut raise_rx).poll(cx).is_ready() {
                        raised = true;
                        connection.set_initial_window_size(1).unwrap();
                    }
                    std::pin::Pin::new(&mut connection).poll(cx)
                })
                .await
                .ok();
            });
            let mut client = client.ready().await.unwrap();
            let request = Request::get("https://example.com/").body(()).unwrap();
            let (response, _) = client.send_request(request, true).unwrap();
            let response = zincio::time::timeout(Duration::from_secs(5), response)
                .await
                .expect("the head needs no window")
                .unwrap();
            // The body is queued on the zero window by now.
            zincio::time::sleep(Duration::from_millis(100)).await;
            raise_tx.send(()).unwrap();
            let mut body = response.into_body();
            let data = zincio::time::timeout(Duration::from_secs(5), body.data())
                .await
                .expect("the body goes out once the window is raised")
                .expect("a body")
                .unwrap();
            assert_eq!(data, "x");
        });
}
