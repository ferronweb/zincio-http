#![cfg(feature = "h1")]
#![allow(clippy::unwrap_used)]

use std::{future::Future, io, time::Duration};

use bytes::Bytes;
use futures_util::StreamExt;
use http_body::Body;
use http_body_util::{BodyExt, Empty, Full};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use zincio_http::{prepare_upgrade, send_early_hints, Http1, Http1Options, HttpProtocol, Incoming};

type ServerTask = tokio::task::JoinHandle<io::Result<()>>;

async fn on_local<F: Future>(future: F) -> F::Output {
    tokio::task::LocalSet::new().run_until(future).await
}

async fn start_with<F, Fut, B, E>(
    capacity: usize,
    options: Http1Options,
    handler: F,
) -> (tokio::io::DuplexStream, ServerTask)
where
    F: Fn(http::Request<Incoming>) -> Fut + 'static,
    Fut: Future<Output = Result<http::Response<B>, E>> + 'static,
    B: Body<Data = Bytes> + Unpin + 'static,
    B::Error: std::error::Error + 'static,
    E: std::error::Error + 'static,
{
    let (client_io, server_io) = tokio::io::duplex(capacity);
    let task = tokio::task::spawn_local(Http1::new(server_io, options).handle(handler));
    (client_io, task)
}

async fn start<F, Fut, B, E>(
    options: Http1Options,
    handler: F,
) -> (tokio::io::DuplexStream, ServerTask)
where
    F: Fn(http::Request<Incoming>) -> Fut + 'static,
    Fut: Future<Output = Result<http::Response<B>, E>> + 'static,
    B: Body<Data = Bytes> + Unpin + 'static,
    B::Error: std::error::Error + 'static,
    E: std::error::Error + 'static,
{
    start_with(4096, options, handler).await
}

async fn round_trip_with<F, Fut, B, E>(
    capacity: usize,
    options: Http1Options,
    handler: F,
    request: &[u8],
) -> (Vec<u8>, io::Result<()>)
where
    F: Fn(http::Request<Incoming>) -> Fut + 'static,
    Fut: Future<Output = Result<http::Response<B>, E>> + 'static,
    B: Body<Data = Bytes> + Unpin + 'static,
    B::Error: std::error::Error + 'static,
    E: std::error::Error + 'static,
{
    let (client_io, server_task) = start_with(capacity, options, handler).await;
    let (mut reader, mut writer) = tokio::io::split(client_io);
    writer.write_all(request).await.unwrap();
    writer.shutdown().await.unwrap();

    let mut response = Vec::new();
    reader.read_to_end(&mut response).await.unwrap();
    (response, server_task.await.unwrap())
}

async fn round_trip<F, Fut, B, E>(handler: F, request: &[u8]) -> (Vec<u8>, io::Result<()>)
where
    F: Fn(http::Request<Incoming>) -> Fut + 'static,
    Fut: Future<Output = Result<http::Response<B>, E>> + 'static,
    B: Body<Data = Bytes> + Unpin + 'static,
    B::Error: std::error::Error + 'static,
    E: std::error::Error + 'static,
{
    round_trip_with(
        4096,
        Http1Options::new().header_read_timeout(None),
        handler,
        request,
    )
    .await
}

#[tokio::test]
async fn test_get_request() {
    on_local(async {
        let (response, result) = round_trip(
            |_req| async {
                Ok::<_, http::Error>(
                    http::Response::builder()
                        .status(200)
                        .body(Full::new(Bytes::from_static(b"Hello, World!")))
                        .unwrap(),
                )
            },
            b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
        )
        .await;

        assert!(response.starts_with(b"HTTP/1.0 200 OK\r\n"));
        assert!(response.ends_with(b"\r\n\r\nHello, World!"));
        result.unwrap();
    })
    .await;
}

#[tokio::test]
async fn test_post_request() {
    on_local(async {
        let (response, result) = round_trip(
            |req| async {
                let body = req.into_body().collect().await.unwrap().to_bytes();
                Ok::<_, http::Error>(
                    http::Response::builder()
                        .status(200)
                        .body(Full::new(body))
                        .unwrap(),
                )
            },
            b"POST / HTTP/1.0\r\nHost: localhost\r\nContent-Length: 14\r\n\r\nHello, zincio!",
        )
        .await;

        assert!(response.starts_with(b"HTTP/1.0 200 OK\r\n"));
        assert!(response.ends_with(b"\r\n\r\nHello, zincio!"));
        result.unwrap();
    })
    .await;
}

#[tokio::test]
async fn test_keep_alive() {
    on_local(async {
        let (client_io, server_task) = start(
            Http1Options::new().header_read_timeout(None),
            |_req| async {
                Ok::<_, http::Error>(
                    http::Response::builder()
                        .status(200)
                        .body(Full::new(Bytes::from_static(b"Hello")))
                        .unwrap(),
                )
            },
        )
        .await;
        let (mut client_reader, mut client_writer) = tokio::io::split(client_io);

        client_writer
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut response_buf = vec![0; 1024];
        let n = client_reader.read(&mut response_buf).await.unwrap();
        response_buf.truncate(n);
        assert!(response_buf.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(response_buf.ends_with(b"\r\n\r\nHello"));

        client_writer
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response_buf = vec![0; 1024];
        let n = client_reader.read(&mut response_buf).await.unwrap();
        response_buf.truncate(n);
        assert!(response_buf.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(response_buf.ends_with(b"\r\n\r\nHello"));

        client_writer.shutdown().await.unwrap();
        server_task.await.unwrap().unwrap();
    })
    .await;
}

#[tokio::test]
async fn test_connection_close() {
    on_local(async {
        let (client_io, server_task) = start(
            Http1Options::new().header_read_timeout(None),
            |_req| async {
                Ok::<_, http::Error>(
                    http::Response::builder()
                        .status(200)
                        .body(Empty::<Bytes>::new())
                        .unwrap(),
                )
            },
        )
        .await;
        let (mut client_reader, mut client_writer) = tokio::io::split(client_io);

        client_writer
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();

        let mut response_buf = Vec::new();
        client_reader.read_to_end(&mut response_buf).await.unwrap();
        assert!(response_buf.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(response_buf
            .windows(19)
            .any(|w| w == b"connection: close\r\n"));

        let n = client_reader.read(&mut response_buf).await.unwrap();
        assert_eq!(n, 0);

        server_task.await.unwrap().unwrap();
    })
    .await;
}

#[tokio::test]
async fn test_fragmented() {
    on_local(async {
        let (client_io, server_task) = start_with(
            16,
            Http1Options::new().header_read_timeout(None),
            |_req| async {
                Ok::<_, http::Error>(
                    http::Response::builder()
                        .status(200)
                        .body(Full::new(Bytes::from_static(b"Hello, World!")))
                        .unwrap(),
                )
            },
        )
        .await;
        let (mut client_reader, mut client_writer) = tokio::io::split(client_io);

        tokio::task::spawn_local(async move {
            client_writer
                .write_all(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                .await
                .unwrap();
        });

        let mut response_buf = Vec::new();
        client_reader.read_to_end(&mut response_buf).await.unwrap();
        assert!(response_buf.starts_with(b"HTTP/1.0 200 OK\r\n"));
        assert!(response_buf.ends_with(b"\r\n\r\nHello, World!"));

        server_task.await.unwrap().unwrap();
    })
    .await;
}

#[tokio::test]
async fn test_fragmented_non_vectored() {
    on_local(async {
        let (client_io, server_task) = start_with(
            16,
            Http1Options::new()
                .header_read_timeout(None)
                .enable_vectored_write(false),
            |_req| async {
                Ok::<_, http::Error>(
                    http::Response::builder()
                        .status(200)
                        .body(Full::new(Bytes::from_static(b"Hello, World!")))
                        .unwrap(),
                )
            },
        )
        .await;
        let (mut client_reader, mut client_writer) = tokio::io::split(client_io);

        tokio::task::spawn_local(async move {
            client_writer
                .write_all(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                .await
                .unwrap();
        });

        let mut response_buf = Vec::new();
        client_reader.read_to_end(&mut response_buf).await.unwrap();
        assert!(response_buf.starts_with(b"HTTP/1.0 200 OK\r\n"));
        assert!(response_buf.ends_with(b"\r\n\r\nHello, World!"));

        server_task.await.unwrap().unwrap();
    })
    .await;
}

#[tokio::test]
async fn test_chunked_response() {
    on_local(async {
        let (response, result) = round_trip(
            |_req| async {
                Ok::<_, http::Error>(
                    http::Response::builder()
                        .status(200)
                        .header(http::header::TRANSFER_ENCODING, "chunked")
                        .body(Full::new(Bytes::from_static(b"Hello, World!")))
                        .unwrap(),
                )
            },
            b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
        )
        .await;

        assert!(response.starts_with(b"HTTP/1.0 200 OK\r\n"));
        assert!(response.ends_with(b"\r\n\r\nD\r\nHello, World!\r\n0\r\n\r\n"));
        result.unwrap();
    })
    .await;
}

#[tokio::test]
async fn test_chunked_response_trailers() {
    on_local(async {
        let (response, result) = round_trip(
            |_req| async {
                let mut trailers = http::HeaderMap::new();
                trailers.insert(http::header::CONTENT_TYPE, "text/plain".parse().unwrap());
                let data = futures_util::stream::once(async move {
                    Ok::<_, std::io::Error>(http_body::Frame::data(Bytes::from_static(
                        b"Hello, World!",
                    )))
                });
                let trailers =
                    futures_util::stream::once(
                        async move { Ok(http_body::Frame::trailers(trailers)) },
                    );
                let body = BodyExt::boxed(http_body_util::StreamBody::new(data.chain(trailers)));

                Ok::<_, http::Error>(
                    http::Response::builder()
                        .status(200)
                        .header(http::header::TRANSFER_ENCODING, "chunked")
                        .body(body)
                        .unwrap(),
                )
            },
            b"GET / HTTP/1.0\r\nHost: localhost\r\nTE: trailers\r\n\r\n",
        )
        .await;

        assert!(response.starts_with(b"HTTP/1.0 200 OK\r\n"));
        assert!(response
            .ends_with(b"\r\n\r\nD\r\nHello, World!\r\n0\r\ncontent-type: text/plain\r\n\r\n"));
        result.unwrap();
    })
    .await;
}

#[tokio::test]
async fn test_chunked_request() {
    on_local(async {
        let (response, result) = round_trip(
            |req| async {
                let body = req.into_body().collect().await.unwrap().to_bytes();
                assert_eq!(&*body, b"Hello, World!");
                Ok::<_, http::Error>(http::Response::new(Full::new(Bytes::from_static(b""))))
            },
            b"POST / HTTP/1.0\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\nD\r\nHello, World!\r\n0\r\n\r\n",
        )
        .await;

        assert!(response.starts_with(b"HTTP/1.0 200 OK\r\n"));
        result.unwrap();
    })
    .await;
}

#[tokio::test]
async fn test_chunked_request_trailers() {
    on_local(async {
        let (response, result) = round_trip(
            |req| async {
                let body = req.into_body().collect().await.unwrap();
                assert_eq!(
                    body.trailers()
                        .and_then(|t| t.get("X-Something"))
                        .map(|v| v.as_bytes()),
                    Some(&b"value"[..])
                );
                assert_eq!(&*body.to_bytes(), b"Hello, World!");
                Ok::<_, http::Error>(http::Response::new(Full::new(Bytes::from_static(b""))))
            },
            b"POST / HTTP/1.0\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nTrailer: X-Something\r\n\r\nD\r\nHello, World!\r\n0\r\nX-Something: value\r\n\r\n",
        )
        .await;

        assert!(response.starts_with(b"HTTP/1.0 200 OK\r\n"));
        result.unwrap();
    })
    .await;
}

#[tokio::test]
async fn test_upgrade_request() {
    on_local(async {
        let (client_io, server_task) = start(
            Http1Options::new().header_read_timeout(None),
            |mut req| async move {
                let upgrade = prepare_upgrade(&mut req);
                tokio::task::spawn_local(async move {
                    let upgraded = upgrade.unwrap().await.unwrap();
                    let (mut reader, mut writer) = tokio::io::split(upgraded);
                    let _ = tokio::io::copy(&mut reader, &mut writer).await;
                });
                Ok::<_, http::Error>(
                    http::Response::builder()
                        .status(101)
                        .header("Upgrade", "echo")
                        .header("Connection", "upgrade")
                        .body(Empty::new())
                        .unwrap(),
                )
            },
        )
        .await;
        let (mut client_reader, mut client_writer) = tokio::io::split(client_io);

        client_writer
            .write_all(
                b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: upgrade\r\nUpgrade: echo\r\n\r\nHello, World!",
            )
            .await
            .unwrap();
        client_writer.shutdown().await.unwrap();

        let mut response_buf = Vec::new();
        client_reader.read_to_end(&mut response_buf).await.unwrap();
        assert!(response_buf.starts_with(b"HTTP/1.1 101 Switching Protocols\r\n"));
        assert!(response_buf.ends_with(b"Hello, World!"));

        server_task.await.unwrap().unwrap();
    })
    .await;
}

#[tokio::test]
async fn test_invalid_request_line() {
    on_local(async {
        let (response, result) = round_trip(
            |_req| async {
                Ok::<_, http::Error>(
                    http::Response::builder()
                        .status(200)
                        .body(Full::new(Bytes::from_static(b"Hello")))
                        .unwrap(),
                )
            },
            b"GET / HTTP?/1.1\r\nHost: localhost\r\n\r\n",
        )
        .await;

        assert!(response.starts_with(b"HTTP/1.1 400 Bad Request\r\n"));
        assert!(result.is_err());
    })
    .await;
}

#[tokio::test]
async fn test_invalid_headers() {
    on_local(async {
        let (response, result) = round_trip(
            |_req| async {
                Ok::<_, http::Error>(
                    http::Response::builder()
                        .status(200)
                        .body(Full::new(Bytes::from_static(b"Hello")))
                        .unwrap(),
                )
            },
            b"GET / HTTP/1.1\r\nHost: localhost\r\nHeader without colon\r\n\r\n",
        )
        .await;

        assert!(response.starts_with(b"HTTP/1.1 400 Bad Request\r\n"));
        assert!(result.is_err());
    })
    .await;
}

#[tokio::test]
async fn test_header_size_limit_exceeded() {
    on_local(async {
        let (client_io, server_task) =
            start(Http1Options::new().header_read_timeout(None), |req| async {
                let _ = req.into_body().collect().await;
                Ok::<_, http::Error>(
                    http::Response::builder()
                        .status(200)
                        .body(Full::new(Bytes::from_static(b"Hello")))
                        .unwrap(),
                )
            })
            .await;
        let (mut client_reader, mut client_writer) = tokio::io::split(client_io);

        let request = format!(
            "GET / HTTP/1.1\r\nHost: localhost\r\nHeader: {}\r\n\r\n",
            "x".repeat(1024 * 1024)
        );
        let _ = client_writer.write_all(request.as_bytes()).await;

        let mut response_buf = Vec::new();
        client_reader.read_to_end(&mut response_buf).await.unwrap();
        // RFC 6585 5: a head over the limit is 431, as one with too many fields.
        assert!(
            response_buf.starts_with(b"HTTP/1.1 431 Request Header Fields Too Large\r\n"),
            "{}",
            String::from_utf8_lossy(&response_buf)
        );
        assert!(server_task.await.unwrap().is_err());
    })
    .await;
}

#[tokio::test]
async fn test_http_pipelining() {
    on_local(async {
        let (client_io, server_task) =
            start(Http1Options::new().header_read_timeout(None), |req| async {
                let path = req.uri().path().to_owned();
                let _ = req.into_body().collect().await;
                Ok::<_, http::Error>(
                    http::Response::builder()
                        .status(200)
                        .body(Full::new(Bytes::from(path.into_bytes())))
                        .unwrap(),
                )
            })
            .await;
        let (mut client_reader, mut client_writer) = tokio::io::split(client_io);

        let requests = concat!(
            "GET /first HTTP/1.1\r\nHost: localhost\r\n\r\n",
            "GET /second HTTP/1.1\r\nHost: localhost\r\n\r\n",
        );
        client_writer.write_all(requests.as_bytes()).await.unwrap();
        client_writer.shutdown().await.unwrap();

        let mut response_buf = Vec::new();
        client_reader.read_to_end(&mut response_buf).await.unwrap();

        // One response per request, in request order.
        let status_line = b"HTTP/1.1 200 OK";
        let statuses = response_buf
            .windows(status_line.len())
            .filter(|w| *w == status_line)
            .count();
        assert_eq!(
            statuses, 2,
            "expected one response per pipelined request, got {statuses}: {response_buf:?}"
        );

        let first = response_buf
            .windows(b"/first".len())
            .position(|w| w == b"/first")
            .expect("first response body missing");
        let second = response_buf
            .windows(b"/second".len())
            .position(|w| w == b"/second")
            .expect("second response body missing");
        assert!(
            first < second,
            "pipelined responses out of FIFO order: {response_buf:?}"
        );

        server_task.await.unwrap().unwrap();
    })
    .await;
}

#[tokio::test]
async fn test_http_pipelining_refused() {
    on_local(async {
        let (response, result) = round_trip_with(
            4096,
            Http1Options::new()
                .header_read_timeout(None)
                .allow_pipelining(false),
            |req| async move {
                let path = req.uri().path().to_owned();
                let _ = req.into_body().collect().await;
                Ok::<_, http::Error>(
                    http::Response::builder()
                        .status(200)
                        .body(Full::new(Bytes::from(path.into_bytes())))
                        .unwrap(),
                )
            },
            concat!(
                "GET /first HTTP/1.1\r\nHost: localhost\r\n\r\n",
                "GET /second HTTP/1.1\r\nHost: localhost\r\n\r\n",
            )
            .as_bytes(),
        )
        .await;

        // Only the first request is answered, and the connection closed.
        let text = String::from_utf8_lossy(&response);
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "{text:?}");
        assert!(
            text.to_ascii_lowercase().contains("connection: close\r\n"),
            "{text:?}"
        );
        assert!(text.ends_with("/first"), "{text:?}");
        assert!(!text.contains("/second"), "{text:?}");
        assert!(result.is_err());
    })
    .await;
}

#[tokio::test]
async fn test_http_pipelining_refused_ignores_trailing_whitespace() {
    on_local(async {
        // Some clients send a CRLF after a request body; it is not a request.
        let (response, result) = round_trip_with(
            4096,
            Http1Options::new()
                .header_read_timeout(None)
                .allow_pipelining(false),
            |req| async {
                let _ = req.into_body().collect().await;
                Ok::<_, http::Error>(http::Response::new(Full::new(Bytes::new())))
            },
            b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\n\r\nhi\r\n",
        )
        .await;

        let text = String::from_utf8_lossy(&response);
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "{text:?}");
        assert!(
            !text.to_ascii_lowercase().contains("connection: close"),
            "{text:?}"
        );
        result.unwrap();
    })
    .await;
}

#[tokio::test]
async fn test_early_hints_before_final_response() {
    on_local(async {
        let (response, result) = round_trip_with(
            4096,
            Http1Options::new()
                .header_read_timeout(None)
                .enable_early_hints(true),
            |mut req| async {
                let mut hints = http::HeaderMap::new();
                hints.insert(
                    http::header::LINK,
                    http::header::HeaderValue::from_static(
                        "<https://cdn.example.com/style.css>; rel=preload; as=style, \
                         <https://api.example.com/next>; rel=next",
                    ),
                );
                let _ = send_early_hints(&mut req, hints).await;
                let _ = req.into_body().collect().await;
                Ok::<_, http::Error>(
                    http::Response::builder()
                        .status(200)
                        .body(Full::new(Bytes::from_static(b"Hello")))
                        .unwrap(),
                )
            },
            b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )
        .await;

        assert!(response.starts_with(b"HTTP/1.1 103 Early Hints\r\n"));
        assert!(response
            .windows(21)
            .any(|w| w == b"\r\n\r\nHTTP/1.1 200 OK\r\n"));
        result.unwrap();
    })
    .await;
}

#[tokio::test]
async fn test_chunked_overrides_content_length() {
    on_local(async {
        let (response, result) = round_trip(
            |req| async {
                let body = req.into_body().collect().await.unwrap().to_bytes();
                assert_eq!(&*body, b"Hello, World!");
                Ok::<_, http::Error>(http::Response::new(Full::new(Bytes::new())))
            },
            b"POST / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\nD\r\nHello, World!\r\n0\r\n\r\n",
        )
        .await;

        assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
        result.unwrap();
    })
    .await;
}

#[tokio::test]
async fn test_chunked_encoding_very_large() {
    on_local(async {
        let (client_io, server_task) = start(
            Http1Options::new().header_read_timeout(None),
            |req| async {
                let _ = req.into_body().collect().await;
                Ok::<_, http::Error>(http::Response::new(Full::new(Bytes::new())))
            },
        )
        .await;
        let (_reader, mut writer) = tokio::io::split(client_io);

        writer
            .write_all(
                format!(
                    "POST / HTTP/1.0\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n{:X}\r\ntest",
                    usize::MAX
                )
                .as_bytes(),
            )
            .await
            .unwrap();

        assert!(server_task.await.unwrap().is_err());
    })
    .await;
}

#[test]
fn test_slowloris() {
    // The timer comes from the zincio runtime, not Tokio.
    zincio::RuntimeBuilder::new()
        .enable_timer(true)
        .build()
        .unwrap()
        .block_on(async move {
            let (client_io, server_io) = tokio::io::duplex(4096);
            let server_task = zincio::spawn(
                Http1::new(
                    server_io,
                    Http1Options::new().header_read_timeout(Some(Duration::from_millis(250))),
                )
                .handle(|req| async {
                    let _ = req.into_body().collect().await;
                    Ok::<_, http::Error>(
                        http::Response::builder()
                            .status(200)
                            .body(Full::new(Bytes::from_static(b"Hello")))
                            .unwrap(),
                    )
                }),
            );
            let (mut client_reader, mut client_writer) = tokio::io::split(client_io);

            let client_task = zincio::spawn(async move {
                let request = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
                for chunk in request.chunks(4) {
                    zincio::time::sleep(Duration::from_millis(50)).await;
                    if client_writer.write_all(chunk).await.is_err() {
                        break;
                    }
                }
            });

            let mut response_buf = Vec::new();
            client_reader.read_to_end(&mut response_buf).await.unwrap();
            assert!(response_buf.starts_with(b"HTTP/1.1 408 Request Timeout\r\n"));

            client_task.cancel();
            assert!(server_task.await.is_err());
        });
}

#[tokio::test]
async fn test_100_continue_response_triggered() {
    on_local(async {
        let (response, result) = round_trip(
            |_req| async {
                Ok::<_, http::Error>(http::Response::new(Full::new(Bytes::from_static(b"OK"))))
            },
            b"POST / HTTP/1.0\r\nHost: localhost\r\nContent-Length: 13\r\nExpect: 100-continue\r\n\r\nHello, World!",
        )
        .await;

        let response = String::from_utf8_lossy(&response);
        let (continue_pos, ok_pos) = (
            response.find("100 Continue").expect("100 Continue"),
            response.find("200 OK").expect("200 OK"),
        );
        assert!(continue_pos < ok_pos);
        result.unwrap();
    })
    .await;
}

#[tokio::test]
async fn test_100_continue_not_sent_on_error() {
    on_local(async {
        let (response, result) = round_trip(
            |_req| async {
                Ok::<_, http::Error>(
                    http::Response::builder()
                        .status(400)
                        .body(Empty::<Bytes>::new())
                        .unwrap(),
                )
            },
            b"POST / HTTP/1.0\r\nHost: localhost\r\nContent-Length: 13\r\nExpect: 100-continue\r\n\r\nHello, World!",
        )
        .await;

        let response = String::from_utf8_lossy(&response);
        assert!(response.contains("400 Bad Request"), "{response}");
        assert!(!response.contains("100 Continue"), "{response}");
        result.unwrap();
    })
    .await;
}

#[tokio::test]
async fn test_100_continue_disabled() {
    on_local(async {
        let (response, result) = round_trip_with(
            4096,
            Http1Options::new()
                .header_read_timeout(None)
                .send_continue_response(false),
            |req| async {
                let body = req.into_body().collect().await.unwrap().to_bytes();
                assert_eq!(&*body, b"Hello, World!");
                Ok::<_, http::Error>(http::Response::new(Full::new(Bytes::from_static(b"OK"))))
            },
            b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 13\r\nExpect: 100-continue\r\nConnection: close\r\n\r\nHello, World!",
        )
        .await;

        let response = String::from_utf8_lossy(&response);
        assert!(response.contains("200 OK"), "{response}");
        assert!(!response.contains("100 Continue"), "{response}");
        result.unwrap();
    })
    .await;
}

#[cfg(all(
    any(target_os = "linux", target_os = "freebsd"),
    feature = "h1-zerocopy"
))]
mod zerocopy {
    use std::cell::Cell;
    use std::io::{Seek, Write};
    use std::os::fd::BorrowedFd;
    use std::pin::Pin;
    use std::rc::Rc;
    use std::task::{Context, Poll};

    use bytes::Bytes;
    use http_body_util::Full;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};

    use zincio_http::{install_zerocopy_fd, Http1, Http1Options, HttpProtocol, ZerocopyWrite};

    use super::{on_local, round_trip_with};

    /// A stream that sends zero-copy bodies itself, by reading the descriptor, and
    /// counts what it sent that way.
    struct SelfSending {
        io: DuplexStream,
        sent: Rc<Cell<u64>>,
    }

    impl AsyncRead for SelfSending {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.io).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for SelfSending {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.io).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.io).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.io).poll_shutdown(cx)
        }
    }

    impl ZerocopyWrite for SelfSending {
        async fn send_zerocopy(&mut self, from: BorrowedFd<'_>, len: u64) -> std::io::Result<()> {
            let mut file = std::fs::File::from(from.try_clone_to_owned()?);
            let mut bytes = vec![0; usize::try_from(len).unwrap()];
            std::io::Read::read_exact(&mut file, &mut bytes)?;
            self.io.write_all(&bytes).await?;
            self.sent.set(self.sent.get() + len);
            Ok(())
        }
    }

    fn file_with(bytes: &[u8]) -> std::fs::File {
        let mut file = tempfile();
        file.write_all(bytes).unwrap();
        file.rewind().unwrap();
        file
    }

    fn tempfile() -> std::fs::File {
        let path = std::env::temp_dir().join(format!(
            "zincio-http-zerocopy-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        std::fs::remove_file(&path).unwrap();
        file
    }

    /// A response from a file the response owns, sent by the stream itself, then an
    /// ordinary response on the same connection.
    #[tokio::test]
    async fn the_stream_sends_an_owned_descriptor_then_the_connection_goes_on() {
        on_local(async {
            let (client_io, server_io) = tokio::io::duplex(1 << 16);
            let sent = Rc::new(Cell::new(0));
            let io = SelfSending {
                io: server_io,
                sent: Rc::clone(&sent),
            };
            let server = Http1::new(io, Http1Options::new().header_read_timeout(None))
                .zerocopy_by_io();
            let server_task = tokio::task::spawn_local(server.handle(|req| async move {
                let mut response = if req.uri().path() == "/file" {
                    http::Response::builder()
                        .header(http::header::CONTENT_LENGTH, "11")
                        .body(Full::new(Bytes::new()))
                        .unwrap()
                } else {
                    http::Response::builder()
                        .body(Full::new(Bytes::from_static(b"plain")))
                        .unwrap()
                };
                if req.uri().path() == "/file" {
                    install_zerocopy_fd(&mut response, file_with(b"from a file"));
                }
                Ok::<_, http::Error>(response)
            }));
            let (mut reader, mut writer) = tokio::io::split(client_io);
            writer
                .write_all(b"GET /file HTTP/1.1\r\nHost: a\r\n\r\nGET /plain HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            let mut response = Vec::new();
            reader.read_to_end(&mut response).await.unwrap();
            let text = String::from_utf8(response).unwrap();
            let first = text
                .find("\r\n\r\nfrom a file")
                .expect("the file's bytes follow its head");
            assert!(text[first..].contains("HTTP/1.1 200 OK"), "{text}");
            assert!(text.ends_with("\r\n\r\nplain"), "{text}");
            assert_eq!(sent.get(), 11, "the stream sent the file itself");
            server_task.await.unwrap().unwrap();
        })
        .await
    }

    /// zincio's emulated sendfile, on a real socket: the file's bytes after the head.
    #[test]
    fn sendfile_sends_an_owned_descriptor_on_a_socket() {
        let runtime = zincio::RuntimeBuilder::new()
            .enable_timer(true)
            .build()
            .unwrap();
        runtime.block_on(async {
            let listener = zincio::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let body: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
            let client_body = body.clone();
            let client = std::thread::spawn(move || {
                use std::io::{Read, Write};
                let mut socket = std::net::TcpStream::connect(addr).unwrap();
                socket
                    .write_all(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n")
                    .unwrap();
                let mut response = Vec::new();
                socket.read_to_end(&mut response).unwrap();
                let head_end = response.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
                assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
                assert!(
                    response[head_end..] == client_body[..],
                    "the file came whole"
                );
            });
            let (stream, _) = listener.accept().await.unwrap();
            let server = Http1::new(
                stream.into_poll().unwrap(),
                Http1Options::new().header_read_timeout(None),
            )
            .zerocopy();
            let length = body.len().to_string();
            server
                .handle(move |_req| {
                    let file = file_with(&body);
                    let length = length.clone();
                    async move {
                        let mut response = http::Response::builder()
                            .header(http::header::CONTENT_LENGTH, length)
                            .body(Full::new(Bytes::new()))
                            .unwrap();
                        install_zerocopy_fd(&mut response, file);
                        Ok::<_, http::Error>(response)
                    }
                })
                .await
                .unwrap();
            client.join().unwrap();
        });
    }

    /// A plain `Http1` sends a hinted response's own body.
    #[tokio::test]
    async fn without_zerocopy_the_body_is_sent() {
        on_local(async {
            let (response, result) = round_trip_with(
                4096,
                Http1Options::new().header_read_timeout(None),
                |_req| async {
                    let mut response = http::Response::builder()
                        .body(Full::new(Bytes::from_static(b"from the body")))
                        .unwrap();
                    install_zerocopy_fd(&mut response, file_with(b"from a file!!"));
                    Ok::<_, http::Error>(response)
                },
                b"GET / HTTP/1.0\r\nHost: a\r\n\r\n",
            )
            .await;
            assert!(response.ends_with(b"\r\n\r\nfrom the body"));
            result.unwrap();
        })
        .await
    }
}

#[tokio::test]
async fn test_upgrade_downcast_gives_back_the_stream_and_what_was_read() {
    on_local(async {
        let (got_tx, got_rx) = tokio::sync::oneshot::channel();
        let got_tx = std::cell::Cell::new(Some(got_tx));
        let (client_io, server_task) = start(
            Http1Options::new().header_read_timeout(None),
            move |mut req| {
                let upgrade = prepare_upgrade(&mut req);
                let got_tx = got_tx.take();
                async move {
                    tokio::task::spawn_local(async move {
                        let upgraded = upgrade.unwrap().await.unwrap();
                        let upgraded = upgraded.downcast::<std::io::Cursor<Vec<u8>>>().unwrap_err();
                        let (mut io, read) = upgraded
                            .downcast::<tokio::io::DuplexStream>()
                            .ok()
                            .expect("the stream the connection was made with");
                        io.write_all(b"raw").await.unwrap();
                        let _ = got_tx.unwrap().send(read);
                    });
                    Ok::<_, http::Error>(
                        http::Response::builder()
                            .status(101)
                            .header("Upgrade", "echo")
                            .header("Connection", "upgrade")
                            .body(Empty::new())
                            .unwrap(),
                    )
                }
            },
        )
        .await;
        let (mut client_reader, mut client_writer) = tokio::io::split(client_io);

        client_writer
            .write_all(
                b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: upgrade\r\nUpgrade: echo\r\n\r\nearly",
            )
            .await
            .unwrap();
        let read = got_rx.await.unwrap();
        assert_eq!(read.as_deref(), Some(&b"early"[..]));

        let mut response = vec![0u8; 256];
        let mut n = 0;
        while !response[..n].ends_with(b"raw") {
            n += client_reader.read(&mut response[n..]).await.unwrap();
        }
        assert!(response.starts_with(b"HTTP/1.1 101 Switching Protocols\r\n"));
        server_task.await.unwrap().unwrap();
    })
    .await;
}
