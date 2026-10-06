#![cfg(feature = "h1")]

use std::time::Duration;

use bytes::Bytes;
use futures_util::StreamExt;
use http_body_util::{BodyExt, Empty, Full};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use zincio_http::{prepare_upgrade, send_early_hints, Http1, Http1Options, HttpProtocol};

#[tokio::test]
async fn test_get_request() {
    tokio::task::LocalSet::new()
        .run_until(async move {
            let (client_io, server_io) = tokio::io::duplex(4096);

            let server = Http1::new(server_io, Http1Options::new().header_read_timeout(None));
            let server_task = tokio::task::spawn_local(server.handle(|_req| async {
                Ok::<_, http::Error>(
                    http::Response::builder()
                        .status(200)
                        .body(Full::new(bytes::Bytes::from_static(b"Hello, World!")))
                        .unwrap(),
                )
            }));

            let (mut client_reader, mut client_writer) = tokio::io::split(client_io);

            client_writer
                .write_all(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                .await
                .unwrap();

            // Read the response
            let mut response_buf = Vec::new();
            client_reader.read_to_end(&mut response_buf).await.unwrap();

            // Assert the response
            assert!(response_buf.starts_with(b"HTTP/1.0 200 OK\r\n"));
            assert!(response_buf.ends_with(b"\r\n\r\nHello, World!"));

            server_task.await.unwrap().unwrap();
        })
        .await
}

#[tokio::test]
async fn test_post_request() {
    tokio::task::LocalSet::new()
        .run_until(async move {
            let (client_io, server_io) = tokio::io::duplex(4096);

            let server = Http1::new(server_io, Http1Options::new().header_read_timeout(None));
            let server_task = tokio::task::spawn_local(server.handle(|req| async {
                let body = req.into_body().collect().await.unwrap().to_bytes();
                Ok::<_, http::Error>(
                    http::Response::builder()
                        .status(200)
                        .body(Full::new(body))
                        .unwrap(),
                )
            }));

            let (mut client_reader, mut client_writer) = tokio::io::split(client_io);

            client_writer
        .write_all(
            b"POST / HTTP/1.0\r\nHost: localhost\r\nContent-Length: 14\r\n\r\nHello, zincio!",
        )
        .await
        .unwrap();

            // Read the response
            let mut response_buf = Vec::new();
            client_reader.read_to_end(&mut response_buf).await.unwrap();

            // Assert the response
            assert!(response_buf.starts_with(b"HTTP/1.0 200 OK\r\n"));
            assert!(response_buf.ends_with(b"\r\n\r\nHello, zincio!"));

            server_task.await.unwrap().unwrap();
        })
        .await
}

#[tokio::test]
async fn test_keep_alive() {
    tokio::task::LocalSet::new()
        .run_until(async move {
            let (client_io, server_io) = tokio::io::duplex(4096);

            let server = Http1::new(server_io, Http1Options::new().header_read_timeout(None));
            let server_task = tokio::task::spawn_local(server.handle(|_req| async {
                Ok::<_, http::Error>(
                    http::Response::builder()
                        .status(200)
                        .body(Full::new(bytes::Bytes::from_static(b"Hello")))
                        .unwrap(),
                )
            }));

            let (mut client_reader, mut client_writer) = tokio::io::split(client_io);

            client_writer
                .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .await
                .unwrap();

            // Read first response
            let mut response_buf = vec![0; 1024];
            let n = client_reader.read(&mut response_buf).await.unwrap();
            response_buf.truncate(n);
            assert!(response_buf.starts_with(b"HTTP/1.1 200 OK\r\n"));
            assert!(response_buf.ends_with(b"\r\n\r\nHello"));

            let _ = client_writer
                .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .await;

            // Read second response
            let mut response_buf = vec![0; 1024];
            let n = client_reader.read(&mut response_buf).await.unwrap();
            response_buf.truncate(n);
            assert!(response_buf.starts_with(b"HTTP/1.1 200 OK\r\n"));
            assert!(response_buf.ends_with(b"\r\n\r\nHello"));

            // Close the client writer to signal the end of the connection
            client_writer.shutdown().await.unwrap();

            server_task.await.unwrap().unwrap();
        })
        .await
}

#[tokio::test]
async fn test_connection_close() {
    tokio::task::LocalSet::new()
        .run_until(async move {
            let (client_io, server_io) = tokio::io::duplex(4096);

            let server = Http1::new(server_io, Http1Options::new().header_read_timeout(None));
            let server_task = tokio::task::spawn_local(server.handle(|_req| async {
                Ok::<_, http::Error>(
                    http::Response::builder()
                        .status(200)
                        .body(Empty::<bytes::Bytes>::new())
                        .unwrap(),
                )
            }));

            let (mut client_reader, mut client_writer) = tokio::io::split(client_io);

            client_writer
                .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();

            // Read the response
            let mut response_buf = Vec::new();
            client_reader.read_to_end(&mut response_buf).await.unwrap();

            // Assert the response
            assert!(response_buf.starts_with(b"HTTP/1.1 200 OK\r\n"));
            assert!(response_buf
                .windows(19)
                .any(|w| w == b"connection: close\r\n"));

            // The connection should be closed by the server. A read should return 0 bytes.
            let n = client_reader.read(&mut response_buf).await.unwrap();
            assert_eq!(n, 0);

            server_task.await.unwrap().unwrap();
        })
        .await
}

#[tokio::test]
async fn test_fragmented() {
    tokio::task::LocalSet::new()
        .run_until(async move {
            let (client_io, server_io) = tokio::io::duplex(16);

            let server = Http1::new(server_io, Http1Options::new().header_read_timeout(None));
            let server_task = tokio::task::spawn_local(server.handle(|_req| async {
                Ok::<_, http::Error>(
                    http::Response::builder()
                        .status(200)
                        .body(Full::new(bytes::Bytes::from_static(b"Hello, World!")))
                        .unwrap(),
                )
            }));

            let (mut client_reader, mut client_writer) = tokio::io::split(client_io);

            tokio::task::spawn_local(async move {
                client_writer
                    .write_all(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                    .await
                    .unwrap();
            });

            // Read the response
            let mut response_buf = Vec::new();
            client_reader.read_to_end(&mut response_buf).await.unwrap();

            println!(
                "response: {:?}",
                std::str::from_utf8(&response_buf).unwrap()
            );
            // Assert the response
            assert!(response_buf.starts_with(b"HTTP/1.0 200 OK\r\n"));
            assert!(response_buf.ends_with(b"\r\n\r\nHello, World!"));

            server_task.await.unwrap().unwrap();
        })
        .await
}

#[tokio::test]
async fn test_fragmented_non_vectored() {
    tokio::task::LocalSet::new()
        .run_until(async move {
            let (client_io, server_io) = tokio::io::duplex(16);

            let server = Http1::new(
                server_io,
                Http1Options::new()
                    .header_read_timeout(None)
                    .enable_vectored_write(false),
            );
            let server_task = tokio::task::spawn_local(server.handle(|_req| async {
                Ok::<_, http::Error>(
                    http::Response::builder()
                        .status(200)
                        .body(Full::new(bytes::Bytes::from_static(b"Hello, World!")))
                        .unwrap(),
                )
            }));

            let (mut client_reader, mut client_writer) = tokio::io::split(client_io);

            tokio::task::spawn_local(async move {
                client_writer
                    .write_all(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                    .await
                    .unwrap();
            });

            // Read the response
            let mut response_buf = Vec::new();
            client_reader.read_to_end(&mut response_buf).await.unwrap();

            println!(
                "response: {:?}",
                std::str::from_utf8(&response_buf).unwrap()
            );
            // Assert the response
            assert!(response_buf.starts_with(b"HTTP/1.0 200 OK\r\n"));
            assert!(response_buf.ends_with(b"\r\n\r\nHello, World!"));

            server_task.await.unwrap().unwrap();
        })
        .await
}

#[tokio::test]
async fn test_chunked_response() {
    tokio::task::LocalSet::new()
        .run_until(async move {
            let (client_io, server_io) = tokio::io::duplex(4096);

            let server = Http1::new(server_io, Http1Options::new().header_read_timeout(None));
            let server_task = tokio::task::spawn_local(server.handle(|_req| async {
                Ok::<_, http::Error>(
                    http::Response::builder()
                        .status(200)
                        .header(http::header::TRANSFER_ENCODING, "chunked")
                        .body(Full::new(bytes::Bytes::from_static(b"Hello, World!")))
                        .unwrap(),
                )
            }));

            let (mut client_reader, mut client_writer) = tokio::io::split(client_io);

            client_writer
                .write_all(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                .await
                .unwrap();

            // Read the response
            let mut response_buf = Vec::new();
            client_reader.read_to_end(&mut response_buf).await.unwrap();

            // Assert the response
            assert!(response_buf.starts_with(b"HTTP/1.0 200 OK\r\n"));
            assert!(response_buf.ends_with(b"\r\n\r\nD\r\nHello, World!\r\n0\r\n\r\n"));

            server_task.await.unwrap().unwrap();
        })
        .await
}

#[tokio::test]
async fn test_chunked_response_trailers() {
    tokio::task::LocalSet::new()
        .run_until(async move {
            let (client_io, server_io) = tokio::io::duplex(4096);

            let server = Http1::new(server_io, Http1Options::new().header_read_timeout(None));
            let server_task = tokio::task::spawn_local(server.handle(|_req| async {
                // Construct ody with trailers
                let mut trailers = http::HeaderMap::new();
                trailers.insert(http::header::CONTENT_TYPE, "text/plain".parse().unwrap());
                let data_stream = futures_util::stream::once(async move {
                    Ok::<_, std::io::Error>(http_body::Frame::data(Bytes::from_static(
                        b"Hello, World!",
                    )))
                });
                let trailer_stream =
                    futures_util::stream::once(
                        async move { Ok(http_body::Frame::trailers(trailers)) },
                    );
                let stream = data_stream.chain(trailer_stream);
                let body = http_body_util::BodyExt::boxed(http_body_util::StreamBody::new(stream));

                Ok::<_, http::Error>(
                    http::Response::builder()
                        .status(200)
                        .header(http::header::TRANSFER_ENCODING, "chunked")
                        .body(body)
                        .unwrap(),
                )
            }));
            let (mut client_reader, mut client_writer) = tokio::io::split(client_io);

            client_writer
                .write_all(b"GET / HTTP/1.0\r\nHost: localhost\r\nTE: trailers\r\n\r\n")
                .await
                .unwrap();

            // Read the response
            let mut response_buf = Vec::new();
            client_reader.read_to_end(&mut response_buf).await.unwrap();

            // Assert the response
            assert!(response_buf.starts_with(b"HTTP/1.0 200 OK\r\n"));
            assert!(response_buf
                .ends_with(b"\r\n\r\nD\r\nHello, World!\r\n0\r\ncontent-type: text/plain\r\n\r\n"));

            server_task.await.unwrap().unwrap();
        })
        .await
}

#[tokio::test]
async fn test_chunked_request() {
    tokio::task::LocalSet::new()
        .run_until(async move {
            let (client_io, server_io) = tokio::io::duplex(4096);

    let server = Http1::new(server_io, Http1Options::new().header_read_timeout(None));
    let server_task = tokio::task::spawn_local(server.handle(|req| async {
        let body = req.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&*body, b"Hello, World!");
        Ok::<_, http::Error>(http::Response::new(Full::new(bytes::Bytes::from_static(
            b"",
        ))))
    }));

    let (mut client_reader, mut client_writer) = tokio::io::split(client_io);

    client_writer
        .write_all(b"POST / HTTP/1.0\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\nD\r\nHello, World!\r\n0\r\n\r\n")
        .await
        .unwrap();

    // Read the response
    let mut response_buf = Vec::new();
    client_reader.read_to_end(&mut response_buf).await.unwrap();

    // Assert the response
    assert!(response_buf.starts_with(b"HTTP/1.0 200 OK\r\n"));

    server_task.await.unwrap().unwrap();})
        .await
}

#[tokio::test]
async fn test_chunked_request_trailers() {
    tokio::task::LocalSet::new()
        .run_until(async move {
            let (client_io, server_io) = tokio::io::duplex(4096);

            let server = Http1::new(server_io, Http1Options::new().header_read_timeout(None));
            let server_task = tokio::task::spawn_local(server.handle(|req| async {
                let body = req.into_body().collect().await.unwrap();
                assert!(body.trailers().is_some());
                assert_eq!(
                    body.trailers()
                        .unwrap()
                        .get("X-Something")
                        .map(|v| v.as_bytes()),
                    Some(&b"value"[..])
                );
                assert_eq!(&*body.to_bytes(), b"Hello, World!");
                Ok::<_, http::Error>(http::Response::new(Full::new(bytes::Bytes::from_static(
                    b"",
                ))))
            }));

            let (mut client_reader, mut client_writer) = tokio::io::split(client_io);

            client_writer
                .write_all(
                    b"POST / HTTP/1.0\r\nHost: localhost\
                      \r\nTransfer-Encoding: chunked\r\nTrailer: X-Something\r\n\r\nD\r\nHello, World!\r\n0\
                      \r\nX-Something: value\r\n\r\n",
                )
                .await
                .unwrap();

            // Read the response
            let mut response_buf = Vec::new();
            client_reader.read_to_end(&mut response_buf).await.unwrap();

            // Assert the response
            assert!(response_buf.starts_with(b"HTTP/1.0 200 OK\r\n"));

            server_task.await.unwrap().unwrap();
        })
        .await
}

#[tokio::test]
async fn test_upgrade_request() {
    tokio::task::LocalSet::new()
        .run_until(async move {
            let (client_io, server_io) = tokio::io::duplex(4096);

    let server = Http1::new(server_io, Http1Options::new().header_read_timeout(None));
    let server_task = tokio::task::spawn_local(server.handle(|mut req| async move {
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
    }));

    let (mut client_reader, mut client_writer) = tokio::io::split(client_io);

    client_writer
        .write_all(
            b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: upgrade\r\nUpgrade: echo\r\n\r\nHello, World!",
        )
        .await
        .unwrap();
    let _ = client_writer.shutdown().await;

    // Read the response
    let mut response_buf = Vec::new();
    client_reader.read_to_end(&mut response_buf).await.unwrap();

    // Assert the response
    assert!(response_buf.starts_with(b"HTTP/1.1 101 Switching Protocols\r\n"));
    assert!(response_buf.ends_with(b"Hello, World!"));

    server_task.await.unwrap().unwrap();})
        .await
}

#[tokio::test]
async fn test_invalid_request_line() {
    tokio::task::LocalSet::new()
        .run_until(async move {
            let (client_io, server_io) = tokio::io::duplex(4096);

            let server = Http1::new(server_io, Http1Options::new().header_read_timeout(None));
            let server_task = tokio::task::spawn_local(server.handle(|_req| async {
                Ok::<_, http::Error>(
                    http::Response::builder()
                        .status(200)
                        .body(Full::new(bytes::Bytes::from_static(b"Hello")))
                        .unwrap(),
                )
            }));

            let (mut client_reader, mut client_writer) = tokio::io::split(client_io);

            client_writer
                .write_all(b"GET / HTTP?/1.1\r\nHost: localhost\r\n\r\n")
                .await
                .unwrap();

            // Read the response
            let mut response_buf = Vec::new();
            client_reader.read_to_end(&mut response_buf).await.unwrap();

            // Expect 400 Bad Request
            assert!(response_buf.starts_with(b"HTTP/1.1 400 Bad Request\r\n"));

            let _ = server_task.await;
        })
        .await
}

#[tokio::test]
async fn test_invalid_headers() {
    tokio::task::LocalSet::new()
        .run_until(async move {
            let (client_io, server_io) = tokio::io::duplex(4096);

            let server = Http1::new(server_io, Http1Options::new().header_read_timeout(None));
            let server_task = tokio::task::spawn_local(server.handle(|_req| async {
                Ok::<_, http::Error>(
                    http::Response::builder()
                        .status(200)
                        .body(Full::new(bytes::Bytes::from_static(b"Hello")))
                        .unwrap(),
                )
            }));

            let (mut client_reader, mut client_writer) = tokio::io::split(client_io);

            client_writer
                .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nHeader without colon\r\n\r\n")
                .await
                .unwrap();

            // Read the response
            let mut response_buf = Vec::new();
            client_reader.read_to_end(&mut response_buf).await.unwrap();

            // Expect 400 Bad Request
            assert!(response_buf.starts_with(b"HTTP/1.1 400 Bad Request\r\n"));

            let _ = server_task.await;
        })
        .await
}

#[tokio::test]
async fn test_header_size_limit_exceeded() {
    tokio::task::LocalSet::new()
        .run_until(async move {
            let (client_io, server_io) = tokio::io::duplex(4096);

            let server = Http1::new(server_io, Http1Options::new().header_read_timeout(None));
            let server_task = tokio::task::spawn_local(server.handle(|req| async {
                let _ = req.into_body().collect().await;
                Ok::<_, http::Error>(
                    http::Response::builder()
                        .status(200)
                        .body(Full::new(bytes::Bytes::from_static(b"Hello")))
                        .unwrap(),
                )
            }));

            let (mut client_reader, mut client_writer) = tokio::io::split(client_io);

            let large_header = "Header: ".to_string() + "x".repeat(1024 * 1024).as_str();
            let _ = client_writer
                .write_all(
                    format!(
                        "GET / HTTP/1.1\r\nHost: localhost\r\n{}\r\n\r\n",
                        large_header
                    )
                    .as_bytes(),
                )
                .await;

            // Read the response
            let mut response_buf = Vec::new();
            client_reader.read_to_end(&mut response_buf).await.unwrap();

            // Expect 400 Bad Request
            assert!(response_buf.starts_with(b"HTTP/1.1 400 Bad Request\r\n"));

            let _ = server_task.await;
        })
        .await;
}

#[tokio::test]
async fn test_http_pipelining() {
    tokio::task::LocalSet::new()
        .run_until(async move {
            let (client_io, server_io) = tokio::io::duplex(4096);

            let server = Http1::new(server_io, Http1Options::new().header_read_timeout(None));
            let server_task = tokio::task::spawn_local(server.handle(|req| async {
                // Echo the request path so the two pipelined responses are
                // distinguishable, which is what lets us assert FIFO order.
                let path = req.uri().path().to_owned();
                let _ = req.into_body().collect().await;
                Ok::<_, http::Error>(
                    http::Response::builder()
                        .status(200)
                        .body(Full::new(bytes::Bytes::from(path.into_bytes())))
                        .unwrap(),
                )
            }));

            let (mut client_reader, mut client_writer) = tokio::io::split(client_io);

            let requests = [
                "GET /first HTTP/1.1\r\nHost: localhost\r\n\r\n",
                "GET /second HTTP/1.1\r\nHost: localhost\r\n\r\n",
            ];
            let _ = client_writer.write_all(requests.join("").as_bytes()).await;
            let _ = client_writer.shutdown().await;

            // Read the responses
            let mut response_buf = Vec::new();
            client_reader.read_to_end(&mut response_buf).await.unwrap();

            // Pipelining requires one response per request, in request order.
            // Asserting only that the buffer *starts with* a 200 would still
            // pass if the second response were never sent at all.
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

            let _ = server_task.await;
        })
        .await;
}

#[tokio::test]
async fn test_early_hints_before_final_response() {
    tokio::task::LocalSet::new()
        .run_until(async move {
            let (client_io, server_io) = tokio::io::duplex(4096);

            let server = Http1::new(
                server_io,
                Http1Options::new()
                    .header_read_timeout(None)
                    .enable_early_hints(true),
            );
            let server_task = tokio::task::spawn_local(server.handle(|mut req| async {
                let mut early_hint_headers = http::HeaderMap::new();
                early_hint_headers.insert(
                    http::header::LINK,
                    http::header::HeaderValue::from_static(
                        "<https://cdn.example.com/style.css>; rel=preload; as=style, \
                        <https://api.example.com/next>; rel=next",
                    ),
                );
                let _ = send_early_hints(&mut req, early_hint_headers).await;
                let _ = req.into_body().collect().await;
                Ok::<_, http::Error>(
                    http::Response::builder()
                        .status(200)
                        .body(Full::new(bytes::Bytes::from_static(b"Hello")))
                        .unwrap(),
                )
            }));

            let (mut client_reader, mut client_writer) = tokio::io::split(client_io);

            let _ = client_writer
                .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .await;
            let _ = client_writer.shutdown().await;

            // Read the responses
            let mut response_buf = Vec::new();
            client_reader.read_to_end(&mut response_buf).await.unwrap();

            println!("response: {:?}", response_buf);
            // Expect 103 Early Hints followed by 200 OK for the final response
            assert!(response_buf.starts_with(b"HTTP/1.1 103 Early Hints\r\n"));
            assert!(response_buf
                .windows(21)
                .any(|w| w == b"\r\n\r\nHTTP/1.1 200 OK\r\n"));

            let _ = server_task.await;
        })
        .await;
}

#[tokio::test]
async fn test_chunked_overrides_content_length() {
    tokio::task::LocalSet::new()
        .run_until(async move {
            let (client_io, server_io) = tokio::io::duplex(4096);

            let server = Http1::new(server_io, Http1Options::new().header_read_timeout(None));
            let server_task = tokio::task::spawn_local(server.handle(|req| async {
                let body = req.into_body().collect().await.unwrap().to_bytes();
                assert_eq!(&*body, b"Hello, World!");
                Ok::<_, http::Error>(http::Response::new(Full::new(bytes::Bytes::from_static(
                    b"",
                ))))
            }));

            let (mut client_reader, mut client_writer) = tokio::io::split(client_io);

            client_writer
                .write_all(
                    b"POST / HTTP/1.1\r\nHost: localhost\r\nConnection: close\
                     \r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n\
                     D\r\nHello, World!\r\n0\r\n\r\n",
                )
                .await
                .unwrap();

            // Read the response
            let mut response_buf = Vec::new();
            client_reader.read_to_end(&mut response_buf).await.unwrap();

            // Assert the response
            assert!(response_buf.starts_with(b"HTTP/1.1 200 OK\r\n"));

            server_task.await.unwrap().unwrap();
        })
        .await
}

#[tokio::test]
async fn test_chunked_encoding_very_large() {
    tokio::task::LocalSet::new()
        .run_until(async move {
            let (client_io, server_io) = tokio::io::duplex(4096);

            let server = Http1::new(server_io, Http1Options::new().header_read_timeout(None));
            let server_task = tokio::task::spawn_local(server.handle(|req| async {
                let body = req.into_body().collect().await.unwrap().to_bytes();
                assert_eq!(&*body, b"Hello, World!");
                Ok::<_, http::Error>(http::Response::new(Full::new(bytes::Bytes::from_static(
                    b"",
                ))))
            }));

            let (_client_reader, mut client_writer) = tokio::io::split(client_io);

            client_writer
                .write_all(
                    format!(
                        "POST / HTTP/1.0\r\nHost: localhost\r\nTransfer-Encoding: chunked\
                        \r\n\r\n{:X}\r\ntest",
                        usize::MAX
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();

            server_task.await.unwrap().unwrap_err();
        })
        .await;
}

#[test]
fn test_slowloris() {
    // A "zincio" runtime has to be built, since this test depends on the timer,
    // which can't be used with Tokio
    zincio::RuntimeBuilder::new()
        .enable_timer(true)
        .build()
        .unwrap()
        .block_on(async move {
            let (client_io, server_io) = tokio::io::duplex(4096);

            let server = Http1::new(
                server_io,
                Http1Options::new().header_read_timeout(Some(Duration::from_millis(250))),
            );
            let server_task = zincio::spawn(server.handle(|req| async {
                let _ = req.into_body().collect().await;
                Ok::<_, http::Error>(
                    http::Response::builder()
                        .status(200)
                        .body(Full::new(bytes::Bytes::from_static(b"Hello")))
                        .unwrap(),
                )
            }));

            let (mut client_reader, mut client_writer) = tokio::io::split(client_io);

            let client_task = zincio::spawn(async move {
                // Simulate a slowloris attack by slowly writing the request
                let data = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
                for chunk in data.chunks(4) {
                    zincio::time::sleep(Duration::from_millis(50)).await;
                    if client_writer.write_all(chunk).await.is_err() {
                        break;
                    }
                }
            });

            // Read the response
            let mut response_buf = Vec::new();
            client_reader.read_to_end(&mut response_buf).await.unwrap();

            assert!(response_buf.starts_with(b"HTTP/1.1 408 Request Timeout\r\n"));

            client_task.cancel();
            let _ = server_task.await;
        });
}

#[tokio::test]
async fn test_100_continue_body_triggered() {
    tokio::task::LocalSet::new()
        .run_until(async move {
            let (client_io, server_io) = tokio::io::duplex(4096);

            let server = Http1::new(server_io, Http1Options::new().header_read_timeout(None));
            let server_task = tokio::task::spawn_local(server.handle(|req| async {
                let body = req.into_body().collect().await.unwrap().to_bytes();
                assert_eq!(&*body, b"Hello, World!");
                Ok::<_, http::Error>(http::Response::new(Full::new(bytes::Bytes::from_static(
                    b"OK",
                ))))
            }));

            let (mut client_reader, mut client_writer) = tokio::io::split(client_io);

            // Write a POST request with Expect: 100-continue and body inline
            client_writer
                .write_all(
                    b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 13\r\nExpect: 100-continue\r\nConnection: close\r\n\r\nHello, World!",
                )
                .await
                .unwrap();

            // Read all output from the server
            let mut response_buf = Vec::new();
            client_reader.read_to_end(&mut response_buf).await.unwrap();
            let response_str = String::from_utf8_lossy(&response_buf);

            // Should contain 100 Continue
            assert!(response_str.contains("100 Continue"), "Expected 100 Continue in response: {}", response_str);

            // Should contain 200 OK
            assert!(response_str.contains("200 OK"), "Expected 200 OK in response: {}", response_str);

            // 100 Continue should come before 200 OK
            let continue_pos = response_str.find("100 Continue").unwrap();
            let ok_pos = response_str.find("200 OK").unwrap();
            assert!(continue_pos < ok_pos, "100 Continue should come before 200 OK");

            server_task.await.unwrap().unwrap();
        })
        .await
}

#[tokio::test]
async fn test_100_continue_response_triggered() {
    tokio::task::LocalSet::new()
        .run_until(async move {
            let (client_io, server_io) = tokio::io::duplex(4096);

            let server = Http1::new(server_io, Http1Options::new().header_read_timeout(None));
            let server_task = tokio::task::spawn_local(server.handle(|_req| async {
                Ok::<_, http::Error>(http::Response::new(Full::new(bytes::Bytes::from_static(
                    b"OK",
                ))))
            }));

            let (mut client_reader, mut client_writer) = tokio::io::split(client_io);

            // Write a POST request with Expect: 100-continue, no body
            // Use Connection: close and shutdown writer to signal end of request
            client_writer
                .write_all(
                    b"POST / HTTP/1.0\r\nHost: localhost\r\nContent-Length: 13\r\nExpect: 100-continue\r\n\r\nHello, World!",
                )
                .await
                .unwrap();

            // Read all output from the server
            let mut response_buf = Vec::new();
            client_reader.read_to_end(&mut response_buf).await.unwrap();
            let response_str = String::from_utf8_lossy(&response_buf);

            // Should contain 100 Continue (response-triggered since handler returned 200)
            assert!(response_str.contains("100 Continue"), "Expected 100 Continue in response: {}", response_str);

            // Should contain 200 OK
            assert!(response_str.contains("200 OK"), "Expected 200 OK in response: {}", response_str);

            // 100 Continue should come before 200 OK
            let continue_pos = response_str.find("100 Continue").unwrap();
            let ok_pos = response_str.find("200 OK").unwrap();
            assert!(continue_pos < ok_pos, "100 Continue should come before 200 OK");

            server_task.await.unwrap().unwrap();
        })
        .await
}

#[tokio::test]
async fn test_100_continue_not_sent_on_error() {
    tokio::task::LocalSet::new()
        .run_until(async move {
            let (client_io, server_io) = tokio::io::duplex(4096);

            let server = Http1::new(server_io, Http1Options::new().header_read_timeout(None));
            let server_task = tokio::task::spawn_local(server.handle(|_req| async {
                Ok::<_, http::Error>(http::Response::builder()
                    .status(400)
                    .body(Empty::<bytes::Bytes>::new())
                    .unwrap())
            }));

            let (mut client_reader, mut client_writer) = tokio::io::split(client_io);

            // Write a POST request with Expect: 100-continue, send body so drain completes
            client_writer
                .write_all(
                    b"POST / HTTP/1.0\r\nHost: localhost\r\nContent-Length: 13\r\nExpect: 100-continue\r\n\r\nHello, World!",
                )
                .await
                .unwrap();

            // Read all output from the server
            let mut response_buf = Vec::new();
            client_reader.read_to_end(&mut response_buf).await.unwrap();
            let response_str = String::from_utf8_lossy(&response_buf);

            // Should contain 400 Bad Request, no 100 Continue
            assert!(response_str.contains("400 Bad Request"), "Expected 400 Bad Request: {}", response_str);
            assert!(!response_str.contains("100 Continue"), "Should NOT contain 100 Continue: {}", response_str);

            server_task.await.unwrap().unwrap();
        })
        .await
}

#[tokio::test]
async fn test_100_continue_disabled() {
    tokio::task::LocalSet::new()
        .run_until(async move {
            let (client_io, server_io) = tokio::io::duplex(4096);

            let server = Http1::new(
                server_io,
                Http1Options::new()
                    .header_read_timeout(None)
                    .send_continue_response(false),
            );
            let server_task = tokio::task::spawn_local(server.handle(|req| async {
                let body = req.into_body().collect().await.unwrap().to_bytes();
                assert_eq!(&*body, b"Hello, World!");
                Ok::<_, http::Error>(http::Response::new(Full::new(bytes::Bytes::from_static(
                    b"OK",
                ))))
            }));

            let (mut client_reader, mut client_writer) = tokio::io::split(client_io);

            client_writer
                .write_all(
                    b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 13\r\nExpect: 100-continue\r\nConnection: close\r\n\r\nHello, World!",
                )
                .await
                .unwrap();

            // Read all output from the server
            let mut response_buf = Vec::new();
            client_reader.read_to_end(&mut response_buf).await.unwrap();
            let response_str = String::from_utf8_lossy(&response_buf);

            // Should contain 200 OK but NO 100 Continue
            assert!(response_str.contains("200 OK"), "Expected 200 OK: {}", response_str);
            assert!(!response_str.contains("100 Continue"), "Should NOT contain 100 Continue: {}", response_str);

            server_task.await.unwrap().unwrap();
        })
        .await
}

#[tokio::test]
async fn test_100_continue_no_duplicate() {
    tokio::task::LocalSet::new()
        .run_until(async move {
            let (client_io, server_io) = tokio::io::duplex(4096);

            let server = Http1::new(server_io, Http1Options::new().header_read_timeout(None));
            let server_task = tokio::task::spawn_local(server.handle(|req| async {
                let body = req.into_body().collect().await.unwrap().to_bytes();
                assert_eq!(&*body, b"Hello, World!");
                Ok::<_, http::Error>(http::Response::new(Full::new(bytes::Bytes::from_static(
                    b"OK",
                ))))
            }));

            let (mut client_reader, mut client_writer) = tokio::io::split(client_io);

            client_writer
                .write_all(
                    b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 13\r\nExpect: 100-continue\r\nConnection: close\r\n\r\nHello, World!",
                )
                .await
                .unwrap();

            // Read all output from the server
            let mut response_buf = Vec::new();
            client_reader.read_to_end(&mut response_buf).await.unwrap();
            let response_str = String::from_utf8_lossy(&response_buf);

            // Count occurrences of "100 Continue"
            let continue_count = response_str.matches("100 Continue").count();
            assert_eq!(continue_count, 1, "Expected exactly one 100 Continue, got {}: {}", continue_count, response_str);

            // Should end with 200 OK after 100 Continue
            assert!(response_str.contains("100 Continue"));
            assert!(response_str.contains("200 OK"));

            server_task.await.unwrap().unwrap();
        })
        .await
}
