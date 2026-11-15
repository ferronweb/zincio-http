//! Interop test: drive a real `h2` client and server over in-memory
//! duplex streams, tap the wire bytes in both directions, and verify
//! that the native frame codec (`zincio_http::h2::codec`) decodes the
//! complete session, including the connection preface, settings
//! exchange, DATA, and GOAWAY frames.

#![cfg(all(feature = "h2", feature = "unstable-internals"))]

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use zincio_http::codec::{Frame, FrameDecoder, CLIENT_PREFACE, DEFAULT_MAX_FRAME_SIZE};

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Capture {
    fn push(&self, bytes: &[u8]) {
        self.0.lock().unwrap().extend_from_slice(bytes);
    }

    fn bytes(&self) -> Vec<u8> {
        self.0.lock().unwrap().clone()
    }
}

/// A transport half that records everything written through it. Each
/// `Tapped` wraps one end of the duplex pair and logs the bytes its
/// side writes, so the two captures together hold the full wire log of
/// the session.
struct Tapped {
    inner: tokio::io::DuplexStream,
    log: Capture,
}

impl AsyncRead for Tapped {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Tapped {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let n = match std::task::ready!(Pin::new(&mut self.inner).poll_write(cx, buf)) {
            Ok(n) => n,
            Err(e) => return Poll::Ready(Err(e)),
        };
        self.log.push(&buf[..n]);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn decode_all(wire: &[u8]) -> Vec<Frame> {
    let mut decoder = FrameDecoder::new(DEFAULT_MAX_FRAME_SIZE);
    decoder.extend(wire);
    let mut frames = Vec::new();
    while let Some(frame) = decoder.next_frame().unwrap_or_else(|e| {
        panic!(
            "decode error at frame {}: {e:?}\nremaining wire ({} bytes): {:02x?}",
            frames.len(),
            wire.len(),
            &wire[..wire.len().min(96)]
        )
    }) {
        frames.push(frame);
    }
    frames
}

fn total_data(frames: &[Frame]) -> usize {
    frames
        .iter()
        .map(|f| match f {
            Frame::Data { data, .. } => data.len(),
            _ => 0,
        })
        .sum()
}

#[tokio::test]
async fn real_h2_session_frames_decode() {
    let (client_end, server_end) = tokio::io::duplex(1 << 16);
    let log_c2s = Capture::default();
    let log_s2c = Capture::default();
    let client_io = Tapped {
        inner: client_end,
        log: log_c2s.clone(),
    };
    let server_io = Tapped {
        inner: server_end,
        log: log_s2c.clone(),
    };

    let server_task = tokio::spawn(async move {
        let mut conn = h2::server::handshake(server_io).await.unwrap();
        while let Some(request) = conn.accept().await {
            let (_request, mut respond) = match request {
                Ok(request) => request,
                Err(_) => break,
            };
            let Ok(mut send) = respond.send_response(http::Response::new(()), false) else {
                break;
            };
            if send
                .send_data(bytes::Bytes::from(vec![0x61; 4096]), false)
                .is_err()
            {
                break;
            }
            if send
                .send_data(bytes::Bytes::from(vec![0x62; 4096]), true)
                .is_err()
            {
                break;
            }
            conn.graceful_shutdown();
        }
    });

    let (mut send_request, conn) = h2::client::handshake(client_io).await.unwrap();
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let _ = conn.await;
        let _ = done_tx.send(());
    });

    let request = http::Request::builder()
        .method("GET")
        .uri("https://example.example/")
        .body(())
        .unwrap();
    let (response, mut send_body) = send_request.send_request(request, false).unwrap();
    send_body
        .send_data(bytes::Bytes::from(vec![0x62; 1024]), true)
        .unwrap();

    let response = tokio::time::timeout(std::time::Duration::from_secs(5), response)
        .await
        .expect("response timed out")
        .unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);

    let mut body = response.into_body();
    let mut received = 0;
    loop {
        match tokio::time::timeout(std::time::Duration::from_secs(5), body.data()).await {
            Ok(Some(Ok(chunk))) => received += chunk.len(),
            Ok(Some(Err(_))) => panic!("response body error"),
            Ok(None) => break,
            Err(_) => panic!("response body timed out"),
        }
    }
    assert_eq!(received, 8192);

    drop(send_request);
    tokio::time::timeout(std::time::Duration::from_secs(5), done_rx)
        .await
        .expect("client connection did not finish")
        .expect("client connection failed");
    tokio::time::timeout(std::time::Duration::from_secs(5), server_task)
        .await
        .expect("server did not finish")
        .expect("server task failed");

    // The client's byte stream starts with the connection preface (which
    // the frame codec itself never sees — the connection layer consumes
    // it), followed by its initial SETTINGS.
    let c2s = log_c2s.bytes();
    assert!(c2s.starts_with(CLIENT_PREFACE), "missing client preface");
    let client_frames = decode_all(&c2s[CLIENT_PREFACE.len()..]);
    assert!(
        matches!(&client_frames[0], Frame::Settings { ack: false, .. }),
        "first client frame was not SETTINGS: {:?}",
        client_frames[0]
    );

    // The request and its 1024-octet body crossed as HEADERS + DATA on a
    // non-zero stream, with the field block completed in one frame.
    let request_headers = client_frames
        .iter()
        .find_map(|f| match f {
            Frame::Headers {
                stream_id,
                end_headers,
                ..
            } => Some((*stream_id, *end_headers)),
            _ => None,
        })
        .expect("no HEADERS frame from client");
    assert_ne!(request_headers.0, 0);
    assert!(request_headers.1, "request HEADERS not end_headers");
    assert_eq!(total_data(&client_frames), 1024);
    assert!(
        client_frames
            .iter()
            .any(|f| matches!(f, Frame::GoAway { .. })),
        "no GOAWAY from client"
    );

    // The server's byte stream opens with its own SETTINGS and carries the
    // response HEADERS, two DATA frames and its GOAWAY.
    let s2c = log_s2c.bytes();
    let server_frames = decode_all(&s2c);
    assert!(
        matches!(&server_frames[0], Frame::Settings { ack: false, .. }),
        "first server frame was not SETTINGS: {:?}",
        server_frames[0]
    );
    assert!(
        server_frames.iter().any(|f| matches!(
            f,
            Frame::Headers {
                end_headers: true,
                ..
            }
        )),
        "no response HEADERS from server"
    );
    assert_eq!(total_data(&server_frames), 8192);
    assert!(
        server_frames
            .iter()
            .any(|f| matches!(f, Frame::GoAway { .. })),
        "no GOAWAY from server"
    );

    // Optional seed capture for the frame codec fuzz target: run with
    // H2_DUMP_SEEDS=fuzz/seeds/http2 to refresh the corpus files.
    if let Ok(dir) = std::env::var("H2_DUMP_SEEDS") {
        std::fs::create_dir_all(&dir).expect("create seeds dir");
        std::fs::write(format!("{dir}/client-session.bin"), &c2s).expect("write client seed");
        std::fs::write(format!("{dir}/server-session.bin"), &s2c).expect("write server seed");
    }
}
