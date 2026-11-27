//! `Http1Options::client_eof_ends_request`: a client that closes the
//! connection before the response drops the request handler, as a reset
//! HTTP/2 stream does. Off by default, as a client may shut down only its
//! sending side and still wait for the response.

#![cfg(feature = "h1")]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::Response;
use http_body_util::Full;
use tokio::io::AsyncWriteExt;
use zincio_http::{Http1, Http1Options, HttpProtocol};

/// Flags its drop.
struct Guard(Arc<AtomicBool>);

impl Drop for Guard {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// A handler that never answers and never wakes its task, as one waiting on
/// a backend that sends nothing; dropping it drops its guard.
async fn never_answers(
    started: Arc<AtomicBool>,
    dropped: Arc<AtomicBool>,
) -> Result<Response<Full<Bytes>>, std::io::Error> {
    let held = Guard(dropped);
    started.store(true, Ordering::SeqCst);
    futures_util::future::pending::<()>().await;
    drop(held);
    Ok(Response::new(Full::new(Bytes::from_static(b"never"))))
}

/// Whether `flag` is set within `limit`.
async fn comes_true(flag: &AtomicBool, limit: Duration) -> bool {
    let start = Instant::now();
    while !flag.load(Ordering::SeqCst) {
        if start.elapsed() > limit {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    true
}

/// Sends a GET to a server with `client_eof_ends_request(enabled)` whose
/// handler never answers, closes the connection, and returns whether the
/// handler was dropped within `limit`.
async fn handler_dropped_after_close(enabled: bool, limit: Duration) -> bool {
    tokio::task::LocalSet::new()
        .run_until(async move {
            let started = Arc::new(AtomicBool::new(false));
            let dropped = Arc::new(AtomicBool::new(false));
            let (mut client_io, server_io) = tokio::io::duplex(4096);
            let server = Http1::new(
                server_io,
                Http1Options::new()
                    .header_read_timeout(None)
                    .client_eof_ends_request(enabled),
            );
            let handler_started = Arc::clone(&started);
            let handler_dropped = Arc::clone(&dropped);
            let server_task = tokio::task::spawn_local(server.handle(move |_req| {
                never_answers(Arc::clone(&handler_started), Arc::clone(&handler_dropped))
            }));
            client_io
                .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .await
                .unwrap();
            assert!(
                comes_true(&started, Duration::from_secs(2)).await,
                "the handler runs"
            );
            drop(client_io);
            let was_dropped = comes_true(&dropped, limit).await;
            server_task.abort();
            was_dropped
        })
        .await
}

#[tokio::test]
async fn a_closed_connection_drops_the_handler_when_enabled() {
    assert!(handler_dropped_after_close(true, Duration::from_secs(2)).await);
}

#[tokio::test]
async fn a_closed_connection_leaves_the_handler_by_default() {
    // The client may have shut down only its sending side.
    assert!(!handler_dropped_after_close(false, Duration::from_millis(300)).await);
}
