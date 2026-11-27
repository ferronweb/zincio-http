//! A client that leaves an HTTP/2 stream before its response drops the
//! stream's handler: by resetting the stream (RST_STREAM), or by closing the
//! connection. A handler that waits for a backend learns so that nobody
//! waits for its answer any more.
//! Before: the handler of a GET, whose request body had ended, was never
//! told of a reset, and a task waiting for its handler was not woken for
//! one, so the handler ran on, also after the connection had ended.

#![cfg(feature = "h2")]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{Request, Response};
use http_body_util::Full;
use zincio_http::{Http2, Http2Options, HttpProtocol, Incoming};

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

/// How the client leaves.
#[derive(Clone, Copy)]
enum Leave {
    /// Drops the stream's handles: the h2 client resets the stream
    /// (RST_STREAM CANCEL), and the connection stays.
    ResetStream,
    /// Closes the connection.
    CloseConnection,
}

/// Sends a GET to a server whose handler never answers, leaves as `leave`,
/// and returns whether the handler was dropped within two seconds.
fn handler_dropped_after(leave: Leave) -> bool {
    zincio::RuntimeBuilder::new()
        .enable_timer(true)
        .build()
        .unwrap()
        .block_on(async move {
            let started = Arc::new(AtomicBool::new(false));
            let dropped = Arc::new(AtomicBool::new(false));
            let (client_io, server_io) = tokio::io::duplex(1 << 16);
            let handler_started = Arc::clone(&started);
            let handler_dropped = Arc::clone(&dropped);
            let server = zincio::spawn(async move {
                Http2::new(server_io, Http2Options::default())
                    .handle(move |_request: Request<Incoming>| {
                        never_answers(Arc::clone(&handler_started), Arc::clone(&handler_dropped))
                    })
                    .await
            });

            let (client, connection) = h2::client::handshake(client_io).await.unwrap();
            let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
            let connection_task = zincio::spawn(async move {
                // Ends when told, and drops the client's end of the
                // connection with it.
                tokio::select! {
                    ended = connection => ended.map_err(|err| err.to_string()),
                    stop = stop_rx => stop.map_err(|err| err.to_string()),
                }
            });
            let mut client = client.ready().await.unwrap();
            let request = Request::get("https://example.com/").body(()).unwrap();
            let (response, stream) = client.send_request(request, true).unwrap();
            assert!(comes_true(&started).await, "the handler runs");
            match leave {
                Leave::ResetStream => drop((response, stream)),
                Leave::CloseConnection => {
                    stop_tx.send(()).unwrap();
                    drop((response, stream, client));
                }
            }
            let was_dropped = comes_true(&dropped).await;
            drop(connection_task);
            drop(server);
            was_dropped
        })
}

/// Whether `flag` is set within two seconds.
async fn comes_true(flag: &AtomicBool) -> bool {
    let start = Instant::now();
    while !flag.load(Ordering::SeqCst) {
        if start.elapsed() > Duration::from_secs(2) {
            return false;
        }
        zincio::time::sleep(Duration::from_millis(10)).await;
    }
    true
}

#[test]
fn a_reset_stream_drops_its_handler() {
    assert!(handler_dropped_after(Leave::ResetStream));
}

#[test]
fn a_closed_connection_drops_the_handlers_of_its_streams() {
    assert!(handler_dropped_after(Leave::CloseConnection));
}
