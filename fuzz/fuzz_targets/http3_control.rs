#![no_main]
//! Fuzz target for the HTTP/3 connection control plane.
//!
//! The driver (`Http3::handle`) consumes the peer's unidirectional streams:
//! the control stream (frames) and the QPACK encoder/decoder streams. Malformed
//! control frames, truncated SETTINGS, and adversarial QPACK decoder-stream
//! instructions are part of the protocol surface and MUST surface as
//! connection errors — never as a panic or `unsafe` violation. The target
//! feeds arbitrary bytes as the peer's control, QPACK encoder, and QPACK
//! decoder streams, drives the connection state machine to its terminal
//! state (an error close, or idle `Pending`), and asserts it never unwinds.
//!
//! The connection is driven by manual polling with a no-op waker. No request
//! streams are offered (so the request-task spawn path is never taken) and
//! both timeouts are disabled, so no runtime is required.

use std::collections::VecDeque;
use std::future::Future;
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use bytes::Bytes;
use http::{Request, Response};
use http_body_util::Full;
use libfuzzer_sys::fuzz_target;
use std::convert::Infallible;

use zincio_http::transport::{
    Accept, BidiStream, Connection, OpenStreams, RecvStream, SendStream, UniStream,
};
use zincio_http::{Http3, Http3Options, HttpProtocol, Incoming, TransportError};

/// A mock unidirectional stream carrying a single inbound buffer followed by
/// a FIN. Outbound sends are accepted and discarded.
struct MockStream {
    chunks: VecDeque<Option<Bytes>>,
}

impl MockStream {
    fn new(data: &[u8]) -> Self {
        let mut chunks = VecDeque::new();
        if !data.is_empty() {
            chunks.push_back(Some(Bytes::copy_from_slice(data)));
        }
        chunks.push_back(None);
        Self { chunks }
    }
}

impl RecvStream for MockStream {
    fn poll_recv(&mut self, _cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>, TransportError>> {
        match self.chunks.pop_front() {
            Some(chunk) => Poll::Ready(Ok(chunk)),
            None => Poll::Pending,
        }
    }

    fn id(&self) -> u64 {
        0
    }
}

impl SendStream for MockStream {
    fn poll_send(
        &mut self,
        _cx: &mut Context<'_>,
        _data: &[u8],
    ) -> Poll<Result<(), TransportError>> {
        Poll::Ready(Ok(()))
    }

    fn poll_finish(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), TransportError>> {
        Poll::Ready(Ok(()))
    }

    fn poll_reset(
        &mut self,
        _cx: &mut Context<'_>,
        _code: u64,
    ) -> Poll<Result<(), TransportError>> {
        Poll::Ready(Ok(()))
    }

    fn poll_stop_sending(
        &mut self,
        _cx: &mut Context<'_>,
        _code: u64,
    ) -> Poll<Result<(), TransportError>> {
        Poll::Ready(Ok(()))
    }
}

impl UniStream for MockStream {}
impl BidiStream for MockStream {}

/// In-memory QUIC connection: hands out fresh outbound streams (control +
/// QPACK encoder/decoder) on open, and replays the peer's queued uni streams
/// (control, QPACK encoder, QPACK decoder) on accept.
struct MockConn {
    peer_unis: VecDeque<Box<dyn UniStream>>,
}

impl MockConn {
    fn new() -> Self {
        Self {
            peer_unis: VecDeque::new(),
        }
    }

    fn add_peer(&mut self, data: &[u8]) {
        self.peer_unis.push_back(Box::new(MockStream::new(data)));
    }
}

impl OpenStreams for MockConn {
    fn poll_open_uni(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<Box<dyn UniStream>, TransportError>> {
        Poll::Ready(Ok(Box::new(MockStream::new(&[]))))
    }
}

impl Accept for MockConn {
    fn poll_accept(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Box<dyn BidiStream>>, TransportError>> {
        Poll::Pending
    }

    fn poll_accept_uni(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Box<dyn UniStream>>, TransportError>> {
        Poll::Ready(Ok(self.peer_unis.pop_front()))
    }
}

impl Connection for MockConn {
    fn is_handshake_complete(&self) -> bool {
        true
    }

    fn poll_shutdown(
        &mut self,
        _cx: &mut Context<'_>,
        _error_code: u64,
    ) -> Poll<Result<(), TransportError>> {
        Poll::Ready(Ok(()))
    }
}

fn noop_waker() -> Waker {
    fn clone(_: *const ()) -> RawWaker {
        RawWaker::new(std::ptr::null(), &VTABLE)
    }
    fn noop(_: *const ()) {}
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
    // SAFETY: the vtable's waker operations are all no-ops and never access
    // the (null) data pointer, so the resulting `Waker` is sound.
    unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) }
}

fuzz_target!(|data: &[u8]| {
    let mut conn = MockConn::new();

    // Control stream: stream type 0x00 followed by the fuzzed frame bytes.
    let mut control = Vec::with_capacity(data.len() + 1);
    control.push(0x00);
    control.extend_from_slice(data);
    conn.add_peer(&control);

    // QPACK encoder stream: stream type 0x01 followed by fuzzed bytes.
    let mut encoder = Vec::with_capacity(data.len() + 1);
    encoder.push(0x01);
    encoder.extend_from_slice(data);
    conn.add_peer(&encoder);

    // QPACK decoder stream: stream type 0x03 followed by fuzzed bytes.
    let mut decoder = Vec::with_capacity(data.len() + 1);
    decoder.push(0x03);
    decoder.extend_from_slice(data);
    conn.add_peer(&decoder);

    let options = Http3Options::default()
        .handshake_timeout(None)
        .header_read_timeout(None)
        .accept_timeout(None);

    let http3 = Http3::new(conn, options);
    let handler = |_req: Request<Incoming>| async move {
        let resp = Response::builder()
            .status(200)
            .body(Full::new(Bytes::from_static(b"x")))
            .expect("failed to create response body");
        Ok::<_, Infallible>(resp)
    };

    let mut fut = Box::pin(http3.handle(handler));
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    // Bound the drive loop: the connection is expected to reach a terminal
    // error close (control stream FIN) or idle `Pending`. A panic here is the
    // bug we are hunting.
    for _ in 0..256 {
        if fut.as_mut().poll(&mut cx).is_ready() {
            break;
        }
    }
});
