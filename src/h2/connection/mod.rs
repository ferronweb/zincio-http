//! HTTP/2 connection (RFC 9113 Sections 3.5, 5.1, 6.5, 8.1).
//!
//! Drives one HTTP/2 connection over an async I/O stream: reads the
//! client's 24-octet preface (with a timeout), sends the server
//! SETTINGS, maintains the peer's SETTINGS state (applying
//! `SETTINGS_HEADER_TABLE_SIZE` to the HPACK encoder and
//! `SETTINGS_MAX_FRAME_SIZE` to the outgoing frame writer), answers
//! SETTINGS frames with ACK, echoes PING, and reports protocol
//! violations with GOAWAY before closing.
//!
//! Frame parsing and validation happen in [`super::codec`]; this module
//! adds the connection- and stream-level wiring: per-stream state,
//! request/response header parsing, request dispatch to the handler,
//! response framing, and the connection-level error handling that
//! h2spec's `http2/4.3`, `http2/5.1`, `http2/6.1`, `http2/6.2`,
//! `http2/6.4` and `http2/8.1` groups cover.

use std::{
    collections::VecDeque,
    future::Future,
    pin::Pin,
    sync::{atomic::AtomicBool, Arc},
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use futures_util::{pin_mut, FutureExt};
use http::{Request, Response, StatusCode};
use http_body::Body;
use rustc_hash::{FxHashMap, FxHashSet};
use tokio_util::sync::CancellationToken;

use super::codec::{
    Frame, FrameDecoder, FrameWriter, Setting, CLIENT_PREFACE, DEFAULT_INITIAL_WINDOW_SIZE,
    DEFAULT_MAX_FRAME_SIZE, MAX_FRAME_SIZE_LIMIT,
};
use super::date::DateCache;
use super::error::Reason;
use super::hpack::{Decoder as HpackDecoder, Encoder, Header as HpackHeader, HpackError};
use super::sanitize_response;
use super::stream::{
    BodyMsg, H2Body, MalformedRequest, ParsedRequest, StreamDriver, StreamEntry, StreamMsg,
};
use crate::early_hints::EarlyHints;
use crate::Incoming;

/// Per-connection behavior options.
#[derive(Debug, Clone, Copy)]
pub struct ConnectionOptions {
    /// Answer requests with `100 Continue` when they carry
    /// `expect: 100-continue`.
    pub send_continue_response: bool,
    /// Add a `Date` header to responses.
    pub send_date_header: bool,
    /// `SETTINGS_MAX_CONCURRENT_STREAMS` announced to the peer.
    pub max_concurrent_streams: u32,
    /// `SETTINGS_INITIAL_WINDOW_SIZE`: per-stream DATA credit we start with.
    pub initial_stream_window_size: u32,
    /// Connection-level DATA credit we start with (RFC 9113 Section 6.9.1).
    pub initial_connection_window_size: u32,
    /// Largest frame (payload) we send or receive (`SETTINGS_MAX_FRAME_SIZE`).
    pub max_frame_size: u32,
    /// Largest decoded header list we accept (`SETTINGS_MAX_HEADER_LIST_SIZE`).
    pub max_header_list_size: u32,
    /// Whether to enable Extended CONNECT
    pub enable_connect_protocol: bool,
    /// Close the connection after this long with no frame from the peer
    /// (RFC 9113 Section 10.5). `None` disables the idle timeout.
    pub idle_timeout: Option<Duration>,
    /// Maximum number of RST_STREAM frames we send in response to
    /// protocol errors made by the peer over the connection's lifetime.
    /// `None` disables the limit; when it is exceeded the connection
    /// closes with GOAWAY `ENHANCE_YOUR_CALM` (RFC 9113 Section 10.5.2).
    pub max_local_error_reset_streams: Option<usize>,
    /// Maximum number of streams the peer reset before we accepted them.
    /// `None` disables the limit; when it is exceeded the connection
    /// closes with GOAWAY `ENHANCE_YOUR_CALM` (RFC 9113 Section 10.5.2).
    pub max_pending_accept_reset_streams: Option<usize>,
    /// Maximum number of frames that may compose a single, not-yet-finalized
    /// header field block (HEADERS/CONTINUATION). Beyond this a stream is
    /// reset as a CONTINUATION flood (CVE-2024-27919).
    pub max_continuation_frames: usize,
}

impl Default for ConnectionOptions {
    #[inline]
    fn default() -> Self {
        ConnectionOptions {
            send_continue_response: false,
            send_date_header: true,
            max_concurrent_streams: 100,
            initial_stream_window_size: DEFAULT_INITIAL_WINDOW_SIZE,
            initial_connection_window_size: DEFAULT_INITIAL_WINDOW_SIZE,
            max_frame_size: DEFAULT_MAX_FRAME_SIZE as u32,
            max_header_list_size: u32::MAX,
            enable_connect_protocol: false,
            idle_timeout: None,
            max_local_error_reset_streams: Some(1024),
            max_pending_accept_reset_streams: Some(20),
            max_continuation_frames: 16,
        }
    }
}

/// The peer's current SETTINGS values. Defaults are the RFC 9113
/// Section 6.5.2 initial values; they change as non-ACK SETTINGS frames
/// arrive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerSettings {
    pub(crate) header_table_size: u32,
    pub(crate) enable_push: u32,
    pub(crate) initial_window_size: u32,
    pub(crate) max_frame_size: usize,
    /// Kept for the field block decoder's bomb protection (C2).
    #[allow(dead_code)]
    pub(crate) max_header_list_size: u32,
}

impl Default for PeerSettings {
    #[inline]
    fn default() -> Self {
        PeerSettings {
            header_table_size: 4096,
            enable_push: 1,
            initial_window_size: DEFAULT_INITIAL_WINDOW_SIZE,
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            max_header_list_size: u32::MAX,
        }
    }
}

/// An HTTP/2 server connection.
///
/// `Io` must be a raw transport: the preface is read byte-exact, so
/// any buffering layer between the socket and this type breaks the
/// initial read.
pub struct Connection<Io> {
    io: Io,
    decoder: FrameDecoder,
    writer: FrameWriter,
    out: Vec<u8>,
    /// Encoder for the field blocks this connection sends; its table
    /// size follows the peer's `SETTINGS_HEADER_TABLE_SIZE`.
    encoder: Encoder,
    /// Decoder for the peer's field blocks; sees every header block on
    /// this connection (RFC 9113 Section 4.3).
    request_decoder: HpackDecoder,
    /// The peer's settings, updated by non-ACK SETTINGS frames.
    peer: PeerSettings,
    /// The settings this connection announced (public RFC defaults
    /// plus `SETTINGS_MAX_CONCURRENT_STREAMS`).
    #[allow(dead_code)]
    local: PeerSettings,
    /// Bounds the wait for the client's 24-octet preface. A peer that
    /// is too slow is disconnected without a GOAWAY.
    preface_timeout: Option<Duration>,
    /// Active streams, keyed by stream id (RFC 9113 Section 5.1).
    streams: FxHashMap<u32, StreamEntry>,
    /// Connection-level send window for DATA payloads (RFC 9113
    /// Section 6.9.1); initial 65,535 octets.
    conn_window: i64,
    /// Stream ids whose streams have ended (closed state per RFC 9113
    /// Section 5.1); used to tell closed-stream frames apart from
    /// idle-stream frames.
    closed_streams: FxHashSet<u32>,
    /// LRU order for `closed_streams` to avoid bulk clear at 4096.
    closed_order: VecDeque<u32>,
    /// Behavior options for this connection (used by [`Connection::handle`]).
    opts: ConnectionOptions,
    /// RST_STREAM frames this endpoint has sent in response to the
    /// peer's protocol errors (bounded by `opts.max_local_error_reset_streams`).
    local_error_resets: usize,
    /// Streams the peer reset before this endpoint accepted them
    /// (bounded by `opts.max_pending_accept_reset_streams`).
    pending_accept_resets: usize,
    /// Wakes the drive loop when a stream task fills its outbound
    /// channel; the loop drains channels between reads.
    wake_tx: Option<kanal::AsyncSender<()>>,
    /// Stream ids whose FIELD_BLOCK completed (END_HEADERS seen) and
    /// awaits finalization; drained one per frame by
    /// [`Connection::process_frames`] in FIFO order for fairness.
    complete_blocks: VecDeque<u32>,
    /// Maximum number of frames a single header field block may span before
    /// it is treated as a CONTINUATION flood and reset (CVE-2024-27919).
    max_continuation_frames: usize,
    /// Scratch buffer reused by [`Connection::drain_pending_data`] to
    /// snapshot stream ids before pumping (avoids a per-call
    /// allocation).
    drain_ids: Vec<u32>,
    /// Highest stream id opened by the peer (RFC 9113 Section 5.1.1).
    highest_stream_id: u32,
    /// A connection error is pending; the loop stops after flushing.
    closing: bool,
    /// Graceful shutdown is in progress: the first GOAWAY is sent and we
    /// only drain already-open streams until they finish or the drain
    /// window elapses (RFC 9113 Section 6.8).
    graceful: bool,
    /// Last stream id advertised in the graceful-shutdown GOAWAY; peers
    /// must not open streams beyond it.
    graceful_last_stream: u32,
    /// Optional token that triggers graceful shutdown when cancelled.
    shutdown: Option<CancellationToken>,
    /// Shared `Date` header value, refreshed periodically for the
    /// responses the stream tasks emit.
    date_cache: Arc<DateCache>,
    /// Buffer for HTTP/2 frame encoding reuse
    frame_buffer: Vec<u8>,
}

impl<Io> Connection<Io>
where
    Io: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    /// Creates a connection over `io`.
    #[inline]
    pub fn new(io: Io, preface_timeout: Option<Duration>) -> Connection<Io> {
        Connection {
            io,
            decoder: FrameDecoder::new(DEFAULT_MAX_FRAME_SIZE),
            writer: FrameWriter::new(DEFAULT_MAX_FRAME_SIZE),
            out: Vec::new(),
            encoder: Encoder::new(4096),
            request_decoder: HpackDecoder::new(4096),
            peer: PeerSettings::default(),
            local: PeerSettings::default(),
            preface_timeout,
            streams: FxHashMap::default(),
            conn_window: DEFAULT_INITIAL_WINDOW_SIZE as i64,
            closed_streams: FxHashSet::default(),
            // Grows on demand up to the 4096-entry LRU bound in
            // `mark_closed`; preallocating would cost ~16 KiB per
            // connection even when it only ever holds a few ids.
            closed_order: VecDeque::new(),
            opts: ConnectionOptions::default(),
            local_error_resets: 0,
            pending_accept_resets: 0,
            wake_tx: None,
            complete_blocks: VecDeque::new(),
            max_continuation_frames: 16,
            drain_ids: Vec::new(),
            highest_stream_id: 0,
            closing: false,
            graceful: false,
            graceful_last_stream: 0,
            shutdown: None,
            date_cache: Arc::new(DateCache::new()),
            frame_buffer: Vec::new(),
        }
    }

    /// Arms a [`CancellationToken`] that triggers a graceful shutdown
    /// when cancelled: the connection sends GOAWAY, stops opening new
    /// streams, drains in-flight responses, then closes (RFC 9113
    /// Section 6.8).
    #[inline]
    pub fn with_shutdown(mut self, token: CancellationToken) -> Self {
        self.shutdown = Some(token);
        self
    }

    /// Drives a connection that never serves requests: the preface
    /// handshake, SETTINGS/PING maintenance and error handling, but no
    /// request dispatch (any request stream is refused).
    ///
    /// Equivalent to [`Connection::handle`] with a handler that never
    /// completes; kept for tests and for callers that only want the
    /// connection-level behavior.
    #[inline]
    pub async fn drive(self) -> std::io::Result<()> {
        self.handle(
            Arc::new(|_| std::future::pending::<Result<Response<Incoming>, std::io::Error>>()),
            ConnectionOptions::default(),
        )
        .await
    }

    /// Serves requests to completion: peer EOF, GOAWAY received,
    /// preface timeout, or an unrecoverable protocol error.
    ///
    /// Each decoded request starts a stream task running `request_fn`
    /// (a clone-free sequential borrow: the loop owns the closure for
    /// the connection's lifetime). Responses are framed onto the wire
    /// by this task as the stream tasks emit them.
    #[inline]
    pub async fn handle<F, Fut, ResB, ResBE, ResE>(
        mut self,
        request_fn: Arc<F>,
        options: ConnectionOptions,
    ) -> std::io::Result<()>
    where
        F: Fn(Request<Incoming>) -> Fut + 'static,
        Fut: Future<Output = Result<Response<ResB>, ResE>> + 'static,
        ResB: Body<Data = Bytes, Error = ResBE> + Unpin + 'static,
        ResBE: std::error::Error + 'static,
        ResE: std::error::Error + 'static,
    {
        self.opts = options;
        // Apply the negotiated native settings before the handshake.
        self.request_decoder
            .set_max_header_list_size(self.opts.max_header_list_size as usize);
        self.decoder
            .set_max_frame_size(self.opts.max_frame_size as usize);
        self.conn_window = self.opts.initial_connection_window_size as i64;
        // Resolved CONTINUATION-flood limit (CVE-2024-27919); `Http2Options`
        // already applies the safe default when none was configured.
        self.max_continuation_frames = options.max_continuation_frames;
        match self.read_preface().await? {
            None => return Ok(()), // preface timeout: close quietly
            Some(false) => {
                // Invalid preface: connection error PROTOCOL_ERROR
                // (RFC 9113 Section 3.5), then close.
                self.goaway(Reason::ProtocolError, b"invalid connection preface");
                self.flush().await?;
                return Ok(());
            }
            Some(true) => {}
        }

        // Our connection preface: SETTINGS announcing our flow-control
        // windows, frame/header limits and concurrency (RFC 9113
        // Sections 3.5 and 6.5.2).
        self.writer.write_settings(
            &mut self.out,
            &[
                Setting {
                    id: 0x03,
                    value: self.opts.max_concurrent_streams,
                },
                Setting {
                    id: 0x04,
                    value: self.opts.initial_stream_window_size,
                },
                Setting {
                    id: 0x05,
                    value: self.opts.max_frame_size,
                },
                Setting {
                    id: 0x08,
                    value: if self.opts.enable_connect_protocol {
                        1
                    } else {
                        0
                    },
                },
            ],
        );
        self.flush().await?;

        let (wake_tx, wake_rx) = kanal::bounded_async(1);
        self.wake_tx = Some(wake_tx);
        // Seed the output buffers modestly instead of pre-reserving tens
        // of kilobytes: typical responses are far smaller than
        // `max_frame_size`, and both buffers grow geometrically on demand.
        // Pre-reserving 64 KiB + `max_frame_size` per connection showed up
        // as ~65 MiB at 1000 connections in heap profiles.
        self.out.reserve(8 * 1024);
        self.frame_buffer.reserve(1024);

        let mut buf = [0u8; 8192];
        let mut wake_rx_drain = Vec::new();
        let mut peer_goaway = false;
        while !peer_goaway && !(self.graceful && self.streams.is_empty()) {
            let wake_recv = wake_rx.recv().fuse();
            let read = tokio::io::AsyncReadExt::read(&mut self.io, &mut buf).fuse();
            // Graceful-shutdown signal: never fires without a token. The
            // clone lives for the loop iteration so the future can borrow
            // it. Stack-pinned on purpose: boxing this future heap-allocated
            // once per loop iteration in heap profiles.
            let shutdown_token = self.shutdown.clone();
            let shutdown_fut = async move {
                match shutdown_token {
                    Some(token) => token.cancelled().await,
                    None => futures_util::future::pending().await,
                }
            }
            .fuse();
            pin_mut!(wake_recv);
            pin_mut!(read);
            pin_mut!(shutdown_fut);
            // Idle timeout (RFC 9113 Section 10.5): no frame received from the
            // peer within `idle_timeout` => graceful shutdown. Recreated each
            // iteration so it measures the gap since the last received frame.
            let timeout = self.opts.idle_timeout;
            let idle_unfuse = std::pin::pin!(async move {
                if let Some(d) = timeout {
                    zincio::time::sleep(d).await;
                } else {
                    futures_util::future::pending::<()>().await;
                }
            });
            let mut idle = idle_unfuse.fuse();
            futures_util::select! {
                n = read => {
                    let n = match n {
                        Ok(n) => n,
                        Err(e) if self.streams.is_empty()
                            && matches!(
                                e.kind(),
                                std::io::ErrorKind::BrokenPipe
                                    | std::io::ErrorKind::ConnectionReset
                                    | std::io::ErrorKind::ConnectionAborted
                                    | std::io::ErrorKind::UnexpectedEof
                            ) => {
                            // Connection abruptly closed while idle (no streams)...
                            return Ok(())
                        }
                        Err(e) => Err(e)?
                    };
                    if n == 0 {
                        break; // peer closed; nothing more to say
                    }
                    self.decoder.extend(&buf[..n]);
                    peer_goaway = self.process_frames(&request_fn).await?;
                    self.drain_outbound();
                    self.flush().await?;
                }
                _ = wake_recv => {
                    // A stream task parked on a full channel; drain it.

                    // But first, drain the wake notifications to prevent busy looping
                    let _ = wake_rx.drain_into(&mut wake_rx_drain);
                    wake_rx_drain.clear();
                    self.drain_outbound();
                    self.flush().await?;
                }
                _ = shutdown_fut => {
                    self.begin_graceful_shutdown();
                    self.flush().await?;
                }
                _ = idle => {
                    // The peer was silent for `idle_timeout`; close the
                    // connection gracefully (GOAWAY) and stop.
                    self.begin_graceful_shutdown();
                    self.flush().await?;
                    break;
                }
            }
        }
        if self.graceful {
            self.finish_graceful_shutdown();
        }
        self.flush().await?;
        Ok(())
    }

    /// Reads the 24-octet client preface.
    ///
    /// Returns `Ok(None)` on timeout (the connection closes quietly —
    /// answering a peer that never spoke is meaningless), `Ok(Some(
    /// true))` on a match, and `Ok(Some(false))` when the peer sent
    /// something else (the caller answers with GOAWAY).
    #[inline]
    async fn read_preface(&mut self) -> std::io::Result<Option<bool>> {
        let mut magic = [0u8; CLIENT_PREFACE.len()];
        match self.preface_timeout {
            Some(timeout) => {
                match zincio::time::timeout(
                    timeout,
                    tokio::io::AsyncReadExt::read_exact(&mut self.io, &mut magic),
                )
                .await
                {
                    Ok(result) => {
                        result?;
                    }
                    Err(_elapsed) => return Ok(None),
                }
            }
            None => {
                tokio::io::AsyncReadExt::read_exact(&mut self.io, &mut magic).await?;
            }
        }
        Ok(Some(magic == CLIENT_PREFACE))
    }

    /// Decodes and handles every frame currently buffered. Returns
    /// `Ok(true)` when the connection should end (peer GOAWAY or an
    /// error we answered with GOAWAY).
    #[inline]
    async fn process_frames<F, Fut, ResB, ResBE, ResE>(
        &mut self,
        request_fn: &Arc<F>,
    ) -> std::io::Result<bool>
    where
        F: Fn(Request<Incoming>) -> Fut + 'static,
        Fut: Future<Output = Result<Response<ResB>, ResE>> + 'static,
        ResB: Body<Data = Bytes, Error = ResBE> + Unpin + 'static,
        ResBE: std::error::Error + 'static,
        ResE: std::error::Error + 'static,
    {
        loop {
            let frame = match self.decoder.next_frame() {
                Ok(Some(frame)) => frame,
                Ok(None) => return Ok(false),
                Err(error) => {
                    // Frame-level violation: GOAWAY with the code the
                    // codec determined (RFC 9113 Sections 6.10, 6.5.2),
                    // then close.
                    self.goaway(error.reason, b"frame error");
                    self.flush().await?;
                    return Ok(true);
                }
            };
            match frame {
                Frame::Settings {
                    ack: false,
                    settings,
                } => {
                    self.apply_peer_settings(&settings);
                    self.writer.write_settings_ack(&mut self.out);
                }
                Frame::Settings { ack: true, .. } => {}
                Frame::Ping {
                    ack: false,
                    payload,
                } => {
                    self.writer.write_ping_ack(&mut self.out, &payload);
                }
                Frame::Ping { ack: true, .. } => {}
                Frame::GoAway { .. } => return Ok(true),
                Frame::Headers {
                    stream_id,
                    end_stream,
                    end_headers,
                    block,
                    ..
                } => {
                    self.handle_headers_frame(stream_id, end_stream, end_headers, &block);
                }
                Frame::Continuation {
                    stream_id,
                    end_headers,
                    block,
                } => {
                    self.handle_continuation(stream_id, end_headers, &block);
                }
                Frame::Data {
                    stream_id,
                    end_stream,
                    data,
                } => {
                    self.handle_data_frame(stream_id, end_stream, data).await;
                }
                Frame::Reset {
                    stream_id,
                    error_code,
                } => {
                    self.handle_reset_frame(stream_id, error_code);
                }
                Frame::Priority { .. } => {}
                Frame::WindowUpdate {
                    stream_id,
                    increment,
                } => self.handle_window_update(stream_id, increment),
                Frame::PushPromise { .. } => {
                    self.goaway(Reason::ProtocolError, b"push promise to server");
                }
                Frame::Unknown { .. } => {}
            }
            // One HEADERS/CONTINUATION chain completes at most one
            // field block per frame arrival; act on it while the
            // handler closure is in scope.
            if let Some(id) = self.take_complete_block() {
                self.finalize_field_block(id, request_fn).await;
            }
            if self.closing {
                self.flush().await?;
                return Ok(true);
            }
        }
    }
}
/// A boxed response body: the handler's body type is erased at the
/// stream boundary so `Connection` stays monomorphic.
struct ConnBody {
    inner: Pin<Box<dyn Body<Data = Bytes, Error = std::io::Error>>>,
}

impl ConnBody {
    #[inline]
    fn new<ResB, ResBE>(body: ResB) -> Self
    where
        ResB: Body<Data = Bytes, Error = ResBE> + Unpin + 'static,
        ResBE: std::error::Error + 'static,
    {
        ConnBody {
            inner: Box::pin(BodyAdapter(Some(Box::pin(body)))),
        }
    }
}

impl Body for ConnBody {
    type Data = Bytes;
    type Error = std::io::Error;

    #[inline]
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        self.inner.as_mut().poll_frame(cx)
    }

    #[inline]
    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

/// Converts any displayable error into an [`io::Error`] without requiring
/// `Send + Sync` (the native connection layer only needs the message, not the
/// source; this keeps the public trait free of `Send`/`Sync` so it works on
/// runtimes such as `zincio` that do not demand them).
#[inline]
fn e2io<E: std::fmt::Display>(e: E) -> std::io::Error {
    #[derive(Debug)]
    struct Msg(String);
    impl std::fmt::Display for Msg {
        #[inline]
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.0)
        }
    }
    impl std::error::Error for Msg {}
    std::io::Error::other(Msg(format!("{e}")))
}

/// Adapts an arbitrary body whose error is not `io::Error` into one
/// that is (the stream layer only deals in `io::Error`).
struct BodyAdapter<ResB>(Option<Pin<Box<ResB>>>);

impl<ResB, ResBE> Body for BodyAdapter<ResB>
where
    ResB: Body<Data = Bytes, Error = ResBE>,
    ResBE: std::error::Error + 'static,
{
    type Data = Bytes;
    type Error = std::io::Error;

    #[inline]
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        let Some(inner) = this.0.as_mut() else {
            return Poll::Ready(None);
        };
        match inner.as_mut().poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => Poll::Ready(Some(Ok(frame))),
            Poll::Ready(Some(Err(error))) => Poll::Ready(Some(Err(e2io(error)))),
            Poll::Ready(None) => {
                this.0 = None;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    #[inline]
    fn size_hint(&self) -> http_body::SizeHint {
        match &self.0 {
            Some(body) => body.size_hint(),
            None => http_body::SizeHint::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StreamDataState {
    Idle,
    Closed,
    Bad,
    Gone,
    Ok,
}

mod handlers;

#[cfg(test)]
mod tests;
