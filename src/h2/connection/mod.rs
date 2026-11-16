//! HTTP/2 connection (RFC 9113 Sections 3.5, 5.1, 6.5, 8.1).
//!
//! Drives one HTTP/2 connection: reads the preface, negotiates SETTINGS,
//! handles PING and flow control, and reports protocol violations with
//! GOAWAY.

use std::{
    collections::VecDeque,
    future::Future,
    pin::Pin,
    sync::{atomic::AtomicBool, Arc},
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use futures_util::{pin_mut, FutureExt, StreamExt};
use http::{Request, Response, StatusCode};
use http_body::Body;
use rustc_hash::{FxHashMap, FxHashSet};
use tokio_util::sync::CancellationToken;

use super::codec::{
    Frame, FrameDecoder, FrameWriter, Setting, CLIENT_PREFACE, DEFAULT_CONNECTION_WINDOW_SIZE,
    DEFAULT_INITIAL_WINDOW_SIZE, DEFAULT_MAX_FRAME_SIZE, MAX_FRAME_SIZE_LIMIT,
};
use super::date::DateCache;
use super::error::Reason;
use super::hpack::{Decoder as HpackDecoder, Encoder, Header as HpackHeader, HpackError};
use super::sanitize_response;

/// How long a closing connection reads on for the peer's close ([`Connection::linger`]).
const LINGER: Duration = Duration::from_secs(2);
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
    pub max_local_error_reset_streams: Option<usize>,
    /// Maximum number of streams the peer reset before we produced a
    /// final response for them (CVE-2023-44487 rapid reset).
    pub max_pending_accept_reset_streams: Option<usize>,
    /// Maximum number of frames that may compose a single, not-yet-finalized
    /// header field block (HEADERS/CONTINUATION), used for CONTINUATION flood
    /// (CVE-2024-27919) detection.
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
            initial_connection_window_size: DEFAULT_CONNECTION_WINDOW_SIZE,
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

/// The peer's current SETTINGS values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerSettings {
    pub(crate) header_table_size: u32,
    pub(crate) enable_push: u32,
    pub(crate) initial_window_size: u32,
    pub(crate) max_frame_size: usize,
}

impl Default for PeerSettings {
    #[inline]
    fn default() -> Self {
        PeerSettings {
            header_table_size: 4096,
            enable_push: 1,
            initial_window_size: DEFAULT_CONNECTION_WINDOW_SIZE,
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
        }
    }
}

struct HeaderTimeoutFut {
    stream_id: u32,
    timed_out: bool,
    fut: zincio::time::Sleep,
    cancel_token: CancellationToken,
}

impl HeaderTimeoutFut {
    fn new(stream_id: u32, timeout: Duration) -> Self {
        let mut fut = zincio::time::sleep(timeout);
        // `zincio`'s `Sleep` seems to register a waker on poll...
        let timed_out = Pin::new(&mut fut)
            .poll(&mut Context::from_waker(std::task::Waker::noop()))
            .is_ready();
        HeaderTimeoutFut {
            stream_id,
            timed_out,
            fut,
            cancel_token: CancellationToken::new(),
        }
    }

    fn get_cancel_token(&self) -> CancellationToken {
        self.cancel_token.clone()
    }
}

impl Future for HeaderTimeoutFut {
    type Output = Option<u32>;

    #[inline]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.timed_out {
            return Poll::Ready(Some(this.stream_id));
        }
        match std::pin::pin!(this.cancel_token.cancelled()).poll(cx) {
            Poll::Ready(_) => {
                this.timed_out = true;
                return Poll::Ready(None);
            }
            Poll::Pending => {}
        }
        match Pin::new(&mut this.fut).poll(cx) {
            Poll::Ready(_) => {
                this.timed_out = true;
                Poll::Ready(Some(this.stream_id))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl futures_util::future::FusedFuture for HeaderTimeoutFut {
    fn is_terminated(&self) -> bool {
        self.timed_out
    }
}

/// An HTTP/2 server connection.
///
/// `Io` must be the raw transport; any buffering layer would break the
/// byte-exact preface read.
pub struct Connection<Io> {
    io: Io,
    decoder: FrameDecoder,
    writer: FrameWriter,
    out: Vec<u8>,
    /// Encoder for this connection's field blocks.
    encoder: Encoder,
    /// Decoder for the peer's field blocks (RFC 9113 Section 4.3).
    request_decoder: HpackDecoder,
    /// The peer's settings.
    peer: PeerSettings,
    /// Bounds the wait for the client preface.
    preface_timeout: Option<Duration>,
    /// Active streams by id (RFC 9113 Section 5.1).
    streams: FxHashMap<u32, StreamEntry>,
    /// Connection-level DATA send window (RFC 9113 Section 6.9.1).
    conn_window: i64,
    /// Stream ids whose streams have ended.
    closed_streams: FxHashSet<u32>,
    /// LRU order for `closed_streams`.
    closed_order: VecDeque<u32>,
    /// Behavior options (used by [`Connection::handle`]).
    opts: ConnectionOptions,
    /// Time allowed for a stream's header block to complete.
    header_read_timeout: Option<std::time::Duration>,
    /// Protocol-error resets this endpoint has sent.
    local_error_resets: usize,
    /// Peer-reset streams counted against the rapid-reset budget.
    pending_accept_resets: f64,
    /// When the rapid-reset budget was last drained.
    pending_accept_since: std::time::Instant,
    /// Wakes the drive loop when a stream task fills its outbound
    /// channel; the loop drains channels between reads.
    wake_tx: Option<kanal::AsyncSender<()>>,
    /// Stream ids whose FIELD_BLOCK completed (END_HEADERS seen) and
    /// awaits finalization.
    complete_blocks: VecDeque<u32>,
    /// Maximum number of frames a single header field block may span before
    /// it is treated as a CONTINUATION flood and reset (CVE-2024-27919).
    max_continuation_frames: usize,
    /// Scratch buffer reused by [`Connection::drain_pending_data`] to
    /// snapshot stream ids before pumping.
    drain_ids: Vec<u32>,
    /// Scratch buffers reused by [`Connection::drain_outbound`].
    outbound_ids: Vec<u32>,
    outbound_msgs: Vec<StreamMsg>,
    /// Highest stream id opened by the peer (RFC 9113 Section 5.1.1).
    highest_stream_id: u32,
    /// A connection error is pending; the loop stops after flushing.
    closing: bool,
    /// Whether the raceful shutdown is in progress.
    graceful: bool,
    /// The peer sent GOAWAY: it opens no more streams, and the connection
    /// closes once the ones it has are done (RFC 9113 Section 6.8).
    peer_goaway: bool,
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
    /// Invoked with a [`std::io::Error`] whenever a stream fails.
    stream_error_callback: Option<crate::StreamErrorCallback>,
    /// First connection-level protocol error seen (set by [`Connection::goaway`]).
    connection_error: Option<std::io::Error>,
    stream_header_timeouts: futures_util::stream::FuturesUnordered<HeaderTimeoutFut>,
    stream_header_timeouts_cancel: FxHashMap<u32, CancellationToken>,
}

impl<Io> Connection<Io>
where
    Io: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    /// Creates a connection osver `io`, with header read timeout.
    #[inline]
    pub fn new(
        io: Io,
        preface_timeout: Option<Duration>,
        header_read_timeout: Option<Duration>,
    ) -> Connection<Io> {
        Connection {
            io,
            decoder: FrameDecoder::new(DEFAULT_MAX_FRAME_SIZE),
            writer: FrameWriter::new(DEFAULT_MAX_FRAME_SIZE),
            out: Vec::new(),
            encoder: Encoder::new(4096),
            request_decoder: HpackDecoder::new(4096),
            peer: PeerSettings::default(),
            preface_timeout,
            header_read_timeout,
            streams: FxHashMap::default(),
            conn_window: DEFAULT_CONNECTION_WINDOW_SIZE as i64,
            closed_streams: FxHashSet::default(),
            closed_order: VecDeque::new(),
            opts: ConnectionOptions::default(),
            local_error_resets: 0,
            pending_accept_resets: 0.0,
            pending_accept_since: std::time::Instant::now(),
            wake_tx: None,
            complete_blocks: VecDeque::new(),
            max_continuation_frames: 16,
            drain_ids: Vec::new(),
            outbound_ids: Vec::new(),
            outbound_msgs: Vec::new(),
            highest_stream_id: 0,
            closing: false,
            graceful: false,
            peer_goaway: false,
            graceful_last_stream: 0,
            shutdown: None,
            date_cache: Arc::new(DateCache::new()),
            frame_buffer: Vec::new(),
            stream_error_callback: None,
            connection_error: None,
            stream_header_timeouts: futures_util::stream::FuturesUnordered::new(),
            stream_header_timeouts_cancel: FxHashMap::default(),
        }
    }

    /// Arms a [`CancellationToken`] that triggers a graceful shutdown:
    /// GOAWAY, then drain in-flight streams (RFC 9113 Section 6.8).
    #[inline]
    pub fn with_shutdown(mut self, token: CancellationToken) -> Self {
        self.shutdown = Some(token);
        self
    }

    /// Attaches a stream error callback invoked with a [`std::io::Error`]
    /// whenever a stream fails.
    #[inline]
    pub fn with_stream_error_callback(mut self, callback: crate::StreamErrorCallback) -> Self {
        self.stream_error_callback = Some(callback);
        self
    }

    /// Reports a stream failure to the configured callback, if any.
    #[inline]
    pub(crate) fn report_stream_error(&self, stream_id: u32, message: impl Into<String>) {
        if let Some(callback) = self.stream_error_callback.as_ref() {
            let error = crate::stream_error_io_error(format!(
                "HTTP/2 stream {stream_id} error: {}",
                message.into()
            ));
            callback(error);
        }
    }

    /// Serves requests to completion: peer EOF, GOAWAY received,
    /// preface timeout, or an unrecoverable protocol error.
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
        self.request_decoder
            .set_max_header_list_size(self.opts.max_header_list_size as usize);
        self.decoder
            .set_max_frame_size(self.opts.max_frame_size as usize);
        self.max_continuation_frames = options.max_continuation_frames;

        match self.read_preface().await? {
            None => return Ok(()), // preface timeout: close quietly
            Some(false) => {
                // Invalid preface: connection error PROTOCOL_ERROR
                // (RFC 9113 Section 3.5), then close.
                self.goaway(Reason::ProtocolError, b"invalid connection preface");
                self.flush().await?;
                return Err(self
                    .connection_error
                    .take()
                    .unwrap_or_else(|| std::io::Error::other("invalid connection preface")));
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
                    id: 0x06,
                    value: self.opts.max_header_list_size,
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
        if let Some(window_update) = self
            .opts
            .initial_connection_window_size
            .checked_sub(DEFAULT_CONNECTION_WINDOW_SIZE)
            .filter(|us| *us != 0)
        {
            self.writer
                .write_window_update(&mut self.out, 0, window_update);
        }
        self.flush().await?;

        let (wake_tx, wake_rx) = kanal::bounded_async(1);
        self.wake_tx = Some(wake_tx);
        self.out.reserve(8 * 1024);
        self.frame_buffer.reserve(1024);

        let mut buf = [0u8; 8192];
        let mut wake_rx_drain = Vec::new();
        let mut close = false;
        let mut idle_sleep = self.opts.idle_timeout.map(zincio::time::sleep);
        while !close && !((self.graceful || self.peer_goaway) && self.streams.is_empty()) {
            let wake_recv = wake_rx.recv().fuse();
            let read = tokio::io::AsyncReadExt::read(&mut self.io, &mut buf).fuse();

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
            // peer within `idle_timeout` => graceful shutdown.
            let idle_unfuse = std::pin::pin!(async {
                if let Some(s) = &mut idle_sleep {
                    s.await;
                } else {
                    futures_util::future::pending::<()>().await;
                }
            });
            let mut idle = idle_unfuse.fuse();

            let stream_unfuse = std::pin::pin!(async {
                loop {
                    if self.stream_header_timeouts.is_empty() {
                        futures_util::future::pending::<()>().await;
                    } else {
                        let stream_id = self.stream_header_timeouts.next().await;
                        if let Some(Some(stream_id)) = stream_id {
                            self.stream_header_timeouts_cancel.remove(&stream_id);
                            return stream_id;
                        }
                    }
                }
            });
            let mut stream = stream_unfuse.fuse();

            futures_util::select! {
                stream_id = stream => {
                    self.handle_header_timeout(stream_id);
                    self.drain_outbound();
                    self.flush().await?;
                }
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
                    close = self.process_frames(&request_fn).await?;
                    self.drain_outbound();
                    self.flush().await?;
                    if let (Some(s), Some(t)) = (&mut idle_sleep, self.opts.idle_timeout) {
                        s.reset(std::time::Instant::now() + t);
                    }
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
        if let Some(error) = self.connection_error.take() {
            return Err(error);
        }
        if self.peer_goaway || self.graceful {
            self.linger().await;
        }
        Ok(())
    }

    /// Ends a connection the peer may still be writing to (after a GOAWAY
    /// either way).
    async fn linger(&mut self) {
        let _ = tokio::io::AsyncWriteExt::shutdown(&mut self.io).await;
        let mut buf = [0u8; 4096];
        let _ = zincio::time::timeout(LINGER, async {
            while let Ok(1..) = tokio::io::AsyncReadExt::read(&mut self.io, &mut buf).await {}
        })
        .await;
    }

    /// Reads the 24-octet client preface. `None` means timeout; `false`
    /// means invalid preface.
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
    /// `Ok(true)` when the connection should end at once (an error we
    /// answered with GOAWAY); a peer's GOAWAY only sets `peer_goaway`.
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
                    let raised = self.apply_peer_settings(&settings);
                    self.writer.write_settings_ack(&mut self.out);
                    if raised {
                        // DATA queued on the smaller windows may go now, after the
                        // ACK (the peer counts the new window from it); no
                        // WINDOW_UPDATE need follow to release it.
                        self.drain_pending_data(None);
                    }
                }
                Frame::Settings { ack: true, .. } => {}
                Frame::Ping {
                    ack: false,
                    payload,
                } => {
                    self.writer.write_ping_ack(&mut self.out, &payload);
                }
                Frame::Ping { ack: true, .. } => {}
                // Read on: what came with it is answered, and the streams it
                // leaves run to their end.
                Frame::GoAway { .. } => self.peer_goaway = true,
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
            inner: Box::pin(BodyAdapter { inner: Some(body) }),
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
/// `Send + Sync`.
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
struct BodyAdapter<ResB> {
    inner: Option<ResB>,
}

impl<ResB, ResBE> Body for BodyAdapter<ResB>
where
    ResB: Body<Data = Bytes, Error = ResBE> + Unpin,
    ResBE: std::error::Error + 'static,
{
    type Data = Bytes;
    type Error = std::io::Error;

    #[inline]
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        let this = self.as_mut().get_mut();
        let Some(inner) = this.inner.as_mut() else {
            return Poll::Ready(None);
        };
        match Pin::new(inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => Poll::Ready(Some(Ok(frame))),
            Poll::Ready(Some(Err(error))) => Poll::Ready(Some(Err(e2io(error)))),
            Poll::Ready(None) => {
                this.inner = None;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    #[inline]
    fn size_hint(&self) -> http_body::SizeHint {
        match &self.inner {
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
    /// More data than the request's `content-length`.
    TooLong,
    Gone,
    Ok,
}

mod handlers;

#[cfg(test)]
mod tests;
