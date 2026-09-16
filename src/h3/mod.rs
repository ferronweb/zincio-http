//! Native HTTP/3 server (RFC 9114) over the [`transport`] abstraction.
//!
//! A single connection task owns the control plane ([`control`]) and
//! accept loops; each accepted request stream is handed to its own task
//! through an async [`tokio::sync::Mutex`], sharing the connection's
//! QPACK codecs ([`stream::SharedCodecs`]) with the driver. Requests and
//! responses are streamed with trailers; `100 Continue` and `103 Early
//! Hints` interim responses are supported, as are `Date` header caching
//! and graceful shutdown via a [`CancellationToken`].

mod control;
mod date;
mod error;
mod frame;
mod options;
pub mod qpack;
#[cfg(feature = "h3-quinn")]
pub mod quinn;
mod settings;
mod stream;
pub mod transport;
mod upgrade;

pub use error::{H3Error, TransportError};
pub use frame::{Frame, FrameDecoder, FrameError, Settings};
pub use options::*;

use std::{
    pin::Pin,
    rc::Rc,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::Instant,
};

use bytes::Bytes;
use futures_util::stream::FuturesUnordered;
use futures_util::{ready, Future, FutureExt, StreamExt};
use http::{Request, Response, StatusCode};
use http_body::{Body, Frame as BodyFrame};
use http_body_util::BodyExt;
use tokio_util::sync::CancellationToken;

use crate::{
    h3::{
        control::{ControlEvent, ControlStreams},
        date::DateCache,
        stream::{RequestStream, SharedCodecs, StreamError},
    },
    EarlyHints, HttpProtocol, Incoming, StreamErrorCallback, Upgrade, Upgraded,
};

/// Application error codes from RFC 9114 Section 8.1 used by the driver.
const H3_NO_ERROR: u64 = 0x0100;
const H3_REQUEST_REJECTED: u64 = 0x010b;

/// Per-connection budgets for the resets a hostile peer can force the
/// server to send or observe (RFC 9114 Section 10.5); `None` disables a
/// budget.
#[derive(Debug, Clone, Copy)]
pub(super) struct ResetLimits {
    pub(super) max_local_error_resets: Option<usize>,
    pub(super) max_pending_accept_resets: Option<usize>,
}

/// Connection-level reset accounting, shared between the driver and the
/// per-request tasks (which cannot themselves close the QUIC connection).
#[derive(Debug)]
struct ConnResetState {
    limits: ResetLimits,
    /// RESET_STREAM frames this endpoint has sent for the peer's protocol
    /// errors (bounded by `limits.max_local_error_resets`).
    local_error_resets: usize,
    /// Streams the peer terminated (RESET_STREAM or STOP_SENDING) before
    /// this endpoint accepted them (bounded by
    /// `limits.max_pending_accept_resets`).
    pending_accept_resets: usize,
    /// Application error code the connection must close with; the driver
    /// drains it on its next turn.
    close_code: Option<u64>,
}

impl ConnResetState {
    /// Records a locally sent protocol-error reset; returns the code the
    /// connection must close with when the budget is exceeded.
    #[inline]
    fn note_local_error_reset(&mut self) -> Option<u64> {
        match self.limits.max_local_error_resets {
            Some(max) if self.local_error_resets >= max => Some(H3Error::ExcessiveLoad.code()),
            _ => {
                self.local_error_resets += 1;
                None
            }
        }
    }

    /// Records a peer-terminated, never-accepted stream; returns the code
    /// the connection must close with when the budget is exceeded.
    #[inline]
    fn note_pending_accept_reset(&mut self) -> Option<u64> {
        match self.limits.max_pending_accept_resets {
            Some(max) if self.pending_accept_resets >= max => Some(H3Error::ExcessiveLoad.code()),
            _ => {
                self.pending_accept_resets += 1;
                None
            }
        }
    }
}

/// The shared handle on a request stream: the connection task, the request
/// task, the response body, and a possible upgrade all work through it.
type SharedRequest = Arc<tokio::sync::Mutex<RequestStream>>;

static HTTP3_INVALID_HEADERS: [http::header::HeaderName; 5] = [
    http::header::HeaderName::from_static("keep-alive"),
    http::header::HeaderName::from_static("proxy-connection"),
    http::header::CONNECTION,
    http::header::TRANSFER_ENCODING,
    http::header::UPGRADE,
];

/// The read half of a shared request stream, as a [`Body`].
pub(crate) struct H3Body {
    stream: SharedRequest,
    data_done: bool,
    send_continue_body: Option<Arc<AtomicBool>>,
}

impl H3Body {
    #[inline]
    fn new(stream: SharedRequest, send_continue_body: Option<Arc<AtomicBool>>) -> Self {
        Self {
            stream,
            data_done: false,
            send_continue_body,
        }
    }
}

impl Body for H3Body {
    type Data = Bytes;
    type Error = std::io::Error;

    #[inline]
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<BodyFrame<Self::Data>, Self::Error>>> {
        // Safety: H3Body is Unpin (all fields are Unpin), so we can get &mut Self.
        let this = unsafe { self.get_unchecked_mut() };

        if !this.data_done {
            loop {
                let mut stream = match std::pin::pin!(this.stream.lock()).poll_unpin(cx) {
                    Poll::Ready(stream) => stream,
                    Poll::Pending => return Poll::Pending,
                };
                match stream.poll_recv_data(cx) {
                    Poll::Ready(Ok(Some(data))) => {
                        if data.is_empty() {
                            continue;
                        }
                        return Poll::Ready(Some(Ok(BodyFrame::data(data))));
                    }
                    Poll::Ready(Ok(None)) => {
                        drop(stream);
                        this.data_done = true;
                        break;
                    }
                    Poll::Ready(Err(err)) => {
                        return Poll::Ready(Some(Err(h3_stream_error_to_io(err))));
                    }
                    Poll::Pending => {
                        if let Some(scb) = this.send_continue_body.as_ref() {
                            scb.store(true, std::sync::atomic::Ordering::Relaxed);
                        }
                        return Poll::Pending;
                    }
                };
            }
        }

        let mut stream = match std::pin::pin!(this.stream.lock()).poll_unpin(cx) {
            Poll::Ready(stream) => stream,
            Poll::Pending => {
                if let Some(scb) = this.send_continue_body.as_ref() {
                    scb.store(true, std::sync::atomic::Ordering::Relaxed);
                }
                return Poll::Pending;
            }
        };
        match stream.poll_recv_trailers(cx) {
            Poll::Ready(Ok(Some(trailers))) => Poll::Ready(Some(Ok(BodyFrame::trailers(trailers)))),
            Poll::Ready(Ok(None)) => Poll::Ready(None),
            Poll::Ready(Err(err)) => Poll::Ready(Some(Err(h3_stream_error_to_io(err)))),
            Poll::Pending => {
                if let Some(scb) = this.send_continue_body.as_ref() {
                    scb.store(true, std::sync::atomic::Ordering::Relaxed);
                }
                Poll::Pending
            }
        }
    }
}

#[inline]
fn h3_control_error_to_io(error: control::ControlError) -> std::io::Error {
    std::io::Error::other(error)
}

#[inline]
fn h3_transport_error_to_io(error: TransportError) -> std::io::Error {
    std::io::Error::other(error)
}

#[inline]
fn h3_stream_error_to_io(error: stream::StreamError) -> std::io::Error {
    std::io::Error::other(error)
}

/// Human-readable name for an HTTP/3 application error code, if known.
#[inline]
fn h3_code_name(code: u64) -> String {
    if let Some(known) = crate::h3::error::H3Error::from_code(code) {
        format!("{known:?}")
    } else {
        // QPACK errors live in a separate family (RFC 9204 Section 6).
        match code {
            0x0200 => "QpackDecompressionFailed".to_string(),
            0x0201 => "QpackEncoderStream".to_string(),
            0x0202 => "QpackDecoderStream".to_string(),
            _ => "Unknown".to_string(),
        }
    }
}

/// Builds a clear connection-level [`std::io::Error`] for an HTTP/3
/// connection torn down with the given application error code.
#[inline]
fn h3_connection_error(code: u64, detail: Option<&str>) -> std::io::Error {
    let name = h3_code_name(code);
    match detail {
        Some(detail) => std::io::Error::other(format!(
            "HTTP/3 connection error: {name} ({code:#x}): {detail}"
        )),
        None => std::io::Error::other(format!("HTTP/3 connection error: {name} ({code:#x})")),
    }
}

/// Builds a stream-level [`std::io::Error`] for an HTTP/3 stream failure.
#[inline]
fn h3_stream_error(stream_id: u64, error: &impl std::fmt::Display) -> std::io::Error {
    std::io::Error::other(format!("HTTP/3 stream {stream_id} error: {error}"))
}

#[inline]
fn remove_invalid_http3_headers(headers: &mut http::HeaderMap) {
    for header in &HTTP3_INVALID_HEADERS {
        headers.remove(header);
    }
    if headers
        .get(http::header::TE)
        .is_some_and(|v| v != "trailers")
    {
        headers.remove(http::header::TE);
    }
}

/// Waits until the peer's SETTINGS bound the QPACK encoder, so field
/// sections can be encoded (RFC 9204 Section 5).
///
/// The control plane wakes this task via `encoder_notify` when the
/// SETTINGS frame arrives; no per-stream waker map is needed.
#[inline]
async fn wait_for_encoder(shared: &Arc<SharedCodecs>, _stream_id: u64) {
    loop {
        if shared.encoder.lock().is_some() {
            return;
        }
        shared.encoder_notify.notified().await;
    }
}

/// Writes an interim (1xx) response HEADERS frame.
#[inline]
async fn send_interim_response(
    stream: &SharedRequest,
    status: StatusCode,
) -> Result<(), std::io::Error> {
    let mut guard = stream.lock().await;
    std::future::poll_fn(|cx| guard.poll_send_response(cx, status, &http::HeaderMap::new()))
        .await
        .map_err(h3_stream_error_to_io)
}

/// Writes the response HEADERS frame for `status`/`headers`, waiting for
/// the peer's SETTINGS first.
#[inline]
async fn send_response(
    stream: &SharedRequest,
    shared: &Arc<SharedCodecs>,
    stream_id: u64,
    status: StatusCode,
    headers: &http::HeaderMap,
) -> Result<(), std::io::Error> {
    wait_for_encoder(shared, stream_id).await;
    let mut guard = stream.lock().await;
    let res = std::future::poll_fn(|cx| guard.poll_send_response(cx, status, headers))
        .await
        .map_err(h3_stream_error_to_io);
    res
}

/// Writes one response DATA frame.
#[inline]
async fn send_data(stream: &SharedRequest, data: Bytes) -> Result<(), std::io::Error> {
    let mut guard = stream.lock().await;
    std::future::poll_fn(|cx| guard.poll_send_data(cx, data.clone()))
        .await
        .map_err(h3_stream_error_to_io)
}

/// Writes the response trailers HEADERS frame.
#[inline]
async fn send_trailers(
    stream: &SharedRequest,
    trailers: &http::HeaderMap,
) -> Result<(), std::io::Error> {
    let mut guard = stream.lock().await;
    std::future::poll_fn(|cx| guard.poll_send_trailers(cx, trailers))
        .await
        .map_err(h3_stream_error_to_io)
}

/// Finishes the response (`FIN`).
#[inline]
async fn send_finish(stream: &SharedRequest) -> Result<(), std::io::Error> {
    let mut guard = stream.lock().await;
    let result = std::future::poll_fn(|cx| guard.poll_finish(cx))
        .await
        .map_err(h3_stream_error_to_io);
    let result2 = std::future::poll_fn(|cx| guard.poll_stopped(cx))
        .await
        .map_err(h3_stream_error_to_io);
    result.or(result2)
}

/// A request task's end is observed by the connection driver through the
/// oneshot completion channel it holds in its `FuturesUnordered`; the
/// sender is dropped when the task finishes.
///
/// Drives one accepted request stream to completion.
#[allow(clippy::type_complexity)]
#[allow(clippy::too_many_arguments)]
async fn handle_request<F, Fut, ResB, ResBE, ResE>(
    stream: SharedRequest,
    shared: Arc<SharedCodecs>,
    stream_id: u64,
    request_fn: Rc<F>,
    date_cache: DateCache,
    send_continue_response: bool,
    send_date_header: bool,
    conn_state: Arc<parking_lot::Mutex<ConnResetState>>,
    stream_error_callback: Option<StreamErrorCallback>,
) where
    F: Fn(Request<Incoming>) -> Fut,
    Fut: std::future::Future<Output = Result<Response<ResB>, ResE>>,
    ResB: Body<Data = Bytes, Error = ResBE> + Unpin,
    ResE: std::error::Error,
    ResBE: std::error::Error,
{
    #[inline]
    fn report(
        callback: &Option<StreamErrorCallback>,
        stream_id: u64,
        error: impl std::fmt::Display,
    ) {
        if let Some(callback) = callback.as_ref() {
            callback(h3_stream_error(stream_id, &error));
        }
    }
    // Read the request.
    let request_headers = {
        let mut guard = stream.lock().await;
        std::future::poll_fn(|cx| guard.poll_headers(cx)).await
    };
    let request = match request_headers {
        Ok(Some(request)) => request,
        // The stream ended without a request: nothing to respond to.
        Ok(None) => return,
        Err(err) => {
            // The peer terminated the stream (RESET_STREAM or
            // STOP_SENDING) before its request was read: a reset for a
            // stream that never reached the handler. Bound how many of
            // these a peer may churn through (RFC 9114 Section 10.5).
            if err.is_stream_scoped() {
                report(&stream_error_callback, stream_id, &err);
                let mut state = conn_state.lock();
                if let Some(code) = state.note_pending_accept_reset() {
                    state.close_code = Some(code);
                }
                return;
            }
            // A malformed request message: abort the stream with
            // `H3_MESSAGE_ERROR` rather than the whole connection (RFC
            // 9114 Section 4.1.2), bounded by the local-reset budget.
            if matches!(err, StreamError::Message) {
                report(&stream_error_callback, stream_id, &err);
                let mut guard = stream.lock().await;
                let code = err.h3_code();
                let _ = std::future::poll_fn(|cx| guard.poll_reset(cx, code)).await;
                let _ = std::future::poll_fn(|cx| guard.poll_stop_sending(cx, code)).await;
                drop(guard);
                let mut state = conn_state.lock();
                if let Some(code) = state.note_local_error_reset() {
                    state.close_code = Some(code);
                }
                return;
            }
            // A connection-scoped protocol violation (a malformed frame,
            // an invalid frame sequence, or a QPACK error): force the
            // connection to close with the matching H3 code.
            conn_state.lock().close_code = Some(err.h3_code());
            return;
        }
    };

    // 100 Continue
    let is_100_continue = send_continue_response
        && request
            .headers()
            .get(http::header::EXPECT)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.eq_ignore_ascii_case("100-continue"));

    let send_continue_body = is_100_continue.then(|| Arc::new(AtomicBool::new(false)));
    let (request_parts, _) = request.into_parts();
    let (request_body, upgrade) = if request_parts.method == http::Method::CONNECT {
        (Incoming::Empty, Some(stream.clone()))
    } else {
        (
            Incoming::Boxed(Box::pin(H3Body::new(
                stream.clone(),
                send_continue_body.clone(),
            ))),
            None,
        )
    };
    let mut request = Request::from_parts(request_parts, request_body);

    // Install early hints
    let (early_hints, mut early_hints_rx) = EarlyHints::new_lazy();
    request.extensions_mut().insert(early_hints);

    // Install HTTP upgrade
    let upgrade = if let Some(recv_stream) = upgrade {
        let (upgrade_tx, upgrade_rx) = oneshot::async_channel();
        let upgrade = Upgrade::new(upgrade_rx);
        let upgraded = upgrade.upgraded.clone();
        request.extensions_mut().insert(upgrade);
        Some((upgrade_tx, upgraded, recv_stream))
    } else {
        None
    };

    let mut response_fut = std::pin::pin!(request_fn(request));
    let mut early_hints_open = true;
    let mut continue_sent = false;
    let response_result = loop {
        if !early_hints_open {
            break response_fut.as_mut().await;
        }

        let next = std::future::poll_fn(|cx| {
            if let Poll::Ready(res) = response_fut.as_mut().poll(cx) {
                return Poll::Ready(Some(futures_util::future::Either::Left(res)));
            }

            match early_hints_rx.poll_recv(cx) {
                Poll::Ready(Some(msg)) => {
                    return Poll::Ready(Some(futures_util::future::Either::Right(Ok(msg))))
                }
                Poll::Ready(None) => {
                    return Poll::Ready(Some(futures_util::future::Either::Right(Err(()))))
                }
                Poll::Pending => {}
            }

            if !continue_sent
                && is_100_continue
                && send_continue_body
                    .as_ref()
                    .is_some_and(|b| b.load(Ordering::Relaxed))
            {
                continue_sent = true;
                return Poll::Ready(None);
            }

            Poll::Pending
        })
        .await;

        match next {
            // HTTP response
            Some(futures_util::future::Either::Left(response_result)) => {
                break response_result;
            }
            // 103 Early Hints
            Some(futures_util::future::Either::Right(Ok((headers, sender)))) => {
                sender
                    .into_inner()
                    .send(
                        send_response(
                            &stream,
                            &shared,
                            stream_id,
                            StatusCode::EARLY_HINTS,
                            &headers,
                        )
                        .await,
                    )
                    .ok();
            }
            Some(futures_util::future::Either::Right(Err(()))) => {
                early_hints_open = false;
            }
            // 100 Continue
            None => {
                if let Err(error) = send_interim_response(&stream, StatusCode::CONTINUE).await {
                    report(&stream_error_callback, stream_id, &error);
                    return;
                }
            }
        }
    };

    let Ok(mut response) = response_result else {
        // Return early if the request handler returns an error
        if let Err(error) = response_result {
            report(
                &stream_error_callback,
                stream_id,
                format_args!("request handler error: {error}"),
            );
        }
        return;
    };

    {
        let response_headers = response.headers_mut();
        if send_date_header {
            if let Some(http_date) = date_cache.get_date_header_value() {
                response_headers
                    .entry(http::header::DATE)
                    .or_insert(http_date);
            }
        }
        remove_invalid_http3_headers(response_headers);
    }

    let response_is_end_stream = response.body().is_end_stream();
    if !response_is_end_stream {
        if let Some(content_length) = response.body().size_hint().exact() {
            if !response
                .headers()
                .contains_key(http::header::CONTENT_LENGTH)
            {
                response
                    .headers_mut()
                    .insert(http::header::CONTENT_LENGTH, content_length.into());
            }
        }
    }

    if is_100_continue
        && !continue_sent
        && !response.status().is_client_error()
        && !response.status().is_server_error()
    {
        if let Err(error) = send_interim_response(&stream, StatusCode::CONTINUE).await {
            report(&stream_error_callback, stream_id, &error);
            return;
        }
    }

    let (response_parts, mut response_body) = response.into_parts();
    if let Err(error) = send_response(
        &stream,
        &shared,
        stream_id,
        response_parts.status,
        &response_parts.headers,
    )
    .await
    {
        report(&stream_error_callback, stream_id, &error);
        return;
    }

    if let Some((upgrade_tx, upgraded, recv_stream)) = upgrade {
        if upgraded.load(Ordering::Relaxed) {
            let (upgraded, task) = self::upgrade::pair(recv_stream);
            let _ = upgrade_tx.send(Upgraded::new(upgraded, None));
            task.await;
            return;
        }
    }

    if !response_is_end_stream {
        while let Some(chunk) = response_body.frame().await {
            match chunk {
                Ok(frame) => {
                    if frame.is_data() {
                        match frame.into_data() {
                            Ok(data) => {
                                if data.is_empty() {
                                    // Don't waste bandwidth using empty frames...
                                    continue;
                                }
                                if let Err(error) = send_data(&stream, data).await {
                                    report(&stream_error_callback, stream_id, &error);
                                    return;
                                }
                            }
                            Err(_) => {
                                report(
                                    &stream_error_callback,
                                    stream_id,
                                    "response body data frame error",
                                );
                                return;
                            }
                        }
                    } else if frame.is_trailers() {
                        match frame.into_trailers() {
                            Ok(mut trailers) => {
                                remove_invalid_http3_headers(&mut trailers);
                                if let Err(error) = send_trailers(&stream, &trailers).await {
                                    report(&stream_error_callback, stream_id, &error);
                                    return;
                                }
                                break;
                            }
                            Err(_) => {
                                report(
                                    &stream_error_callback,
                                    stream_id,
                                    "response body trailers frame error",
                                );
                                return;
                            }
                        }
                    }
                }
                Err(error) => {
                    report(
                        &stream_error_callback,
                        stream_id,
                        format_args!("response body error: {error}"),
                    );
                    return;
                }
            }
        }
    }

    if let Err(error) = send_finish(&stream).await {
        report(&stream_error_callback, stream_id, &error);
    }
}

/// An HTTP/3 connection handler.
///
/// `Http3` wraps a QUIC connection (`Io`) and drives the HTTP/3 server
/// connection over the native transport stack. It supports:
///
/// - Concurrent request stream handling
/// - Streaming request/response bodies and trailers
/// - Automatic `100 Continue` and `103 Early Hints` interim responses
/// - Per-connection `Date` header caching
/// - Graceful shutdown via a [`CancellationToken`]
///
/// # Construction
///
/// ```rust,ignore
/// let http3 = Http3::new(quic_connection, Http3Options::default());
/// ```
///
/// # Serving requests
///
/// Use the [`HttpProtocol`] trait methods ([`handle`](HttpProtocol::handle) /
/// [`handle_with_error_fn`](HttpProtocol::handle_with_error_fn)) to drive the
/// connection to completion.
pub struct Http3<Io> {
    io_to_handshake: Option<Io>,
    date_header_value_cached: DateCache,
    options: Http3Options,
    cancel_token: Option<CancellationToken>,
    stream_error_callback: Option<StreamErrorCallback>,
}

impl<Io> Http3<Io>
where
    Io: transport::Connection + Unpin + 'static,
{
    /// Creates a new `Http3` connection handler wrapping the given QUIC
    /// connection.
    ///
    /// The `options` value controls HTTP/3 protocol configuration, connection
    /// setup and accept timeouts, and optional behaviour such as automatic
    /// `100 Continue` responses; see [`Http3Options`] for details.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let http3 = Http3::new(quic_connection, Http3Options::default());
    /// ```
    #[inline]
    pub fn new(io: Io, options: Http3Options) -> Self {
        Self {
            io_to_handshake: Some(io),
            date_header_value_cached: DateCache::default(),
            options,
            cancel_token: None,
            stream_error_callback: None,
        }
    }

    /// Attaches a [`CancellationToken`] for graceful shutdown.
    ///
    /// When the token is cancelled, the handler sends an HTTP/3 graceful
    /// shutdown signal (GOAWAY), stops accepting new request streams, and
    /// exits cleanly once the in-flight requests have drained.
    #[inline]
    pub fn graceful_shutdown_token(mut self, token: CancellationToken) -> Self {
        self.cancel_token = Some(token);
        self
    }

    /// Attaches a stream error callback invoked with a [`std::io::Error`]
    /// whenever an HTTP/3 stream fails (for example a malformed request,
    /// a reset by the peer, or a response write failure).
    ///
    /// Connection-level failures continue to surface as the `Err` return
    /// value of [`HttpProtocol::handle`]; this callback only observes
    /// per-stream failures so they can be logged.
    #[inline]
    pub fn stream_error_callback<F>(mut self, callback: F) -> Self
    where
        F: Fn(std::io::Error) + Send + Sync + 'static,
    {
        self.stream_error_callback = Some(std::sync::Arc::new(callback));
        self
    }
}

impl<Io> HttpProtocol for Http3<Io>
where
    Io: transport::Connection + Unpin + 'static,
{
    #[allow(clippy::manual_async_fn)]
    #[inline]
    fn handle<F, Fut, ResB, ResBE, ResE>(
        self,
        request_fn: F,
    ) -> impl std::future::Future<Output = Result<(), std::io::Error>>
    where
        F: Fn(Request<super::Incoming>) -> Fut + 'static,
        Fut: std::future::Future<Output = Result<Response<ResB>, ResE>> + 'static,
        ResB: http_body::Body<Data = bytes::Bytes, Error = ResBE> + Unpin + 'static,
        ResE: std::error::Error + 'static,
        ResBE: std::error::Error + 'static,
    {
        async move {
            let request_fn = Rc::new(request_fn);
            let Http3 {
                mut io_to_handshake,
                date_header_value_cached,
                options,
                cancel_token,
                stream_error_callback,
            } = self;
            let mut conn = io_to_handshake
                .take()
                .ok_or_else(|| std::io::Error::other("no io to handshake"))?;
            let date_cache = date_header_value_cached;
            let send_continue_response = options.send_continue_response;
            let send_date_header = options.send_date_header;

            // The QUIC handshake may not be complete yet (0-RTT); wait for
            // it, bounded by the handshake timeout. Server-side QUIC
            // connections are already complete when handed over.
            if let Some(timeout) = options.handshake_timeout {
                zincio::time::timeout(timeout, async {
                    while !conn.is_handshake_complete() {
                        zincio::time::sleep(std::time::Duration::from_millis(1)).await;
                    }
                })
                .await
                .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "handshake timeout")
                })?;
            } else {
                while !conn.is_handshake_complete() {
                    zincio::time::sleep(std::time::Duration::from_millis(1)).await;
                }
            }

            let mut controls = ControlStreams::new(options.local_settings.clone());
            let shared = controls.shared().clone();
            // Request-stream tasks record connection-scoped errors and reset
            // accounting here; the driver closes the connection with the
            // recorded H3 code (a request task cannot itself close the QUIC
            // connection).
            let conn_state: Arc<parking_lot::Mutex<ConnResetState>> =
                Arc::new(parking_lot::Mutex::new(ConnResetState {
                    limits: ResetLimits {
                        max_local_error_resets: options.max_local_error_reset_streams,
                        max_pending_accept_resets: options.max_pending_accept_reset_streams,
                    },
                    local_error_resets: 0,
                    pending_accept_resets: 0,
                    close_code: None,
                }));
            let mut ongoing: FuturesUnordered<oneshot::AsyncReceiver<()>> = FuturesUnordered::new();
            let mut cancel_fut: Option<Pin<Box<dyn std::future::Future<Output = ()> + Send>>> =
                None;
            if let Some(token) = cancel_token.as_ref() {
                cancel_fut = Some(Box::pin(token.cancelled()));
            }
            let mut accept_sleep: Option<zincio::time::Sleep> = None;
            let mut shutdown_sleep: Option<zincio::time::Sleep> = None;
            // Once graceful shutdown has drained every in-flight request we
            // must not issue `CONNECTION_CLOSE` immediately: quinn's
            // `close()` sends exactly one frame and then stops transmitting,
            // discarding any response bytes still buffered in the send
            // scheduler. A short grace window lets the background transmit
            // flush those bytes so the peer observes the response, not the
            // close.
            let mut drain_grace: Option<zincio::time::Sleep> = None;
            let mut shutdown = false;
            let mut control_dead = false;
            // When set, the connection is being torn down by a protocol error
            // and must close with this H3 code (rather than the graceful
            // GOAWAY + H3_NO_ERROR path).
            let mut closing_with: Option<u64> = None;
            // Human-readable detail for `closing_with`, when the error that
            // triggered the close carried more context than its code.
            let mut closing_detail: Option<String> = None;
            let mut outcome: Option<Result<(), std::io::Error>> = None;
            let mut last_request_id = 0u64;

            // Bring up the control plane (control stream plus QPACK
            // encoder/decoder streams) and write the initial SETTINGS.
            std::future::poll_fn(|cx| -> Poll<Result<(), std::io::Error>> {
                ready!(controls
                    .poll_init(&mut conn, cx)
                    .map_err(h3_control_error_to_io))?;
                ready!(controls.poll_flush(cx).map_err(h3_control_error_to_io))?;
                Poll::Ready(Ok(()))
            })
            .await?;

            std::future::poll_fn(|cx| loop {
                // A request-stream task hit a connection-scoped error: close
                // the connection with the H3 code it recorded.
                if let Some(code) = conn_state.lock().close_code.take() {
                    if closing_with.is_none() {
                        closing_with = Some(code);
                        shutdown = true;
                        control_dead = true;
                    }
                }

                // Accept-timeout window: refreshed whenever a request
                // stream is accepted; it bounds waiting for the next one.
                let mut timeout_fired = false;
                if let Some(sleep) = accept_sleep.as_mut() {
                    if let Poll::Ready(()) = Pin::new(&mut *sleep).poll(cx) {
                        accept_sleep = None;
                        timeout_fired = true;
                    }
                } else if let Some(accept_timeout) = options.accept_timeout {
                    accept_sleep = Some(zincio::time::sleep(accept_timeout));
                    continue;
                }

                // Shutdown backstop: while graceful shutdown is pending on
                // in-flight requests, re-poll periodically so the close
                // with `H3_NO_ERROR` cannot be starved by a lost wake-up.
                if let Some(sleep) = shutdown_sleep.as_mut() {
                    if let Poll::Ready(()) = Pin::new(&mut *sleep).poll(cx) {
                        sleep.reset(Instant::now() + std::time::Duration::from_millis(10));
                    }
                }

                // Graceful shutdown trigger.
                let mut cancel_fired = false;
                if let Some(fut) = cancel_fut.as_mut() {
                    if let Poll::Ready(()) = fut.as_mut().poll(cx) {
                        cancel_fired = true;
                    }
                }
                if !shutdown {
                    if cancel_fired {
                        shutdown = true;
                        outcome = Some(Ok(()));
                    } else if timeout_fired {
                        shutdown = true;
                        outcome = Some(Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "accept timeout",
                        )));
                    }
                }

                // Hand the request streams' queued QPACK encoder
                // instructions to the control plane.
                controls.queue_encoder_streams_from_shared(&shared);

                // Write the control plane's outbound streams. If the peer tore
                // it down while we were shutting down (e.g. an h3 0.0.8 client
                // resets its receive side once it sees GOAWAY), we stop trying
                // to flush — the connection is already draining — but we must
                // NOT close yet: in-flight requests still need to be served so
                // the peer receives their responses before the application
                // close. `control_dead` records that state so we neither spin
                // on a terminal error nor send a close prematurely.
                if !control_dead {
                    match controls.poll_flush(cx) {
                        Poll::Ready(Ok(())) => {}
                        Poll::Ready(Err(err)) => {
                            if shutdown {
                                control_dead = true;
                            } else {
                                closing_with = Some(err.h3_code());
                                closing_detail = Some(err.to_string());
                                shutdown = true;
                                control_dead = true;
                            }
                        }
                        Poll::Pending => {}
                    }
                }

                // Read the peer's control plane and react to its events.
                if !control_dead {
                    loop {
                        match controls.poll_read(&mut conn, cx) {
                            Poll::Ready(Ok(Some(ControlEvent::Goaway { .. }))) => {
                                // The client is going away: stop accepting new
                                // request streams and close once the in-flight
                                // ones drain.
                                if !shutdown {
                                    shutdown = true;
                                    outcome = Some(Ok(()));
                                }
                            }
                            Poll::Ready(Ok(Some(_))) => {}
                            Poll::Ready(Ok(None)) => {}
                            Poll::Ready(Err(err)) => {
                                if shutdown {
                                    control_dead = true;
                                    break;
                                }
                                closing_with = Some(err.h3_code());
                                closing_detail = Some(err.to_string());
                                shutdown = true;
                                control_dead = true;
                                break;
                            }
                            Poll::Pending => break,
                        }
                    }
                }

                // Shutdown: either a protocol error (close immediately with
                // the recorded H3 code) or a graceful drain (GOAWAY, then
                // H3_NO_ERROR once every in-flight request has drained).
                if shutdown {
                    if let Some(code) = closing_with {
                        ready!(conn
                            .poll_shutdown(cx, code)
                            .map_err(h3_transport_error_to_io))?;
                        if let Some(outcome) = outcome.take() {
                            return Poll::Ready(outcome);
                        }
                        return Poll::Ready(Err(h3_connection_error(
                            code,
                            closing_detail.as_deref(),
                        )));
                    }
                    if controls.goaway_sent().is_none() {
                        controls.send_goaway(last_request_id);
                    }
                    if ongoing.is_empty() {
                        // Give the send scheduler a grace window to flush
                        // the last response before we close. See the comment
                        // on `drain_grace` above.
                        if let Some(grace) = drain_grace.as_mut() {
                            if Pin::new(&mut *grace).poll(cx).is_ready() {
                                ready!(conn
                                    .poll_shutdown(cx, H3_NO_ERROR)
                                    .map_err(h3_transport_error_to_io))?;
                                return Poll::Ready(outcome.take().unwrap_or(Ok(())));
                            }
                        } else {
                            drain_grace =
                                Some(zincio::time::sleep(std::time::Duration::from_millis(50)));
                        }
                    } else if shutdown_sleep.is_none() {
                        shutdown_sleep =
                            Some(zincio::time::sleep(std::time::Duration::from_millis(10)));
                    }
                }

                // Accept request streams.
                loop {
                    match conn.poll_accept(cx) {
                        Poll::Ready(Ok(Some(stream))) => {
                            let id = stream.id();
                            last_request_id = last_request_id.max(id);
                            if let Some(sleep) = accept_sleep.as_mut() {
                                if let Some(timeout) = options.accept_timeout {
                                    sleep.reset(Instant::now() + timeout);
                                } else {
                                    accept_sleep = None;
                                }
                            } else {
                                accept_sleep = None;
                            }
                            if shutdown
                                && (controls.goaway_sent().is_none()
                                    || id > controls.goaway_sent().unwrap_or(u64::MAX))
                            {
                                // A request after our GOAWAY: reject it
                                // (RFC 9114 Section 5.2).
                                let mut rejected = RequestStream::new(stream, shared.clone());
                                let _ = rejected.poll_reset(cx, H3_REQUEST_REJECTED);
                            } else {
                                let (end_tx, end_rx) = oneshot::async_channel();
                                ongoing.push(end_rx);
                                let request_stream = Arc::new(tokio::sync::Mutex::new(
                                    RequestStream::new(stream, shared.clone()),
                                ));
                                let request_fn = request_fn.clone();
                                let date_cache = date_cache.clone();
                                let shared = shared.clone();
                                let conn_state_for_task = conn_state.clone();
                                let stream_error_callback = stream_error_callback.clone();
                                zincio::spawn(async move {
                                    let _end = end_tx;
                                    handle_request(
                                        request_stream,
                                        shared.clone(),
                                        id,
                                        request_fn,
                                        date_cache,
                                        send_continue_response,
                                        send_date_header,
                                        conn_state_for_task,
                                        stream_error_callback,
                                    )
                                    .await;
                                });
                            }
                        }
                        // The connection closed: nothing left to do.
                        Poll::Ready(Ok(None)) => {
                            return Poll::Ready(Ok(()));
                        }
                        Poll::Ready(Err(err)) => {
                            return Poll::Ready(Err(h3_transport_error_to_io(err)));
                        }
                        Poll::Pending => {
                            break;
                        }
                    }
                }

                // Collect finished request tasks. Their completion
                // receivers were registered on first poll, so parking
                // below wakes whenever one finishes; a completion can
                // race the registration, so re-check before parking. An
                // empty set yields `None` from `poll_next` (there are no
                // completions to observe).
                match ongoing.poll_next_unpin(cx) {
                    Poll::Ready(Some(Ok(()))) => continue,
                    Poll::Ready(Some(Err(_))) => continue,
                    Poll::Ready(None) => {}
                    Poll::Pending => {}
                }
                if ongoing.is_empty() && shutdown {
                    continue;
                }

                return Poll::Pending;
            })
            .await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_error_message_includes_stream_id() {
        let error = h3_stream_error(9, &"reset by peer with code 0xc");
        let text = error.to_string();
        assert!(text.contains("stream 9"), "got: {text}");
        assert!(text.contains("reset by peer"), "got: {text}");
    }

    #[test]
    fn connection_error_names_known_codes() {
        let error = h3_connection_error(H3Error::GeneralProtocol.code(), None);
        let text = error.to_string();
        assert!(text.contains("HTTP/3 connection error"), "got: {text}");
        assert!(text.contains("GeneralProtocol"), "got: {text}");
        assert!(text.contains("0x101"), "got: {text}");
    }

    #[test]
    fn connection_error_carries_detail() {
        let error = h3_connection_error(H3Error::FrameUnexpected.code(), Some("bad frame"));
        let text = error.to_string();
        assert!(text.contains("FrameUnexpected"), "got: {text}");
        assert!(text.contains("bad frame"), "got: {text}");
    }

    #[test]
    fn unknown_code_is_reported_as_unknown() {
        assert_eq!(h3_code_name(0x0101), "GeneralProtocol");
        assert_eq!(h3_code_name(0x0200), "QpackDecompressionFailed");
        assert_eq!(h3_code_name(0xdead_beef), "Unknown");
    }
}
