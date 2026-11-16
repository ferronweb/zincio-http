//! Native HTTP/3 server (RFC 9114) over the [`transport`] abstraction.
//!
//! A connection task owns the control plane and accepts request streams,
//! each handled by its own task over the shared QPACK codecs ([`stream::SharedCodecs`]).

mod control;
mod date;
mod error;
mod frame;
mod options;
#[cfg(feature = "unstable-internals")]
pub mod qpack;
#[cfg(not(feature = "unstable-internals"))]
mod qpack;
#[cfg(feature = "h3-quinn")]
pub mod quinn;
mod settings;
mod stream;
#[cfg(feature = "unstable-internals")]
pub mod transport;
#[cfg(not(feature = "unstable-internals"))]
mod transport;
mod upgrade;

#[cfg(feature = "unstable-internals")]
pub use error::{H3Error, TransportError};
#[cfg(not(feature = "unstable-internals"))]
use error::{H3Error, TransportError};
#[cfg(feature = "unstable-internals")]
pub use frame::{
    Frame, FrameDecoder, FrameError, Settings, MAX_FRAME_PAYLOAD, MAX_SETTINGS_ENTRIES,
    MAX_SETTINGS_PAYLOAD,
};

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
    response::sanitize_response_headers,
    EarlyHints, HttpProtocol, Incoming, StreamErrorCallback, Upgrade, Upgraded,
};

/// Application error codes from RFC 9114 Section 8.1 used by the driver.
const H3_NO_ERROR: u64 = 0x0100;
const H3_REQUEST_REJECTED: u64 = 0x010b;

/// How fast the budget for streams reset before acceptance refills
/// (`ConnResetState::note_pending_accept_reset`).
const PENDING_ACCEPT_RESETS_PER_SECOND: f64 = 50.0;

/// Per-connection budgets for resets a hostile peer can force (RFC 9114
/// Section 10.5); `None` disables a budget.
#[derive(Debug, Clone, Copy)]
pub(super) struct ResetLimits {
    pub(super) max_local_error_resets: Option<usize>,
    pub(super) max_pending_accept_resets: Option<usize>,
}

/// Reset accounting shared by the driver and request tasks.
#[derive(Debug)]
struct ConnResetState {
    limits: ResetLimits,
    /// Protocol-error resets this endpoint has sent.
    local_error_resets: usize,
    /// Streams the peer terminated before acceptance; drains over time.
    pending_accept_resets: f64,
    /// When `pending_accept_resets` was last drained.
    pending_accept_since: Instant,
    /// Application error code the driver must close with.
    close_code: Option<u64>,
}

impl ConnResetState {
    /// Records a locally sent reset, returning a close code when the budget
    /// is exceeded.
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

    /// Records a peer reset before acceptance, refilling the budget over
    /// time. Rapid Reset still exhausts it.
    #[inline]
    fn note_pending_accept_reset(&mut self, now: Instant) -> Option<u64> {
        let max = self.limits.max_pending_accept_resets?;
        let elapsed = now.saturating_duration_since(self.pending_accept_since);
        let drained = elapsed.as_secs_f64() * PENDING_ACCEPT_RESETS_PER_SECOND;
        self.pending_accept_resets = (self.pending_accept_resets - drained).max(0.0) + 1.0;
        self.pending_accept_since = now;
        #[allow(clippy::cast_precision_loss)]
        let over = self.pending_accept_resets > max as f64;
        over.then(|| H3Error::ExcessiveLoad.code())
    }
}

/// The shared handle on a request stream: the connection task, the request
/// task, the response body, and a possible upgrade all work through it.
type SharedRequest = Arc<tokio::sync::Mutex<RequestStream>>;

/// The read half of a shared request stream, as a [`Body`].
pub(crate) struct H3Body {
    stream: SharedRequest,
    data_done: bool,
    send_continue_body: Option<Arc<AtomicBool>>,
    /// The connection's reset accounting, so body-time failures can still
    /// close the connection.
    conn_state: Arc<parking_lot::Mutex<ConnResetState>>,
    content_length: Option<u64>,
    data_read: u64,
}

impl H3Body {
    #[inline]
    fn new(
        stream: SharedRequest,
        send_continue_body: Option<Arc<AtomicBool>>,
        conn_state: Arc<parking_lot::Mutex<ConnResetState>>,
        content_length: Option<u64>,
    ) -> Self {
        Self {
            stream,
            data_done: false,
            send_continue_body,
            conn_state,
            content_length,
            data_read: 0,
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

        if this.content_length.is_some_and(|cl| this.data_read > cl) {
            return Poll::Ready(Some(Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "content length exceeded",
            ))));
        }

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
                        this.data_read += data.len() as u64;
                        return Poll::Ready(Some(Ok(BodyFrame::data(data))));
                    }
                    Poll::Ready(Ok(None)) => {
                        drop(stream);
                        this.data_done = true;
                        break;
                    }
                    Poll::Ready(Err(err)) => {
                        report_connection_error(&this.conn_state, &err);
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

        if this.content_length.is_some_and(|cl| this.data_read != cl) {
            return Poll::Ready(Some(Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "content length doesn't match actual body size",
            ))));
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
            Poll::Ready(Err(err)) => {
                report_connection_error(&this.conn_state, &err);
                Poll::Ready(Some(Err(h3_stream_error_to_io(err))))
            }
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

/// Records a connection-scoped failure that surfaced while the request body
/// was read. A QPACK failure while decoding trailers must still close the
/// connection (RFC 9204 Section 6).
#[inline]
fn report_connection_error(
    conn_state: &Arc<parking_lot::Mutex<ConnResetState>>,
    error: &stream::StreamError,
) {
    if let stream::StreamError::Qpack(err) = error {
        conn_state.lock().close_code = Some(err.code() as u64);
    }
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

/// Waits until the peer's SETTINGS bound the QPACK encoder.
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

/// Ends a response that cannot be completed with `H3_INTERNAL_ERROR`.
async fn abort(stream: &SharedRequest) {
    let mut guard = stream.lock().await;
    let _ = std::future::poll_fn(|cx| guard.poll_reset(cx, H3Error::Internal.code())).await;
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

/// Drives one accepted request stream to completion. The driver observes
/// the task through its oneshot completion receiver.
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
    header_timeout: Option<std::time::Duration>,
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
        let poll_headers = std::future::poll_fn(|cx| guard.poll_headers(cx));
        if let Some(timeout) = header_timeout {
            match zincio::time::timeout(timeout, poll_headers).await {
                Ok(result) => result,
                Err(_) => {
                    report(
                        &stream_error_callback,
                        stream_id,
                        format_args!("stream header read timeout"),
                    );
                    let mut guard = stream.lock().await;
                    let code = H3Error::RequestCancelled.code();
                    let _ = std::future::poll_fn(|cx| guard.poll_reset(cx, code)).await;
                    let _ = std::future::poll_fn(|cx| guard.poll_stop_sending(cx, code)).await;
                    drop(guard);
                    let mut state = conn_state.lock();
                    if let Some(code) = state.note_local_error_reset() {
                        state.close_code = Some(code);
                    }
                    return;
                }
            }
        } else {
            poll_headers.await
        }
    };
    let (request, content_length) = match request_headers {
        Ok(Some(request)) => request,
        // The stream ended without a request: nothing to respond to.
        Ok(None) => return,
        Err(err) => {
            // The peer reset the stream before the request was read; count
            // it against the rapid-reset budget (RFC 9114 Section 10.5).
            if err.is_stream_scoped() {
                report(&stream_error_callback, stream_id, &err);
                let mut state = conn_state.lock();
                if let Some(code) = state.note_pending_accept_reset(Instant::now()) {
                    state.close_code = Some(code);
                }
                return;
            }
            // A malformed request aborts only its stream (RFC 9114
            // Section 4.1.2), bounded by the local-reset budget.
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
            // A connection-scoped protocol violation: close with its H3
            // code.
            conn_state.lock().close_code = Some(err.h3_code());
            return;
        }
    };

    let is_100_continue = send_continue_response
        && request
            .headers()
            .get(http::header::EXPECT)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.eq_ignore_ascii_case("100-continue"));

    let send_continue_body = is_100_continue.then(|| Arc::new(AtomicBool::new(false)));
    let (request_parts, _) = request.into_parts();
    let (request_body, upgrade) = if request_parts.method == http::Method::CONNECT {
        (Incoming::Empty, Some(Arc::clone(&stream)))
    } else {
        (
            Incoming::Boxed(Box::pin(H3Body::new(
                Arc::clone(&stream),
                send_continue_body.clone(),
                Arc::clone(&conn_state),
                content_length,
            ))),
            None,
        )
    };
    let mut request = Request::from_parts(request_parts, request_body);

    let (early_hints, mut early_hints_rx) = EarlyHints::new_lazy();
    request.extensions_mut().insert(early_hints);

    let upgrade = if let Some(recv_stream) = upgrade {
        let (upgrade_tx, upgrade_rx) = oneshot::async_channel();
        let upgrade = Upgrade::new(upgrade_rx);
        let upgraded = Arc::clone(&upgrade.upgraded);
        request.extensions_mut().insert(upgrade);
        Some((upgrade_tx, upgraded, recv_stream))
    } else {
        None
    };

    let is_head = request.method() == http::Method::HEAD;
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
            Some(futures_util::future::Either::Left(response_result)) => {
                break response_result;
            }
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
            None => {
                if let Err(error) = send_interim_response(&stream, StatusCode::CONTINUE).await {
                    report(&stream_error_callback, stream_id, &error);
                    abort(&stream).await;
                    return;
                }
            }
        }
    };

    let Ok(mut response) = response_result else {
        if let Err(error) = response_result {
            report(
                &stream_error_callback,
                stream_id,
                format_args!("request handler error: {error}"),
            );
        }
        abort(&stream).await;
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
        sanitize_response_headers(response_headers);
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
            abort(&stream).await;
            return;
        }
    }

    let (response_parts, mut response_body) = response.into_parts();
    if let Err(error) = send_response(
        &stream,
        &shared,
        stream_id,
        if upgrade.is_some() && response_parts.status == StatusCode::SWITCHING_PROTOCOLS {
            // HTTP/3 upgrades use 200 OK, not 101 Switching Protocols
            StatusCode::OK
        } else {
            response_parts.status
        },
        &response_parts.headers,
    )
    .await
    {
        report(&stream_error_callback, stream_id, &error);
        abort(&stream).await;
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

    if !response_is_end_stream && !is_head {
        while let Some(chunk) = response_body.frame().await {
            match chunk {
                Ok(frame) => {
                    if frame.is_data() {
                        match frame.into_data() {
                            Ok(data) => {
                                if data.is_empty() {
                                    continue;
                                }
                                if let Err(error) = send_data(&stream, data).await {
                                    report(&stream_error_callback, stream_id, &error);
                                    abort(&stream).await;
                                    return;
                                }
                            }
                            Err(_) => {
                                report(
                                    &stream_error_callback,
                                    stream_id,
                                    "response body data frame error",
                                );
                                abort(&stream).await;
                                return;
                            }
                        }
                    } else if frame.is_trailers() {
                        match frame.into_trailers() {
                            Ok(mut trailers) => {
                                sanitize_response_headers(&mut trailers);
                                if let Err(error) = send_trailers(&stream, &trailers).await {
                                    report(&stream_error_callback, stream_id, &error);
                                    abort(&stream).await;
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
                                abort(&stream).await;
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
                    abort(&stream).await;
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
/// `Http3` wraps a QUIC connection and drives concurrent request streams,
/// streaming bodies and trailers, interim responses, `Date` caching, and
/// graceful shutdown.
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
    /// connection. See [`Http3Options`] for configuration.
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

    /// Attaches a [`CancellationToken`] for graceful shutdown. Cancelling it
    /// sends GOAWAY and drains in-flight requests before closing.
    #[inline]
    pub fn graceful_shutdown_token(mut self, token: CancellationToken) -> Self {
        self.cancel_token = Some(token);
        self
    }

    /// Attaches a callback invoked whenever an HTTP/3 stream fails.
    /// Connection-level failures still surface as the handler's `Err`.
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
            let header_read_timeout = options.header_read_timeout;
            let enable_connect_protocol = options.local_settings.enable_connect_protocol;

            // The handshake may still be incomplete (0-RTT).
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
            let shared = Arc::clone(controls.shared());
            // Request tasks record connection-scoped errors and reset
            // accounting here; the driver acts on them.
            let conn_state: Arc<parking_lot::Mutex<ConnResetState>> =
                Arc::new(parking_lot::Mutex::new(ConnResetState {
                    limits: ResetLimits {
                        max_local_error_resets: options.max_local_error_reset_streams,
                        max_pending_accept_resets: options.max_pending_accept_reset_streams,
                    },
                    local_error_resets: 0,
                    pending_accept_resets: 0.0,
                    pending_accept_since: Instant::now(),
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
            // quinn's `close()` stops transmitting after one frame and can
            // discard buffered response bytes. Give the sender a short grace
            // window before closing.
            let mut drain_grace: Option<zincio::time::Sleep> = None;
            let mut shutdown = false;
            let mut control_dead = false;
            // Set when tearing down with a protocol error rather than a
            // graceful GOAWAY.
            let mut closing_with: Option<u64> = None;
            // Human-readable detail for `closing_with`.
            let mut closing_detail: Option<String> = None;
            let mut outcome: Option<Result<(), std::io::Error>> = None;
            let mut last_request_id = 0u64;

            // Open the control plane and write the initial SETTINGS.
            std::future::poll_fn(|cx| -> Poll<Result<(), std::io::Error>> {
                ready!(controls
                    .poll_init(&mut conn, cx)
                    .map_err(h3_control_error_to_io))?;
                ready!(controls.poll_flush(cx).map_err(h3_control_error_to_io))?;
                Poll::Ready(Ok(()))
            })
            .await?;

            std::future::poll_fn(|cx| loop {
                // A request task recorded a connection-scoped error.
                if let Some(code) = conn_state.lock().close_code.take() {
                    if closing_with.is_none() {
                        closing_with = Some(code);
                        shutdown = true;
                        control_dead = true;
                    }
                }

                // The accept timeout only runs while no request is in flight.
                let mut timeout_fired = false;
                if !ongoing.is_empty() {
                    accept_sleep = None;
                } else if let Some(sleep) = accept_sleep.as_mut() {
                    if let Poll::Ready(()) = Pin::new(&mut *sleep).poll(cx) {
                        accept_sleep = None;
                        timeout_fired = true;
                    }
                } else if let Some(accept_timeout) = options.accept_timeout {
                    accept_sleep = Some(zincio::time::sleep(accept_timeout));
                    continue;
                }

                // Re-poll periodically while waiting for in-flight requests
                // to drain.
                if let Some(sleep) = shutdown_sleep.as_mut() {
                    if let Poll::Ready(()) = Pin::new(&mut *sleep).poll(cx) {
                        sleep.reset(Instant::now() + std::time::Duration::from_millis(10));
                        // Re-register the wake-up for the new deadline.
                        let _ = Pin::new(&mut *sleep).poll(cx);
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

                // Register the driver waker for encoder-stream pushes.
                {
                    let mut waiter = shared.driver_waiter.lock();
                    if waiter.as_ref().is_none_or(|w| !w.will_wake(cx.waker())) {
                        *waiter = Some(cx.waker().clone());
                    }
                }

                // Hand queued QPACK encoder instructions to the control
                // plane.
                controls.queue_encoder_streams_from_shared(&shared);

                // Write the control plane's outbound streams. If the peer
                // tears it down during shutdown, stop flushing but keep serving
                // in-flight requests.
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
                                // The client is going away: stop accepting
                                // and drain.
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

                // Shutdown: close with the recorded H3 error, or send GOAWAY
                // and drain gracefully.
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
                        // Let the sender flush the last response before
                        // closing.
                        let grace = drain_grace.get_or_insert_with(|| {
                            zincio::time::sleep(std::time::Duration::from_millis(50))
                        });
                        if Pin::new(&mut *grace).poll(cx).is_ready() {
                            ready!(conn
                                .poll_shutdown(cx, H3_NO_ERROR)
                                .map_err(h3_transport_error_to_io))?;
                            return Poll::Ready(outcome.take().unwrap_or(Ok(())));
                        }
                    } else if shutdown_sleep.is_none() {
                        let mut backstop =
                            zincio::time::sleep(std::time::Duration::from_millis(10));
                        // Registers the wake-up; the top of the loop re-arms it.
                        let _ = Pin::new(&mut backstop).poll(cx);
                        shutdown_sleep = Some(backstop);
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
                                let mut rejected = RequestStream::new(
                                    stream,
                                    Arc::clone(&shared),
                                    enable_connect_protocol,
                                );
                                let _ = rejected.poll_reset(cx, H3_REQUEST_REJECTED);
                            } else {
                                let (end_tx, end_rx) = oneshot::async_channel();
                                ongoing.push(end_rx);
                                let request_stream =
                                    Arc::new(tokio::sync::Mutex::new(RequestStream::new(
                                        stream,
                                        Arc::clone(&shared),
                                        enable_connect_protocol,
                                    )));
                                let request_fn = std::rc::Rc::clone(&request_fn);
                                let date_cache = date_cache.clone();
                                let shared = Arc::clone(&shared);
                                let conn_state_for_task = Arc::clone(&conn_state);
                                let stream_error_callback = stream_error_callback.clone();
                                zincio::spawn(async move {
                                    let _end = end_tx;
                                    handle_request(
                                        request_stream,
                                        shared,
                                        id,
                                        request_fn,
                                        date_cache,
                                        send_continue_response,
                                        send_date_header,
                                        conn_state_for_task,
                                        stream_error_callback,
                                        header_read_timeout,
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

                // Reap finished request tasks.
                match ongoing.poll_next_unpin(cx) {
                    Poll::Ready(Some(Ok(()))) => continue,
                    Poll::Ready(Some(Err(_))) => continue,
                    Poll::Ready(None) => {}
                    Poll::Pending => {}
                }
                // Go round once more to arm the drain-grace timer before
                // parking.
                if ongoing.is_empty() && shutdown && drain_grace.is_none() {
                    continue;
                }

                return Poll::Pending;
            })
            .await
        }
    }
}
