use http::{Request, Response};
use http_body::Body;
use tokio_util::sync::CancellationToken;

use crate::h2::connection::{Connection, ConnectionOptions};
use crate::h2::date::DateCache;
use crate::h2::options::Http2Options;
use crate::{HttpProtocol, Incoming, StreamErrorCallback};

pub mod codec;
pub mod connection;
mod date;
pub mod error;
pub mod hpack;
pub mod options;
mod stream;

pub(crate) use stream::H2Body;

/// Header fields a server must strip from a response before sending it
/// on an HTTP/2 connection (RFC 9113 Section 8.1.2.2): these are
/// connection-level concerns, not per-message headers.
pub(crate) const HTTP2_INVALID_HEADERS: [http::header::HeaderName; 5] = [
    http::header::HeaderName::from_static("keep-alive"),
    http::header::HeaderName::from_static("proxy-connection"),
    http::header::CONNECTION,
    http::header::TRANSFER_ENCODING,
    http::header::UPGRADE,
];

/// Mangles a response into HTTP/2-legal shape: injects a `Date` header
/// when configured and removes connection-specific response headers.
#[inline]
pub(super) fn sanitize_response<ResB>(
    response: &mut Response<ResB>,
    send_date_header: bool,
    date_cache: &DateCache,
) where
    ResB: Body<Data = bytes::Bytes>,
{
    let response_headers = response.headers_mut();
    if send_date_header {
        if let Some(http_date) = date_cache.get_date_header_value() {
            response_headers
                .entry(http::header::DATE)
                .or_insert(http_date);
        }
    }
    for header in &HTTP2_INVALID_HEADERS {
        if let http::header::Entry::Occupied(entry) = response_headers.entry(header) {
            entry.remove();
        }
    }
    if response_headers
        .get(http::header::TE)
        .is_some_and(|v| v != "trailers")
    {
        response_headers.remove(http::header::TE);
    }
}

/// An HTTP/2 connection handler.
///
/// `Http2` wraps an async I/O stream (`Io`) and drives the HTTP/2 server
/// connection using the native implementation in [`connection`]. It
/// supports:
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
/// let http2 = Http2::new(tcp_stream, Http2Options::default());
/// ```
///
/// # Serving requests
///
/// Use the [`HttpProtocol`] trait methods ([`handle`](HttpProtocol::handle) /
/// [`handle_with_error_fn`](HttpProtocol::handle_with_error_fn)) to drive the
/// connection to completion.
pub struct Http2<Io> {
    io_to_handshake: Option<Io>,
    options: Http2Options,
    cancel_token: Option<CancellationToken>,
    stream_error_callback: Option<StreamErrorCallback>,
}

impl<Io> Http2<Io>
where
    Io: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + 'static,
{
    /// Creates a new `Http2` connection handler wrapping the given I/O stream.
    ///
    /// The `options` value controls HTTP/2 protocol configuration, handshake
    /// and accept timeouts, and optional behaviour such as automatic
    /// `100 Continue` responses; see [`Http2Options`] for details.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let http2 = Http2::new(tcp_stream, Http2Options::default());
    /// ```
    #[inline]
    pub fn new(io: Io, options: Http2Options) -> Self {
        Self {
            io_to_handshake: Some(io),
            options,
            cancel_token: None,
            stream_error_callback: None,
        }
    }

    /// Attaches a [`CancellationToken`] for graceful shutdown.
    ///
    /// When the token is cancelled, the handler sends HTTP/2 graceful shutdown
    /// signals (GOAWAY), stops accepting new streams, and exits cleanly.
    #[inline]
    pub fn graceful_shutdown_token(mut self, token: CancellationToken) -> Self {
        self.cancel_token = Some(token);
        self
    }

    /// Attaches a stream error callback invoked with a [`std::io::Error`]
    /// whenever an HTTP/2 stream fails (for example a malformed request,
    /// a flow-control violation, or a reset).
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

impl<Io> HttpProtocol for Http2<Io>
where
    Io: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + 'static,
{
    #[inline]
    async fn handle<F, Fut, ResB, ResBE, ResE>(self, request_fn: F) -> Result<(), std::io::Error>
    where
        F: Fn(Request<Incoming>) -> Fut + 'static,
        Fut: std::future::Future<Output = Result<Response<ResB>, ResE>> + 'static,
        ResB: http_body::Body<Data = bytes::Bytes, Error = ResBE> + Unpin + 'static,
        ResE: std::error::Error + 'static,
        ResBE: std::error::Error + 'static,
    {
        let preface_timeout = self.options.handshake_timeout;
        let options = ConnectionOptions {
            send_continue_response: self.options.send_continue_response,
            send_date_header: self.options.send_date_header,
            max_concurrent_streams: self.options.max_concurrent_streams,
            initial_stream_window_size: self.options.initial_stream_window_size,
            initial_connection_window_size: self.options.initial_connection_window_size,
            max_frame_size: self.options.max_frame_size,
            max_header_list_size: self.options.max_header_list_size,
            enable_connect_protocol: self.options.enable_connect_protocol,
            idle_timeout: self.options.idle_timeout,
            max_local_error_reset_streams: self.options.max_local_error_reset_streams,
            max_pending_accept_reset_streams: self.options.max_pending_accept_reset_streams,
            max_continuation_frames: self.options.max_continuation_frames.unwrap_or_else(|| {
                let header = self.options.max_header_list_size as u64;
                let frame = self.options.max_frame_size as u64;
                let base = header / frame + u64::from(!header.is_multiple_of(frame));
                (base + base / 5 + 10) as usize
            }),
        };
        // The trait hands us a plain `Fn`; the native connection needs
        // a `Clone` closure (it is reused across streams). Wrap it in an
        // `Arc` so the spawned task can own a cheap clone.
        let shared = std::sync::Arc::new(request_fn);

        let connection = Connection::new(
            self.io_to_handshake
                .ok_or_else(|| std::io::Error::other("no io to handshake"))?,
            preface_timeout,
        );
        let connection = if let Some(token) = self.cancel_token {
            connection.with_shutdown(token)
        } else {
            connection
        };
        let connection = if let Some(callback) = self.stream_error_callback {
            connection.with_stream_error_callback(callback)
        } else {
            connection
        };
        connection.handle(shared, options).await
    }
}
