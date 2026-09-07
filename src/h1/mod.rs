mod body;
mod options;
mod write;
mod writebuf;
mod zerocopy;

pub(crate) use body::Http1Body;
pub use options::*;
pub use zerocopy::*;

#[cfg(unix)]
pub(crate) type RawHandle = std::os::fd::RawFd;
#[cfg(windows)]
pub(crate) type RawHandle = std::os::windows::io::RawHandle;

use std::{mem::MaybeUninit, time::UNIX_EPOCH};

use bytes::{Buf, Bytes, BytesMut};
use http::{header, HeaderMap, HeaderValue, Request, Response, Version};
use http_body::Body;
use http_body_util::Empty;
use memchr::memchr3_iter;
use tokio::io::AsyncReadExt;
use tokio_util::sync::CancellationToken;

use crate::{h1::writebuf::WriteBuf, EarlyHints, HttpProtocol, Incoming, Upgrade, Upgraded};

const HEX_DIGITS: &[u8; 16] = b"0123456789ABCDEF";
const WRITE_BUF_BATCH_THRESHOLD: usize = 16384;

/// An HTTP/1.x connection handler.
///
/// `Http1` wraps an async I/O stream (`Io`) and provides a complete
/// HTTP/1.0 and HTTP/1.1 server implementation, including:
///
/// - Request head parsing (via [`httparse`])
/// - Streaming request bodies (content-length and chunked transfer-encoding)
/// - Chunked response encoding and trailer support
/// - `100 Continue` and `103 Early Hints` interim responses
/// - HTTP connection upgrades (e.g. WebSocket)
/// - Optional zero-copy response sending on Linux or FreeBSD (see `Http1::zerocopy`)
/// - Keep-alive connection reuse
/// - Graceful shutdown via a [`CancellationToken`]
///
/// # Construction
///
/// ```rust,ignore
/// let http1 = Http1::new(tcp_stream, Http1Options::default());
/// ```
///
/// # Serving requests
///
/// Use the [`HttpProtocol`] trait methods ([`handle`](HttpProtocol::handle) /
/// [`handle_with_error_fn`](HttpProtocol::handle_with_error_fn)) to drive the
/// connection to completion:
///
/// ```rust,ignore
/// http1.handle(|req| async move {
///     Ok::<_, Infallible>(Response::new(Full::new(Bytes::from("Hello!"))))
/// }).await?;
/// ```
pub struct Http1<Io> {
    io: Io,
    options: options::Http1Options,
    cancel_token: Option<CancellationToken>,
    parsed_headers: Box<[MaybeUninit<httparse::Header<'static>>]>,
    date_header_value_cached: Option<(String, std::time::SystemTime)>,
    cached_headers: Option<HeaderMap>,
    read_buf: BytesMut,
    response_head_buf: Vec<u8>,
    write_buf: WriteBuf,
    connection_idle: bool,
}

#[cfg(all(
    any(target_os = "linux", target_os = "freebsd"),
    feature = "h1-zerocopy"
))]
impl<Io> Http1<Io>
where
    for<'a> Io: tokio::io::AsyncRead
        + tokio::io::AsyncWrite
        + zincio::io::AsInnerRawHandle<'a>
        + Unpin
        + 'static,
{
    /// Converts this `Http1` into an [`Http1Zerocopy`] that uses emulated
    /// sendfile (Linux only) to send response bodies without copying data
    /// through user space.
    ///
    /// The response body must have a `ZerocopyResponse` extension installed
    /// (via [`install_zerocopy`]) containing the file descriptor to send from.
    /// Responses without that extension are sent normally.
    ///
    /// Only available on Linux and FreeBSD, and only when `Io`
    /// implements [`zincio::io::AsInnerRawHandle`].
    #[inline]
    pub fn zerocopy(self) -> Http1Zerocopy<Io> {
        Http1Zerocopy { inner: self }
    }
}

impl<Io> Http1<Io>
where
    Io: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + 'static,
{
    /// Creates a new `Http1` connection handler wrapping the given I/O stream.
    ///
    /// The `options` value controls limits, timeouts, and optional features;
    /// see [`Http1Options`] for details.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let http1 = Http1::new(tcp_stream, Http1Options::default());
    /// ```
    #[inline]
    pub fn new(io: Io, options: options::Http1Options) -> Self {
        // Safety: u8 is a primitive type, so we can safely assume initialization
        let read_buf = BytesMut::with_capacity(options.max_header_size);
        let parsed_headers: Box<[MaybeUninit<httparse::Header<'static>>]> =
            Box::new_uninit_slice(options.max_header_count);
        Self {
            io,
            options,
            cancel_token: None,
            parsed_headers,
            date_header_value_cached: None,
            cached_headers: None,
            read_buf,
            response_head_buf: Vec::with_capacity(1024),
            write_buf: WriteBuf::new(),
            connection_idle: false,
        }
    }

    #[inline]
    fn get_date_header_value(&mut self) -> &str {
        let now = std::time::SystemTime::now();
        if self.date_header_value_cached.as_ref().is_none_or(|v| {
            v.1.duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs())
                != now.duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs())
        }) {
            let value = httpdate::fmt_http_date(now).to_string();
            self.date_header_value_cached = Some((value, now));
        }
        self.date_header_value_cached
            .as_ref()
            .map(|v| v.0.as_str())
            .unwrap_or("")
    }

    /// Attaches a [`CancellationToken`] for graceful shutdown.
    ///
    /// After the current in-flight request has been fully handled and its
    /// response written, the connection loop checks whether the token has been
    /// cancelled. If it has, the loop exits cleanly instead of waiting for the
    /// next request.
    ///
    /// This allows the server to drain active connections without abruptly
    /// closing them mid-response.
    #[inline]
    pub fn graceful_shutdown_token(mut self, token: CancellationToken) -> Self {
        self.cancel_token = Some(token);
        self
    }

    #[inline]
    async fn fill_buf(&mut self) -> Result<usize, std::io::Error> {
        if self.read_buf.capacity() - self.read_buf.len() < 1024 {
            self.read_buf.reserve(1024);
        }
        let spare_capacity = self.read_buf.spare_capacity_mut();
        // Safety: The buffer is are read only after the request head has been parsed
        let n = self
            .io
            .read(unsafe {
                &mut *std::ptr::slice_from_raw_parts_mut(
                    spare_capacity.as_mut_ptr() as *mut u8,
                    spare_capacity.len(),
                )
            })
            .await?;
        if n == 0 {
            return Ok(0);
        }
        unsafe { self.read_buf.set_len(self.read_buf.len() + n) };
        Ok(n)
    }

    #[inline]
    async fn get_head(
        &mut self,
    ) -> Result<Option<(Bytes, &mut [MaybeUninit<httparse::Header<'static>>])>, std::io::Error>
    {
        let mut request_line_read = false;
        let mut bytes_read: usize = 0;
        let mut whitespace_trimmed = None;
        let mut just_started = true;
        while bytes_read < self.options.max_header_size {
            let old_bytes_read = bytes_read;
            let begin_search = old_bytes_read.saturating_sub(3);

            let have_to_read_buf = !just_started || self.read_buf.is_empty();
            just_started = false;
            if have_to_read_buf {
                let n = self.fill_buf().await?;
                if n == 0 {
                    if whitespace_trimmed.is_none() {
                        return Ok(None);
                    }
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "unexpected EOF",
                    ));
                } else {
                    self.connection_idle = false;
                }
                bytes_read = (old_bytes_read + n).min(self.options.max_header_size);
            } else {
                bytes_read =
                    (old_bytes_read + self.read_buf.len()).min(self.options.max_header_size)
            }

            if whitespace_trimmed.is_none() {
                whitespace_trimmed = self.read_buf[old_bytes_read..bytes_read]
                    .iter()
                    .position(|b| !b.is_ascii_whitespace());
            }

            if let Some(whitespace_trimmed) = whitespace_trimmed {
                // Validate first line (request line) before checking for header/body separator
                if !request_line_read {
                    let memchr = memchr3_iter(
                        b' ',
                        b'\r',
                        b'\n',
                        &self.read_buf[whitespace_trimmed..bytes_read],
                    );
                    let mut spaces = 0;
                    for separator_index in memchr {
                        if self.read_buf[whitespace_trimmed + separator_index] == b' ' {
                            if spaces >= 2 {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::InvalidInput,
                                    "bad request first line",
                                ));
                            }
                            spaces += 1;
                        } else if spaces == 2 {
                            request_line_read = true;
                            break;
                        } else {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidInput,
                                "bad request first line",
                            ));
                        }
                    }
                }

                if request_line_read {
                    let begin_search = begin_search.max(whitespace_trimmed);
                    if let Some((separator_index, separator_len)) =
                        search_header_body_separator(&self.read_buf[begin_search..bytes_read])
                    {
                        let to_parse_length =
                            begin_search + separator_index + separator_len - whitespace_trimmed;
                        self.read_buf.advance(whitespace_trimmed);
                        let head = self.read_buf.split_to(to_parse_length);
                        return Ok(Some((head.freeze(), &mut self.parsed_headers)));
                    }
                }
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "request too large",
        ))
    }

    #[inline]
    pub(crate) async fn handle_with_error_fn_and_zerocopy<
        F,
        Fut,
        ResB,
        ResBE,
        ResE,
        EF,
        EFut,
        EResB,
        EResBE,
        EResE,
        ZF,
        ZFut,
    >(
        mut self,
        request_fn: F,
        error_fn: EF,
        mut zerocopy_fn: Option<ZF>,
    ) -> Result<(), std::io::Error>
    where
        F: Fn(Request<Incoming>) -> Fut + 'static,
        Fut: std::future::Future<Output = Result<Response<ResB>, ResE>> + 'static,
        ResB: Body<Data = bytes::Bytes, Error = ResBE> + Unpin + 'static,
        ResE: std::error::Error + 'static,
        ResBE: std::error::Error + 'static,
        EF: FnOnce(bool) -> EFut,
        EFut: std::future::Future<Output = Result<Response<EResB>, EResE>>,
        EResB: Body<Data = bytes::Bytes, Error = EResBE> + Unpin + 'static,
        EResE: std::error::Error + 'static,
        EResBE: std::error::Error + 'static,
        ZF: FnMut(RawHandle, &'static Io, u64) -> ZFut,
        ZFut: std::future::Future<Output = Result<(), std::io::Error>>,
    {
        let mut keep_alive = true;

        while keep_alive {
            let (mut request, body_tx, send_continue_body) = match if let Some(timeout) =
                self.options.header_read_timeout
            {
                zincio::time::timeout(timeout, async {
                    if let Some(token) = self.cancel_token.clone() {
                        token.run_until_cancelled(self.read_request()).await
                    } else {
                        Some(self.read_request().await)
                    }
                })
                .await
            } else {
                Ok(Some(self.read_request().await))
            } {
                Ok(Some(Ok(Some(d)))) => d,
                Ok(Some(Ok(None))) => {
                    return Ok(());
                }
                Ok(Some(Err(e)))
                    if self.connection_idle
                        && matches!(
                            e.kind(),
                            std::io::ErrorKind::BrokenPipe
                                | std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::ConnectionAborted
                                | std::io::ErrorKind::UnexpectedEof
                        ) =>
                {
                    // HTTP/1.x abruptly closed when idle
                    return Ok(());
                }
                Ok(Some(Err(e))) => {
                    if let Ok(mut response) = error_fn(false).await {
                        response
                            .headers_mut()
                            .insert(header::CONNECTION, HeaderValue::from_static("close"));

                        let _ = self
                            .write_response(response, Version::HTTP_11, false, zerocopy_fn.as_mut())
                            .await;
                    }
                    return Err(e);
                }
                Ok(None) => {
                    // Graceful shutdown
                    return Ok(());
                }
                Err(_) if self.connection_idle => {
                    // Idle connection
                    return Ok(());
                }
                Err(_) => {
                    // Timeout error
                    if let Ok(mut response) = error_fn(true).await {
                        response
                            .headers_mut()
                            .insert(header::CONNECTION, HeaderValue::from_static("close"));

                        let _ = self
                            .write_response(response, Version::HTTP_11, false, zerocopy_fn.as_mut())
                            .await;
                    }
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "header read timeout",
                    ));
                }
            };

            // Connection header detection
            let connection_header_split = request
                .headers()
                .get(header::CONNECTION)
                .and_then(|v| v.to_str().ok())
                .map(|v| v.split(",").map(|v| v.trim()));
            let is_connection_close = connection_header_split
                .clone()
                .is_some_and(|mut split| split.any(|v| v.eq_ignore_ascii_case("close")));
            let is_connection_keep_alive = connection_header_split
                .is_some_and(|mut split| split.any(|v| v.eq_ignore_ascii_case("keep-alive")));
            keep_alive = !is_connection_close
                && (is_connection_keep_alive || request.version() == http::Version::HTTP_11);

            let version = request.version();
            let is_100_continue = send_continue_body.is_some();

            // 103 Early Hints
            let early_hints_fut = if self.options.enable_early_hints {
                let (early_hints, mut early_hints_rx) = EarlyHints::new_lazy();
                request.extensions_mut().insert(early_hints);
                // Safety: the function below is used only in futures_util::future::select
                // Also, another function that would borrow self would read data,
                // while this function would write data
                let mut_self = unsafe { std::mem::transmute::<&mut Self, &mut Self>(&mut self) };
                futures_util::future::Either::Left(async move {
                    while let Some((headers, sender)) =
                        std::future::poll_fn(|cx| early_hints_rx.poll_recv(cx)).await
                    {
                        sender
                            .into_inner()
                            .send(mut_self.write_early_hints(version, headers).await)
                            .ok();
                    }
                    futures_util::future::pending::<Result<(), std::io::Error>>().await
                })
            } else {
                futures_util::future::Either::Right(futures_util::future::pending::<
                    Result<(), std::io::Error>,
                >())
            };

            // Content-Length header
            let content_length = request
                .headers()
                .get(header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);
            let chunked = request
                .headers()
                .get(header::TRANSFER_ENCODING)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| {
                    v.split(',')
                        .any(|v| v.trim().eq_ignore_ascii_case("chunked"))
                });
            let has_trailers = request
                .headers()
                .get(header::TRAILER)
                .map(|v| v.to_str().ok().is_some_and(|s| !s.is_empty()))
                .unwrap_or(false);
            let write_trailers = request
                .headers()
                .get(header::TE)
                .and_then(|v| v.to_str().ok())
                .map(|v| {
                    v.split(',')
                        .any(|v| v.trim().eq_ignore_ascii_case("trailers"))
                })
                .unwrap_or(false);

            // Install HTTP upgrade
            let (upgrade_tx, upgrade_rx) = oneshot::async_channel();
            let upgrade = Upgrade::new(upgrade_rx);
            let upgraded = upgrade.upgraded.clone();
            request.extensions_mut().insert(upgrade);

            let mut continue_sent = false;
            let mut response = {
                let read_body_fut = async {
                    if chunked {
                        self.read_chunked_body_fn(
                            body_tx,
                            has_trailers,
                            &send_continue_body,
                            &mut continue_sent,
                            version,
                        )
                        .await
                    } else {
                        self.read_body_fn(
                            body_tx,
                            content_length,
                            &send_continue_body,
                            &mut continue_sent,
                            version,
                        )
                        .await
                    }
                };
                let read_body_fut_pin = std::pin::pin!(read_body_fut);
                let request_fut = request_fn(request);
                let request_fut_pin = std::pin::pin!(request_fut);
                let early_hints_fut_pin = std::pin::pin!(early_hints_fut);

                let select_read_body_either =
                    futures_util::future::select(request_fut_pin, early_hints_fut_pin);
                let select_either =
                    futures_util::future::select(read_body_fut_pin, select_read_body_either).await;

                let (response, body_fut) = match select_either {
                    futures_util::future::Either::Left((result, request_fut)) => {
                        result?;
                        (
                            match request_fut.await {
                                futures_util::future::Either::Left((response, _)) => response,
                                futures_util::future::Either::Right((_, _)) => unreachable!(),
                            },
                            None,
                        )
                    }
                    futures_util::future::Either::Right((response, read_body_fut)) => (
                        match response {
                            futures_util::future::Either::Left((response, _)) => response,
                            futures_util::future::Either::Right((_, _)) => unreachable!(),
                        },
                        Some(read_body_fut),
                    ),
                };

                // Drain away remaining body
                if let Some(body_fut) = body_fut {
                    body_fut.await?;
                }

                response.map_err(|e| std::io::Error::other(e.to_string()))?
            };

            // Response-triggered 100 Continue
            if !continue_sent
                && is_100_continue
                && !response.status().is_client_error()
                && !response.status().is_server_error()
            {
                self.write_100_continue(version).await?;
            }

            let mut was_upgraded = false;
            if upgraded.load(std::sync::atomic::Ordering::Relaxed) {
                was_upgraded = true;
                response
                    .headers_mut()
                    .insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
            } else if keep_alive {
                if version == Version::HTTP_10
                    || response.headers().contains_key(header::CONNECTION)
                {
                    response
                        .headers_mut()
                        .insert(header::CONNECTION, HeaderValue::from_static("keep-alive"));
                }
            } else if version == Version::HTTP_11
                || response.headers().contains_key(header::CONNECTION)
            {
                response
                    .headers_mut()
                    .insert(header::CONNECTION, HeaderValue::from_static("close"));
            }

            self.write_response(response, version, write_trailers, zerocopy_fn.as_mut())
                .await?;

            if was_upgraded {
                // HTTP upgrade
                let frozen_buf = self.read_buf.freeze();
                let _ = upgrade_tx.send(Upgraded::new(
                    self.io,
                    if frozen_buf.is_empty() {
                        None
                    } else {
                        Some(frozen_buf)
                    },
                ));
                return Ok(());
            }

            if self.cancel_token.as_ref().is_some_and(|t| t.is_cancelled()) {
                // Graceful shutdown requested, break out of loop
                break;
            }

            self.connection_idle = true;
        }
        Ok(())
    }
}

impl<Io> HttpProtocol for Http1<Io>
where
    Io: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + 'static,
{
    #[inline]
    fn handle_with_error_fn<F, Fut, ResB, ResBE, ResE, EF, EFut, EResB, EResBE, EResE>(
        self,
        request_fn: F,
        error_fn: EF,
    ) -> impl std::future::Future<Output = Result<(), std::io::Error>>
    where
        F: Fn(Request<Incoming>) -> Fut + 'static,
        Fut: std::future::Future<Output = Result<Response<ResB>, ResE>> + 'static,
        ResB: Body<Data = bytes::Bytes, Error = ResBE> + Unpin + 'static,
        ResE: std::error::Error + 'static,
        ResBE: std::error::Error + 'static,
        EF: FnOnce(bool) -> EFut,
        EFut: std::future::Future<Output = Result<Response<EResB>, EResE>>,
        EResB: Body<Data = bytes::Bytes, Error = EResBE> + Unpin + 'static,
        EResE: std::error::Error + 'static,
        EResBE: std::error::Error + 'static,
    {
        #[allow(clippy::type_complexity)]
        let no_zerocopy: Option<
            Box<
                dyn FnMut(
                    RawHandle,
                    &Io,
                    u64,
                ) -> Box<
                    dyn std::future::Future<Output = Result<(), std::io::Error>>
                        + Unpin
                        + Send
                        + Sync,
                >,
            >,
        > = None;
        self.handle_with_error_fn_and_zerocopy(request_fn, error_fn, no_zerocopy)
    }

    #[inline]
    fn handle<F, Fut, ResB, ResBE, ResE>(
        self,
        request_fn: F,
    ) -> impl std::future::Future<Output = Result<(), std::io::Error>>
    where
        F: Fn(Request<Incoming>) -> Fut + 'static,
        Fut: std::future::Future<Output = Result<Response<ResB>, ResE>> + 'static,
        ResB: Body<Data = bytes::Bytes, Error = ResBE> + Unpin + 'static,
        ResE: std::error::Error + 'static,
        ResBE: std::error::Error + 'static,
    {
        self.handle_with_error_fn(request_fn, |is_timeout| async move {
            let mut response = Response::builder();
            if is_timeout {
                response = response.status(http::StatusCode::REQUEST_TIMEOUT);
            } else {
                response = response.status(http::StatusCode::BAD_REQUEST);
            }
            response.body(Empty::new())
        })
    }
}

/// Searches for the header/body separator in a given slice.
/// Returns the index of the separator and the length of the separator.
#[inline]
fn search_header_body_separator(slice: &[u8]) -> Option<(usize, usize)> {
    if slice.len() < 2 {
        // Slice too short
        return None;
    }
    for (i, b) in slice.iter().copied().enumerate() {
        if b == b'\r' {
            if slice[i + 1..].chunks(3).next() == Some(&b"\n\r\n"[..]) {
                return Some((i, 4));
            }
        } else if b == b'\n' && slice.get(i + 1) == Some(&b'\n') {
            return Some((i, 2));
        }
    }
    None
}

/// Writes the chunk size to the given buffer in hexadecimal format, followed by `\r\n`.
#[inline]
fn write_chunk_size(dst: &mut [u8; 18], len: usize) -> &[u8] {
    let mut n = len;
    let mut pos = dst.len() - 2;
    loop {
        pos -= 1;
        dst[pos] = HEX_DIGITS[n & 0xF];
        n >>= 4;
        if n == 0 {
            break;
        }
    }
    dst[dst.len() - 2] = b'\r';
    dst[dst.len() - 1] = b'\n';
    &dst[pos..]
}
