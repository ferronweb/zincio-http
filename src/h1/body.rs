use std::{
    future::Future,
    mem::MaybeUninit,
    pin::Pin,
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{Context, Poll},
};

use bytes::Buf;
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Uri, Version};
use http_body::Body;
use kanal::AsyncReceiver;
use memchr::memmem;

use crate::{h1::Http1, Incoming};

/// Coordinates `100 Continue` between the request-body consumer and the
/// socket reader.
///
/// The handler signals interest by polling the body; the socket reader sends
/// `100 Continue` before blocking for body bytes. Both sides run as separate
/// tasks, so the flag alone is not enough: if the reader is already parked in
/// a socket read when the handler polls, nothing would wake it and a client
/// that strictly waits for `100` before sending the body would deadlock
/// (curl masks this with its 1s expect-timeout fallback; OkHttp does not).
/// The `Notify` closes that race: setting interest always wakes the reader,
/// and the reader always re-checks interest after waking.
#[derive(Default)]
pub(crate) struct ContinueSignal {
    wanted: AtomicBool,
    notify: tokio::sync::Notify,
}

impl ContinueSignal {
    /// Records the handler's interest in the body and wakes the reader.
    #[inline]
    fn request(&self) {
        self.wanted.store(true, Ordering::Relaxed);
        self.notify.notify_one();
    }

    /// Whether the handler has asked for the body.
    #[inline]
    fn is_wanted(&self) -> bool {
        self.wanted.load(Ordering::Relaxed)
    }
}

impl<Io> Http1<Io>
where
    Io: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + 'static,
{
    #[inline]
    pub(crate) async fn read_body_fn(
        &mut self,
        body_tx: kanal::AsyncSender<Result<http_body::Frame<bytes::Bytes>, std::io::Error>>,
        content_length: u64,
        send_continue_body: &Option<Arc<ContinueSignal>>,
        continue_sent: &mut bool,
        version: Version,
    ) -> Result<(), std::io::Error> {
        let mut remaining = content_length;
        let mut just_started = true;
        while remaining > 0 {
            if !*continue_sent
                && send_continue_body
                    .as_ref()
                    .is_some_and(|signal| signal.is_wanted())
            {
                *continue_sent = true;
                self.write_100_continue(version).await?;
            }

            let have_to_read_buf = !just_started || self.read_buf.is_empty();
            just_started = false;
            if have_to_read_buf {
                let Some(n) = self.fill_buf_or_wanted(send_continue_body).await?
                else {
                    continue;
                };
                if n == 0 {
                    break;
                }
            }
            let chunk = self
                .read_buf
                .split_to(
                    self.read_buf
                        .len()
                        .min(remaining.min(usize::MAX as u64) as usize),
                )
                .freeze();
            remaining -= chunk.len() as u64;

            let _ = body_tx.send(Ok(http_body::Frame::data(chunk))).await;
        }
        Ok(())
    }

    #[inline]
    pub(crate) async fn read_body_chunk(
        &mut self,
        would_have_trailers: bool,
        send_continue_body: &Option<Arc<ContinueSignal>>,
        continue_sent: &mut bool,
        version: Version,
    ) -> Result<bytes::Bytes, std::io::Error> {
        let len = {
            // Safety: u8 is a primitive type, so we can safely assume initialization
            let mut len_buf_pos: usize = 0;
            let mut just_started = true;
            loop {
                if len_buf_pos >= 48 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "chunk length buffer overflow",
                    ));
                }

                let begin_search = len_buf_pos.saturating_sub(1);

                let have_to_read_buf = !just_started || self.read_buf.is_empty();
                just_started = false;
                if have_to_read_buf {
                    if !*continue_sent
                        && send_continue_body
                            .as_ref()
                            .is_some_and(|signal| signal.is_wanted())
                    {
                        *continue_sent = true;
                        self.write_100_continue(version).await?;
                    }
                    let Some(n) = self.fill_buf_or_wanted(send_continue_body).await?
                    else {
                        continue;
                    };
                    if n == 0 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "unexpected EOF",
                        ));
                    }
                    len_buf_pos += n;
                } else {
                    len_buf_pos += self.read_buf.len();
                }

                if let Some(pos) =
                    memmem::find(&self.read_buf[begin_search..len_buf_pos.min(48)], b"\r\n")
                {
                    let numbers = std::str::from_utf8(&self.read_buf[..begin_search + pos])
                        .map_err(|_| {
                            std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "invalid chunk length",
                            )
                        })?;
                    let len = usize::from_str_radix(numbers, 16).map_err(|_| {
                        std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid chunk length")
                    })?;
                    // Ignore the trailing CRLF
                    self.read_buf.advance(begin_search + pos + 2);
                    break len;
                }
            }
        };
        // Safety: u8 is a primitive type, so we can safely assume initialization
        let mut read = 0;
        if len == 0 && would_have_trailers {
            return Ok(bytes::Bytes::new()); // Empty terminating chunk
        }
        let mut just_started = true;
        // + 2, because we need to read the trailing CRLF
        let Some(len_plus_two) = len.checked_add(2) else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "chunk length too large",
            ));
        };
        while read < len_plus_two {
            let have_to_read_buf = !just_started || self.read_buf.is_empty();
            just_started = false;
            if have_to_read_buf {
                if !*continue_sent
                    && send_continue_body
                        .as_ref()
                        .is_some_and(|signal| signal.is_wanted())
                {
                    *continue_sent = true;
                    self.write_100_continue(version).await?;
                }
                let Some(n) = self.fill_buf_or_wanted(send_continue_body).await?
                else {
                    continue;
                };
                if n == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "unexpected EOF",
                    ));
                }
                read += n;
            } else {
                read += self.read_buf.len();
            }
        }
        let chunk = self.read_buf.split_to(len).freeze();
        self.read_buf.advance(2); // Ignore the trailing CRLF
        Ok(chunk)
    }

    #[inline]
    pub(crate) async fn read_trailers(&mut self) -> Result<Option<HeaderMap>, std::io::Error> {
        // Safety: u8 is a primitive type, so we can safely assume initialization
        let mut bytes_read: usize = 0;
        let mut just_started = true;
        while bytes_read < self.options.max_header_size {
            let old_bytes_read = bytes_read;
            let begin_search = old_bytes_read.saturating_sub(3);

            let have_to_read_buf = !just_started || self.read_buf.is_empty();
            just_started = false;
            if have_to_read_buf {
                let n = self.fill_buf().await?;
                if n == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "unexpected EOF",
                    ));
                }
                bytes_read = (old_bytes_read + n).min(self.options.max_header_size);
            } else {
                bytes_read =
                    (old_bytes_read + self.read_buf.len()).min(self.options.max_header_size)
            }

            if bytes_read >= 2 && self.read_buf[0] == b'\r' && self.read_buf[1] == b'\n' {
                // No trailers, return None
                return Ok(None);
            }

            if let Some(separator_index) =
                memmem::find(&self.read_buf[begin_search..bytes_read], b"\r\n\r\n")
            {
                let to_parse_length = begin_search + separator_index + 4;
                let buf_ro = self.read_buf.split_to(to_parse_length).freeze();

                let mut httparse_trailers =
                    vec![httparse::EMPTY_HEADER; self.options.max_header_count].into_boxed_slice();
                let status = httparse::parse_headers(&buf_ro, &mut httparse_trailers)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
                if let httparse::Status::Complete((_, trailers)) = status {
                    let mut trailers_constructed = HeaderMap::new();
                    for header in trailers {
                        if header == &httparse::EMPTY_HEADER {
                            // No more headers...
                            break;
                        }
                        let name = HeaderName::from_bytes(header.name.as_bytes())
                            .map_err(|e| std::io::Error::other(e.to_string()))?;
                        let value_start = header.value.as_ptr() as usize - buf_ro.as_ptr() as usize;
                        let value_len = header.value.len();
                        // Safety: the header value is already validated by httparse
                        let value = unsafe {
                            HeaderValue::from_maybe_shared_unchecked(
                                buf_ro.slice(value_start..(value_start + value_len)),
                            )
                        };
                        trailers_constructed.append(name, value);
                    }

                    return Ok(Some(trailers_constructed));
                } else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "trailer headers incomplete",
                    ));
                }
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "request too large",
        ))
    }

    /// Reads socket bytes, returning `Ok(None)` when the handler asked for
    /// the body while waiting (the caller re-checks interest and loops).
    /// `Ok(Some(n))` carries the `fill_buf` byte count, with 0 meaning EOF.
    #[inline]
    async fn fill_buf_or_wanted(
        &mut self,
        send_continue_body: &Option<Arc<ContinueSignal>>,
    ) -> Result<Option<usize>, std::io::Error> {
        match send_continue_body.as_ref() {
            Some(signal) => {
                // futures_util::select rather than tokio::select!: the latter
                // needs tokio's `macros` feature, which this crate does not
                // enable.
                let notified = std::pin::pin!(signal.notify.notified());
                let fill = std::pin::pin!(self.fill_buf());
                match futures_util::future::select(notified, fill).await {
                    futures_util::future::Either::Left((_, _)) => Ok(None),
                    futures_util::future::Either::Right((res, _)) => res.map(Some),
                }
            }
            // No Expect: 100-continue on this request; plain socket read.
            None => self.fill_buf().await.map(Some),
        }
    }

    #[inline]
    pub(crate) async fn read_chunked_body_fn(
        &mut self,
        body_tx: kanal::AsyncSender<Result<http_body::Frame<bytes::Bytes>, std::io::Error>>,
        would_have_trailers: bool,
        send_continue_body: &Option<Arc<ContinueSignal>>,
        continue_sent: &mut bool,
        version: Version,
    ) -> Result<(), std::io::Error> {
        loop {
            let chunk = self
                .read_body_chunk(
                    would_have_trailers,
                    send_continue_body,
                    continue_sent,
                    version,
                )
                .await?;
            if chunk.is_empty() {
                break;
            }

            let _ = body_tx.send(Ok(http_body::Frame::data(chunk))).await;
        }
        if would_have_trailers {
            // Trailers
            let trailers = self.read_trailers().await?;
            if let Some(trailers) = trailers {
                let _ = body_tx.send(Ok(http_body::Frame::trailers(trailers))).await;
            }
        }
        Ok(())
    }

    #[inline]
    pub(crate) async fn read_request(
        &mut self,
    ) -> Result<
        Option<(
            Request<Incoming>,
            kanal::AsyncSender<Result<http_body::Frame<bytes::Bytes>, std::io::Error>>,
            Option<Arc<ContinueSignal>>,
        )>,
        std::io::Error,
    > {
        let (request, body_tx, send_continue_body) = {
            let Some((head, headers)) = self.get_head().await? else {
                return Ok(None);
            };
            // Safety: The headers are read only after the request head has been parsed
            let headers = unsafe {
                std::mem::transmute::<
                    &mut [MaybeUninit<httparse::Header<'static>>],
                    &mut [MaybeUninit<httparse::Header<'_>>],
                >(headers)
            };
            let mut req = httparse::Request::new(&mut []);
            let status = req
                .parse_with_uninit_headers(&head, headers)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            if status.is_partial() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "partial request head",
                ));
            }

            // Convert httparse HTTP request to `http` one
            let (body_tx, body_rx) = kanal::bounded_async(2);

            // Detect 100-continue and create flag before building the body
            let is_100_continue = self.options.send_continue_response
                && req.headers.iter().any(|h| {
                    h.name.eq_ignore_ascii_case("expect")
                        && h.value.eq_ignore_ascii_case(b"100-continue")
                });
            let send_continue_body = is_100_continue.then(|| Arc::new(ContinueSignal::default()));

            let request_body = Http1Body {
                inner: body_rx,
                inner_fut: None,
                send_continue_body: send_continue_body.clone(),
            };
            let mut request = Request::new(Incoming::H1(request_body));
            match req.version {
                Some(0) => *request.version_mut() = http::Version::HTTP_10,
                Some(1) => *request.version_mut() = http::Version::HTTP_11,
                _ => *request.version_mut() = http::Version::HTTP_11,
            };
            if let Some(method) = req.method {
                *request.method_mut() = Method::from_bytes(method.as_bytes())
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
            }
            if let Some(path) = req.path {
                *request.uri_mut() =
                    Uri::from_str(path).map_err(|e| std::io::Error::other(e.to_string()))?;
            }
            let mut header_map = self.cached_headers.take().unwrap_or_default();
            header_map.clear();
            let additional_capacity = req.headers.len().saturating_sub(header_map.capacity());
            if additional_capacity > 0 {
                header_map.reserve(additional_capacity);
            }
            for header in req.headers {
                if header == &httparse::EMPTY_HEADER {
                    // No more headers...
                    break;
                }
                let name = HeaderName::from_bytes(header.name.as_bytes())
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
                let value_start = header.value.as_ptr() as usize - head.as_ptr() as usize;
                let value_len = header.value.len();
                // Safety: the header value is already validated by httparse
                let value = unsafe {
                    HeaderValue::from_maybe_shared_unchecked(
                        head.slice(value_start..(value_start + value_len)),
                    )
                };
                header_map.append(name, value);
            }
            *request.headers_mut() = header_map;

            (request, body_tx, send_continue_body)
        };
        Ok(Some((request, body_tx, send_continue_body)))
    }
}

#[allow(clippy::type_complexity)]
pub(crate) struct Http1Body {
    inner: AsyncReceiver<Result<http_body::Frame<bytes::Bytes>, std::io::Error>>,
    inner_fut: Option<
        Pin<
            Box<
                kanal::ReceiveFuture<
                    'static,
                    Result<http_body::Frame<bytes::Bytes>, std::io::Error>,
                >,
            >,
        >,
    >,
    send_continue_body: Option<Arc<ContinueSignal>>,
}

impl Body for Http1Body {
    type Data = bytes::Bytes;
    type Error = std::io::Error;

    #[inline]
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        loop {
            if let Some(inner_fut) = &mut this.inner_fut {
                match Pin::new(inner_fut).poll(cx) {
                    Poll::Ready(Ok(Ok(frame))) => {
                        this.inner_fut.take();
                        return Poll::Ready(Some(Ok(frame)));
                    }
                    Poll::Ready(Ok(Err(e))) => {
                        this.inner_fut.take();
                        return Poll::Ready(Some(Err(e)));
                    }
                    Poll::Ready(Err(_)) => {
                        this.inner_fut.take();
                        return Poll::Ready(None);
                    }
                    Poll::Pending => {
                        if let Some(signal) = this.send_continue_body.as_ref() {
                            signal.request();
                        }
                        return Poll::Pending;
                    }
                }
            }

            let fut = this.inner.recv();
            // SAFETY: inner_fut lives as long as inner after storing in struct
            let fut = unsafe {
                std::mem::transmute::<
                    kanal::ReceiveFuture<
                        '_,
                        Result<http_body::Frame<bytes::Bytes>, std::io::Error>,
                    >,
                    kanal::ReceiveFuture<
                        'static,
                        Result<http_body::Frame<bytes::Bytes>, std::io::Error>,
                    >,
                >(fut)
            };
            this.inner_fut = Some(Box::pin(fut));
        }
    }
}
