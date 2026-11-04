use std::io::IoSlice;

use futures_util::FutureExt;
use http::{header, HeaderMap, HeaderValue, Response, Version};
use http_body::Body;
use http_body_util::BodyExt;
use tokio::io::AsyncWriteExt;

use crate::h1::{
    write_chunk_size, Http1, ZerocopyResponse, ZerocopySend, WRITE_BUF_BATCH_THRESHOLD,
};

impl<Io> Http1<Io>
where
    Io: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + 'static,
{
    #[inline]
    pub(crate) async fn write_response<Z: ZerocopySend<Io>>(
        &mut self,
        mut response: Response<
            impl Body<Data = bytes::Bytes, Error = impl std::error::Error> + Unpin,
        >,
        version: Version,
        write_trailers: bool,
        is_head: bool,
        zerocopy: &mut Z,
    ) -> Result<(), std::io::Error> {
        // Date header
        if self.options.send_date_header {
            response.headers_mut().insert(
                header::DATE,
                HeaderValue::from_str(self.get_date_header_value())
                    .map_err(|e| std::io::Error::other(e.to_string()))?,
            );
        }

        // If the body has a size hint, set the Content-Length header if it's not already set
        if let Some(suggested_content_length) = response.body().size_hint().exact() {
            let headers = response.headers_mut();
            if !headers.contains_key(header::CONTENT_LENGTH) {
                headers.insert(header::CONTENT_LENGTH, suggested_content_length.into());
            }
        }

        let chunked = response
            .headers()
            .get(header::TRANSFER_ENCODING)
            .map(|v| {
                v.to_str().ok().is_some_and(|s| {
                    s.split(',')
                        .any(|s| s.trim().eq_ignore_ascii_case("chunked"))
                })
            })
            .unwrap_or_else(|| {
                response
                    .headers()
                    .get(header::CONTENT_LENGTH)
                    .and_then(|v| v.to_str().ok())
                    .is_none_or(|s| s.parse::<u64>().is_err())
            });

        if chunked {
            response.headers_mut().insert(
                header::TRANSFER_ENCODING,
                HeaderValue::from_static("chunked"),
            );
            while response
                .headers_mut()
                .remove(header::CONTENT_LENGTH)
                .is_some()
            {}
        }

        let (parts, body, chunked) = if !is_head {
            let (parts, body) = response.into_parts();
            (parts, Some(body), chunked)
        } else {
            let (parts, _) = response.into_parts();
            (parts, None, false)
        };

        self.response_head_buf.clear();
        let estimated_head_len = 30 + parts.headers.len() * 30; // Similar to Hyper's heuristic
        if self.response_head_buf.capacity() < estimated_head_len {
            self.response_head_buf
                .reserve(estimated_head_len - self.response_head_buf.capacity());
        }
        let head = &mut self.response_head_buf;
        if version == Version::HTTP_10 {
            head.extend_from_slice(b"HTTP/1.0 ");
        } else {
            head.extend_from_slice(b"HTTP/1.1 ");
        }
        let status = parts.status;
        head.extend_from_slice(status.as_str().as_bytes());
        if let Some(canonical_reason) = status.canonical_reason() {
            head.extend_from_slice(b" ");
            head.extend_from_slice(canonical_reason.as_bytes());
        }
        head.extend_from_slice(b"\r\n");
        for (name, value) in &parts.headers {
            head.extend_from_slice(name.as_str().as_bytes());
            head.extend_from_slice(b": ");
            head.extend_from_slice(value.as_bytes());
            head.extend_from_slice(b"\r\n");
        }
        head.extend_from_slice(b"\r\n");
        unsafe {
            self.write_buf.push(IoSlice::new(head));
        }

        if !chunked {
            if let Some(content_length) = parts
                .headers
                .get(header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
            {
                if let Some(zero_copy) = parts.extensions.get::<ZerocopyResponse>() {
                    if zerocopy.enabled() {
                        // Zerocopy
                        unsafe {
                            self.write_buf
                                .flush(&mut self.io, self.options.enable_vectored_write)
                                .await?
                        };
                        zerocopy
                            .send(zero_copy, &mut self.io, content_length)
                            .await?;
                        self.io.flush().await?;
                        let reclaimed_headers = parts.headers;
                        self.cached_headers = Some(reclaimed_headers);
                        return Ok(());
                    }
                }
            }
        }

        if let Some(mut body) = body {
            let mut trailers_written = false;
            let mut first_chunk = true;
            while let Some(chunk) = futures_util::select_biased! {
                // Biased, to not flush the buffer before attempting to read the next chunk

                chunk = body.frame().fuse() => chunk,
                _ = (async {
                    if !first_chunk {
                        let _ = unsafe {
                            self.write_buf
                                .flush(&mut self.io, self.options.enable_vectored_write)
                                .await
                        };
                        let _ = self.io.flush().await;
                    }
                    std::future::pending::<()>().await
                }).fuse() => unreachable!()
            } {
                first_chunk = false;
                let chunk = chunk.map_err(|e| std::io::Error::other(e.to_string()))?;
                match chunk.into_data() {
                    Ok(data) => {
                        if data.is_empty() {
                            continue;
                        }
                        if chunked {
                            let mut chunk_size_buf = [0u8; 18];
                            let chunk_size = write_chunk_size(&mut chunk_size_buf, data.len());
                            self.write_buf.push_copy(chunk_size);
                            self.write_buf.push_bytes(data);
                            unsafe {
                                self.write_buf.push(IoSlice::new(b"\r\n"));
                            }
                        } else {
                            self.write_buf.push_bytes(data);
                        }
                        while self.write_buf.len() >= WRITE_BUF_BATCH_THRESHOLD {
                            let bytes_written = unsafe {
                                self.write_buf
                                    .write(&mut self.io, self.options.enable_vectored_write)
                                    .await?
                            };
                            if bytes_written == 0 {
                                return Err(std::io::ErrorKind::WriteZero.into());
                            }
                        }
                    }
                    Err(chunk) => {
                        if let Ok(trailers) = chunk.into_trailers() {
                            if write_trailers {
                                unsafe {
                                    self.write_buf.push(IoSlice::new(b"0\r\n"));
                                    for (name, value) in &trailers {
                                        self.write_buf.push_copy(name.as_str().as_bytes());
                                        self.write_buf.push(IoSlice::new(b": "));
                                        self.write_buf.push_copy(value.as_bytes());
                                        self.write_buf.push(IoSlice::new(b"\r\n"));
                                    }
                                    self.write_buf.push(IoSlice::new(b"\r\n"));
                                }
                                trailers_written = true;
                            }
                            break;
                        }
                    }
                };
            }
            if chunked && !trailers_written {
                // Terminating chunk
                unsafe {
                    self.write_buf.push(IoSlice::new(b"0\r\n\r\n"));
                }
            }
        }
        unsafe {
            self.write_buf
                .flush(&mut self.io, self.options.enable_vectored_write)
                .await?;
        }
        self.io.flush().await?;
        let reclaimed_headers = parts.headers;
        self.cached_headers = Some(reclaimed_headers);

        Ok(())
    }

    #[inline]
    pub(crate) async fn write_100_continue(
        &mut self,
        version: Version,
    ) -> Result<(), std::io::Error> {
        if version == Version::HTTP_10 {
            self.io.write_all(b"HTTP/1.0 100 Continue\r\n\r\n").await?;
        } else {
            self.io.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await?;
        }
        self.io.flush().await?;

        Ok(())
    }

    #[inline]
    pub(crate) async fn write_early_hints(
        &mut self,
        version: Version,
        headers: HeaderMap,
    ) -> Result<(), std::io::Error> {
        let mut head = Vec::new();
        if version == Version::HTTP_10 {
            head.extend_from_slice(b"HTTP/1.0 103 Early Hints\r\n");
        } else {
            head.extend_from_slice(b"HTTP/1.1 103 Early Hints\r\n");
        }
        let mut current_header_name = None;
        for (name, value) in headers {
            if let Some(name) = name {
                current_header_name = Some(name);
            };
            if let Some(current_header_name) = &current_header_name {
                head.extend_from_slice(current_header_name.as_str().as_bytes());
                if value.is_empty() {
                    head.extend_from_slice(b":\r\n");
                    continue;
                }
                head.extend_from_slice(b": ");
                head.extend_from_slice(value.as_bytes());
                head.extend_from_slice(b"\r\n");
            }
        }
        head.extend_from_slice(b"\r\n");

        self.io.write_all(&head).await?;

        Ok(())
    }
}
