//! HTTP/2 stream layer (RFC 9113 Sections 5 and 8): one task per
//! stream, message-passing with the connection task over bounded
//! channels.
//!
//! Division of labour:
//!
//! - The connection task ([`super::connection::Connection`]) owns the
//!   socket, the HPACK encoder/decoder and the frame writer. It
//!   validates HEADERS field blocks, runs the stream-state machine
//!   (idle/open/half-closed/closed), and turns messages from the
//!   stream tasks into frames.
//! - Each stream task runs the user's `request_fn` and pipes the
//!   response body back over a [`mpsc`] channel ([`StreamMsg`]). It
//!   never touches the wire or the HPACK tables.
//! - The request body handed to the user is [`H2Body`], fed by the
//!   connection task over a second bounded channel ([`BodyMsg`]); peer
//!   RST_STREAM frames arrive on a separate channel the task polls
//!   beside the response future.
//!
//! Flow control lives on the connection side (C2): this module queues
//! DATA via `StreamEntry::pending_data` and the connection drains it
//! under the flow-control windows.

use std::{
    collections::VecDeque,
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{Context, Poll},
};

use bytes::Bytes;
use http::{HeaderMap, Method, Response, StatusCode, Uri};
use http_body::{Body, Frame};
use pin_project_lite::pin_project;

use super::hpack::Header;
use crate::early_hints::EarlyHintsReceiver;

/// Messages the connection task sends to a stream task: request body
/// frames and terminal signals.
#[derive(Debug)]
pub(crate) enum BodyMsg {
    Data(Bytes),
    Trailers(HeaderMap),
    EndStream,
}

/// Messages a stream task sends to the connection task. The connection
/// turns them into frames; order is preserved (FIFO), so the response
/// header always precedes its body.
#[derive(Debug)]
pub(crate) enum StreamMsg {
    /// Final response headers. `end_stream` sets END_STREAM on the
    /// HEADERS frame (only used when the response has no body).
    Headers {
        parts: http::response::Parts,
        end_stream: bool,
    },
    /// Interim response (100 Continue, 103 Early Hints); never carries
    /// END_STREAM.
    Informational {
        parts: http::response::Parts,
    },
    Data {
        data: Bytes,
        end_stream: bool,
    },
    Trailers {
        trailers: HeaderMap,
    },
    /// Stream error initiated by the stream task (e.g. a body error).
    Reset {
        error_code: u32,
    },
    /// The stream task has finished; the connection may drop its state.
    Closed,
}

/// Per-stream state kept by the connection task (RFC 9113 Section 5.1).
pub(crate) struct StreamEntry {
    /// Request body delivery (receiver lives in the task's [`H2Body`]).
    /// `None` when the request ended with HEADERS (typical GET): no body
    /// frames can arrive, so no channel is allocated at all.
    pub(crate) body_tx: Option<kanal::AsyncSender<BodyMsg>>,
    /// Peer RST_STREAM notifications (receiver lives in the task).
    pub(crate) reset_tx: kanal::AsyncSender<u32>,
    /// Outbound response messages (sender lives in the task).
    pub(crate) msg_rx: kanal::AsyncReceiver<StreamMsg>,
    /// Driver's sender clone; moved out when the task spawns.
    pub(crate) msg_tx: Option<kanal::AsyncSender<StreamMsg>>,
    /// Receiver half for the request body; moved out when the task
    /// spawns (the H2Body hands it to the user).
    pub(crate) body_rx: Option<kanal::AsyncReceiver<BodyMsg>>,
    /// Receiver half for peer resets; moved out when the task spawns.
    pub(crate) reset_rx: Option<kanal::AsyncReceiver<u32>>,
    /// Wakes the drive loop when the task's channel is full.
    pub(crate) wake_tx: Option<kanal::AsyncSender<()>>,
    /// Field block fragments between HEADERS and END_HEADERS.
    pub(crate) field_block: Vec<u8>,
    /// The END_STREAM flag of the frame that opened the field block.
    pub(crate) pending_end_stream: bool,
    /// The request HEADERS were parsed and the task spawned.
    pub(crate) request_started: bool,
    /// The peer sent END_STREAM on this stream (request side done).
    pub(crate) remote_ended: bool,
    /// We sent END_STREAM on this stream (response side done).
    pub(crate) local_ended: bool,
    /// Parsed `content-length`, when present; enforced at end-of-body.
    pub(crate) content_length: Option<u64>,
    /// Sum of DATA payload lengths received so far.
    pub(crate) data_sum: u64,
    /// A trailer section was already received (only one is allowed).
    pub(crate) trailers_seen: bool,
    /// The stream task has finished and signalled `StreamMsg::Closed`
    /// (its message channel is now empty). The stream itself lives on
    /// until `local_ended` so any flow-controlled `pending_data` can
    /// still be drained by WINDOW_UPDATE.
    pub(crate) task_done: bool,
    /// Server-side flow-control window for this stream (RFC 9113
    /// Section 6.9): DATA payloads we may still send.
    pub(crate) send_window: i64,
    /// DATA chunks queued because the peer's flow-control window ran
    /// out; each entry is `(bytes, end_stream)`. Drained as the window
    /// opens up (WINDOW_UPDATE or SETTINGS_INITIAL_WINDOW_SIZE).
    pub(crate) pending_data: VecDeque<(Bytes, bool)>,
    /// Deficit for DRR fairness when draining `pending_data` across
    /// streams under connection flow-control.
    pub(crate) deficit: usize,
    /// Header field size
    pub(crate) header_list_size: usize,
    /// Frames seen so far in the open field block (HEADERS without
    /// END_HEADERS plus each CONTINUATION). Resets to 0 when the block
    /// completes; bounded by the connection's continuation-flood limit.
    pub(crate) continuation_frames: usize,
}

impl StreamEntry {
    #[inline]
    pub(crate) fn new(
        reset_tx: kanal::AsyncSender<u32>,
        msg_rx: kanal::AsyncReceiver<StreamMsg>,
    ) -> Self {
        StreamEntry {
            body_tx: None,
            reset_tx,
            msg_rx,
            msg_tx: None,
            body_rx: None,
            reset_rx: None,
            wake_tx: None,
            field_block: Vec::new(),
            pending_end_stream: false,
            request_started: false,
            remote_ended: false,
            local_ended: false,
            content_length: None,
            data_sum: 0,
            trailers_seen: false,
            task_done: false,
            send_window: 65535,
            pending_data: VecDeque::new(),
            deficit: 0,
            header_list_size: 0,
            continuation_frames: 0,
        }
    }

    /// Extends the in-flight field block with one fragment (HEADERS or
    /// CONTINUATION payload).
    #[inline]
    pub(crate) fn extend_block(&mut self, block: &[u8]) {
        self.field_block.extend_from_slice(block);
    }

    /// Takes and clears the accumulated field block.
    #[inline]
    pub(crate) fn take_block(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.field_block)
    }

    /// Forwards a request body message to the task; `Ok(false)` when the
    /// task has gone away or when there is no body channel (the request
    /// ended with HEADERS, so no body reader exists).
    #[inline]
    pub(crate) async fn send_body(&mut self, msg: BodyMsg) -> bool {
        match &self.body_tx {
            Some(tx) => tx.send(msg).await.is_ok(),
            None => false,
        }
    }

    #[inline]
    pub(crate) fn send_reset(&self, code: u32) {
        let _ = self.reset_tx.try_send(code);
    }
}

/// The request body type exposed as `Incoming::H2`.
///
/// Backed by a bounded channel the connection task fills with DATA
/// frames and trailers. Polling marks the `send_continue_body` flag so
/// the driver can emit `100 Continue` on first demand (RFC 9113
/// Section 8.1.1).
pub(crate) struct H2Body {
    inner: kanal::AsyncReceiver<BodyMsg>,
    inner_fut: Option<Pin<Box<kanal::ReceiveFuture<'static, BodyMsg>>>>,
    send_continue_body: Option<Arc<AtomicBool>>,
    ended: bool,
}

impl H2Body {
    #[inline]
    pub(crate) fn new(
        rx: kanal::AsyncReceiver<BodyMsg>,
        send_continue_body: Option<Arc<AtomicBool>>,
    ) -> Self {
        H2Body {
            inner: rx,
            inner_fut: None,
            send_continue_body,
            ended: false,
        }
    }
}

impl Body for H2Body {
    type Data = Bytes;
    type Error = std::io::Error;

    #[inline]
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if this.ended {
            return Poll::Ready(None);
        }
        loop {
            if let Some(inner_fut) = &mut this.inner_fut {
                match Pin::new(inner_fut).poll(cx) {
                    Poll::Ready(Ok(BodyMsg::Data(data))) => {
                        this.inner_fut.take();
                        return Poll::Ready(Some(Ok(Frame::data(data))));
                    }
                    Poll::Ready(Ok(BodyMsg::Trailers(trailers))) => {
                        this.inner_fut.take();
                        return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
                    }
                    Poll::Ready(Ok(BodyMsg::EndStream)) => {
                        this.ended = true;
                        this.inner_fut.take();
                        return Poll::Ready(None);
                    }
                    Poll::Ready(Err(_)) => {
                        // The connection dropped the stream (reset, closed,
                        // connection gone).
                        this.ended = true;
                        this.inner_fut.take();
                        return Poll::Ready(None);
                    }
                    Poll::Pending => {
                        if let Some(scb) = this.send_continue_body.as_ref() {
                            scb.store(true, Ordering::Relaxed);
                        }
                        return Poll::Pending;
                    }
                }
            }

            let fut = this.inner.recv();
            // SAFETY: inner_fut lives as long as inner after storing in struct
            let fut = unsafe {
                std::mem::transmute::<
                    kanal::ReceiveFuture<'_, BodyMsg>,
                    kanal::ReceiveFuture<'static, BodyMsg>,
                >(fut)
            };
            this.inner_fut = Some(Box::pin(fut));
        }
    }
}

/// A decoded and validated request, ready for the stream task.
pub(crate) struct ParsedRequest {
    pub(crate) method: Method,
    pub(crate) uri: Uri,
    pub(crate) headers: HeaderMap,
    /// Parsed `content-length`, or `None` when absent.
    pub(crate) content_length: Option<u64>,
    /// The request carries `expect: 100-continue`.
    pub(crate) expect_continue: bool,
    pub(crate) is_connect: bool,
}

/// The HEADERS block was rejected as malformed (RFC 9113
/// Section 8.1.2.6): the connection answers with a stream error
/// PROTOCOL_ERROR.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct MalformedRequest;

/// Header names a request must not carry (RFC 9113 Section 8.1.2.2).
const CONNECTION_SPECIFIC: &[&[u8]] = &[
    b"connection",
    b"keep-alive",
    b"proxy-connection",
    b"transfer-encoding",
    b"upgrade",
];

#[inline]
pub(crate) fn is_connection_specific(name: &[u8]) -> bool {
    CONNECTION_SPECIFIC
        .iter()
        .any(|forbidden| **forbidden == *name)
}

/// Validates a decoded request field block and builds an
/// `http::Request`-ready representation.
///
/// Every violation is a *stream* error (malformed request, RFC 9113
/// Section 8.1.2.6): pseudo-header rules (Section 8.1.2.1), required
/// and unique request pseudo-headers (Section 8.1.2.3),
/// connection-specific header fields (Section 8.1.2.2) and
/// `content-length` syntax (Section 8.1.2.6).
#[inline]
pub(crate) fn parse_request(headers: &[Header]) -> Result<ParsedRequest, MalformedRequest> {
    let mut method: Option<&[u8]> = None;
    let mut scheme: Option<&[u8]> = None;
    let mut authority: Option<&[u8]> = None;
    let mut path: Option<&[u8]> = None;
    let mut protocol: Option<&[u8]> = None;
    let mut regular = HeaderMap::new();
    let mut content_length: Option<u64> = None;
    let mut content_length_conflict = false;

    let mut pseudo_phase = true;
    for header in headers {
        let name = header.name();
        let value = header.value_bytes();
        if name.first() == Some(&b':') {
            if !pseudo_phase {
                // A pseudo-header after a regular header (Section
                // 8.1.2.1).
                return Err(MalformedRequest);
            }
            match name {
                b":method" => {
                    if method.is_some() {
                        return Err(MalformedRequest);
                    }
                    method = Some(value);
                }
                b":scheme" => {
                    if scheme.is_some() {
                        return Err(MalformedRequest);
                    }
                    scheme = Some(value);
                }
                b":authority" => {
                    if authority.is_some() {
                        return Err(MalformedRequest);
                    }
                    authority = Some(value);
                }
                b":path" => {
                    if path.is_some() {
                        return Err(MalformedRequest);
                    }
                    path = Some(value);
                }
                b":protocol" => {
                    if protocol.is_some() {
                        return Err(MalformedRequest);
                    }
                    protocol = Some(value);
                }
                // Unknown or response-defined pseudo-header (Sections
                // 8.1.2.1).
                _ => return Err(MalformedRequest),
            }
        } else {
            pseudo_phase = false;
            if is_connection_specific(name) {
                return Err(MalformedRequest);
            }
            if name == b"te" && !te_is_trailers(value) {
                return Err(MalformedRequest);
            }
            if name == b"content-length" {
                let value = parse_content_length(value)?;
                if let Some(previous) = content_length {
                    if previous != value {
                        content_length_conflict = true;
                    }
                } else {
                    content_length = Some(value);
                }
            }
            if name.iter().any(|byte| byte.is_ascii_uppercase()) {
                // Field names must be lowercase (Section 8.1.2.1);
                // `HeaderName::from_bytes` would quietly normalize.
                return Err(MalformedRequest);
            }
            let name = http::header::HeaderName::from_bytes(name).map_err(|_| MalformedRequest)?;
            let value = http::header::HeaderValue::from_maybe_shared(value.clone())
                .map_err(|_| MalformedRequest)?;
            regular.append(name, value);
        }
    }

    let is_connect = method == Some(&b"CONNECT"[..]);
    let Some(method) = method else {
        return Err(MalformedRequest);
    };
    if is_connect {
        // CONNECT (Sections 8.3, 8.5): only :authority (and optionally
        // :protocol, RFC 8441).
        let Some(authority) = authority else {
            return Err(MalformedRequest);
        };
        if scheme.is_some() || path.is_some() {
            return Err(MalformedRequest);
        }
        if content_length_conflict {
            return Err(MalformedRequest);
        }
        let uri = Uri::try_from(authority).map_err(|_| MalformedRequest)?;
        return Ok(ParsedRequest {
            method: Method::from_bytes(method).map_err(|_| MalformedRequest)?,
            uri,
            headers: regular,
            content_length,
            expect_continue: false,
            is_connect: true,
        });
    }
    if protocol.is_some() {
        // :protocol is only valid aboard CONNECT (RFC 8441).
        return Err(MalformedRequest);
    }
    let Some(scheme) = scheme else {
        return Err(MalformedRequest);
    };
    let Some(path) = path else {
        return Err(MalformedRequest);
    };
    if path.is_empty() {
        return Err(MalformedRequest);
    }

    let uri = {
        let scheme = std::str::from_utf8(scheme).map_err(|_| MalformedRequest)?;
        let mut builder = Uri::builder();
        builder = builder.scheme(scheme);
        if let Some(authority) = authority.as_ref() {
            let authority = std::str::from_utf8(authority).map_err(|_| MalformedRequest)?;
            builder = builder.authority(authority);
        }
        let path = std::str::from_utf8(path).map_err(|_| MalformedRequest)?;
        match builder.path_and_query(path).build() {
            Ok(uri) => uri,
            // :authority was omitted: fall back to the origin form so
            // the target URI still round-trips.
            Err(_) => Uri::try_from(path).map_err(|_| MalformedRequest)?,
        }
    };

    let expect_continue = regular
        .get(http::header::EXPECT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("100-continue"));

    if content_length_conflict {
        return Err(MalformedRequest);
    }

    Ok(ParsedRequest {
        method: Method::from_bytes(method).map_err(|_| MalformedRequest)?,
        uri,
        headers: regular,
        content_length,
        expect_continue,
        is_connect: false,
    })
}

/// The TE field is only legal with the single value "trailers"
/// (RFC 9113 Section 8.1.2.2).
#[inline]
pub(crate) fn te_is_trailers(value: &[u8]) -> bool {
    std::str::from_utf8(value)
        .ok()
        .is_some_and(|value| value.split(',').all(|part| part.trim() == "trailers"))
}

/// Parses a content-length header value into a `u64`; anything but
/// bare digits (optionally framed by OWS) is malformed.
#[inline]
pub(crate) fn parse_content_length(value: &[u8]) -> Result<u64, MalformedRequest> {
    let start = match value
        .iter()
        .position(|byte| *byte != b' ' && *byte != b'\t')
    {
        // Empty or all-whitespace.
        None => return Err(MalformedRequest),
        Some(start) => start,
    };
    let end = value
        .iter()
        .rposition(|byte| *byte != b' ' && *byte != b'\t')
        .unwrap_or(start);
    let value = &value[start..=end];
    if value.is_empty() || value.iter().any(|byte| !byte.is_ascii_digit()) {
        return Err(MalformedRequest);
    }
    let mut result: u64 = 0;
    for &byte in value {
        result = result
            .checked_mul(10)
            .and_then(|n| n.checked_add((byte - b'0') as u64))
            .ok_or(MalformedRequest)?;
    }
    Ok(result)
}

/// Validates a trailer field block (RFC 9113 Section 8.1.2.1):
/// pseudo-header fields are not allowed in trailers.
#[inline]
pub(crate) fn parse_trailers(headers: &[Header]) -> Result<HeaderMap, MalformedRequest> {
    let mut trailers = HeaderMap::new();
    for header in headers {
        let name = header.name();
        if name.first() == Some(&b':') {
            return Err(MalformedRequest);
        }
        if name.iter().any(|byte| byte.is_ascii_uppercase()) {
            return Err(MalformedRequest);
        }
        let name = http::header::HeaderName::from_bytes(name).map_err(|_| MalformedRequest)?;
        let value = http::header::HeaderValue::from_maybe_shared(header.value_bytes().clone())
            .map_err(|_| MalformedRequest)?;
        trailers.append(name, value);
    }
    Ok(trailers)
}

pub(crate) use service::StreamDriver;

mod service;

#[cfg(test)]
mod tests;
