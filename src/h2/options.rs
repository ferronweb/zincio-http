use std::time::Duration;

use crate::h2::codec::{
    DEFAULT_CONNECTION_WINDOW_SIZE, DEFAULT_INITIAL_WINDOW_SIZE, DEFAULT_MAX_FRAME_SIZE,
};

/// HTTP/2 server configuration.
///
/// Build one with [`Http2Options::default`] and override individual fields
/// with the builder methods, then hand it to [`Http2::new`](crate::Http2::new).
///
/// Unlike the framing/header limits below, the connection window settings
/// ([`initial_stream_window_size`](Http2Options::initial_stream_window_size)
/// and [`initial_connection_window_size`](Http2Options::initial_connection_window_size))
/// are advisory: a client may shrink them with its own `SETTINGS`, and the
/// server honours the smaller value.
#[derive(Debug, Clone)]
pub struct Http2Options {
    /// Max time to wait for the client's preface before giving up.
    pub(crate) handshake_timeout: Option<Duration>,
    /// Send a `100 Continue` response as soon as a request's headers arrive,
    /// before its body has been fully read.
    pub(crate) send_continue_response: bool,
    /// Insert a `Date` header into every response when absent.
    pub(crate) send_date_header: bool,
    /// Maximum number of concurrent streams the server allows.
    pub(crate) max_concurrent_streams: u32,
    /// Initial per-stream flow-control window the server advertises.
    pub(crate) initial_stream_window_size: u32,
    /// Initial connection-level flow-control window the server uses.
    pub(crate) initial_connection_window_size: u32,
    /// Largest frame payload the server will send or receive.
    pub(crate) max_frame_size: u32,
    /// Largest uncompressed header list the server will accept.
    pub(crate) max_header_list_size: u32,
    /// Whether to enable Extended CONNECT
    pub(crate) enable_connect_protocol: bool,
    /// Close a connection after this long with no frame from the peer
    /// (RFC 9113 Section 10.5). `None` disables the idle timeout.
    pub(crate) idle_timeout: Option<Duration>,
    /// Maximum number of RST_STREAM frames this endpoint sends in
    /// response to protocol errors made by the peer across the lifetime
    /// of the connection. `None` disables the limit.
    pub(crate) max_local_error_reset_streams: Option<usize>,
    /// Maximum number of streams the peer reset before this endpoint
    /// accepted them (their request was never dispatched). `None`
    /// disables the limit.
    pub(crate) max_pending_accept_reset_streams: Option<usize>,
    /// Maximum number of frames that may make up a single, not-yet-finalized
    /// header field block (HEADERS or PUSH_PROMISE without END_HEADERS
    /// followed by CONTINUATION frames). A peer that keeps a field block
    /// open across more frames than this is running a CONTINUATION flood
    /// (CVE-2024-27919 et al.) and the offending stream is reset with
    /// `RST_STREAM` `PROTOCOL_ERROR`. `None` selects a safe default derived
    /// from `max_header_list_size` / `max_frame_size` plus a packing buffer.
    pub(crate) max_continuation_frames: Option<usize>,
}

impl Default for Http2Options {
    #[inline]
    fn default() -> Self {
        Http2Options {
            handshake_timeout: Some(Duration::from_secs(10)),
            send_continue_response: true,
            send_date_header: true,
            max_concurrent_streams: 200,
            initial_stream_window_size: DEFAULT_INITIAL_WINDOW_SIZE,
            // RFC 9113 Section 6.9.1: the connection send window starts
            // at 65535; the peer raises it with WINDOW_UPDATE. Do not
            // raise this without also sending a WINDOW_UPDATE that
            // advertises the larger receive window, or the peer will
            // treat our sends as a flow-control violation.
            initial_connection_window_size: DEFAULT_CONNECTION_WINDOW_SIZE,
            max_frame_size: DEFAULT_MAX_FRAME_SIZE as u32,
            max_header_list_size: 1024 * 16,
            enable_connect_protocol: false,
            idle_timeout: None,
            max_local_error_reset_streams: Some(1024),
            max_pending_accept_reset_streams: Some(20),
            max_continuation_frames: None,
        }
    }
}

impl Http2Options {
    /// Sets the maximum time to wait for a client to send the HTTP/2
    /// preface before aborting the connection.
    #[inline]
    pub fn handshake_timeout(mut self, handshake_timeout: Option<Duration>) -> Self {
        self.handshake_timeout = handshake_timeout;
        self
    }

    /// Sends `100 Continue` responses automatically when a request has a body.
    ///
    /// Defaults to `true`.
    #[inline]
    pub fn send_continue_response(mut self, send_continue_response: bool) -> Self {
        self.send_continue_response = send_continue_response;
        self
    }

    /// Inserts a `Date` header into responses that lack one.
    ///
    /// Defaults to `true`.
    #[inline]
    pub fn send_date_header(mut self, send_date_header: bool) -> Self {
        self.send_date_header = send_date_header;
        self
    }

    /// Sets the maximum number of concurrent streams allowed on a connection.
    ///
    /// Defaults to `200`.
    #[inline]
    pub fn max_concurrent_streams(mut self, max_concurrent_streams: u32) -> Self {
        self.max_concurrent_streams = max_concurrent_streams;
        self
    }

    /// Sets the initial per-stream flow-control window size advertised to the
    /// client. Defaults to `1_048_576`.
    #[inline]
    pub fn initial_stream_window_size(mut self, initial_stream_window_size: u32) -> Self {
        self.initial_stream_window_size = initial_stream_window_size;
        self
    }

    /// Sets the initial connection-level flow-control window size.
    /// Defaults to `1_048_576`.
    #[inline]
    pub fn initial_connection_window_size(mut self, initial_connection_window_size: u32) -> Self {
        self.initial_connection_window_size = initial_connection_window_size;
        self
    }

    /// Sets the maximum frame size the server will send or receive.
    /// Defaults to the RFC 9113 default (`16_384`); must not exceed
    /// `2^24 - 1`.
    #[inline]
    pub fn max_frame_size(mut self, max_frame_size: u32) -> Self {
        self.max_frame_size = max_frame_size;
        self
    }

    /// Sets the maximum size of an uncompressed header list the server will
    /// accept. Defaults to `16_384`.
    #[inline]
    pub fn max_header_list_size(mut self, max_header_list_size: u32) -> Self {
        self.max_header_list_size = max_header_list_size;
        self
    }

    /// Sets whether to enable the Extended CONNECT protocol, allowing for
    /// example for tunneling WebSockets over HTTP/2. Defaults to `false`.
    #[inline]
    pub fn enable_connect_protocol(mut self, enable: bool) -> Self {
        self.enable_connect_protocol = enable;
        self
    }

    /// Sets the idle timeout: a connection that receives no frame from the
    /// peer for this long is closed gracefully with a `GOAWAY` (RFC 9113
    /// Section 10.5). Defaults to `None` (no idle timeout).
    #[inline]
    pub fn idle_timeout(mut self, idle_timeout: Option<Duration>) -> Self {
        self.idle_timeout = idle_timeout;
        self
    }

    /// Sets the maximum number of RST_STREAM frames this endpoint sends in
    /// response to protocol errors made by the peer across the lifetime of
    /// the connection. When the peer keeps producing protocol errors past
    /// this many local resets, the connection is closed with a GOAWAY of
    /// type `ENHANCE_YOUR_CALM` (RFC 9113 Section 10.5.2). `None` disables
    /// the limit. Defaults to `Some(1024)`.
    #[inline]
    pub fn max_local_error_reset_streams(mut self, max: Option<usize>) -> Self {
        self.max_local_error_reset_streams = max;
        self
    }

    /// Sets the maximum number of streams the peer reset before this endpoint
    /// accepted them (their request was never dispatched) that may be
    /// counted at a time. When the peer keeps opening and resetting streams
    /// faster than they are consumed, the connection is closed with a GOAWAY
    /// of type `ENHANCE_YOUR_CALM` (RFC 9113 Section 10.5.2). `None` disables
    /// the limit. Defaults to `Some(20)`.
    #[inline]
    pub fn max_pending_accept_reset_streams(mut self, max: Option<usize>) -> Self {
        self.max_pending_accept_reset_streams = max;
        self
    }

    /// Sets the maximum number of frames that may compose a single header
    /// field block that has not yet been terminated by END_HEADERS. A field
    /// block is opened by a HEADERS (or PUSH_PROMISE) frame without
    /// END_HEADERS and continued by CONTINUATION frames. When a peer keeps
    /// one open past this many frames, it is a CONTINUATION flood and the
    /// stream is reset with `RST_STREAM` `PROTOCOL_ERROR`.
    ///
    /// `None` (the default) computes a safe bound automatically: the
    /// configured `max_header_list_size` divided by `max_frame_size`,
    /// plus a ~20% packing buffer and a fixed slack of 10 frames. This is
    /// enough for any honestly-packed header block while catching floods
    /// that never close the block.
    ///
    /// Defaults to `None`.
    #[inline]
    pub fn max_continuation_frames(mut self, max: Option<usize>) -> Self {
        self.max_continuation_frames = max;
        self
    }
}
