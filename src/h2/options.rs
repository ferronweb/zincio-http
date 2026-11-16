use std::time::Duration;

use crate::h2::codec::{
    DEFAULT_CONNECTION_WINDOW_SIZE, DEFAULT_INITIAL_WINDOW_SIZE, DEFAULT_MAX_FRAME_SIZE,
};

/// HTTP/2 server configuration.
///
/// Build with [`Http2Options::default`] and override fields with the builder
/// methods.
#[derive(Debug, Clone)]
pub struct Http2Options {
    /// Max time to wait for the client's preface before giving up.
    pub(crate) handshake_timeout: Option<Duration>,
    pub(crate) header_read_timeout: Option<std::time::Duration>,
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
    /// produced a final response for them . `None` disables the limit.
    pub(crate) max_pending_accept_reset_streams: Option<usize>,
    /// Maximum number of frames that may make up a single, not-yet-finalized
    /// header field block (HEADERS or PUSH_PROMISE without END_HEADERS
    /// followed by CONTINUATION frames). `None` selects a safe default derived
    /// from `max_header_list_size` / `max_frame_size` plus a packing buffer.
    pub(crate) max_continuation_frames: Option<usize>,
}

impl Http2Options {
    /// Creates options with the defaults shown below.
    ///
    /// | Option | Default |
    /// |---|---|
    /// | handshake_timeout | 10 seconds |
    /// | header_read_timeout | 10 seconds |
    /// | send_continue_response | `true` |
    /// | send_date_header | `true` |
    /// | max_concurrent_streams | 200 |
    /// | initial_stream_window_size | `1048576` |
    /// | initial_connection_window_size | `65535` |
    /// | max_frame_size | `16384` |
    /// | max_header_list_size | `16384` |
    /// | enable_connect_protocol | `false` |
    /// | idle_timeout | none |
    /// | max_local_error_reset_streams | 1,024 |
    /// | max_pending_accept_reset_streams | 20 |
    /// | max_continuation_frames | calculated safe default |
    pub fn new() -> Self {
        Self {
            handshake_timeout: Some(Duration::from_secs(10)),
            header_read_timeout: Some(Duration::from_secs(30)),
            send_continue_response: true,
            send_date_header: true,
            max_concurrent_streams: 200,
            initial_stream_window_size: DEFAULT_INITIAL_WINDOW_SIZE,
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

    /// Sets the maximum time to wait for a client to send the HTTP/2
    /// preface before aborting the connection.
    #[inline]
    pub fn handshake_timeout(mut self, handshake_timeout: Option<Duration>) -> Self {
        self.handshake_timeout = handshake_timeout;
        self
    }

    /// Sets the timeout for reading the complete request head.
    ///
    /// If the client does not send a full set of request headers within this
    /// duration the HTTP/2 stream is closed with `RST_STREAM`.
    /// Pass `None` to disable the timeout entirely. Defaults to **30 seconds**.
    #[inline]
    pub fn header_read_timeout(mut self, header_read_timeout: Option<Duration>) -> Self {
        self.header_read_timeout = header_read_timeout;
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
    /// Defaults to `65_535`.
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
        self.max_frame_size = max_frame_size.clamp(16_384, 16_777_215);
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

    /// Sets the idle timeout: a connection that receives no frame for this
    /// long is closed gracefully with a GOAWAY. `None` disables it.
    #[inline]
    pub fn idle_timeout(mut self, idle_timeout: Option<Duration>) -> Self {
        self.idle_timeout = idle_timeout;
        self
    }

    /// Sets the budget for resets sent in response to peer protocol errors.
    /// Exceeding it closes with GOAWAY `ENHANCE_YOUR_CALM` (RFC 9113 Section
    /// 10.5.2). Defaults to 1024.
    #[inline]
    pub fn max_local_error_reset_streams(mut self, max: Option<usize>) -> Self {
        self.max_local_error_reset_streams = max;
        self
    }

    /// Sets how many peer-reset streams may be counted before a final
    /// response. The budget refills at 50 per second (RFC 9113 Section
    /// 10.5.2). Defaults to 20.
    #[inline]
    pub fn max_pending_accept_reset_streams(mut self, max: Option<usize>) -> Self {
        self.max_pending_accept_reset_streams = max;
        self
    }

    /// Sets the maximum frames in one header block before it is treated as a
    /// CONTINUATION flood. `None` computes a safe bound from the other
    /// limits (the configured `max_header_list_size` divided by `max_frame_size`,
    /// plus a ~20% packing buffer and a fixed slack of 10 frames).
    #[inline]
    pub fn max_continuation_frames(mut self, max: Option<usize>) -> Self {
        self.max_continuation_frames = max;
        self
    }
}

impl Default for Http2Options {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}
