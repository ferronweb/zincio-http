//! Configuration options for the native HTTP/3 connection driver.

use crate::h3::settings::LocalSettings;

/// Configuration options for the HTTP/3 connection handler.
///
/// Use the builder-style methods to customise behaviour, then pass the finished
/// value to [`Http3::new`](super::Http3::new).
///
/// # Examples
///
/// ```rust,ignore
/// let options = Http3Options::default()
///     .handshake_timeout(Some(std::time::Duration::from_secs(10)))
///     .accept_timeout(Some(std::time::Duration::from_secs(60)));
/// ```
pub struct Http3Options {
    pub(super) local_settings: LocalSettings,
    pub(super) accept_timeout: Option<std::time::Duration>,
    pub(super) handshake_timeout: Option<std::time::Duration>,
    pub(super) send_continue_response: bool,
    pub(super) send_date_header: bool,
    pub(super) max_local_error_reset_streams: Option<usize>,
    pub(super) max_pending_accept_reset_streams: Option<usize>,
}

impl Http3Options {
    /// Creates a new `Http3Options` with the following defaults:
    ///
    /// | Option | Default |
    /// |---|---|
    /// | `accept_timeout` | 30 seconds |
    /// | `handshake_timeout` | 30 seconds |
    /// | `send_continue_response` | `true` |
    /// | `send_date_header` | `true` |
    /// | `qpack_max_table_capacity` | `0` (RFC 9204 default) |
    /// | `qpack_blocked_streams` | `0` (RFC 9204 default) |
    /// | `max_field_section_size` | 65,536 |
    /// | `enable_connect_protocol` | `false` |
    /// | `max_local_error_reset_streams` | `1024` |
    /// | `max_pending_accept_reset_streams` | `20` |
    ///
    /// The QPACK/limit settings are advertised to the peer in this
    /// endpoint's SETTINGS frame and bound its codecs: the decoder's
    /// dynamic-table capacity and blocked-stream budget come from
    /// `qpack_max_table_capacity` and `qpack_blocked_streams`; the peer's
    /// encoder is limited by them in turn. `max_field_section_size` bounds
    /// how large a field section this endpoint will accept.
    #[inline]
    pub fn new() -> Self {
        Self {
            local_settings: LocalSettings::default(),
            accept_timeout: Some(std::time::Duration::from_secs(30)),
            handshake_timeout: Some(std::time::Duration::from_secs(30)),
            send_continue_response: true,
            send_date_header: true,
            max_local_error_reset_streams: Some(1024),
            max_pending_accept_reset_streams: Some(20),
        }
    }

    /// Sets the maximum dynamic-table capacity this endpoint will grant the
    /// peer's QPACK encoder via `SETTINGS_QPACK_MAX_TABLE_CAPACITY` (RFC
    /// 9204 Section 5).
    ///
    /// This is also the capacity this endpoint's own QPACK decoder uses. It
    /// must not exceed 2^30 - 1. Defaults to **`0`** (no dynamic table).
    #[inline]
    pub fn qpack_max_table_capacity(mut self, capacity: u64) -> Self {
        self.local_settings.qpack_max_table_capacity = capacity;
        self
    }

    /// Sets how many field sections this endpoint will keep blocked while
    /// waiting for dynamic-table entries via
    /// `SETTINGS_QPACK_BLOCKED_STREAMS` (RFC 9204 Section 5).
    ///
    /// Defaults to **`0`**.
    #[inline]
    pub fn qpack_blocked_streams(mut self, max: u64) -> Self {
        self.local_settings.qpack_blocked_streams = max;
        self
    }

    /// Sets the maximum field-section size this endpoint will accept via
    /// `SETTINGS_MAX_FIELD_SECTION_SIZE` (RFC 9114 Section 7.2.4.1).
    ///
    /// The size of a field section is the sum of its fields' name and value
    /// lengths plus 32 bytes per field (RFC 9114 Section 4.2.2), and the
    /// budget applies to a stream's field sections as a whole (request
    /// headers and trailers).
    ///
    /// Pass `None` for unlimited (the RFC default). The number of fields a
    /// section may carry is capped either way, so a section always costs a
    /// bounded amount of memory.
    #[inline]
    pub fn max_field_section_size(mut self, max: Option<u64>) -> Self {
        self.local_settings.max_field_section_size = max;
        self
    }

    /// Advertises support for the Extended CONNECT method via
    /// `SETTINGS_ENABLE_CONNECT_PROTOCOL` (RFC 9114 Section 7.2.4.1).
    ///
    /// Defaults to **`false`**.
    #[inline]
    pub fn enable_connect_protocol(mut self, enable: bool) -> Self {
        self.local_settings.enable_connect_protocol = enable;
        self
    }

    /// Sets the timeout for waiting on the next accepted HTTP/3 request
    /// resolver.
    ///
    /// If no new request arrives before this duration, the connection is
    /// gracefully shut down and the handler returns a timeout error.
    /// Pass `None` to disable this timeout. Defaults to **30 seconds**.
    #[inline]
    pub fn accept_timeout(mut self, timeout: Option<std::time::Duration>) -> Self {
        self.accept_timeout = timeout;
        self
    }

    /// Sets the timeout for the initial HTTP/3 connection setup (QUIC
    /// handshake and stream setup).
    ///
    /// If the setup does not complete within this duration, the handler
    /// returns an I/O timeout error. Pass `None` to disable this timeout.
    /// Defaults to **30 seconds**.
    #[inline]
    pub fn handshake_timeout(mut self, timeout: Option<std::time::Duration>) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    /// Controls whether a `100 Continue` interim response is sent when a
    /// request contains an `Expect: 100-continue` header.
    ///
    /// Defaults to **`true`**.
    #[inline]
    pub fn send_continue_response(mut self, send: bool) -> Self {
        self.send_continue_response = send;
        self
    }

    /// Controls whether a `Date` header is automatically added to every
    /// response.
    ///
    /// The value is cached and refreshed at most once per second.
    /// Defaults to **`true`**.
    #[inline]
    pub fn send_date_header(mut self, send: bool) -> Self {
        self.send_date_header = send;
        self
    }

    /// Sets the maximum number of RESET_STREAM frames this endpoint sends
    /// in response to protocol errors made by the peer across the lifetime
    /// of the connection (RFC 9114 Section 10.5): a peer that keeps
    /// sending malformed requests past this limit costs the connection
    /// rather than the stream, which is then closed with `H3_EXCESSIVE_LOAD`.
    /// `None` disables the limit. Defaults to `Some(1024)`.
    #[inline]
    pub fn max_local_error_reset_streams(mut self, max: Option<usize>) -> Self {
        self.max_local_error_reset_streams = max;
        self
    }

    /// Sets how many streams the peer may open and then terminate
    /// (RESET_STREAM or STOP_SENDING) before this endpoint accepts them
    /// (RFC 9114 Section 10.5). The budget refills at 50 streams a second,
    /// so cancelled requests spread over a connection's life never use it
    /// up; a peer that churns through streams faster exceeds it, and the
    /// connection is closed with `H3_EXCESSIVE_LOAD`. `None` disables the
    /// limit. Defaults to `Some(20)`.
    #[inline]
    pub fn max_pending_accept_reset_streams(mut self, max: Option<usize>) -> Self {
        self.max_pending_accept_reset_streams = max;
        self
    }
}

impl Default for Http3Options {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}
