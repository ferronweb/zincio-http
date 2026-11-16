//! Configuration options for the native HTTP/3 connection driver.

use crate::h3::settings::LocalSettings;

/// Configuration options for the HTTP/3 connection handler.
///
/// Use the builder methods to customise behaviour, then pass the value to
/// [`Http3::new`](super::Http3::new).
pub struct Http3Options {
    pub(super) local_settings: LocalSettings,
    pub(super) accept_timeout: Option<std::time::Duration>,
    pub(super) handshake_timeout: Option<std::time::Duration>,
    pub(super) header_read_timeout: Option<std::time::Duration>,
    pub(super) send_continue_response: bool,
    pub(super) send_date_header: bool,
    pub(super) max_local_error_reset_streams: Option<usize>,
    pub(super) max_pending_accept_reset_streams: Option<usize>,
}

impl Http3Options {
    /// Creates options with the defaults shown below.
    ///
    /// | Option | Default |
    /// |---|---|
    /// | `accept_timeout` | 30 seconds |
    /// | `handshake_timeout` | 30 seconds |
    /// | `header_read_timeout` | 30 seconds |
    /// | `send_continue_response` | `true` |
    /// | `send_date_header` | `true` |
    /// | `qpack_max_table_capacity` | `0` |
    /// | `qpack_blocked_streams` | `0` |
    /// | `max_field_section_size` | 65,536 |
    /// | `enable_connect_protocol` | `false` |
    /// | `max_local_error_reset_streams` | `1024` |
    /// | `max_pending_accept_reset_streams` | `20` |
    #[inline]
    pub fn new() -> Self {
        Self {
            local_settings: LocalSettings::default(),
            accept_timeout: Some(std::time::Duration::from_secs(30)),
            handshake_timeout: Some(std::time::Duration::from_secs(30)),
            header_read_timeout: Some(std::time::Duration::from_secs(30)),
            send_continue_response: true,
            send_date_header: true,
            max_local_error_reset_streams: Some(1024),
            max_pending_accept_reset_streams: Some(20),
        }
    }

    /// Sets the QPACK dynamic-table capacity advertised to the peer (RFC 9204
    /// Section 5). Defaults to `0`.
    #[inline]
    pub fn qpack_max_table_capacity(mut self, capacity: u64) -> Self {
        self.local_settings.qpack_max_table_capacity = capacity.min(1_073_741_823);
        self
    }

    /// Sets how many blocked field sections the peer may have (RFC 9204
    /// Section 5). Defaults to `0`.
    #[inline]
    pub fn qpack_blocked_streams(mut self, max: u64) -> Self {
        self.local_settings.qpack_blocked_streams = max;
        self
    }

    /// Sets the maximum decoded field-section size this endpoint accepts
    /// (RFC 9114 Section 7.2.4.1). `None` means unlimited.
    #[inline]
    pub fn max_field_section_size(mut self, max: Option<u64>) -> Self {
        self.local_settings.max_field_section_size = max;
        self
    }

    /// Advertises Extended CONNECT via `SETTINGS_ENABLE_CONNECT_PROTOCOL`
    /// (RFC 9114 Section 7.2.4.1). Defaults to `false`.
    #[inline]
    pub fn enable_connect_protocol(mut self, enable: bool) -> Self {
        self.local_settings.enable_connect_protocol = enable;
        self
    }

    /// Sets the timeout for waiting on the next request. `None` disables it.
    /// Defaults to 30 seconds.
    #[inline]
    pub fn accept_timeout(mut self, timeout: Option<std::time::Duration>) -> Self {
        self.accept_timeout = timeout;
        self
    }

    /// Sets the timeout for the initial QUIC handshake. `None` disables it.
    /// Defaults to 30 seconds.
    #[inline]
    pub fn handshake_timeout(mut self, timeout: Option<std::time::Duration>) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    /// Sets the timeout for reading the complete request head. `None`
    /// disables it. Defaults to 30 seconds.
    #[inline]
    pub fn header_read_timeout(mut self, timeout: Option<std::time::Duration>) -> Self {
        self.header_read_timeout = timeout;
        self
    }

    /// Controls automatic `100 Continue` responses to `Expect:
    /// 100-continue`. Defaults to `true`.
    #[inline]
    pub fn send_continue_response(mut self, send: bool) -> Self {
        self.send_continue_response = send;
        self
    }

    /// Controls automatic `Date` response headers. Defaults to `true`.
    #[inline]
    pub fn send_date_header(mut self, send: bool) -> Self {
        self.send_date_header = send;
        self
    }

    /// Sets the protocol-error reset budget per connection (RFC 9114 Section
    /// 10.5). Exceeding it closes with `H3_EXCESSIVE_LOAD`. Defaults to 1024.
    #[inline]
    pub fn max_local_error_reset_streams(mut self, max: Option<usize>) -> Self {
        self.max_local_error_reset_streams = max;
        self
    }

    /// Sets how many streams the peer may reset before acceptance. The budget
    /// refills at 50 per second (RFC 9114 Section 10.5). Defaults to 20.
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
