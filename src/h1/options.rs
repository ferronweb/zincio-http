/// Configuration options for the HTTP/1.x connection handler.
///
/// Use the builder-style methods to customise behaviour, then pass the finished
/// value to [`Http1::new`](super::Http1::new).
///
/// # Examples
///
/// ```rust,ignore
/// let options = Http1Options::new()
///     .max_header_size(8192)
///     .send_date_header(false)
///     .header_read_timeout(Some(std::time::Duration::from_secs(10)));
/// ```
#[derive(Debug, Clone)]
pub struct Http1Options {
    pub(crate) max_header_size: usize,
    pub(crate) max_header_count: usize,
    pub(crate) send_date_header: bool,
    pub(crate) header_read_timeout: Option<std::time::Duration>,
    pub(crate) send_continue_response: bool,
    pub(crate) enable_early_hints: bool,
    pub(crate) enable_vectored_write: bool,
    pub(crate) allow_pipelining: bool,
}

impl Http1Options {
    /// Creates a new `Http1Options` with the following defaults:
    ///
    /// | Option | Default |
    /// |---|---|
    /// | `max_header_size` | 16 384 bytes |
    /// | `max_header_count` | 128 |
    /// | `send_date_header` | `true` |
    /// | `header_read_timeout` | 30 seconds |
    /// | `send_continue_response` | `true` |
    /// | `enable_early_hints` | `false` |
    /// | `enable_vectored_write` | `true` |
    /// | `allow_pipelining` | `true` |
    pub fn new() -> Self {
        Self {
            max_header_size: 16384,
            max_header_count: 128,
            send_date_header: true,
            header_read_timeout: Some(std::time::Duration::from_secs(30)),
            send_continue_response: true,
            enable_early_hints: false,
            enable_vectored_write: true,
            allow_pipelining: true,
        }
    }

    /// Sets the maximum number of bytes that may be read while parsing the
    /// request head (status line + headers).
    ///
    /// Requests whose head exceeds this limit are rejected with an
    /// `InvalidData` I/O error. Defaults to **16 384** bytes.
    pub fn max_header_size(mut self, size: usize) -> Self {
        self.max_header_size = size;
        self
    }

    /// Sets the maximum number of headers that will be parsed per request.
    ///
    /// Headers beyond this count are rejected by the underlying `httparse`
    /// parser. Defaults to **128**.
    pub fn max_header_count(mut self, count: usize) -> Self {
        self.max_header_count = count;
        self
    }

    /// Controls whether a `Date` header is automatically added to every
    /// response.
    ///
    /// The value is cached and refreshed at most once per second.
    /// Defaults to **`true`**.
    pub fn send_date_header(mut self, send: bool) -> Self {
        self.send_date_header = send;
        self
    }

    /// Controls whether vectored I/O (`write_vectored`) is used when writing
    /// responses.
    ///
    /// When the underlying stream does not support vectored writes the
    /// implementation falls back to a flattened `write` regardless of this
    /// setting. Defaults to **`true`**.
    pub fn enable_vectored_write(mut self, enable: bool) -> Self {
        self.enable_vectored_write = enable;
        self
    }

    /// Sets the timeout for reading the complete request head.
    ///
    /// If the client does not send a full set of request headers within this
    /// duration the connection is closed with a `408 Request Timeout` response.
    /// Pass `None` to disable the timeout entirely. Defaults to **30 seconds**.
    pub fn header_read_timeout(mut self, timeout: Option<std::time::Duration>) -> Self {
        self.header_read_timeout = timeout;
        self
    }

    /// Controls whether a `100 Continue` interim response is sent when the
    /// request contains an `Expect: 100-continue` header.
    ///
    /// Defaults to **`true`**.
    pub fn send_continue_response(mut self, send: bool) -> Self {
        self.send_continue_response = send;
        self
    }

    /// Controls whether `103 Early Hints` responses can be sent before the
    /// final response.
    ///
    /// When enabled, an `EarlyHints` handle is inserted into each request's
    /// extensions so that the handler can push early hint headers to the client.
    /// Defaults to **`false`**.
    pub fn enable_early_hints(mut self, enable: bool) -> Self {
        self.enable_early_hints = enable;
        self
    }

    /// Controls whether pipelined requests are served (RFC 9112 Section
    /// 9.3.2).
    ///
    /// When disabled, a connection on which the next request has already
    /// arrived when a response is sent is closed after that response, with
    /// `Connection: close`, and the connection ends with an `InvalidData`
    /// I/O error; the pipelined request is not read. Defaults to
    /// **`true`**.
    pub fn allow_pipelining(mut self, allow: bool) -> Self {
        self.allow_pipelining = allow;
        self
    }
}

impl Default for Http1Options {
    fn default() -> Self {
        Self::new()
    }
}
