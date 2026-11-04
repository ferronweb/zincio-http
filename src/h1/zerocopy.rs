#[cfg(all(
    any(target_os = "linux", target_os = "freebsd"),
    feature = "h1-zerocopy"
))]
use http::Response;
use http_body::Body;
#[cfg(all(
    any(target_os = "linux", target_os = "freebsd"),
    feature = "h1-zerocopy"
))]
use http_body_util::Empty;

#[cfg(all(
    any(target_os = "linux", target_os = "freebsd"),
    feature = "h1-zerocopy"
))]
use super::{Http1, HttpProtocol};

/// A response body to be sent from a file descriptor, installed by
/// [`install_zerocopy`] or [`install_zerocopy_fd`].
#[derive(Clone)]
pub struct ZerocopyResponse {
    source: ZerocopySource,
}

#[derive(Clone)]
enum ZerocopySource {
    /// The caller keeps the descriptor open ([`install_zerocopy`]).
    Raw(super::RawHandle),
    /// The response owns the descriptor ([`install_zerocopy_fd`]).
    #[cfg(unix)]
    Owned(std::sync::Arc<std::os::fd::OwnedFd>),
}

// A raw handle is a pointer on Windows.
#[cfg(windows)]
unsafe impl Send for ZerocopyResponse {}
#[cfg(windows)]
unsafe impl Sync for ZerocopyResponse {}

#[cfg(unix)]
impl ZerocopyResponse {
    /// The descriptor to send the body from.
    #[inline]
    pub fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        use std::os::fd::AsFd;
        match &self.source {
            // Safety: `install_zerocopy`'s caller guarantees the descriptor
            // stays open until the response body has been sent.
            ZerocopySource::Raw(fd) => unsafe { std::os::fd::BorrowedFd::borrow_raw(*fd) },
            ZerocopySource::Owned(fd) => fd.as_fd(),
        }
    }
}

/// Installs a zero-copy hint on an HTTP response, directing the connection
/// handler to use emulated sendfile (Linux and FreeBSD only) to transmit
/// the body.
///
/// [`install_zerocopy_fd`] does the same without `unsafe`, for a descriptor
/// the response may own.
///
/// # Parameters
///
/// - `response` – the response whose extensions will receive the hint.
/// - `handle` – the raw file descriptor of the file to send. The caller is
///   responsible for ensuring the file descriptor remains valid and open for
///   the entire duration of the response write.
///
/// # Safety
///
/// The caller must guarantee that `handle` is a valid, open file descriptor
/// that will not be closed before the response body has been fully sent.
pub unsafe fn install_zerocopy(response: &mut http::Response<impl Body>, handle: super::RawHandle) {
    response.extensions_mut().insert(ZerocopyResponse {
        source: ZerocopySource::Raw(handle),
    });
}

/// Installs a zero-copy hint on an HTTP response, as [`install_zerocopy`],
/// with the response owning `fd`: it stays open while the body is sent and
/// closes when the response is dropped.
#[cfg(unix)]
pub fn install_zerocopy_fd(
    response: &mut http::Response<impl Body>,
    fd: impl Into<std::os::fd::OwnedFd>,
) {
    response.extensions_mut().insert(ZerocopyResponse {
        source: ZerocopySource::Owned(std::sync::Arc::new(fd.into())),
    });
}

/// How a connection handler sends a response body installed with
/// [`install_zerocopy`] or [`install_zerocopy_fd`].
pub trait ZerocopySend<Io> {
    /// Whether such bodies are sent this way at all; otherwise the response's
    /// own body is sent.
    #[inline]
    fn enabled(&self) -> bool {
        true
    }

    /// Sends exactly `len` bytes of `body`'s descriptor to `io`, after
    /// everything written to it so far.
    fn send<'a>(
        &'a mut self,
        body: &'a ZerocopyResponse,
        io: &'a mut Io,
        len: u64,
    ) -> impl std::future::Future<Output = Result<(), std::io::Error>> + 'a;
}

/// Responses are sent from their bodies only ([`Http1`]).
pub(crate) struct NoZerocopy;

impl<Io> ZerocopySend<Io> for NoZerocopy {
    #[inline]
    fn enabled(&self) -> bool {
        false
    }

    #[inline]
    fn send<'a>(
        &'a mut self,
        _body: &'a ZerocopyResponse,
        _io: &'a mut Io,
        _len: u64,
    ) -> impl std::future::Future<Output = Result<(), std::io::Error>> + 'a {
        std::future::ready(Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "zero-copy sending is not enabled",
        )))
    }
}

/// zincio's emulated sendfile ([`Http1::zerocopy`]).
pub struct Sendfile;

#[cfg(all(
    any(target_os = "linux", target_os = "freebsd"),
    feature = "h1-zerocopy"
))]
impl<Io> ZerocopySend<Io> for Sendfile
where
    for<'b> Io: zincio::io::AsInnerRawHandle<'b>,
{
    #[inline]
    async fn send<'a>(
        &'a mut self,
        body: &'a ZerocopyResponse,
        io: &'a mut Io,
        len: u64,
    ) -> Result<(), std::io::Error> {
        zincio::io::sendfile_exact(&body.as_fd(), &*io, len).await?;
        Ok(())
    }
}

/// An I/O stream that sends a zero-copy response body itself
/// ([`Http1::zerocopy_by_io`]): one whose bytes need more than a plain
/// sendfile to the socket, such as a kernel TLS stream that first hands its
/// connection to the kernel.
#[cfg(unix)]
pub trait ZerocopyWrite {
    /// Sends exactly `len` bytes from `from`, after everything written to the
    /// stream so far.
    fn send_zerocopy(
        &mut self,
        from: std::os::fd::BorrowedFd<'_>,
        len: u64,
    ) -> impl std::future::Future<Output = Result<(), std::io::Error>>;
}

/// The stream's own [`ZerocopyWrite`] ([`Http1::zerocopy_by_io`]).
pub struct ByIo;

#[cfg(unix)]
impl<Io: ZerocopyWrite> ZerocopySend<Io> for ByIo {
    #[inline]
    fn send<'a>(
        &'a mut self,
        body: &'a ZerocopyResponse,
        io: &'a mut Io,
        len: u64,
    ) -> impl std::future::Future<Output = Result<(), std::io::Error>> + 'a {
        io.send_zerocopy(body.as_fd(), len)
    }
}

/// An HTTP/1.x connection handler that uses emulated sendfile for zero-copy
/// response body transmission on Linux and FreeBSD.
///
/// Obtain an instance via [`Http1::zerocopy`]. When a response has a
/// `ZerocopyResponse` extension installed (see [`install_zerocopy`]), the
/// handler will use an approach dependent on the runtime environment
/// to stream the file from the kernel page cache to the socket,
/// bypassing user-space copies.
///
/// For responses without that extension the behaviour is identical to the
/// regular [`Http1`] handler.
///
/// Only available on Linux and FreeBSD.
#[cfg(all(
    any(target_os = "linux", target_os = "freebsd"),
    feature = "h1-zerocopy"
))]
pub struct Http1Zerocopy<Io, S = Sendfile> {
    pub(super) inner: Http1<Io>,
    pub(super) sender: S,
}

#[cfg(all(
    any(target_os = "linux", target_os = "freebsd"),
    feature = "h1-zerocopy"
))]
impl<Io, S> HttpProtocol for Http1Zerocopy<Io, S>
where
    Io: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + 'static,
    S: ZerocopySend<Io>,
{
    fn handle_with_error_fn<F, Fut, ResB, ResBE, ResE, EF, EFut, EResB, EResBE, EResE>(
        self,
        request_fn: F,
        error_fn: EF,
    ) -> impl std::future::Future<Output = Result<(), std::io::Error>>
    where
        F: Fn(http::Request<super::Incoming>) -> Fut + 'static,
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
        self.inner
            .handle_with_error_fn_and_zerocopy(request_fn, error_fn, self.sender)
    }

    fn handle<F, Fut, ResB, ResBE, ResE>(
        self,
        request_fn: F,
    ) -> impl std::future::Future<Output = Result<(), std::io::Error>>
    where
        F: Fn(http::Request<super::Incoming>) -> Fut + 'static,
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
