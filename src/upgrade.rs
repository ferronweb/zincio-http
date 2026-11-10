use std::{
    future::Future,
    pin::Pin,
    sync::{atomic::AtomicBool, Arc},
    task::ready,
};

use bytes::BufMut;
use futures_util::FutureExt;
use http::Request;
use http_body::Body;
use send_wrapper::SendWrapper;
use tokio::io::{AsyncRead, AsyncWrite};

/// Represents a successfully upgraded HTTP connection.
///
/// After a successful HTTP upgrade handshake (e.g. WebSocket or HTTP/2
/// cleartext), the original TCP stream is handed off as an [`Upgraded`] value.
/// It implements both [`AsyncRead`] and [`AsyncWrite`], so it can be used as a
/// plain async I/O object by the protocol taking over the connection.
///
/// Any bytes that were already read from the socket as part of the HTTP request
/// but not yet consumed are prepended to the read stream via the `leftover`
/// buffer, ensuring no data is lost during the transition.
pub struct Upgraded {
    io: SendWrapper<Box<dyn UpgradedIo>>,
    leftover: Option<bytes::Bytes>,
    has_ended: bool,
}

/// The connection's own I/O, kept as its type so [`Upgraded::downcast`] can
/// hand it back.
trait UpgradedIo: AsyncRead + AsyncWrite + Unpin {
    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any>;
    fn is_a(&self, type_id: std::any::TypeId) -> bool;
}

impl<T: AsyncRead + AsyncWrite + Unpin + 'static> UpgradedIo for T {
    #[inline]
    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }

    #[inline]
    fn is_a(&self, type_id: std::any::TypeId) -> bool {
        std::any::TypeId::of::<T>() == type_id
    }
}

impl Upgraded {
    #[inline]
    pub(super) fn new(
        io: impl AsyncRead + AsyncWrite + Unpin + 'static,
        leftover: Option<bytes::Bytes>,
    ) -> Self {
        Self {
            io: SendWrapper::new(Box::new(io)),
            leftover,
            has_ended: false,
        }
    }

    /// The I/O the connection was served on, when it is a `T`, with the bytes
    /// read from it past the request and not yet read from this `Upgraded`;
    /// otherwise the `Upgraded` unchanged. For a protocol that needs the
    /// connection itself, such as one handing a kernel TLS socket to
    /// `splice`.
    ///
    /// # Panics
    ///
    /// On a thread other than the one the connection was served on, as any
    /// other use of an `Upgraded`.
    #[inline]
    pub fn downcast<T: AsyncRead + AsyncWrite + Unpin + 'static>(
        self,
    ) -> Result<(T, Option<bytes::Bytes>), Self> {
        // The boxed value's type, not the box's (which is I/O too).
        if !(**self.io).is_a(std::any::TypeId::of::<T>()) {
            return Err(self);
        }
        let io = self
            .io
            .take()
            .into_any()
            .downcast::<T>()
            .expect("the type was checked above");
        Ok((*io, self.leftover))
    }
}

impl AsyncRead for Upgraded {
    #[inline]
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let orig_buf_len = buf.remaining();
        if let Some(leftover) = &mut self.leftover {
            let slice_len = leftover.len().min(buf.remaining());
            let leftover_to_write = leftover.split_to(slice_len);
            buf.put(leftover_to_write);
            if leftover.is_empty() {
                self.leftover = None;
            }
            return std::task::Poll::Ready(Ok(()));
        }
        match Pin::new(&mut **self.io).poll_read(cx, buf) {
            std::task::Poll::Ready(Err(e))
                if matches!(e.kind(), std::io::ErrorKind::UnexpectedEof) =>
            {
                self.has_ended = true;
                std::task::Poll::Ready(Ok(()))
            }
            poll => {
                if poll.is_ready() && buf.remaining() == orig_buf_len {
                    // No data has been read, mark the I/O as "ended".
                    //
                    // If there was no data where more data would be expected,
                    // this would be Poll::Pending (pending I/O op)...
                    self.has_ended = true;
                }
                poll
            }
        }
    }
}

impl AsyncWrite for Upgraded {
    #[inline]
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match Pin::new(&mut **self.io).poll_write(cx, buf) {
            std::task::Poll::Ready(Err(e))
                if self.has_ended && matches!(e.kind(), std::io::ErrorKind::BrokenPipe) =>
            {
                std::task::Poll::Ready(Ok(0))
            }
            poll => poll,
        }
    }

    #[inline]
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match Pin::new(&mut **self.io).poll_flush(cx) {
            std::task::Poll::Ready(Err(e))
                if self.has_ended && matches!(e.kind(), std::io::ErrorKind::BrokenPipe) =>
            {
                std::task::Poll::Ready(Ok(()))
            }
            poll => poll,
        }
    }

    #[inline]
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match Pin::new(&mut **self.io).poll_shutdown(cx) {
            std::task::Poll::Ready(Err(e))
                if self.has_ended && matches!(e.kind(), std::io::ErrorKind::BrokenPipe) =>
            {
                std::task::Poll::Ready(Ok(()))
            }
            poll => poll,
        }
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }

    #[inline]
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> std::task::Poll<std::io::Result<usize>> {
        Pin::new(&mut **self.io).poll_write_vectored(cx, bufs)
    }
}

#[derive(Clone)]
pub(super) struct Upgrade {
    inner: Arc<tokio::sync::Mutex<oneshot::AsyncReceiver<Upgraded>>>,
    pub(super) upgraded: Arc<AtomicBool>,
}

impl Upgrade {
    #[inline]
    pub(super) fn new(inner: oneshot::AsyncReceiver<Upgraded>) -> Self {
        Self {
            inner: Arc::new(tokio::sync::Mutex::new(inner)),
            upgraded: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl Future for Upgrade {
    type Output = Option<Upgraded>;

    #[inline]
    fn poll(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let mut inner = ready!(std::pin::pin!(self.inner.lock()).poll_unpin(cx));
        match inner.poll_unpin(cx) {
            std::task::Poll::Ready(result) => std::task::Poll::Ready(result.ok()),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

/// A future that resolves to an [`Upgraded`] connection once the HTTP upgrade
/// handshake has been completed by the server side.
///
/// Obtain an `OnUpgrade` by calling [`prepare_upgrade`] on an incoming
/// request. The future will yield `Some(Upgraded)` when the server has
/// finished writing the upgrade response, or `None` if the upgrade was
/// cancelled or the connection was closed before the handshake completed.
///
/// # Example
///
/// ```rust,ignore
/// if let Some(on_upgrade) = prepare_upgrade(&mut request) {
///     tokio::spawn(async move {
///         if let Some(upgraded) = on_upgrade.await {
///             // `upgraded` is now a raw async I/O stream
///         }
///     });
/// }
/// ```
#[derive(Clone)]
pub struct OnUpgrade {
    inner: Upgrade,
}

impl Future for OnUpgrade {
    type Output = Option<Upgraded>;

    #[inline]
    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.inner.poll_unpin(cx)
    }
}

/// Prepares an HTTP upgrade on the given request.
///
/// This function removes the internal `Upgrade` token from the request's
/// extensions and marks the connection as "to be upgraded". The returned
/// [`OnUpgrade`] future resolves to the raw [`Upgraded`] I/O stream after the
/// server has sent the `101 Switching Protocols` response.
///
/// Returns `None` if the request does not carry an upgrade token, which
/// happens when the connection handler was not configured to support upgrades
/// or the upgrade extension has already been consumed.
///
/// # Panics
///
/// Does not panic; returns `None` instead of panicking on missing state.
#[inline]
pub fn prepare_upgrade(req: &mut Request<impl Body>) -> Option<OnUpgrade> {
    req.extensions_mut().remove::<Upgrade>().map(|inner| {
        inner
            .upgraded
            .store(true, std::sync::atomic::Ordering::Relaxed);
        OnUpgrade { inner }
    })
}
