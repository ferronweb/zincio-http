//! HTTP/3 request-stream upgrade to raw bidirectional I/O (CONNECT /
//! WebTransport-style handoff).
//!
//! After the server sends its final response, the application may take the
//! underlying request stream over as raw [`tokio::io`] I/O. The request
//! stream is shared with the driver through an async [`tokio::sync::Mutex`],
//! so the receive half becomes an [`AsyncRead`] (`H3Upgraded`) while the
//! send half keeps writing through the same handle, driven by the
//! [`UpgradedSendStreamTask`] until the other side hangs up.
//!
//! The pattern (a bounded kanal bridge plus an error oneshot) mirrors the
//! original `hyper`/`h3` upgrade implementation.

use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::{Buf, Bytes};
use futures_util::FutureExt;
use tokio::io::{AsyncWrite, ReadBuf};
use tokio::sync::Mutex;

use crate::h3::h3_stream_error_to_io;
use crate::h3::stream::{RequestStream, StreamError};

/// Splits a shared request stream into read and write halves for an
/// upgraded connection.
///
/// The returned `H3Upgraded` reads the remaining request body (and any
/// bytes the peer keeps sending) through the stream's receive path; the
/// returned task writes the consumer's output on the send path until the
/// consumer closes it.
#[inline]
pub(super) fn pair(inner: Arc<Mutex<RequestStream>>) -> (H3Upgraded, UpgradedSendStreamTask) {
    let (tx, rx) = kanal::bounded_async(1);
    let (error_tx, error_rx) = oneshot::async_channel();

    (
        H3Upgraded {
            send_stream: UpgradedSendStreamBridge { tx, error_rx },
            inner: inner.clone(),
            buf: Bytes::new(),
        },
        UpgradedSendStreamTask {
            inner,
            send_fut: None,
            rx_fut: None,
            rx,
            error_tx: Some(error_tx),
        },
    )
}

/// The read half of an upgraded stream.
pub(super) struct H3Upgraded {
    send_stream: UpgradedSendStreamBridge,
    inner: Arc<Mutex<RequestStream>>,
    buf: Bytes,
}

impl tokio::io::AsyncRead for H3Upgraded {
    #[inline]
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        read_buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        // The request may not have been fully read when the upgrade happened;
        // drain whatever the stream still holds as raw bytes.
        if self.buf.is_empty() {
            self.buf = loop {
                let mut guard = match std::pin::pin!(self.inner.lock()).poll_unpin(cx) {
                    Poll::Ready(guard) => guard,
                    Poll::Pending => return Poll::Pending,
                };
                match guard.poll_recv_data(cx) {
                    Poll::Ready(Ok(None)) => return Poll::Ready(Ok(())),
                    Poll::Ready(Ok(Some(buf))) if !buf.has_remaining() => continue,
                    Poll::Ready(Ok(Some(mut buf))) => {
                        break buf.copy_to_bytes(buf.remaining());
                    }
                    Poll::Ready(Err(e)) => {
                        return Poll::Ready(Err(h3_stream_error_to_io(e)));
                    }
                    Poll::Pending => return Poll::Pending,
                }
            };
        }
        let cnt = std::cmp::min(self.buf.len(), read_buf.remaining());
        read_buf.put_slice(&self.buf[..cnt]);
        self.buf.advance(cnt);
        Poll::Ready(Ok(()))
    }
}

struct UpgradedSendStreamBridge {
    tx: kanal::AsyncSender<Box<[u8]>>,
    error_rx: oneshot::AsyncReceiver<std::io::Error>,
}

impl AsyncWrite for H3Upgraded {
    #[inline]
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let n = buf.len();
        match std::pin::pin!(self.send_stream.tx.send(buf.into())).poll(cx) {
            Poll::Ready(Ok(())) => return Poll::Ready(Ok(n)),
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(_task_dropped)) => {
                // If the task dropped, check whether it did so with an error;
                // otherwise it is a broken pipe.
            }
        };
        match Pin::new(&mut self.send_stream.error_rx).poll(cx) {
            Poll::Ready(Ok(reason)) => Poll::Ready(Err(std::io::Error::other(reason))),
            Poll::Ready(Err(_task_dropped)) => {
                Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }

    #[inline]
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let _ = self.send_stream.tx.close();
        match Pin::new(&mut self.send_stream.error_rx).poll(cx) {
            Poll::Ready(Ok(reason)) => Poll::Ready(Err(std::io::Error::other(reason))),
            Poll::Ready(Err(_task_dropped)) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Drives the send half of an upgraded stream: forwards the consumer's
/// writes from the kanal bridge onto the request stream and finishes it
/// when the consumer closes, propagating any stream error back.
pub(super) struct UpgradedSendStreamTask {
    inner: Arc<Mutex<RequestStream>>,
    #[allow(clippy::type_complexity)]
    send_fut: Option<Pin<Box<dyn Future<Output = Result<(), StreamError>>>>>,
    rx_fut: Option<Pin<Box<kanal::ReceiveFuture<'static, Box<[u8]>>>>>,
    rx: kanal::AsyncReceiver<Box<[u8]>>,
    error_tx: Option<oneshot::Sender<std::io::Error>>,
}

impl UpgradedSendStreamTask {
    /// One send-data step: consumes `data` on the shared request stream.
    #[inline]
    async fn send_data(inner: Arc<Mutex<RequestStream>>, data: Bytes) -> Result<(), StreamError> {
        let mut guard = inner.lock().await;
        // `Bytes::clone` is a refcount bump; the peer's flow control shows up
        // as `Pending` on the inner poll.
        std::future::poll_fn(move |cx| guard.poll_send_data(cx, data.clone())).await
    }

    /// Finishes the send half (`FIN`) once the consumer closed its write side.
    #[inline]
    async fn finish(inner: Arc<Mutex<RequestStream>>) -> Result<(), StreamError> {
        let mut guard = inner.lock().await;
        std::future::poll_fn(|cx| guard.poll_finish(cx)).await
    }

    #[inline]
    fn tick(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        let this = self.get_mut();

        // Manual `select()` over the in-flight send future and the consumer's
        // write channel, so the task lives no longer than necessary.
        loop {
            if let Some(mut fut) = this.send_fut.take() {
                match fut.as_mut().poll(cx) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(e)) => {
                        return Poll::Ready(Err(h3_stream_error_to_io(e)));
                    }
                    Poll::Pending => {
                        this.send_fut = Some(fut);
                        return Poll::Pending;
                    }
                }
            }

            let rx_fut = if let Some(fut) = &mut this.rx_fut {
                fut
            } else {
                let fut = this.rx.recv();
                // SAFETY: rx_fut lives as long as rx, which is owned by self.
                // The stream is not moved out of rx, so it is safe to extend its
                // lifetime to 'static.
                let fut = unsafe {
                    std::mem::transmute::<
                        kanal::ReceiveFuture<'_, Box<[u8]>>,
                        kanal::ReceiveFuture<'static, Box<[u8]>>,
                    >(fut)
                };
                this.rx_fut = Some(Box::pin(fut));
                this.rx_fut.as_mut().expect("rx_fut is Some")
            };

            match std::pin::pin!(rx_fut).poll(cx) {
                Poll::Ready(Ok(cursor)) => {
                    this.rx_fut = None;
                    this.send_fut = Some(Box::pin(Self::send_data(
                        this.inner.clone(),
                        Bytes::from_owner(cursor),
                    )));
                }
                Poll::Ready(Err(_)) => {
                    this.rx_fut = None;
                    this.send_fut = Some(Box::pin(Self::finish(this.inner.clone())));
                }
                Poll::Pending => {
                    return Poll::Pending;
                }
            }
        }
    }
}

impl Future for UpgradedSendStreamTask {
    type Output = ();

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.as_mut().tick(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(()),
            Poll::Ready(Err(err)) => {
                if let Some(tx) = self.error_tx.take() {
                    let _ = tx.send(err);
                }
                Poll::Ready(())
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
