//! The write half shared by HTTP/2 and HTTP/3 upgraded streams.
//!
//! Upgrades hand the application a `tokio::io` stream while the protocol
//! task keeps owning the real transport. Writes cross a bounded kanal
//! channel; when the task exits, its error (if any) is delivered over a
//! one-shot channel so the writer can report the cause instead of a bare
//! broken pipe.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::AsyncWrite;

/// Writer side of the bridge between an upgraded stream and the task
/// that drives the protocol stream.
pub(crate) struct UpgradedSendStreamBridge {
    tx: kanal::AsyncSender<Box<[u8]>>,
    error_rx: oneshot::AsyncReceiver<std::io::Error>,
}

impl UpgradedSendStreamBridge {
    /// Creates the writer, the bytes receiver the protocol task drains,
    /// and the sender it reports its final error through.
    #[inline]
    pub(crate) fn channel() -> (
        Self,
        kanal::AsyncReceiver<Box<[u8]>>,
        oneshot::Sender<std::io::Error>,
    ) {
        let (tx, rx) = kanal::bounded_async(1);
        let (error_tx, error_rx) = oneshot::async_channel();
        (Self { tx, error_rx }, rx, error_tx)
    }
}

impl AsyncWrite for UpgradedSendStreamBridge {
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
        match std::pin::pin!(self.tx.send(buf.into())).poll(cx) {
            Poll::Ready(Ok(())) => return Poll::Ready(Ok(n)),
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(_task_dropped)) => {
                // If the task dropped, check whether it did so with an error;
                // otherwise it is a broken pipe.
            }
        };
        match Pin::new(&mut self.error_rx).poll(cx) {
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
        let _ = self.tx.close();
        match Pin::new(&mut self.error_rx).poll(cx) {
            Poll::Ready(Ok(reason)) => Poll::Ready(Err(std::io::Error::other(reason))),
            Poll::Ready(Err(_task_dropped)) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}
