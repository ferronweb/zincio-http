//! The write half shared by HTTP/2 and HTTP/3 upgraded streams.
//!
//! Upgrades hand the application a `tokio::io` stream while the protocol
//! task keeps owning the underlying transport.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::AsyncWrite;

/// Writer side of the bridge between an upgraded stream and the task
/// that drives the protocol stream.
pub(crate) struct UpgradedSendStreamBridge {
    tx: kanal::AsyncSender<Box<[u8]>>,
    #[allow(clippy::type_complexity)]
    tx_fut: Option<Pin<Box<kanal::SendFuture<'static, Box<[u8]>>>>>,
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
        (
            Self {
                tx,
                tx_fut: None,
                error_rx,
            },
            rx,
            error_tx,
        )
    }
}

impl AsyncWrite for UpgradedSendStreamBridge {
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let this = self.get_mut();

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let n = buf.len();

        loop {
            match this.tx.try_send(buf.into()) {
                Ok(true) => return Poll::Ready(Ok(n)),
                Ok(false) => {}
                Err(_) => return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into())),
            }

            // Since `kanal` doesn't expose method to wait until capacity is released,
            // let's just send a 0-byte message instead (HTTP/2 and HTTP/3 upgrade impls
            // would just filter them away).
            let boxed_buf = Box::new([]);
            let send_fut = this.tx.send(boxed_buf);
            // SAFETY: tx_fut lives as long as tx, which is owned by self.
            let send_fut = unsafe {
                std::mem::transmute::<
                    kanal::SendFuture<'_, Box<[u8]>>,
                    kanal::SendFuture<'static, Box<[u8]>>,
                >(send_fut)
            };
            let mut send_fut = Box::pin(send_fut);

            match Pin::new(&mut send_fut).poll(cx) {
                Poll::Ready(Ok(_)) => {
                    // Try sending real data again in the next iteration
                }
                Poll::Pending => {
                    // tx_fut has to be stored for the waker to get triggered in kanal.
                    // Data may be put on internal waitlist, but it's 0-byte anyway.
                    this.tx_fut = Some(send_fut);
                    break;
                }
                _ => {
                    break;
                }
            }
        }

        match Pin::new(&mut this.error_rx).poll(cx) {
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
