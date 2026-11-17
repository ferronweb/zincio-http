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
    tx_fut: Option<Pin<Box<dyn Future<Output = Result<usize, kanal::SendError>>>>>,
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

        loop {
            let (mut tx_fut, preexisting) = if let Some(tx_fut) = this.tx_fut.take() {
                (tx_fut, true)
            } else {
                let n = buf.len();

                let mut boxed_buf_option: Option<Box<[u8]>> = Some(buf.into());
                match this.tx.try_send_option(&mut boxed_buf_option) {
                    Ok(true) => return Poll::Ready(Ok(n)),
                    Ok(false) => {
                        // Fall back to the slow path, which can return Poll::Pending.
                        // At least the channel isn't closed.
                    }
                    Err(_) => return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into())),
                }

                // It would be unlikely for boxed_buf_option to be None at this point,
                // but if it's None, re-create boxed buffer just in case.
                let boxed_buf = boxed_buf_option.unwrap_or_else(|| buf.into());
                let send_fut = this.tx.send(boxed_buf);
                // SAFETY: tx_fut lives as long as tx, which is owned by self.
                let send_fut = unsafe {
                    std::mem::transmute::<
                        kanal::SendFuture<'_, Box<[u8]>>,
                        kanal::SendFuture<'static, Box<[u8]>>,
                    >(send_fut)
                };
                let box_send_fut: Box<dyn Future<Output = Result<usize, kanal::SendError>>> =
                    Box::new(async move { send_fut.await.map(|_| n) });
                (Box::into_pin(box_send_fut), false)
            };
            match Pin::new(&mut tx_fut).poll(cx) {
                Poll::Ready(Ok(n)) => {
                    // If it was pre-existing, the Poll::Ready(Ok(n)) would be returned for data
                    // that wasn't specified in `poll_write`, causing the application to drop
                    // the chunk that would be sent.
                    if !preexisting {
                        return Poll::Ready(Ok(n));
                    }
                }
                Poll::Pending => {
                    this.tx_fut = Some(tx_fut);
                    return Poll::Pending;
                }
                Poll::Ready(Err(_task_dropped)) => {
                    break;
                }
            };
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
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        let this = self.get_mut();
        if let Some(tx_fut) = &mut this.tx_fut {
            let flush_result = std::task::ready!(Pin::new(tx_fut).poll(cx));
            this.tx_fut = None;
            if flush_result.is_err() {
                return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
            }
        }
        Poll::Ready(Ok(()))
    }

    #[inline]
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        // From tokio docs, invocation of a shutdown implies an invocation of flush.
        std::task::ready!(self.as_mut().poll_flush(cx))?;

        let _ = self.tx.close();
        match Pin::new(&mut self.error_rx).poll(cx) {
            Poll::Ready(Ok(reason)) => Poll::Ready(Err(std::io::Error::other(reason))),
            Poll::Ready(Err(_task_dropped)) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}
