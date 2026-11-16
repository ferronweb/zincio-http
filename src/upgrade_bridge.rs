//! The write half shared by HTTP/2 and HTTP/3 upgraded streams.
//!
//! Upgrades hand the application a `tokio::io` stream while the protocol
//! task keeps owning the real transport. Writes cross a bounded kanal
//! channel; when the task exits, its error (if any) is delivered over a
//! one-shot channel so the writer can report the cause instead of a bare
//! broken pipe.
//!
//! A write that finds the channel full is accepted all the same: its send
//! is kept and waits in the channel's queue, and the next write, flush or
//! shutdown waits for it. Polling a send once and dropping it would take it
//! out of that queue, and the writer would never be woken when the channel
//! has room again.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::AsyncWrite;

/// Writer side of the bridge between an upgraded stream and the task
/// that drives the protocol stream.
pub(crate) struct UpgradedSendStreamBridge {
    tx: kanal::AsyncSender<Box<[u8]>>,
    /// The send of a write that found the channel full.
    sending: Option<Sending>,
    error_rx: oneshot::AsyncReceiver<std::io::Error>,
}

/// A send waiting for room in the channel, on a sender of its own.
type Sending = Pin<Box<dyn Future<Output = Result<(), kanal::SendError>> + Send>>;

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
                sending: None,
                error_rx,
            },
            rx,
            error_tx,
        )
    }

    /// Waits for the write the channel had no room for.
    #[inline]
    fn poll_sending(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        let Some(sending) = self.sending.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        match sending.as_mut().poll(cx) {
            Poll::Ready(sent) => {
                self.sending = None;
                match sent {
                    Ok(()) => Poll::Ready(Ok(())),
                    Err(_task_dropped) => self.poll_closed(cx).map(Err),
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }

    /// Why the task dropped its end: its error, or a broken pipe.
    #[inline]
    fn poll_closed(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Error> {
        match Pin::new(&mut self.error_rx).poll(cx) {
            Poll::Ready(Ok(reason)) => Poll::Ready(std::io::Error::other(reason)),
            Poll::Ready(Err(_task_dropped)) => Poll::Ready(std::io::ErrorKind::BrokenPipe.into()),
            Poll::Pending => Poll::Pending,
        }
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

        match self.poll_sending(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }

        let n = buf.len();
        let mut data = Some(Box::<[u8]>::from(buf));
        match self.tx.try_send_option(&mut data) {
            Ok(true) => return Poll::Ready(Ok(n)),
            Ok(false) => {}
            // If the task dropped, check whether it did so with an error;
            // otherwise it is a broken pipe.
            Err(_task_dropped) => return self.poll_closed(cx).map(Err),
        }

        // The channel is full: the send waits in its queue, where it holds
        // this task's waker, and the bytes are taken now. Its own sender
        // lets the future live in the bridge.
        let tx = self.tx.clone();
        let data = data.expect("a full channel leaves the data");
        let mut sending: Sending = Box::pin(async move { tx.send(data).await });
        match sending.as_mut().poll(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(n)),
            Poll::Ready(Err(_task_dropped)) => self.poll_closed(cx).map(Err),
            Poll::Pending => {
                self.sending = Some(sending);
                Poll::Ready(Ok(n))
            }
        }
    }

    #[inline]
    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        self.poll_sending(cx)
    }

    #[inline]
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        // What was written last reaches the task before the channel closes.
        match self.poll_sending(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        let _ = self.tx.close();
        match Pin::new(&mut self.error_rx).poll(cx) {
            Poll::Ready(Ok(reason)) => Poll::Ready(Err(std::io::Error::other(reason))),
            Poll::Ready(Err(_task_dropped)) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}
