use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf, Bytes};
use futures_util::StreamExt;
use tokio::io::{AsyncWrite, ReadBuf};

/// Wraps request stream in read and write halves for an
/// upgraded connection.
///
/// The returned `H2Upgraded` reads the remaining request body (and any
/// bytes the peer keeps sending) through the stream's receive path; the
/// returned task writes the consumer's output on the send path until the
/// consumer closes it.
#[inline]
pub(super) fn pair(
    inner_rx: kanal::AsyncReceiver<super::stream::BodyMsg>,
    inner_tx: kanal::AsyncSender<super::stream::StreamMsg>,
    reset_rx: kanal::AsyncReceiver<u32>,
    wake_tx: kanal::AsyncSender<()>,
) -> (H2Upgraded, UpgradedSendStreamTask) {
    let (tx, rx) = kanal::bounded_async(1);
    let (error_tx, error_rx) = oneshot::async_channel();

    (
        H2Upgraded {
            send_stream: UpgradedSendStreamBridge { tx, error_rx },
            inner: inner_rx,
            inner_fut: None,
            buf: Bytes::new(),
        },
        UpgradedSendStreamTask {
            inner: inner_tx,
            inner_fut: None,
            rx,
            rx_fut: None,
            error_tx: Some(error_tx),
            reset_rx,
            wake_tx,
            end: false,
        },
    )
}

/// The read half of an upgraded stream.
pub(super) struct H2Upgraded {
    send_stream: UpgradedSendStreamBridge,
    inner_fut: Option<kanal::ReceiveStream<'static, super::stream::BodyMsg>>,
    inner: kanal::AsyncReceiver<super::stream::BodyMsg>,
    buf: Bytes,
}

impl tokio::io::AsyncRead for H2Upgraded {
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
                let fut = if let Some(fut) = &mut self.inner_fut {
                    fut
                } else {
                    let stream = self.inner.stream();
                    // SAFETY: inner_fut lives as long as inner, which is owned by self.
                    // The stream is not moved out of inner, so it is safe to extend its
                    // lifetime to 'static.
                    let stream = unsafe {
                        std::mem::transmute::<
                            kanal::ReceiveStream<'_, super::stream::BodyMsg>,
                            kanal::ReceiveStream<'static, super::stream::BodyMsg>,
                        >(stream)
                    };
                    self.inner_fut = Some(stream);
                    self.inner_fut.as_mut().expect("inner_fut is Some")
                };
                match fut.poll_next_unpin(cx) {
                    Poll::Ready(None) | Poll::Ready(Some(super::stream::BodyMsg::EndStream)) => {
                        self.inner_fut = None;
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Ready(Some(super::stream::BodyMsg::Data(buf)))
                        if !buf.has_remaining() =>
                    {
                        self.inner_fut = None;
                        continue;
                    }
                    Poll::Ready(Some(super::stream::BodyMsg::Data(mut buf))) => {
                        self.inner_fut = None;
                        break buf.copy_to_bytes(buf.remaining());
                    }
                    Poll::Ready(Some(super::stream::BodyMsg::Trailers(_))) => {
                        self.inner_fut = None;
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::BrokenPipe,
                            "client sent unexpected trailers",
                        )));
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

impl AsyncWrite for H2Upgraded {
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
    inner_fut: Option<Pin<Box<kanal::SendFuture<'static, super::stream::StreamMsg>>>>,
    inner: kanal::AsyncSender<super::stream::StreamMsg>,
    #[allow(clippy::type_complexity)]
    rx_fut: Option<Pin<Box<kanal::ReceiveFuture<'static, Box<[u8]>>>>>,
    rx: kanal::AsyncReceiver<Box<[u8]>>,
    error_tx: Option<oneshot::Sender<std::io::Error>>,
    reset_rx: kanal::AsyncReceiver<u32>,
    wake_tx: kanal::AsyncSender<()>,
    end: bool,
}

impl UpgradedSendStreamTask {
    #[inline]
    fn tick(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        let this = self.get_mut();
        let mut flush = false;

        // Manual `select()` over the in-flight send future and the consumer's
        // write channel, so the task lives no longer than necessary.
        loop {
            if let Some(mut fut) = this.inner_fut.take() {
                match fut.as_mut().poll(cx) {
                    Poll::Ready(Ok(())) => {
                        if !this.end {
                            flush = true;
                        }
                    }
                    Poll::Ready(Err(_)) => {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::BrokenPipe,
                            "request stream closed",
                        )));
                    }
                    Poll::Pending => {
                        this.inner_fut = Some(fut);
                        if flush {
                            let _ = this.wake_tx.try_send(());
                        }
                        return Poll::Pending;
                    }
                }
            }

            if this.end {
                return Poll::Ready(Ok(()));
            }

            match std::pin::pin!(this.reset_rx.recv()).poll(cx) {
                Poll::Ready(_) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "request stream reset",
                    )))
                }
                Poll::Pending => {}
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
                    let msg = super::stream::StreamMsg::Data {
                        data: Bytes::from_owner(cursor),
                        end_stream: false,
                    };
                    let inner_fut = this.inner.send(msg);
                    // SAFETY: inner_fut lives as long as inner after storing in struct
                    let inner_fut = unsafe {
                        std::mem::transmute::<
                            kanal::SendFuture<'_, super::stream::StreamMsg>,
                            kanal::SendFuture<'static, super::stream::StreamMsg>,
                        >(inner_fut)
                    };
                    this.inner_fut = Some(Box::pin(inner_fut));
                }
                Poll::Ready(Err(_)) => {
                    this.rx_fut = None;
                    let msg = super::stream::StreamMsg::Data {
                        data: Bytes::new(),
                        end_stream: true,
                    };
                    let inner_fut = this.inner.send(msg);
                    // SAFETY: inner_fut lives as long as inner after storing in struct
                    let inner_fut = unsafe {
                        std::mem::transmute::<
                            kanal::SendFuture<'_, super::stream::StreamMsg>,
                            kanal::SendFuture<'static, super::stream::StreamMsg>,
                        >(inner_fut)
                    };
                    this.inner_fut = Some(Box::pin(inner_fut));
                    this.end = true;
                }
                Poll::Pending => {
                    if flush {
                        let _ = this.wake_tx.try_send(());
                    }
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
