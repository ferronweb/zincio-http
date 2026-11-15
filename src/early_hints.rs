use std::{
    collections::VecDeque,
    sync::Arc,
    task::{Context, Poll, Waker},
};

use http::{HeaderMap, Request};
use http_body::Body;
use parking_lot::Mutex;

type EarlyHintsResult = Result<(), std::io::Error>;
pub(super) type EarlyHintsMessage = (
    HeaderMap,
    tokio::sync::Mutex<oneshot::Sender<EarlyHintsResult>>,
);

#[derive(Clone)]
pub(super) struct EarlyHints {
    inner: Arc<Mutex<LazyEarlyHintsState>>,
}

pub(super) struct EarlyHintsReceiver {
    inner: Arc<Mutex<LazyEarlyHintsState>>,
}

#[derive(Default)]
struct LazyEarlyHintsState {
    closed: bool,
    queue: VecDeque<EarlyHintsMessage>,
    receiver_waker: Option<Waker>,
}

impl EarlyHints {
    #[inline]
    pub(super) fn new_lazy() -> (Self, EarlyHintsReceiver) {
        let inner = Arc::new(Mutex::new(LazyEarlyHintsState::default()));
        (
            Self {
                inner: Arc::clone(&inner),
            },
            EarlyHintsReceiver { inner },
        )
    }

    #[inline]
    async fn send(&self, headers: HeaderMap) -> EarlyHintsResult {
        let (tx, rx) = oneshot::async_channel();
        let message = (headers, tokio::sync::Mutex::new(tx));
        let receiver_waker = {
            let mut state = self.inner.lock();
            if state.closed {
                return Err(std::io::Error::other("early hints receiver closed"));
            }
            state.queue.push_back(message);
            state.receiver_waker.take()
        };
        if let Some(receiver_waker) = receiver_waker {
            receiver_waker.wake();
        }
        rx.await.map_err(std::io::Error::other)?
    }
}

impl EarlyHintsReceiver {
    #[inline]
    pub(super) fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<EarlyHintsMessage>> {
        let mut state = self.inner.lock();
        if let Some(message) = state.queue.pop_front() {
            return Poll::Ready(Some(message));
        }
        if state.closed {
            return Poll::Ready(None);
        }
        state.receiver_waker = Some(cx.waker().clone());
        Poll::Pending
    }
    #[inline]
    pub(super) fn close(&mut self) {
        let receiver_waker = {
            let mut state = self.inner.lock();
            if state.closed {
                None
            } else {
                state.closed = true;
                state.queue.clear();
                state.receiver_waker.take()
            }
        };
        if let Some(receiver_waker) = receiver_waker {
            receiver_waker.wake();
        }
    }
}

impl Drop for EarlyHintsReceiver {
    #[inline]
    fn drop(&mut self) {
        self.close();
    }
}

/// Sends a `103 Early Hints` response for the given request.
///
/// Early hints allow the server to push `Link` (or other) headers to the
/// client before the final response is ready, enabling the browser to begin
/// preloading resources (stylesheets, scripts, fonts, etc.) while the handler
/// is still computing the response.
///
/// # Requirements
///
/// The connection must be HTTP/2 or HTTP/3, or if HTTP/1.1, the server must
/// have been created with
/// [`Http1Options::enable_early_hints`](crate::h1::Http1Options::enable_early_hints)
/// set to `true`. When that option is enabled the handler inserts an
/// `EarlyHints` token into each request's extensions. If the token is absent
/// (i.e. early hints were not enabled) this function returns an error.
///
/// # Errors
///
/// Returns `Err` if:
/// - Early hints are not enabled on the connection (`"early hints not supported"`).
/// - The connection handler has already shut down and can no longer accept
///   interim responses.
/// - Writing the `103` response to the underlying I/O stream fails.
///
/// # Example
///
/// ```rust,ignore
/// use http::HeaderMap;
///
/// let mut link_headers = HeaderMap::new();
/// link_headers.insert(
///     http::header::LINK,
///     "</style.css>; rel=preload; as=style".parse().unwrap(),
/// );
/// send_early_hints(&mut request, link_headers).await?;
/// ```
#[inline]
pub async fn send_early_hints(
    req: &mut Request<impl Body>,
    headers: HeaderMap,
) -> Result<(), std::io::Error> {
    req.extensions()
        .get::<EarlyHints>()
        .ok_or_else(|| std::io::Error::other("early hints not supported"))?
        .send(headers)
        .await
}
