//! The reset signal of one stream, from the connection task to the stream
//! task.
//!
//! The connection sets it when the peer resets the stream (RST_STREAM), and
//! it is set when the connection drops the stream, as when the connection
//! ends. It stays set, and the stream task is woken for it: a task that
//! waits for its handler, which may never wake it, sees it at once and
//! drops the handler.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use futures_util::task::AtomicWaker;

/// Not reset.
const NONE: u64 = 0;
/// Set with the error code in the low 32 bits.
const RESET: u64 = 1 << 32;
/// The sender was dropped without a code: the stream is gone.
const DROPPED: u64 = 2 << 32;

#[derive(Debug, Default)]
struct Shared {
    state: AtomicU64,
    waker: AtomicWaker,
}

/// The connection's half.
#[derive(Debug)]
pub(crate) struct ResetSender(Arc<Shared>);

/// The stream task's half; clones see the same signal.
#[derive(Debug, Clone)]
pub(crate) struct ResetReceiver(Arc<Shared>);

/// A new signal, not set.
pub(crate) fn channel() -> (ResetSender, ResetReceiver) {
    let shared = Arc::new(Shared::default());
    (ResetSender(Arc::clone(&shared)), ResetReceiver(shared))
}

impl ResetSender {
    /// The peer reset the stream with `code`; the first reset counts.
    pub(crate) fn send(&self, code: u32) {
        self.set(RESET | u64::from(code));
    }

    fn set(&self, state: u64) {
        let first = self
            .0
            .state
            .compare_exchange(NONE, state, Ordering::AcqRel, Ordering::Acquire)
            .is_ok();
        // Set before, the task was woken then.
        if first {
            self.0.waker.wake();
        }
    }
}

impl Drop for ResetSender {
    fn drop(&mut self) {
        self.set(DROPPED);
    }
}

impl ResetReceiver {
    /// `Ready(Some(code))` once the peer reset the stream, `Ready(None)`
    /// once the connection dropped it; else registers the task to be woken.
    pub(crate) fn poll_reset(&self, cx: &mut Context<'_>) -> Poll<Option<u32>> {
        if let Some(reset) = self.check() {
            return Poll::Ready(reset);
        }
        self.0.waker.register(cx.waker());
        // Set between the check and the registration: seen now.
        match self.check() {
            Some(reset) => Poll::Ready(reset),
            None => Poll::Pending,
        }
    }

    fn check(&self) -> Option<Option<u32>> {
        let state = self.0.state.load(Ordering::Acquire);
        if state == NONE {
            None
        } else if state & RESET != 0 {
            // The low 32 bits are the code.
            let bytes = state.to_le_bytes();
            Some(Some(u32::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3],
            ])))
        } else {
            Some(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::task::{Wake, Waker};

    struct Count(AtomicUsize);

    impl Wake for Count {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn a_reset_wakes_the_waiting_task_and_stays_set() {
        let count = Arc::new(Count(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&count));
        let mut cx = Context::from_waker(&waker);
        let (tx, rx) = channel();
        assert_eq!(rx.poll_reset(&mut cx), Poll::Pending);
        tx.send(0x8);
        assert_eq!(count.0.load(Ordering::SeqCst), 1, "woken");
        assert_eq!(rx.poll_reset(&mut cx), Poll::Ready(Some(0x8)));
        assert_eq!(
            rx.clone().poll_reset(&mut cx),
            Poll::Ready(Some(0x8)),
            "stays set"
        );
        tx.send(0x2);
        assert_eq!(
            rx.poll_reset(&mut cx),
            Poll::Ready(Some(0x8)),
            "the first reset counts"
        );
    }

    #[test]
    fn a_dropped_sender_wakes_the_waiting_task() {
        let count = Arc::new(Count(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&count));
        let mut cx = Context::from_waker(&waker);
        let (tx, rx) = channel();
        assert_eq!(rx.poll_reset(&mut cx), Poll::Pending);
        drop(tx);
        assert_eq!(count.0.load(Ordering::SeqCst), 1, "woken");
        assert_eq!(rx.poll_reset(&mut cx), Poll::Ready(None));
    }
}
