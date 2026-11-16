use std::{
    pin::Pin,
    task::{Context, Poll},
};

use http_body::Body;

#[cfg(feature = "h2")]
use crate::H2Body;
#[cfg(feature = "h1")]
use crate::Http1Body;

/// An incoming HTTP request body.
///
/// `Incoming` is the concrete body type placed inside every
/// [`Request`](http::Request) passed to the user-supplied handler.
#[allow(private_interfaces)]
pub enum Incoming {
    #[cfg(feature = "h1")]
    H1(Http1Body),
    #[cfg(feature = "h2")]
    H2(H2Body),
    #[cfg(feature = "h3")]
    Boxed(Pin<Box<dyn Body<Data = bytes::Bytes, Error = std::io::Error> + Send + Sync>>),
    #[cfg(any(feature = "h2", feature = "h3"))]
    Empty,
}

impl Body for Incoming {
    type Data = bytes::Bytes;
    type Error = std::io::Error;

    #[inline]
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        match self.get_mut() {
            #[cfg(feature = "h1")]
            Self::H1(ref mut inner) => Pin::new(inner).poll_frame(cx),
            #[cfg(feature = "h2")]
            Self::H2(ref mut inner) => Pin::new(inner).poll_frame(cx),
            #[cfg(feature = "h3")]
            Self::Boxed(inner) => inner.as_mut().poll_frame(cx),
            #[cfg(any(feature = "h2", feature = "h3"))]
            Self::Empty => Poll::Ready(None),
        }
    }

    #[inline]
    fn is_end_stream(&self) -> bool {
        match self {
            #[cfg(feature = "h1")]
            Self::H1(inner) => inner.is_end_stream(),
            #[cfg(feature = "h2")]
            Self::H2(inner) => inner.is_end_stream(),
            #[cfg(feature = "h3")]
            Self::Boxed(inner) => inner.is_end_stream(),
            #[cfg(any(feature = "h2", feature = "h3"))]
            Self::Empty => true,
        }
    }

    #[inline]
    fn size_hint(&self) -> http_body::SizeHint {
        match self {
            #[cfg(feature = "h1")]
            Self::H1(inner) => inner.size_hint(),
            #[cfg(feature = "h2")]
            Self::H2(inner) => inner.size_hint(),
            #[cfg(feature = "h3")]
            Self::Boxed(inner) => inner.size_hint(),
            #[cfg(any(feature = "h2", feature = "h3"))]
            Self::Empty => http_body::SizeHint::default(),
        }
    }
}
