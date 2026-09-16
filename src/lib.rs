//! # zincio-http
//!
//! High-performance HTTP/1.1, HTTP/2, and HTTP/3 server implementation
//! for the [`zincio`] async runtime.
//!
//! `zincio-http` provides protocol-specific connection handlers behind a common
//! [`HttpProtocol`] trait. Handlers receive an `http::Request<`[`Incoming`]`>`
//! and return an `http::Response<B>` where `B` implements
//! [`http_body::Body`] with `bytes::Bytes` chunks.
//!
//! ## Feature highlights
//!
//! - **Zero-copy static file serving** - supports zero-copy response sending for static file serving on Linux and FreeBSD.
//! - **100 Continue** - Supports automatically sending `100 Continue` before the final response.
//! - **103 Early Hints** - Supports sending `103 Early Hints` before the final response.
//!
//! ## Feature flags
//!
//! - `h1`: Enables HTTP/1.x support.
//! - `h2`: Enables HTTP/2 support.
//! - `h3`: Enables HTTP/3 support.
//! - `h1-zerocopy`: Enables Linux and FreeBSD-only zero-copy response sending for HTTP/1.x.
//!
//! ## Early hints
//!
//! Use [`send_early_hints`] from a request handler to send `103 Early Hints`
//! before the final response.
//!
//! ## Example
//!
//! ```rust,no_run
//! # #[cfg(feature = "h1")]
//! # fn main() -> std::io::Result<()> {
//! use bytes::Bytes;
//! use http::Response;
//! use http_body_util::Full;
//! use zincio::net::TcpListener;
//! use zincio::RuntimeBuilder;
//! use zincio_http::{Http1, Http1Options, HttpProtocol};
//!
//! let runtime = RuntimeBuilder::new().enable_timer(true).build()?;
//!
//! runtime.block_on(async {
//!     let listener = TcpListener::bind("127.0.0.1:8080")?;
//!     let (stream, _) = listener.accept().await?;
//!     stream.set_nodelay(true)?;
//!
//!     Http1::new(stream.into_poll()?, Http1Options::default())
//!         .handle(|_request| async move {
//!             let response = Response::new(Full::new(Bytes::from_static(b"Hello World")));
//!             Ok::<_, std::convert::Infallible>(response)
//!         })
//!         .await
//! })
//! # }
//! # #[cfg(not(feature = "h1"))]
//! # fn main() {}
//! ```
#![cfg_attr(docsrs, feature(doc_cfg))]

mod early_hints;
#[cfg(feature = "h1")]
mod h1;
#[cfg(feature = "h2")]
mod h2;
#[cfg(feature = "h3")]
mod h3;
mod incoming;
mod upgrade;

#[cfg(any(feature = "h2", feature = "h3"))]
pub mod hpack;

pub use early_hints::*;
#[cfg(feature = "h1")]
pub use h1::*;
#[cfg(feature = "h2")]
pub use h2::connection::*;
#[cfg(feature = "h2")]
pub use h2::options::Http2Options;
#[cfg(feature = "h2")]
pub use h2::*;
#[cfg(feature = "h3")]
pub use h3::*;
pub use incoming::*;
pub use upgrade::*;

use http::{Request, Response};
use http_body::Body;
use std::sync::Arc;

/// Callback invoked when an HTTP/2 or HTTP/3 stream fails.
///
/// The argument is always a [`std::io::Error`] describing the stream
/// failure (including the stream id where known), so handlers do not
/// need to depend on protocol-specific error types.
pub type StreamErrorCallback = Arc<dyn Fn(std::io::Error) + Send + Sync + 'static>;

/// Builds a stream-error [`std::io::Error`] with a human-readable message.
#[inline]
pub fn stream_error_io_error(message: impl Into<String>) -> std::io::Error {
    std::io::Error::other(message.into())
}

/// A trait representing an HTTP protocol (for example, HTTP/1.1, HTTP/2, HTTP/3).
///
/// This trait provides a simple, type-erased interface for handling HTTP requests
/// across different protocol versions.
pub trait HttpProtocol: Sized {
    fn handle<F, Fut, ResB, ResBE, ResE>(
        self,
        request_fn: F,
    ) -> impl std::future::Future<Output = Result<(), std::io::Error>>
    where
        F: Fn(Request<Incoming>) -> Fut + 'static,
        Fut: std::future::Future<Output = Result<Response<ResB>, ResE>> + 'static,
        ResB: Body<Data = bytes::Bytes, Error = ResBE> + Unpin + 'static,
        ResE: std::error::Error + 'static,
        ResBE: std::error::Error + 'static;

    #[allow(unused_variables)]
    #[inline]
    fn handle_with_error_fn<F, Fut, ResB, ResBE, ResE, EF, EFut, EResB, EResBE, EResE>(
        self,
        request_fn: F,
        error_fn: EF,
    ) -> impl std::future::Future<Output = Result<(), std::io::Error>>
    where
        F: Fn(Request<Incoming>) -> Fut + 'static,
        Fut: std::future::Future<Output = Result<Response<ResB>, ResE>> + 'static,
        ResB: Body<Data = bytes::Bytes, Error = ResBE> + Unpin + 'static,
        ResE: std::error::Error + 'static,
        ResBE: std::error::Error + 'static,
        EF: FnOnce(bool) -> EFut,
        EFut: std::future::Future<Output = Result<Response<EResB>, EResE>>,
        EResB: Body<Data = bytes::Bytes, Error = EResBE> + Unpin + 'static,
        EResE: std::error::Error + 'static,
        EResBE: std::error::Error + 'static,
    {
        self.handle(request_fn)
    }
}
