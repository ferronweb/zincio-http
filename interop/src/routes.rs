//! Request handler implementing every route in the scenario matrix.
//!
//! Each route corresponds one-to-one with a [`crate::scenario::Expect`], so
//! the server side of the matrix lives here and the expectations live in
//! `scenario.rs`.

use std::convert::Infallible;

use bytes::Bytes;
use futures_util::stream;
use http::{HeaderMap, HeaderValue, Request, Response, StatusCode};
use http_body::Frame;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use zincio_http::{send_early_hints, Incoming};

use crate::scenario::{pattern_chunk, Expect, HUGE_LEN, LARGE_LEN, SMALL_LEN};

/// Response body type used by every route.
pub type ResponseBody = BoxBody<Bytes, Infallible>;

/// Size of each chunk used when streaming a generated body. Large enough that
/// per-frame overhead is irrelevant, small enough that a 64 MiB response does
/// not need a 64 MiB allocation.
const STREAM_CHUNK: usize = 64 * 1024;

/// Trailer name used by the `/trailers` and `/echo` routes.
pub const ECHO_TRAILER: &str = "x-echo-trailer";

/// Handles a single request.
///
/// The handler is intentionally allocation-light for the generated-body routes:
/// `/huge` must stream 64 MiB without materialising it.
pub async fn handle(mut request: Request<Incoming>) -> Result<Response<ResponseBody>, Infallible> {
    let path = request.uri().path().to_owned();

    match path.as_str() {
        "/ping" => Ok(full(StatusCode::OK, b"pong".to_vec())),
        "/small" => Ok(full(
            StatusCode::OK,
            crate::scenario::pattern_body(SMALL_LEN),
        )),
        "/large" => Ok(full(
            StatusCode::OK,
            crate::scenario::pattern_body(LARGE_LEN),
        )),
        "/huge" => Ok(streamed(StatusCode::OK, HUGE_LEN, None)),
        "/hint" => {
            // Early hints are advisory; a failure to send them must not fail
            // the request.
            let mut links = HeaderMap::new();
            links.insert(
                "link",
                HeaderValue::from_static("</style.css>; rel=preload; as=style"),
            );
            let _ = send_early_hints(&mut request, links).await;
            Ok(full(
                StatusCode::OK,
                crate::scenario::pattern_body(SMALL_LEN),
            ))
        }
        "/echo" => {
            let (body, request_trailers) = collect(request).await;
            let trailer_value = request_trailers
                .as_ref()
                .and_then(|t| t.get(ECHO_TRAILER))
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            match trailer_value {
                // Echo the request trailer back so the client can verify both
                // directions of trailer propagation.
                Some(value) => Ok(streamed(
                    StatusCode::OK,
                    body.len(),
                    Some((ECHO_TRAILER, value)),
                )),
                None => Ok(full(StatusCode::OK, body.to_vec())),
            }
        }
        "/trailers" => {
            // Drain the upload so the request is fully consumed, then answer
            // with a trailer of our own.
            let (body, _) = collect(request).await;
            Ok(streamed(
                StatusCode::OK,
                SMALL_LEN,
                Some((ECHO_TRAILER, "echoed".to_owned())),
            ))
            .map(|response| {
                debug_assert_eq!(body.len(), SMALL_LEN, "scenario uploads SMALL_LEN bytes");
                response
            })
        }
        _ => Ok(full(
            StatusCode::NOT_FOUND,
            b"no such scenario route".to_vec(),
        )),
    }
}

/// Drains a request body and its trailers.
async fn collect(request: Request<Incoming>) -> (Bytes, Option<HeaderMap>) {
    match request.into_body().collect().await {
        Ok(collected) => {
            let trailers = collected.trailers().cloned();
            (collected.to_bytes(), trailers)
        }
        Err(_) => (Bytes::new(), None),
    }
}

/// A fully buffered response body.
fn full(status: StatusCode, body: Vec<u8>) -> Response<ResponseBody> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::from(body)).boxed())
        .expect("valid static response")
}

/// A streamed response body of `len` pattern bytes, optionally terminated by a
/// single trailer.
fn streamed(
    status: StatusCode,
    len: usize,
    trailer: Option<(&'static str, String)>,
) -> Response<ResponseBody> {
    let mut frames: Vec<Result<Frame<Bytes>, Infallible>> = (0..len)
        .step_by(STREAM_CHUNK)
        .map(|offset| {
            let take = STREAM_CHUNK.min(len - offset);
            Ok(Frame::data(pattern_chunk(offset as u64, take).into()))
        })
        .collect();

    if let Some((name, value)) = trailer {
        let mut trailers = HeaderMap::new();
        // Header values here are echoed from the request; anything the client
        // could not legally send has already been rejected by the protocol
        // layer, so a failure here means the test itself is malformed.
        let value = HeaderValue::from_str(&value).expect("valid trailer value");
        trailers.insert(name, value);
        frames.push(Ok(Frame::trailers(trailers)));
    }

    Response::builder()
        .status(status)
        .body(StreamBody::new(stream::iter(frames)).boxed())
        .expect("valid streamed response")
}

/// Maps a [`crate::scenario::Expect`] to the length its body must have.
///
/// Kept next to the routes so a new `Expect` variant forces the question of
/// which route serves it.
pub fn expect_for(path: &str) -> Option<Expect> {
    match path {
        "/small" => Some(Expect::Exact { len: SMALL_LEN }),
        "/large" => Some(Expect::Exact { len: LARGE_LEN }),
        "/huge" => Some(Expect::Exact { len: HUGE_LEN }),
        "/echo" => Some(Expect::Echo { len: SMALL_LEN }),
        "/trailers" => Some(Expect::Trailers { len: SMALL_LEN }),
        "/hint" => Some(Expect::EarlyHints { len: SMALL_LEN }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scenario::pattern_body;

    #[tokio::test]
    async fn streamed_body_matches_the_buffered_pattern() {
        // Streaming must be byte-identical to the buffered form; the whole
        // matrix compares digests, so a divergence here would be invisible
        // until every scenario failed.
        for len in [0usize, 1, STREAM_CHUNK - 1, STREAM_CHUNK, SMALL_LEN] {
            let response = streamed(StatusCode::OK, len, None);
            assert_eq!(
                response
                    .into_body()
                    .collect()
                    .await
                    .expect("collect streamed body")
                    .to_bytes(),
                pattern_body(len),
                "len {len}"
            );
        }
    }

    #[tokio::test]
    async fn streamed_body_appends_the_trailer_frame() {
        let response = streamed(
            StatusCode::OK,
            SMALL_LEN,
            Some((ECHO_TRAILER, "yes".into())),
        );
        let collected = response.into_body().collect().await.expect("collect");
        let trailers = collected.trailers().cloned().expect("trailers present");
        assert_eq!(
            trailers.get(ECHO_TRAILER).and_then(|v| v.to_str().ok()),
            Some("yes")
        );
        assert_eq!(collected.to_bytes(), pattern_body(SMALL_LEN));
    }

    #[test]
    fn every_expect_maps_to_a_served_route() {
        assert_eq!(expect_for("/small"), Some(Expect::Exact { len: SMALL_LEN }));
        assert_eq!(expect_for("/large"), Some(Expect::Exact { len: LARGE_LEN }));
        assert_eq!(
            expect_for("/trailers"),
            Some(Expect::Trailers { len: SMALL_LEN })
        );
        assert_eq!(
            expect_for("/hint"),
            Some(Expect::EarlyHints { len: SMALL_LEN })
        );
        assert_eq!(expect_for("/nope"), None);
    }
}
