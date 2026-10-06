# zincio-http

High-performance HTTP server primitives for the `zincio` runtime.

`zincio-http` provides HTTP/1.0, HTTP/1.1, HTTP/2, and HTTP/3 connection
handlers behind a shared `HttpProtocol` trait. Each handler receives an
`http::Request<Incoming>` and returns an `http::Response<B>`, where
`B: http_body::Body<Data = bytes::Bytes>`.

## Highlights

- HTTP/1.x, HTTP/2, and HTTP/3 handlers with a common interface
- Streaming request/response bodies and trailers
- Automatic `100 Continue` support
- `103 Early Hints` support via `send_early_hints`
- HTTP/1 upgrade support (`prepare_upgrade` / `OnUpgrade`)
- Linux and FreeBSD zero-copy response sending for HTTP/1.x (`h1-zerocopy` feature)
- Graceful shutdown support for all protocol handlers via `CancellationToken`
- **Custom HTTP/2 and HTTP/3 implementations**, without dependencies on Hyperium's `h2` and `h3` crates

## Installation

```toml
[dependencies]
zincio-http = "0.4"
```

By default, this crate enables: `h1`, `h1-zerocopy`, and `h2`.

### Feature flags

| Feature       | Enables                                                                  |
| ------------- | ------------------------------------------------------------------------ |
| `h1`          | HTTP/1.0 / HTTP/1.1 connection handler                                   |
| `h1-zerocopy` | Linux / FreeBSD zero-copy HTTP/1.x response sending (`splice`-based)     |
| `h2`          | HTTP/2 connection handler (in-house)                                     |
| `h3`          | HTTP/3 connection handler (native RFC 9114 implementation)               |
| `h3-quinn`    | QUIC transport adapter for `h3` (`zincio_http::quinn`, built on `quinn`) |

For a smaller build, disable default features and opt in explicitly:

```toml
[dependencies]
zincio-http = { version = "0.4", default-features = false, features = ["h1"] }
```

## Quickstart (HTTP/1.1)

```rust
use bytes::Bytes;
use http::Response;
use http_body_util::Full;
use zincio::net::TcpListener;
use zincio::RuntimeBuilder;
use zincio_http::{Http1, Http1Options, HttpProtocol};

fn main() -> std::io::Result<()> {
    let runtime = RuntimeBuilder::new().enable_timer(true).build()?;

    runtime.block_on(async {
        let listener = TcpListener::bind("127.0.0.1:8080")?;
        loop {
            let (stream, _) = listener.accept().await?;
            stream.set_nodelay(true)?;
            let stream = stream.into_poll()?;

            zincio::spawn(async move {
                if let Err(e) = Http1::new(stream, Http1Options::default())
                    .handle(|_request| async move {
                        Ok::<_, std::convert::Infallible>(Response::new(Full::new(
                            Bytes::from_static(b"Hello World"),
                        )))
                    })
                    .await
                {
                    eprintln!("HTTP error: {:?}", e);
                }
            });
        }
    })
}
```

## Early hints (`103`)

Use `send_early_hints` from your handler before returning the final response.

Notes:

- HTTP/2 and HTTP/3: available by default
- HTTP/1.x: requires `Http1Options::enable_early_hints(true)`

```rust
use http::{header, HeaderMap, Response};
use http_body_util::Empty;
use zincio_http::send_early_hints;

let handler = |mut req| async move {
    let mut hints = HeaderMap::new();
    hints.insert(
        header::LINK,
        "</app.css>; rel=preload; as=style".parse().unwrap(),
    );
    let _ = send_early_hints(&mut req, hints).await;

    Ok::<_, std::convert::Infallible>(Response::new(Empty::<bytes::Bytes>::new()))
};
```

## HTTP options

`Http1Options`, `Http2Options`, and `Http3Options` all expose:

- handshake / accept timeouts
- automatic `100 Continue`
- HTTP protocol-specific configuration

## HTTP/1 upgrades

For upgrade workflows (for example WebSocket-style handoff), call
`prepare_upgrade(&mut request)` in your handler and await the returned
`OnUpgrade` future after sending a `101 Switching Protocols` response.

The resolved `Upgraded` type implements `tokio::io::AsyncRead + AsyncWrite`.

## Linux/FreeBSD zero-copy (HTTP/1.x)

When built with `h1-zerocopy` on Linux or FreeBSD:

1. Convert your handler with `.zerocopy()`
2. Mark responses with `unsafe install_zerocopy(response, raw_fd)`

Responses carrying that extension are sent via kernel-assisted transfer. Other
responses fall back to normal HTTP/1 writes.

## Graceful shutdown

`Http1`, `Http2`, and `Http3` expose:

```rust,ignore
.graceful_shutdown_token(token)
```

Cancel the token to stop accepting new work and shut down the connection
cleanly.

## Benchmarks

The crate ships Criterion benchmarks for the HPACK/QPACK codecs:

```sh
# HPACK encode + decode
cargo bench --features h2 --bench h2_hpack

# HPACK encode with large headers
cargo bench --features h2 --bench h2_hpack_large

# QPACK round-trip (table sizes 0/512/4096, Huffman on/off)
cargo bench --features h3 --bench h3_qpack

# QPACK encode with large headers
cargo bench --features h3 --bench h3_qpack_large
```

## Crate API at a glance

- `HttpProtocol`: common protocol trait (`handle`, `handle_with_error_fn`)
- `Incoming`: type-erased request body type used in all handlers
- `send_early_hints`: send a `103 Early Hints` interim response
- `Http1` / `Http1Options`
- `Http2` / `Http2Options`
- `Http3` / `Http3Options`
- `zincio_http::quinn::Connection`: QUIC transport adapter (with `h3-quinn`)
- `prepare_upgrade`, `OnUpgrade`, `Upgraded` (HTTP/1 upgrade flow)

## License

[MIT](./LICENSE)
