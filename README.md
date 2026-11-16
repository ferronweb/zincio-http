# zincio-http

[![Static Badge](https://img.shields.io/badge/Documentation-orange?style=flat-square)](https://docs.rs/zincio-http)
[![Crates.io](https://img.shields.io/crates/v/zincio-http?style=flat-square)](https://crates.io/crates/zincio-http)
[![GitHub Repo stars](https://img.shields.io/github/stars/ferronweb/zincio-http?style=flat-square)](https://github.com/ferronweb/zincio-http)
[![GitHub License](https://img.shields.io/github/license/ferronweb/zincio-http?style=flat-square)](https://github.com/ferronweb/zincio-http/blob/main/LICENSE)

High-performance HTTP server primitives for the `zincio` runtime.

`zincio-http` provides HTTP/1.0, HTTP/1.1, HTTP/2, and HTTP/3 server implementations on top of the `zincio` asynchronous Rust runtime.

## Highlights

- HTTP/1.x, HTTP/2, and HTTP/3 handlers with a common interface
- Streaming request/response bodies and trailers
- Automatic `100 Continue` support
- `103 Early Hints` support via `send_early_hints`
- HTTP/1.x upgrade support (`prepare_upgrade` / `OnUpgrade`)
- Linux and FreeBSD zero-copy response sending for HTTP/1.x (`h1-zerocopy` feature)
- Graceful shutdown support for all protocol handlers via `CancellationToken`
- **Custom HTTP/2 and HTTP/3 implementations**, without dependencies on Hyperium's `h2` and `h3` crates

## Installation

```toml
[dependencies]
zincio-http = "0.5"
```

By default, this crate enables: `h1`, `h1-zerocopy`, and `h2`.

### Feature flags

| Feature       | Enables                                                                                |
| ------------- | -------------------------------------------------------------------------------------- |
| `h1`          | HTTP/1.0 / HTTP/1.1 connection handler                                                 |
| `h1-zerocopy` | Linux / FreeBSD zero-copy HTTP/1.x response sending                                    |
| `h2`          | HTTP/2 connection handler                                                              |
| `h3`          | HTTP/3 connection handler                                                              |
| `h3-quinn`    | QUIC transport adapter for `h3`, built on [`quinn`](https://github.com/quinn-rs/quinn) |

For a smaller build, disable default features and opt in explicitly:

```toml
[dependencies]
zincio-http = { version = "0.5", default-features = false, features = ["h1"] }
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

## Contributing

Feedback, bug reports, and testing are welcome. See [CONTRIBUTING.md](./CONTRIBUTING.md) for setup, checks, and guidelines.

## License

[MIT](./LICENSE)
