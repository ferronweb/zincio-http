//! Criterion benchmarks for the native QPACK codec.
//!
//! These exercise the hot paths of HTTP/3 header processing: encoding a
//! realistic header set and decoding the resulting field section. The
//! encoder stream produced alongside each block is fed to a fresh decoder
//! first, so the decode measurement reflects a real (self-contained) round
//! trip rather than an empty table. Table sizes 0 / 512 / 4096 bracket the
//! dynamic-table range, and both Huffman on/off are covered. Run with
//!
//! ```sh
//! cargo bench --features h3 --bench h3_qpack
//! ```

use bytes::Bytes;
use criterion::{criterion_group, criterion_main, Criterion};
use zincio_http::qpack::{Decoder, Encoder};

/// A named header-set producer used to drive the round-trip benchmarks.
type HeaderCase = (&'static str, &'static dyn Fn() -> Vec<(Bytes, Bytes)>);

fn request_headers() -> Vec<(Bytes, Bytes)> {
    vec![
        (Bytes::from_static(b":method"), Bytes::from_static(b"GET")),
        (
            Bytes::from_static(b":path"),
            Bytes::from_static(b"/index.html"),
        ),
        (Bytes::from_static(b":scheme"), Bytes::from_static(b"https")),
        (
            Bytes::from_static(b":authority"),
            Bytes::from_static(b"example.com"),
        ),
        (
            Bytes::from_static(b"user-agent"),
            Bytes::from_static(b"zincio-http/0.3"),
        ),
        (
            Bytes::from_static(b"accept"),
            Bytes::from_static(b"text/html"),
        ),
        (
            Bytes::from_static(b"accept-encoding"),
            Bytes::from_static(b"gzip, deflate, br"),
        ),
    ]
}

fn response_headers() -> Vec<(Bytes, Bytes)> {
    vec![
        (Bytes::from_static(b":status"), Bytes::from_static(b"200")),
        (
            Bytes::from_static(b"content-type"),
            Bytes::from_static(b"text/html; charset=utf-8"),
        ),
        (
            Bytes::from_static(b"server"),
            Bytes::from_static(b"zincio-http"),
        ),
        (
            Bytes::from_static(b"cache-control"),
            Bytes::from_static(b"max-age=3600"),
        ),
        (
            Bytes::from_static(b"content-encoding"),
            Bytes::from_static(b"gzip"),
        ),
        (
            Bytes::from_static(b"date"),
            Bytes::from_static(b"Thu, 01 Jan 1970 00:00:00 GMT"),
        ),
    ]
}

/// Encodes `headers` with the given capacity/Huffman settings and returns
/// the field-section block plus the full encoder stream the decoder needs.
fn encode(headers: &[(Bytes, Bytes)], capacity: u64, huffman: bool) -> (Bytes, Bytes) {
    let mut encoder = Encoder::new(capacity, huffman);
    let mut encoder_stream = Vec::new();
    if let Some(bytes) = encoder.set_capacity(capacity) {
        encoder_stream.extend_from_slice(&bytes);
    }
    let encoded = encoder.encode_section(0, headers);
    encoder_stream.extend_from_slice(&encoded.encoder_stream);
    (encoded.block, Bytes::from(encoder_stream))
}

fn bench_roundtrip(c: &mut Criterion) {
    let cases: &[HeaderCase] = &[
        ("request", &request_headers),
        ("response", &response_headers),
    ];
    let capacities = [0u64, 512, 4096];

    let mut group = c.benchmark_group("qpack");
    for (name, headers_fn) in cases {
        let headers = headers_fn();
        for &capacity in &capacities {
            for &huffman in &[false, true] {
                let tag = format!("{name}/cap_{capacity}/huff_{huffman}");
                let (block, encoder_stream) = encode(&headers, capacity, huffman);

                group.bench_function(format!("{tag}/encode"), |b| {
                    b.iter(|| {
                        let mut encoder = Encoder::new(capacity, huffman);
                        if let Some(bytes) = encoder.set_capacity(capacity) {
                            std::hint::black_box(&bytes);
                        }
                        encoder.encode_section(0, &headers)
                    });
                });

                group.bench_function(format!("{tag}/decode"), |b| {
                    b.iter(|| {
                        let mut decoder = Decoder::new(capacity, 100);
                        decoder
                            .feed_encoder_stream(&encoder_stream)
                            .expect("encoder stream accepted");
                        decoder
                            .decode_block(&block, 1, 0)
                            .expect("decode")
                            .expect("block not blocked")
                    });
                });
            }
        }
    }
    group.finish();
}

criterion_group!(benches, bench_roundtrip);
criterion_main!(benches);
