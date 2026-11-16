use bytes::Bytes;
use criterion::{criterion_group, criterion_main, Criterion};
use zincio_http::hpack::{Decoder, Encoder, Header};

fn sample_headers() -> Vec<Header> {
    vec![
        Header::new(":method", "GET"),
        Header::new(":path", "/index.html"),
        Header::new(":scheme", "https"),
        Header::new(":authority", "example.com"),
        Header::new("user-agent", "criterion/0.5"),
        Header::new("accept", "text/html"),
        Header::new("accept-encoding", "gzip, deflate"),
    ]
}

fn bench_encode(c: &mut Criterion) {
    let headers = sample_headers();
    let mut encoder = Encoder::new(4096);
    c.bench_function("hpack_encode", |b| {
        b.iter(|| {
            let mut out = Vec::with_capacity(64);
            encoder.encode(&headers, &mut out);
            out
        });
    });
}

fn bench_decode(c: &mut Criterion) {
    let headers = sample_headers();
    let mut encoder = Encoder::new(4096);
    let mut block = Vec::with_capacity(64);
    encoder.encode(&headers, &mut block);
    let block = Bytes::from(block);
    c.bench_function("hpack_decode", |b| {
        b.iter(|| {
            let mut decoder = Decoder::new(4096);
            decoder.decode(&block, &mut 0).expect("decode")
        });
    });
}

criterion_group!(benches, bench_encode, bench_decode);
criterion_main!(benches);
