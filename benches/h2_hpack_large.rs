use bytes::Bytes;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use zincio_http::hpack::{Encoder, Header};

fn populated_encoder(n: usize) -> (Encoder, Vec<Header>) {
    let mut encoder = Encoder::new(1 << 20);
    let headers: Vec<Header> = (0..n)
        .map(|i| {
            Header::new(
                Bytes::copy_from_slice(format!("x{i}").as_bytes()),
                Bytes::copy_from_slice(format!("v{i}").as_bytes()),
            )
        })
        .collect();
    let mut out = Vec::new();
    encoder.encode(&headers, &mut out);
    (encoder, headers)
}

fn bench_large_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("hpack_large_encode");
    for &n in &[32usize, 64, 128, 256, 512] {
        let (mut encoder, headers) = populated_encoder(n);
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| {
                let mut out = Vec::new();
                encoder.encode(&headers, &mut out);
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_large_encode);
criterion_main!(benches);
