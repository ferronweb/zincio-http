use bytes::Bytes;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use zincio_http::qpack::Encoder;

fn populated_encoder(n: usize) -> (Encoder, Vec<(Bytes, Bytes)>) {
    let mut encoder = Encoder::new(1 << 24, false);
    let headers: Vec<(Bytes, Bytes)> = (0..n)
        .map(|i| {
            (
                Bytes::copy_from_slice(format!("x{i}").as_bytes()),
                Bytes::copy_from_slice(format!("v{i}").as_bytes()),
            )
        })
        .collect();
    let _ = encoder.encode_section(0, &headers);
    (encoder, headers)
}

fn bench_large_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("qpack_large_encode");
    for &n in &[32usize, 64, 128, 256, 512] {
        let (mut encoder, headers) = populated_encoder(n);
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| {
                let _ = encoder.encode_section(0, &headers);
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_large_encode);
criterion_main!(benches);
