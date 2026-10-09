# quiche driver image: Cloudflare's QUIC + HTTP/3 stack.
#
# quiche is the QUIC + HTTP/3 implementation behind Cloudflare's edge and
# cloudflared, so its QPACK encoder and loss recovery differ meaningfully from
# the other H3 clients in the matrix. The version is pinned (toolchain,
# quiche, Cargo.lock) so an upstream release cannot turn into an unexplained
# failure here.
#
# quiche links BoringSSL, which it builds from source when vendored: the build
# stage needs a C++ toolchain plus cmake, perl, and Go (BoringSSL's build
# script is written in Go). The runtime carries only the static binary.

FROM rust:1.99-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
        cmake g++ make perl golang pkg-config libclang-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --locked --release \
    && mkdir -p /out \
    && cp target/release/interop-driver /out/interop-driver

FROM debian:bookworm-slim AS driver
COPY --from=build /out/interop-driver /usr/local/bin/interop-driver
ENTRYPOINT ["/usr/local/bin/interop-driver"]
