# neqo driver image: Mozilla's QUIC + HTTP/3 stack used in Firefox.
#
# neqo's client is the stable, production-hardened side (its server exists
# only to test the client), which is exactly the opinion this matrix wants on
# the server's HTTP/3 behaviour. The version is pinned (toolchain, neqo
# revision, Cargo.lock) so an upstream release cannot turn into an unexplained
# failure here.
#
# neqo's TLS backend is NSS. It uses a system NSS when new enough, otherwise it
# fetches and compiles its pinned NSS release automatically; the toolchain
# below covers both paths (bookworm's NSS 3.87 predates the required 3.126, so
# the self-provisioning path is the one that runs). bindgen needs libclang in
# either case.

# The toolchain is newer than quiche's: neqo main requires rustc 1.90+.
FROM rust:1.93-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential clang cmake pkg-config python3 perl gyp ninja-build \
        libnss3-dev libnspr4-dev zlib1g-dev libclang-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY clients/neqo/Cargo.toml clients/neqo/Cargo.lock ./
COPY clients/neqo/src ./src
# Bookworm's NSS (3.87) predates nss-rs's minimum (3.126), so build Mozilla's
# pinned NSS release from source instead of using the system one.
ENV NSS_NO_PKG_CONFIG=1
RUN cargo build --locked --release \
    && mkdir -p /out/nsslib \
    && cp target/release/interop-driver /out/interop-driver \
    && NSSLIB="$(dirname "$(find target/release/build -name libnss3.so | head -1)")" \
    && echo "bundling self-built NSS from $NSSLIB" \
    && cp "$NSSLIB"/lib*.so* /out/nsslib/

FROM debian:bookworm-slim AS driver
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates libnspr4 libnss3 libsqlite3-0 zlib1g \
    && rm -rf /var/lib/apt/lists/*
# The self-built NSS 3.126 the driver linked against. It must come before the
# system NSS on the search path: the system 3.87 is too old and initialisation
# refuses it (UnsupportedVersion). softokn/freebl ride along because NSS
# loads them at runtime from its own directory.
COPY --from=build /out/nsslib /usr/local/lib/interop-nss
COPY --from=build /out/interop-driver /usr/local/bin/interop-driver
ENV LD_LIBRARY_PATH=/usr/local/lib/interop-nss
ENTRYPOINT ["/usr/local/bin/interop-driver"]
