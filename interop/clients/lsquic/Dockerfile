# lsquic driver image: LiteSpeed's QUIC + HTTP/3 stack.
#
# lsquic is the QUIC stack behind LiteSpeed/OpenLiteSpeed and the `lsquic`
# command-line client, so its TLS (BoringSSL), QPACK, and loss recovery are a
# genuinely independent H3 opinion in the matrix.
#
# BoringSSL and lsquic are pinned by commit so an upstream release cannot
# turn into an unexplained matrix failure.
#
# The build stage clones and compiles both libraries from source; the runtime
# carries only the statically linked driver.

FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates git build-essential cmake perl golang-go zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src

# BoringSSL, pinned. lsquic requires it for QUIC's TLS 1.3 handshake.
RUN git clone https://boringssl.googlesource.com/boringssl /src/boringssl \
    && git -C /src/boringssl checkout e20e8486554098772673b55ea76bb003d0b330e5
RUN cd /src/boringssl \
    && cmake -DBUILD_TESTING=OFF . \
    && make -j"$(nproc)"

# lsquic, pinned, with its ls-qpack and ls-hpack submodules.
# NOTE: No -DCMAKE_BUILD_TYPE=Release, since a debug build of lsquic
#       intentionally emits non-minimal frame lengths/SETTINGS...
RUN git clone https://github.com/litespeedtech/lsquic.git /src/lsquic \
    && git -C /src/lsquic checkout cd23e526e53387ad7a2fada9a4479d2353ee2b42 \
    && git -C /src/lsquic submodule update --init --recursive
RUN cd /src/lsquic \
    && cmake -DBUILD_TESTING=OFF \
             -DBORINGSSL_DIR=/src/boringssl . \
    && make -j"$(nproc)"

WORKDIR /driver
COPY Makefile main.c endpoint.c endpoint.h types.h ./
RUN make BORINGSSL_DIR=/src/boringssl LSQUIC_DIR=/src/lsquic \
        LSQUIC_BUILD_DIR=/src/lsquic \
    && mkdir -p /out \
    && cp interop-driver-lsquic /out/interop-driver

FROM debian:bookworm-slim AS driver
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates libstdc++6 zlib1g \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/interop-driver /usr/local/bin/interop-driver
ENTRYPOINT ["/usr/local/bin/interop-driver"]
