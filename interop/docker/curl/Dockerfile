# curl driver images.
#
# Build target `driver` speaks HTTP/1.1 and HTTP/2 via nghttp2. Builds in
# seconds, so it runs on every pull request.
#
# Build target `http3` speaks all three via a from-source curl against ngtcp2.
# Slow, so CI builds and caches it separately.
#
# Why Dockerfiles we own rather than registry images: `curlimages/curl`
# hardcodes `ENTRYPOINT ["curl"]`, and testcontainers cannot clear a
# third-party image's entrypoint. Owning the images is the only way to give the
# driver a clean entrypoint. It is also the only route to a current HTTP/3 curl:
# the official image has no HTTP/3, and every HTTP/3-capable curl image on a
# registry is a stale personal build (`ymuski/curl-http3:8.2.1` dates from 2022).

ARG CURL_IMAGE=curlimages/curl:8.22.0

# No packages are installed here on purpose: `curlimages/curl` runs as a
# non-root user, so `apk add` cannot run in this stage. Everything the driver
# needs (curl, sha256sum, awk, printf) is already present; sha256sum and awk come
# from busybox.
FROM ${CURL_IMAGE} AS driver
COPY --chmod=0755 clients/curl-driver.sh /usr/local/bin/interop-driver
ENTRYPOINT ["/usr/local/bin/interop-driver"]

# ---------------------------------------------------------------------------
# HTTP/3-capable curl.
#
# Base must be `alpine:edge`, not a release branch: curl only enables HTTP/3
# when the TLS library exposes the QUIC API, which needs OpenSSL 3.5+.
# Alpine 3.21 ships 3.3.7 while edge has 3.5.9. Edge is rolling, so CI caches
# the built image rather than rebuilding per pull request.
#
# Alpine does not package `libngtcp2_crypto_ossl` (the OpenSSL backend curl's
# CMake requires), so ngtcp2 is built from source. nghttp3 comes from Alpine.
# Clone without `git submodule update`: curl's submodules vendor QUIC libraries
# for its bundled examples, which this build does not use.
# ---------------------------------------------------------------------------
FROM alpine:edge AS ngtcp2-build
RUN apk add --no-cache \
	autoconf automake build-base cmake git libtool openssl-dev pkgconf samurai
WORKDIR /src/ngtcp2
ARG NGTCP2_VERSION=v1.25.0
RUN git clone --depth 1 --branch ${NGTCP2_VERSION} https://github.com/ngtcp2/ngtcp2.git .
RUN cmake -B build -G Ninja \
	-DCMAKE_BUILD_TYPE=Release \
	-DBUILD_TESTING=OFF \
	-DENABLE_OPENSSL=ON
RUN cmake --build build --parallel "$(nproc)"
RUN cmake --install build

FROM alpine:edge AS http3-build
RUN apk add --no-cache \
	autoconf automake brotli-dev build-base c-ares-dev cmake git libidn2-dev \
	libpsl-dev libtool linux-headers nghttp2-dev nghttp3-dev openssl-dev perl \
	pkgconf samurai zlib-dev zstd-dev
COPY --from=ngtcp2-build /usr/local/lib/libngtcp2* /usr/local/lib/
COPY --from=ngtcp2-build /usr/local/lib/pkgconfig/libngtcp2* /usr/local/lib/pkgconfig/
COPY --from=ngtcp2-build /usr/local/include/ngtcp2 /usr/local/include/ngtcp2
WORKDIR /src/curl
ARG CURL_VERSION=curl-8_19_0
RUN git clone --depth 1 --branch ${CURL_VERSION} https://github.com/curl/curl.git .
RUN cmake -B build -G Ninja \
	-DBUILD_SHARED_LIBS=OFF \
	-DBUILD_TESTING=OFF \
	-DBUILD_CURL_EXE=ON \
	-DCURL_USE_OPENSSL=ON \
	-DUSE_NGTCP2=ON \
	-DUSE_NGTCP2_TLS=ON \
	-DUSE_NGHTTP3=ON \
	-DENABLE_DEBUG=OFF \
	-DCMAKE_BUILD_TYPE=Release
RUN cmake --build build --parallel "$(nproc)"

FROM alpine:edge AS http3
RUN apk add --no-cache \
	brotli c-ares ca-certificates libidn2 libpsl nghttp2 nghttp3 openssl zlib zstd
COPY --from=ngtcp2-build /usr/local/lib/libngtcp2.so* /usr/local/lib/
COPY --from=ngtcp2-build /usr/local/lib/libngtcp2_crypto_ossl.so* /usr/local/lib/
COPY --from=http3-build /src/curl/build/src/curl /usr/local/bin/curl
COPY --chmod=0755 clients/curl-driver.sh /usr/local/bin/interop-driver
ENTRYPOINT ["/usr/local/bin/interop-driver"]
