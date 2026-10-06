# curl driver image.
#
# Build target `driver` speaks HTTP/1.1 and HTTP/2 via nghttp2. Builds in
# seconds, so it runs on every pull request.
#
# Why a Dockerfile we own rather than the official image: `curlimages/curl`
# hardcodes `ENTRYPOINT ["curl"]`, and testcontainers cannot clear a
# third-party image's entrypoint. Owning the image is the only way to give the
# driver a clean entrypoint.
#
# # HTTP/3 target (not yet built)
#
# HTTP/3 needs a separate image and is not wired up yet. The recipe, so the
# next attempt does not have to rediscover it:
#
# - Base must be `alpine:edge`, not a release branch. curl only enables HTTP/3
#   when the TLS library exposes the QUIC API, which needs OpenSSL 3.5+;
#   Alpine 3.21 ships 3.3.7 while edge has 3.5.9.
# - The runtime packages are `ngtcp2 nghttp3 openssl` (there is no
#   `ngtcp2-openssl` package; the unprefixed `ngtcp2` is the OpenSSL build, and
#   `-gnutls` is the GnuTLS one).
# - Alpine's own `curl` package (8.22.0) has HTTP/2 but *not* HTTP/3, so curl
#   must be built from source. Note that `curlimages/curl` is HTTP/3-less too,
#   and every HTTP/3-capable curl image on a registry is a stale personal build
#   -- `ymuski/curl-http3:8.2.1` dates from 2022 -- so this is the only route to
#   testing a current curl over HTTP/3.
# - Clone without `git submodule update`: curl's submodules vendor the QUIC
#   libraries for its bundled examples, which this build does not use, and
#   fetching them shallowly fails.
# - The remaining blocker is the CMake configure step: `-DUSE_NGTCP2=ON
#   -DUSE_NGTCP2_TLS=ON -DUSE_NGHTTP3=ON` against curl-8_19_0 exits non-zero
#   without a diagnostic. Capture the full CMake output before changing flags
#   again.
#
# The HTTP/3 *server* side is already verified against a real HTTP/3 client --
# see the curl invocations in ../README.md.

ARG CURL_IMAGE=curlimages/curl:8.21.0

# No packages are installed here on purpose: `curlimages/curl` runs as a
# non-root user, so `apk add` cannot run in this stage. Everything the driver
# needs (curl, sha256sum, awk, printf) is already present; sha256sum and awk come
# from busybox.
FROM ${CURL_IMAGE} AS driver
COPY --chmod=0755 clients/curl-driver.sh /usr/local/bin/interop-driver
ENTRYPOINT ["/usr/local/bin/interop-driver"]
