# Go driver image: net/http plus x/net/http2 for h2c.
#
# Go's HPACK encoder (x/net/http2/hpack) is the third independent encoder in
# the matrix, after nghttp2-via-curl and the in-repo codec, and its flow
# control strategy differs from both. The version pins are deliberate: a moving
# toolchain or x/net would turn an upstream change into an unexplained failure.

FROM golang:1.27-alpine AS build
WORKDIR /src
COPY clients/go.mod clients/go.sum clients/go-driver.go ./
RUN go mod download && CGO_ENABLED=0 go build -o /out/interop-driver ./go-driver.go

FROM alpine:3.24 AS driver
COPY --from=build /out/interop-driver /usr/local/bin/interop-driver
ENTRYPOINT ["/usr/local/bin/interop-driver"]
