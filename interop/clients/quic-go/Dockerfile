# quic-go driver image: the Go HTTP/3 stack behind Caddy and many CDNs.
#
# quic-go v0.63 needs Go 1.26+, hence the newer toolchain image than the
# net/http driver uses. Versions are pinned (toolchain, quic-go, go.sum) so an
# upstream release cannot turn into an unexplained failure here.

FROM golang:1.27-alpine AS build
WORKDIR /src
COPY . ./
RUN go mod download && CGO_ENABLED=0 go build -o /out/interop-driver ./main.go

FROM alpine:3.24 AS driver
RUN apk add --no-cache ca-certificates
COPY --from=build /out/interop-driver /usr/local/bin/interop-driver
ENTRYPOINT ["/usr/local/bin/interop-driver"]
