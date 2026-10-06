# `zincio-http` interop harness

Drives **real, third-party HTTP clients** against the native `zincio-http`
server, so that bugs a from-scratch HTTP/2 or HTTP/3 implementation can have --
but a same-implementation test client cannot see -- are caught before release.

This crate lives **outside the main workspace**. It depends on the library by
path (exactly like `../fuzz`), which gives it its own `Cargo.lock` and `target/`
and keeps `testcontainers` and the client image build out of the published
crate's dependency tree.

## Why this exists

Every bug in `zincio-http`'s changelog that a *real external* client found
escaped the automated suite:

| Version | Bug | Found by |
| --- | --- | --- |
| 0.4.2 | max-frame-size `SETTINGS` asymmetry -> frame-size mismatch | libnghttp2 |
| 0.4.2 | `curl: (18) stream 0 reset` on HTTP/3 | curl |
| 0.4.8 | flow-control reset on large response bodies | hyper |

All three are in flow control, `SETTINGS` negotiation, and stream
termination. Those are exactly the areas where two implementations can share
the *same* misreading of an RFC and still agree with each other, so testing
only against an in-repo reference client cannot catch them.

## Layout

| Path | Purpose |
| --- | --- |
| `src/scenario.rs` | The declarative scenario matrix. Single source of truth for what is tested and what is expected. |
| `src/routes.rs` | Request handler serving exactly those scenarios. |
| `src/server.rs` | Starts HTTP/1.1, HTTP/2 (h2c), and HTTP/3 (QUIC) listeners. |
| `src/client.rs` | Driver abstraction plus the normalised observation format every client reports in. |
| `src/container.rs` | `testcontainers`-backed drivers for third-party clients. |
| `tests/h2_smoke.rs` | Container-free consistency check of the matrix itself. |
| `docker/` | Pinned Dockerfiles for clients with no trustworthy prebuilt image. |
| `clients/` | Small client programs copied into images (Go, Node, Python). |

## Design notes

**The matrix is authoritative.** Each scenario declares the status, body
length, and body digest it expects. A client driver only reports *what it
observed*; the Rust harness decides whether that is correct. Otherwise every new
client would re-encode the same expectations and drift.

**Bodies are a repeating `ABCD` pattern.** A repeating 4-byte sequence rather
than a single byte means a SHA-256 over the body detects truncation,
duplication, *and* reordering, while remaining cheap to generate for a 64 MiB
response. The digest is computed by the harness from the same pattern bytes,
so it is never duplicated in a client script.

**The two header scenarios share one limit.** `many_headers` must be accepted
and `big_header_rejected` must be refused by the same
`max_header_list_size`. A unit test asserts both directions, so moving the
limit fails a test instead of quietly changing what either scenario means.

**HTTP/2 is served as h2c, not TLS.** QUIC mandates TLS so HTTP/3 needs a
certificate, but serving HTTP/2 in cleartext keeps container drivers down to a
couple of flags with no trust-anchor configuration.

**Capability negotiation, not hard-coded skips.** Scenarios declare the
[`Capability`](src/scenario.rs) they need; drivers declare what they implement.
The matrix is the intersection, so an unimplemented capability becomes a
reported skip rather than a spurious failure.

## Coverage

Registered clients, and what each can actually observe:

| Client | Protocols | Scenarios |
| --- | --- | --- |
| `curl` (nghttp2) | HTTP/1.1, HTTP/2 | 18 scenario runs |

Not yet covered:

- **HTTP/3 through a container.** The HTTP/3 *server* is verified against a real
  HTTP/3 client (curl with ngtcp2, exact digest match -- see below), but no
  containerised HTTP/3 client is registered yet. Building one requires
  compiling curl from source, and its CMake configure step is unresolved; the
  full recipe is left in `docker/curl/Dockerfile` so the next attempt does not
  have to rediscover it. `KNOWN_UNCOVERED_PROTOCOLS` in `src/clients.rs` names
  this gap explicitly, and a *new* uncovered protocol still fails the suite.
- **Concurrent streams.** Needs a client that can drive several streams at once;
  curl makes one request per invocation. The scenario exists, and `h2spec`
  covers the protocol-level behaviour meanwhile.
- **Response trailers and 103 Early Hints as observed by a client.** curl cannot
  surface either, so those scenarios currently run only in
  `tests/h2_smoke.rs`.

## Running

Server plus an in-process consistency check:

```sh
cargo test
```

Drive the server manually (useful for poking at a client interactively):

```sh
cargo run --bin interop-server -- --h1-port 18080 --h2-port 18081 --h3-port 18443
# prints: h1=18080 h2=18081 h3=18443
#         READY

curl -s http://127.0.0.1:18080/small
curl -s --http2-prior-knowledge http://127.0.0.1:18081/large
curl -sk --http3-only https://localhost:18443/large
```

## CI

`.github/workflows/interop.yml` runs the whole matrix on every pull request.
Client images are built in a separate step so a broken Dockerfile fails with a
clear message rather than as a matrix full of container-start failures, and so
docker's layer cache is warm before the tests start.

`ZINCIO_INTEROP_REQUIRE=1` is set in CI: without it the suite skips itself when
Docker is unreachable, which is convenient for contributors but must not hide a
broken runner.

`ZINCIO_INTEROP_CLIENTS=curl cargo test` restricts the run to named clients, which
is how the cheap lane stays separate from the expensive image builds.

## Gotcha worth knowing

The `h2` crate's `RecvStream` **never replenishes its flow-control window on
its own**. Its documentation is explicit that the caller must call
`flow_control().release_capacity(n)` after consuming data. A driver that
omits this stalls at exactly the advertised window (65535 bytes with the
default settings) and looks like a server-side flow-control bug -- which is
very nearly what it looked like before `tests/h2_smoke.rs` existed. See
`read_response` in that file for the correct pattern.
